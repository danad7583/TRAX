//! Three-record genesis with explicit caller authorization.
//!
//! Signatures establish key possession; the trust callback separately decides
//! which identities the host authorizes. Nonce freshness and retirement policy
//! belong to that host. Other proof schemas cannot replace this
//! transcript or change its pinned participant keys.

use ed25519_dalek::{SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::config::{TransmissionProfile, GENESIS_SCHEMA_VERSION};
use crate::crypto::{ed25519_sign, ed25519_verify, hash_domain};
use crate::encoding::encode_deterministic;
use crate::TraxError;

const GENESIS_DOMAIN: &[u8] = b"TRAX:GENESIS:V2\0";
const NODE_DOMAIN: &[u8] = b"TRAX:GENESIS:NODE:V2\0";
const ANCHOR_DOMAIN: &[u8] = b"TRAX:GENESIS:ANCHOR:V2\0";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GenesisStep {
    Offer,
    Accept,
    Confirm,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GenesisEvent {
    pub version: u8,
    pub step: GenesisStep,
    #[serde(with = "bytes32")]
    pub previous_tip: [u8; 32],
    #[serde(with = "bytes32")]
    pub nonce: [u8; 32],
    #[serde(with = "bytes32")]
    pub initiator_public_key: [u8; 32],
    #[serde(with = "optional_bytes32")]
    pub responder_public_key: Option<[u8; 32]>,
    pub profile: TransmissionProfile,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GenesisNode {
    pub event: GenesisEvent,
    #[serde(with = "serde_bytes")]
    pub signature: Vec<u8>,
}

/// A transcript identifier alone is not authentication or caller authorization.
pub fn genesis_node_id(node: &GenesisNode) -> Result<[u8; 32], TraxError> {
    node.event.profile.validate()?;
    hash_encoded(&node.event.profile, NODE_DOMAIN, node)
}

pub fn create_genesis_offer(
    key: &SigningKey,
    nonce: [u8; 32],
    profile: TransmissionProfile,
) -> Result<GenesisNode, TraxError> {
    profile.validate()?;
    checked_key(&key.verifying_key().to_bytes())?;
    sign_event(
        GenesisEvent {
            version: GENESIS_SCHEMA_VERSION,
            step: GenesisStep::Offer,
            previous_tip: [0; 32],
            nonce,
            initiator_public_key: key.verifying_key().to_bytes(),
            responder_public_key: None,
            profile,
        },
        key,
    )
}

pub fn accept_genesis_offer(
    offer: &GenesisNode,
    key: &SigningKey,
    mut trust: impl FnMut(&[u8; 32]) -> bool,
) -> Result<GenesisNode, TraxError> {
    verify_offer(offer)?;
    let responder = key.verifying_key().to_bytes();
    checked_key(&responder)?;
    if responder == offer.event.initiator_public_key {
        return Err(TraxError::InvalidInput(
            "genesis participants must have distinct keys",
        ));
    }
    authorize(&offer.event.initiator_public_key, &mut trust)?;
    let mut event = offer.event.clone();
    event.step = GenesisStep::Accept;
    event.previous_tip = genesis_node_id(offer)?;
    event.responder_public_key = Some(responder);
    sign_event(event, key)
}

pub fn confirm_genesis(
    offer: &GenesisNode,
    acceptance: &GenesisNode,
    key: &SigningKey,
    mut trust: impl FnMut(&[u8; 32]) -> bool,
) -> Result<GenesisNode, TraxError> {
    let responder = verify_offer_and_acceptance(offer, acceptance)?;
    if key.verifying_key().to_bytes() != offer.event.initiator_public_key {
        return Err(TraxError::SignerMismatch);
    }
    authorize(&responder, &mut trust)?;
    let mut event = acceptance.event.clone();
    event.step = GenesisStep::Confirm;
    event.previous_tip = genesis_node_id(acceptance)?;
    sign_event(event, key)
}

/// Fully authenticated and explicitly authorized genesis. No deserialize or
/// unchecked constructor exists, and its shared anchor covers all three signed
/// records. Verification does not establish freshness against a rolled-back host.
#[derive(Debug, Clone)]
pub struct VerifiedGenesis {
    nodes: [GenesisNode; 3],
    anchor: [u8; 32],
}

impl VerifiedGenesis {
    pub fn verify(
        nodes: [GenesisNode; 3],
        mut trust: impl FnMut(&[u8; 32]) -> bool,
    ) -> Result<Self, TraxError> {
        let responder = verify_offer_and_acceptance(&nodes[0], &nodes[1])?;
        let confirmation = &nodes[2];
        verify_event_shape(&confirmation.event)?;
        if confirmation.event.step != GenesisStep::Confirm
            || !same_parameters(&nodes[1].event, &confirmation.event)
            || confirmation.event.responder_public_key != Some(responder)
        {
            return Err(TraxError::InvalidInput(
                "genesis confirmation context mismatch",
            ));
        }
        if confirmation.event.previous_tip != genesis_node_id(&nodes[1])? {
            return Err(TraxError::RelationshipMismatch);
        }
        verify_signature(confirmation, &nodes[0].event.initiator_public_key)?;
        // Never invoke caller policy on a transcript that has failed its
        // structural, profile, linkage or cryptographic verification.
        authorize(&nodes[0].event.initiator_public_key, &mut trust)?;
        authorize(&responder, &mut trust)?;
        let anchor = hash_encoded(&nodes[0].event.profile, ANCHOR_DOMAIN, &nodes)?;
        Ok(Self { nodes, anchor })
    }

    pub fn nodes(&self) -> &[GenesisNode; 3] {
        &self.nodes
    }
    pub fn anchor(&self) -> [u8; 32] {
        self.anchor
    }
    pub fn profile(&self) -> &TransmissionProfile {
        &self.nodes[0].event.profile
    }
    pub fn initiator_key(&self) -> [u8; 32] {
        self.nodes[0].event.initiator_public_key
    }
    pub fn responder_key(&self) -> [u8; 32] {
        self.nodes[1]
            .event
            .responder_public_key
            .expect("verified responder key")
    }
}

fn hash_encoded<T: Serialize>(
    profile: &TransmissionProfile,
    domain: &[u8],
    value: &T,
) -> Result<[u8; 32], TraxError> {
    let encoded = encode_deterministic(value)?;
    hash_domain(profile.hash_algorithm, domain, &[&encoded])
}

fn checked_key(bytes: &[u8; 32]) -> Result<VerifyingKey, TraxError> {
    let key = VerifyingKey::from_bytes(bytes).map_err(|_| TraxError::Crypto)?;
    if key.is_weak() {
        return Err(TraxError::Crypto);
    }
    Ok(key)
}

fn event_signing_bytes(event: &GenesisEvent) -> Result<Vec<u8>, TraxError> {
    let encoded = encode_deterministic(event)?;
    let mut bytes = Vec::with_capacity(GENESIS_DOMAIN.len() + encoded.len());
    bytes.extend_from_slice(GENESIS_DOMAIN);
    bytes.extend_from_slice(&encoded);
    Ok(bytes)
}

fn sign_event(event: GenesisEvent, key: &SigningKey) -> Result<GenesisNode, TraxError> {
    let signature = ed25519_sign(key, &event_signing_bytes(&event)?);
    Ok(GenesisNode { event, signature })
}

fn verify_signature(node: &GenesisNode, expected_key: &[u8; 32]) -> Result<(), TraxError> {
    if node.signature.len() != 64
        || !ed25519_verify(
            &checked_key(expected_key)?,
            &event_signing_bytes(&node.event)?,
            &node.signature,
        )
    {
        return Err(TraxError::BadSignature);
    }
    Ok(())
}

fn verify_event_shape(event: &GenesisEvent) -> Result<(), TraxError> {
    if event.version != GENESIS_SCHEMA_VERSION {
        return Err(TraxError::InvalidInput("unsupported genesis event version"));
    }
    event.profile.validate()?;
    checked_key(&event.initiator_public_key)?;
    if let Some(responder) = event.responder_public_key {
        checked_key(&responder)?;
        if responder == event.initiator_public_key {
            return Err(TraxError::InvalidInput(
                "genesis participants must have distinct keys",
            ));
        }
    }
    Ok(())
}

fn verify_offer(offer: &GenesisNode) -> Result<(), TraxError> {
    verify_event_shape(&offer.event)?;
    if offer.event.step != GenesisStep::Offer
        || offer.event.previous_tip != [0; 32]
        || offer.event.responder_public_key.is_some()
    {
        return Err(TraxError::InvalidInput("invalid genesis offer shape"));
    }
    verify_signature(offer, &offer.event.initiator_public_key)
}

fn same_parameters(first: &GenesisEvent, second: &GenesisEvent) -> bool {
    first.version == second.version
        && first.nonce == second.nonce
        && first.initiator_public_key == second.initiator_public_key
        && first.profile == second.profile
}

fn verify_offer_and_acceptance(
    offer: &GenesisNode,
    acceptance: &GenesisNode,
) -> Result<[u8; 32], TraxError> {
    verify_offer(offer)?;
    verify_event_shape(&acceptance.event)?;
    let responder = acceptance
        .event
        .responder_public_key
        .ok_or(TraxError::InvalidInput(
            "genesis acceptance needs a responder key",
        ))?;
    if acceptance.event.step != GenesisStep::Accept
        || !same_parameters(&offer.event, &acceptance.event)
    {
        return Err(TraxError::InvalidInput(
            "genesis acceptance context mismatch",
        ));
    }
    if acceptance.event.previous_tip != genesis_node_id(offer)? {
        return Err(TraxError::RelationshipMismatch);
    }
    verify_signature(acceptance, &responder)?;
    Ok(responder)
}

fn authorize(key: &[u8; 32], trust: &mut impl FnMut(&[u8; 32]) -> bool) -> Result<(), TraxError> {
    if !trust(key) {
        return Err(TraxError::InvalidInput(
            "genesis identity is not authorized by caller",
        ));
    }
    Ok(())
}

/// Exact byte-string representation shared by protocol hashes, keys and nonces.
pub(crate) mod bytes32 {
    use serde::{
        de::{Error, Visitor},
        Deserializer, Serializer,
    };
    use std::fmt;

    pub fn serialize<S: Serializer>(value: &[u8; 32], serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_bytes(value)
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<[u8; 32], D::Error> {
        struct Bytes32Visitor;
        impl<'de> Visitor<'de> for Bytes32Visitor {
            type Value = [u8; 32];
            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a byte string of exactly 32 bytes")
            }
            fn visit_bytes<E: Error>(self, value: &[u8]) -> Result<Self::Value, E> {
                value
                    .try_into()
                    .map_err(|_| E::invalid_length(value.len(), &self))
            }
            fn visit_byte_buf<E: Error>(self, value: Vec<u8>) -> Result<Self::Value, E> {
                self.visit_bytes(&value)
            }
        }
        deserializer.deserialize_bytes(Bytes32Visitor)
    }
}

pub(crate) mod optional_bytes32 {
    use serde::{de::Visitor, Deserializer, Serializer};
    use std::fmt;

    pub fn serialize<S: Serializer>(
        value: &Option<[u8; 32]>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        match value {
            Some(bytes) => serializer.serialize_some(serde_bytes::Bytes::new(bytes)),
            None => serializer.serialize_none(),
        }
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Option<[u8; 32]>, D::Error> {
        struct OptionalBytes32Visitor;
        impl<'de> Visitor<'de> for OptionalBytes32Visitor {
            type Value = Option<[u8; 32]>;
            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("null or a byte string of exactly 32 bytes")
            }
            fn visit_none<E: serde::de::Error>(self) -> Result<Self::Value, E> {
                Ok(None)
            }
            fn visit_unit<E: serde::de::Error>(self) -> Result<Self::Value, E> {
                Ok(None)
            }
            fn visit_some<D: Deserializer<'de>>(
                self,
                deserializer: D,
            ) -> Result<Self::Value, D::Error> {
                super::bytes32::deserialize(deserializer).map(Some)
            }
        }
        deserializer.deserialize_option(OptionalBytes32Visitor)
    }
}
