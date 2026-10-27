//! K-free, three-record V2 genesis with explicit caller authorization.
//!
//! Signatures establish key possession; the trust callback separately decides
//! which identities the host authorizes. Nonce freshness and retirement policy
//! belong to that host. Legacy Packet 0 and rotation proofs cannot replace this
//! transcript or change its pinned participant keys.

use ed25519_dalek::{SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::config::{HashAlgorithm, SigningAlgorithm};
use crate::crypto::{ed25519_sign, ed25519_verify};
use crate::encoding::encode_deterministic;
use crate::transmission_crypto::hash_v2;
use crate::TraxError;

pub const TRANSMISSION_VERSION_V2: u8 = 2;
pub const MAX_TRANSMISSION_PACKETS_V2: u32 = 1_048_576;
pub const MAX_TRANSMISSION_PAYLOAD_BYTES_V2: u64 = 256 * 1024 * 1024;
pub const MAX_WIRE_PACKET_BYTES_V2: u32 = 1024 * 1024;
pub const MAX_TRANSMISSION_TIMEOUT_MS_V2: u64 = 24 * 60 * 60 * 1000;

const GENESIS_DOMAIN: &[u8] = b"TRAX:GENESIS:V2\0";
const NODE_DOMAIN: &[u8] = b"TRAX:GENESIS:NODE:V2\0";
const ANCHOR_DOMAIN: &[u8] = b"TRAX:GENESIS:ANCHOR:V2\0";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransmissionLimitsV2 {
    pub max_packets: u32,
    pub max_payload_bytes: u64,
    pub max_packet_payload_bytes: u32,
    pub max_wire_packet_bytes: u32,
    pub timeout_ms: u64,
}

impl Default for TransmissionLimitsV2 {
    fn default() -> Self {
        Self {
            max_packets: 16_384,
            max_payload_bytes: 16 * 1024 * 1024,
            max_packet_payload_bytes: 1400,
            max_wire_packet_bytes: 4096,
            timeout_ms: 30_000,
        }
    }
}

impl TransmissionLimitsV2 {
    pub fn validate(&self) -> Result<(), TraxError> {
        if self.max_packets == 0 || self.max_packets > MAX_TRANSMISSION_PACKETS_V2 {
            return Err(TraxError::InvalidInput(
                "V2 packet-count limit is out of bounds",
            ));
        }
        if self.max_payload_bytes == 0 || self.max_payload_bytes > MAX_TRANSMISSION_PAYLOAD_BYTES_V2
        {
            return Err(TraxError::InvalidInput(
                "V2 transmission payload limit is out of bounds",
            ));
        }
        if self.max_wire_packet_bytes == 0 || self.max_wire_packet_bytes > MAX_WIRE_PACKET_BYTES_V2
        {
            return Err(TraxError::InvalidInput(
                "V2 encoded-packet limit is out of bounds",
            ));
        }
        if self.max_packet_payload_bytes == 0
            || u64::from(self.max_packet_payload_bytes) > self.max_payload_bytes
            || self.max_packet_payload_bytes > self.max_wire_packet_bytes
        {
            return Err(TraxError::InvalidInput(
                "V2 per-packet payload limit is out of bounds",
            ));
        }
        if self.timeout_ms == 0 || self.timeout_ms > MAX_TRANSMISSION_TIMEOUT_MS_V2 {
            return Err(TraxError::InvalidInput(
                "V2 provisional timeout is out of bounds",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransmissionProfileV2 {
    pub version: u8,
    pub signing_algorithm: SigningAlgorithm,
    pub hash_algorithm: HashAlgorithm,
    pub limits: TransmissionLimitsV2,
}

impl Default for TransmissionProfileV2 {
    fn default() -> Self {
        Self {
            version: TRANSMISSION_VERSION_V2,
            signing_algorithm: SigningAlgorithm::Ed25519,
            hash_algorithm: HashAlgorithm::Sha512256,
            limits: TransmissionLimitsV2::default(),
        }
    }
}

impl TransmissionProfileV2 {
    pub fn validate(&self) -> Result<(), TraxError> {
        if self.version != TRANSMISSION_VERSION_V2 {
            return Err(TraxError::InvalidInput(
                "unsupported transmission profile version",
            ));
        }
        match self.signing_algorithm {
            SigningAlgorithm::Ed25519 if !cfg!(feature = "crypto-ed25519") => {
                return Err(TraxError::UnsupportedAlgorithm);
            }
            SigningAlgorithm::Ed25519 => {}
        }
        match self.hash_algorithm {
            HashAlgorithm::Blake3 if !cfg!(feature = "hash-blake3") => {
                return Err(TraxError::UnsupportedAlgorithm);
            }
            HashAlgorithm::Blake3 | HashAlgorithm::Sha512256 => {}
        }
        self.limits.validate()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GenesisStepV2 {
    Offer,
    Accept,
    Confirm,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GenesisEventV2 {
    pub version: u8,
    pub step: GenesisStepV2,
    #[serde(with = "bytes32")]
    pub previous_tip: [u8; 32],
    #[serde(with = "bytes32")]
    pub nonce: [u8; 32],
    #[serde(with = "bytes32")]
    pub initiator_public_key: [u8; 32],
    #[serde(with = "optional_bytes32")]
    pub responder_public_key: Option<[u8; 32]>,
    pub profile: TransmissionProfileV2,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GenesisNodeV2 {
    pub event: GenesisEventV2,
    #[serde(with = "serde_bytes")]
    pub signature: Vec<u8>,
}

/// A transcript identifier alone is not authentication or caller authorization.
pub fn genesis_node_id(node: &GenesisNodeV2) -> Result<[u8; 32], TraxError> {
    node.event.profile.validate()?;
    hash_encoded(&node.event.profile, NODE_DOMAIN, node)
}

pub fn create_genesis_offer(
    key: &SigningKey,
    nonce: [u8; 32],
    profile: TransmissionProfileV2,
) -> Result<GenesisNodeV2, TraxError> {
    profile.validate()?;
    checked_key(&key.verifying_key().to_bytes())?;
    sign_event(
        GenesisEventV2 {
            version: TRANSMISSION_VERSION_V2,
            step: GenesisStepV2::Offer,
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
    offer: &GenesisNodeV2,
    key: &SigningKey,
    mut trust: impl FnMut(&[u8; 32]) -> bool,
) -> Result<GenesisNodeV2, TraxError> {
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
    event.step = GenesisStepV2::Accept;
    event.previous_tip = genesis_node_id(offer)?;
    event.responder_public_key = Some(responder);
    sign_event(event, key)
}

pub fn confirm_genesis(
    offer: &GenesisNodeV2,
    acceptance: &GenesisNodeV2,
    key: &SigningKey,
    mut trust: impl FnMut(&[u8; 32]) -> bool,
) -> Result<GenesisNodeV2, TraxError> {
    let responder = verify_offer_and_acceptance(offer, acceptance)?;
    if key.verifying_key().to_bytes() != offer.event.initiator_public_key {
        return Err(TraxError::SignerMismatch);
    }
    authorize(&responder, &mut trust)?;
    let mut event = acceptance.event.clone();
    event.step = GenesisStepV2::Confirm;
    event.previous_tip = genesis_node_id(acceptance)?;
    sign_event(event, key)
}

/// Fully authenticated and explicitly authorized V2 genesis. No deserialize or
/// unchecked constructor exists, and its shared anchor covers all three signed
/// records. Verification does not establish freshness against a rolled-back host.
#[derive(Debug, Clone)]
pub struct VerifiedGenesisV2 {
    nodes: [GenesisNodeV2; 3],
    anchor: [u8; 32],
}

impl VerifiedGenesisV2 {
    pub fn verify(
        nodes: [GenesisNodeV2; 3],
        mut trust: impl FnMut(&[u8; 32]) -> bool,
    ) -> Result<Self, TraxError> {
        let responder = verify_offer_and_acceptance(&nodes[0], &nodes[1])?;
        let confirmation = &nodes[2];
        verify_event_shape(&confirmation.event)?;
        if confirmation.event.step != GenesisStepV2::Confirm
            || !same_parameters(&nodes[1].event, &confirmation.event)
            || confirmation.event.responder_public_key != Some(responder)
        {
            return Err(TraxError::InvalidInput(
                "genesis confirmation context mismatch",
            ));
        }
        if confirmation.event.previous_tip != genesis_node_id(&nodes[1])? {
            return Err(TraxError::TipMismatch);
        }
        verify_signature(confirmation, &nodes[0].event.initiator_public_key)?;
        // Never invoke caller policy on a transcript that has failed its
        // structural, profile, linkage or cryptographic verification.
        authorize(&nodes[0].event.initiator_public_key, &mut trust)?;
        authorize(&responder, &mut trust)?;
        let anchor = hash_encoded(&nodes[0].event.profile, ANCHOR_DOMAIN, &nodes)?;
        Ok(Self { nodes, anchor })
    }

    pub fn nodes(&self) -> &[GenesisNodeV2; 3] {
        &self.nodes
    }
    pub fn anchor(&self) -> [u8; 32] {
        self.anchor
    }
    pub fn profile(&self) -> &TransmissionProfileV2 {
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
    profile: &TransmissionProfileV2,
    domain: &[u8],
    value: &T,
) -> Result<[u8; 32], TraxError> {
    let encoded = encode_deterministic(value)?;
    hash_v2(profile.hash_algorithm, domain, &[&encoded])
}

fn checked_key(bytes: &[u8; 32]) -> Result<VerifyingKey, TraxError> {
    let key = VerifyingKey::from_bytes(bytes).map_err(|_| TraxError::Crypto)?;
    if key.is_weak() {
        return Err(TraxError::Crypto);
    }
    Ok(key)
}

fn event_signing_bytes(event: &GenesisEventV2) -> Result<Vec<u8>, TraxError> {
    let encoded = encode_deterministic(event)?;
    let mut bytes = Vec::with_capacity(GENESIS_DOMAIN.len() + encoded.len());
    bytes.extend_from_slice(GENESIS_DOMAIN);
    bytes.extend_from_slice(&encoded);
    Ok(bytes)
}

fn sign_event(event: GenesisEventV2, key: &SigningKey) -> Result<GenesisNodeV2, TraxError> {
    let signature = ed25519_sign(key, &event_signing_bytes(&event)?);
    Ok(GenesisNodeV2 { event, signature })
}

fn verify_signature(node: &GenesisNodeV2, expected_key: &[u8; 32]) -> Result<(), TraxError> {
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

fn verify_event_shape(event: &GenesisEventV2) -> Result<(), TraxError> {
    if event.version != TRANSMISSION_VERSION_V2 {
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

fn verify_offer(offer: &GenesisNodeV2) -> Result<(), TraxError> {
    verify_event_shape(&offer.event)?;
    if offer.event.step != GenesisStepV2::Offer
        || offer.event.previous_tip != [0; 32]
        || offer.event.responder_public_key.is_some()
    {
        return Err(TraxError::InvalidInput("invalid genesis offer shape"));
    }
    verify_signature(offer, &offer.event.initiator_public_key)
}

fn same_parameters(first: &GenesisEventV2, second: &GenesisEventV2) -> bool {
    first.version == second.version
        && first.nonce == second.nonce
        && first.initiator_public_key == second.initiator_public_key
        && first.profile == second.profile
}

fn verify_offer_and_acceptance(
    offer: &GenesisNodeV2,
    acceptance: &GenesisNodeV2,
) -> Result<[u8; 32], TraxError> {
    verify_offer(offer)?;
    verify_event_shape(&acceptance.event)?;
    let responder = acceptance
        .event
        .responder_public_key
        .ok_or(TraxError::InvalidInput(
            "genesis acceptance needs a responder key",
        ))?;
    if acceptance.event.step != GenesisStepV2::Accept
        || !same_parameters(&offer.event, &acceptance.event)
    {
        return Err(TraxError::InvalidInput(
            "genesis acceptance context mismatch",
        ));
    }
    if acceptance.event.previous_tip != genesis_node_id(offer)? {
        return Err(TraxError::TipMismatch);
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

/// Exact byte-string representation shared by V2 hashes, keys and nonces.
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

mod optional_bytes32 {
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
