//! Canonical packet records and authenticated transmission artifacts.
//!
//! Wire objects are untrusted data. Only `session::Relationship` and
//! `storage::DurableRelationship` may construct a verified-transmission token.

use crate::config::TransmissionProfile;
use crate::crypto::{hash_domain, Hash};
use crate::encoding::encode_deterministic;
use crate::{HashAlgorithm, TraxError};
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransmissionKind {
    Request,
    Response,
}

/// A session proposal bound to the exact current relationship predecessor.
/// It becomes history only with the first fully verified request.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionContext {
    pub version: u8,
    #[serde(with = "serde_bytes")]
    pub relationship_id: Hash,
    pub profile: TransmissionProfile,
    #[serde(with = "serde_bytes")]
    pub initiator: Hash,
    #[serde(with = "serde_bytes")]
    pub responder: Hash,
    #[serde(with = "serde_bytes")]
    pub nonce: Hash,
    pub session_index: u64,
    #[serde(with = "serde_bytes")]
    pub previous_tip: Hash,
    #[serde(with = "serde_bytes")]
    pub previous_history_hash: Hash,
    pub previous_record_count: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PacketEvent {
    pub version: u8,
    #[serde(with = "serde_bytes")]
    pub relationship_id: Hash,
    #[serde(with = "serde_bytes")]
    pub session_id: Hash,
    pub transmission_id: u64,
    #[serde(with = "serde_bytes")]
    pub initiator: Hash,
    #[serde(with = "serde_bytes")]
    pub sender: Hash,
    #[serde(with = "serde_bytes")]
    pub receiver: Hash,
    pub key_epoch: u64,
    pub kind: TransmissionKind,
    pub message_type: String,
    pub packet_index: u32,
    pub counter: u64,
    #[serde(with = "serde_bytes")]
    pub previous_tip: Hash,
    #[serde(with = "serde_bytes")]
    pub payload_hash: Hash,
    pub payload_len: u32,
    pub is_final: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransmissionCommitment {
    pub version: u8,
    pub purpose: String,
    #[serde(with = "serde_bytes")]
    pub relationship_id: Hash,
    #[serde(with = "serde_bytes")]
    pub session_id: Hash,
    pub transmission_id: u64,
    #[serde(with = "serde_bytes")]
    pub initiator: Hash,
    #[serde(with = "serde_bytes")]
    pub sender: Hash,
    #[serde(with = "serde_bytes")]
    pub receiver: Hash,
    pub key_epoch: u64,
    pub kind: TransmissionKind,
    pub message_type: String,
    #[serde(with = "serde_bytes")]
    pub starting_tip: Hash,
    pub first_counter: u64,
    pub last_counter: u64,
    pub packet_count: u32,
    pub payload_bytes: u64,
    #[serde(with = "serde_bytes")]
    pub merkle_root: Hash,
    #[serde(with = "serde_bytes")]
    pub final_event_tip: Hash,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransmissionSeal {
    pub commitment: TransmissionCommitment,
    #[serde(with = "serde_bytes")]
    pub signature: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Packet {
    pub event: PacketEvent,
    #[serde(with = "serde_bytes")]
    pub payload: Vec<u8>,
    pub authentication: Option<TransmissionSeal>,
    /// Present only in packet zero of the session's first request. Its context
    /// is authenticated transitively by that request's final signature.
    pub session_start: Option<SessionContext>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionCloseCommitment {
    pub version: u8,
    pub purpose: String,
    #[serde(with = "serde_bytes")]
    pub relationship_id: Hash,
    #[serde(with = "serde_bytes")]
    pub session_id: Hash,
    pub session_index: u64,
    #[serde(with = "serde_bytes")]
    pub initiator: Hash,
    #[serde(with = "serde_bytes")]
    pub responder: Hash,
    #[serde(with = "serde_bytes")]
    pub final_data_tip: Hash,
    #[serde(with = "serde_bytes")]
    pub session_history_hash: Hash,
    #[serde(with = "serde_bytes")]
    pub relationship_history_hash: Hash,
    pub first_counter: u64,
    pub last_counter: u64,
    pub packet_count: u64,
    pub transmission_id: u64,
    pub terminal_counter: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionTerminal {
    pub commitment: SessionCloseCommitment,
    #[serde(with = "serde_bytes")]
    pub signature: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionCheckpoint {
    #[serde(with = "serde_bytes")]
    pub session_id: Hash,
    pub session_index: u64,
    #[serde(with = "serde_bytes")]
    pub tip: Hash,
    #[serde(with = "serde_bytes")]
    pub history_hash: Hash,
    pub packet_count: u64,
    pub transmission_id: u64,
    pub closed: bool,
}

/// An exact external state pin. Freshness and application transaction coupling
/// belong to the host; possessing this serializable value grants no authority.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RelationshipCheckpoint {
    #[serde(with = "serde_bytes")]
    pub relationship_id: Hash,
    #[serde(with = "serde_bytes")]
    pub tip: Hash,
    #[serde(with = "serde_bytes")]
    pub history_hash: Hash,
    pub record_count: u64,
    pub completed_sessions: u64,
    #[serde(with = "crate::genesis::optional_bytes32")]
    pub last_session_id: Option<Hash>,
    pub active_session: Option<SessionCheckpoint>,
}

/// Only produced after complete Rust admission, and after fsync for durable
/// reception. Intermediate packets cannot construct this token.
#[derive(Debug)]
pub struct VerifiedTransmission {
    packets: Vec<Packet>,
}

impl VerifiedTransmission {
    pub(crate) fn from_packets(packets: Vec<Packet>) -> Self {
        Self { packets }
    }
    pub fn packets(&self) -> &[Packet] {
        &self.packets
    }
    pub fn commitment(&self) -> &TransmissionCommitment {
        &self
            .packets
            .last()
            .expect("verified nonempty transmission")
            .authentication
            .as_ref()
            .expect("verified final authentication")
            .commitment
    }
    pub fn payload(&self) -> Vec<u8> {
        self.packets
            .iter()
            .flat_map(|p| p.payload.iter().copied())
            .collect()
    }
    pub fn payload_chunks(&self) -> impl Iterator<Item = &[u8]> {
        self.packets.iter().map(|p| p.payload.as_slice())
    }
}

pub fn event_tip(algorithm: HashAlgorithm, event: &PacketEvent) -> Result<Hash, TraxError> {
    hash_domain(
        algorithm,
        b"TRAX:EVENT:V3\0",
        &[&encode_deterministic(event)?],
    )
}

pub(crate) fn signing_bytes<T: Serialize>(domain: &[u8], value: &T) -> Result<Vec<u8>, TraxError> {
    let mut bytes = domain.to_vec();
    bytes.extend_from_slice(&encode_deterministic(value)?);
    Ok(bytes)
}
