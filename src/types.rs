use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtectedHeaders {
    pub aaip_ver: String,
    pub trax_ver: String,
    pub alg: String,
    pub kid: Vec<u8>,
    pub msg_type: String,
    pub schema_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AaipMessage {
    pub agent_id: String,
    pub timestamp: String, // RFC3339
    pub nonce: Vec<u8>,
    pub counter: u64,
    pub session_id: Vec<u8>,
    pub payload: serde_bytes::ByteBuf,
    pub key_rotation_block: Option<RotationBlock>,
    pub signature: Vec<u8>, // COSE_Sign1 bytes
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RotationBlock {
    pub new_pubkey: Vec<u8>,
    pub signed_by_old: Vec<u8>,
    pub ts: String,
    pub meta: Option<serde_bytes::ByteBuf>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DagNode {
    pub prev_tip_hash: [u8; 32],
    pub segment_anchor: [u8; 32],
    pub index: u64,
    pub ts: u64,
    pub op_type: u8,
    pub peer_id: [u8; 16],
    pub counter: u64,
    pub signature: Vec<u8>,
}

/// A normal post-genesis event. Its tip is the domain-separated hash of its
/// deterministic encoding; the payload itself may be stored out of band.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PostGenesisEventV1 {
    pub version: u8,
    pub session_id: [u8; 32],
    pub lineage_key_id: [u8; 32],
    pub receiver_id: [u8; 32],
    pub segment_index: u64,
    pub counter: u64,
    pub previous_tip: [u8; 32],
    pub content_hash: [u8; 32],
    pub payload_hash: [u8; 32],
}

/// Canonical, versioned context authenticated by a segment signature.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SegmentCommitmentV1 {
    pub version: u8,
    pub k: u32,
    pub session_id: [u8; 32],
    pub segment_index: u64,
    pub first_counter: u64,
    pub last_counter: u64,
    pub starting_committed_tip: [u8; 32],
    pub final_provisional_tip: [u8; 32],
    pub ordered_merkle_root: [u8; 32],
    pub lineage_key_id: [u8; 32],
    pub receiver_id: [u8; 32],
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SegmentSealV1 {
    pub commitment: SegmentCommitmentV1,
    pub signature: Vec<u8>,
}

/// A proof is the ordered events plus their signed, context-bound seal.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SegmentProof {
    pub events: Vec<PostGenesisEventV1>,
    pub seal: SegmentSealV1,
}

#[derive(Debug, Clone)]
pub struct AcceptanceWindow {
    pub last_seen: u64,
    pub window: u64,
}
