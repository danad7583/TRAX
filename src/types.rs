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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SegmentProof {
    pub k: u32,
    pub nodes: Vec<DagNode>,
    pub cumulative_hash: [u8; 32],
}

#[derive(Debug, Clone)]
pub struct AcceptanceWindow {
    pub last_seen: u64,
    pub window: u64,
}
