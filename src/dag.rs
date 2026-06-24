//! DAG nodes and K-window segment proofs per §5.1
use crate::types::{DagNode, SegmentProof};
use crate::crypto::hash32;

pub fn cumulative_hash(nodes: &[DagNode]) -> [u8;32] {
    let mut acc = [0u8;32];
    for n in nodes {
        let mut enc = Vec::with_capacity(128);
        enc.extend_from_slice(&n.prev_tip_hash);
        enc.extend_from_slice(&n.segment_anchor);
        enc.extend_from_slice(&n.index.to_le_bytes());
        enc.extend_from_slice(&n.ts.to_le_bytes());
        enc.push(n.op_type);
        enc.extend_from_slice(&n.peer_id);
        enc.extend_from_slice(&n.counter.to_le_bytes());
        enc.extend_from_slice(&n.signature);
        let h = hash32(&enc);
        for (i,b) in h.iter().enumerate() { acc[i] ^= b; }
    }
    acc
}

pub fn verify_segment_proof(p: &SegmentProof) -> bool {
    if p.nodes.len() != p.k as usize { return false; }
    cumulative_hash(&p.nodes) == p.cumulative_hash
}
