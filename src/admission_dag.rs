//! Local in-memory DAG admission path for verified Packet 0 envelopes.

use crate::admission::{decode_admission_envelope_v1, verify_admission_envelope_v1_for_receiver};
use crate::crypto::hash32;
use crate::encoding::encode_deterministic;
use crate::errors::TraxError;
use crate::types::DagNode;
use serde::{Deserialize, Serialize};

pub const PACKET0_ADMISSION_OP: u8 = 0;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AdmittedPacket0Event {
    pub envelope_hash: Vec<u8>,
    pub sender_public_key: Vec<u8>,
    pub receiver_public_key: Vec<u8>,
    pub session_id: Vec<u8>,
    pub nonce: Vec<u8>,
    pub payload_hash: Vec<u8>,
    pub message_type: String,
    pub proof_type: String,
    pub dag_parent_refs: Vec<Vec<u8>>,
}

#[derive(Debug, Clone)]
pub struct AdmittedPacket0Node {
    pub node_id: [u8; 32],
    pub event: AdmittedPacket0Event,
    pub dag_node: DagNode,
}

#[derive(Debug, Default)]
pub struct LocalAdmissionDag {
    nodes: Vec<AdmittedPacket0Node>,
    tip_hash: [u8; 32],
}

impl LocalAdmissionDag {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    pub fn nodes(&self) -> &[AdmittedPacket0Node] {
        &self.nodes
    }

    pub fn admit_packet0(
        &mut self,
        envelope: &[u8],
        payload: &[u8],
        receiver_public_key: &[u8],
    ) -> Result<[u8; 32], TraxError> {
        if !verify_admission_envelope_v1_for_receiver(envelope, payload, receiver_public_key)? {
            return Err(TraxError::BadSignature);
        }

        let envelope = decode_admission_envelope_v1(envelope)?;
        let envelope_bytes = encode_deterministic(&envelope)?;
        let event = AdmittedPacket0Event {
            envelope_hash: hash32(&envelope_bytes).to_vec(),
            sender_public_key: envelope.sender_public_key.clone(),
            receiver_public_key: envelope.receiver_public_key.clone(),
            session_id: envelope.session_id.clone(),
            nonce: envelope.nonce.clone(),
            payload_hash: envelope.payload_hash.clone(),
            message_type: envelope.message_type.clone(),
            proof_type: envelope.proof_type.clone(),
            dag_parent_refs: envelope.dag_parent_refs.clone(),
        };

        let event_bytes = encode_deterministic(&event)?;
        let node_id = hash32(&event_bytes);
        let dag_node = DagNode {
            prev_tip_hash: self.tip_hash,
            segment_anchor: node_id,
            index: self.nodes.len() as u64,
            ts: 0,
            op_type: PACKET0_ADMISSION_OP,
            peer_id: peer_id_from_public_key(&event.sender_public_key),
            counter: self.nodes.len() as u64,
            signature: envelope.signature,
        };

        self.tip_hash = node_id;
        self.nodes.push(AdmittedPacket0Node {
            node_id,
            event,
            dag_node,
        });

        Ok(node_id)
    }
}

fn peer_id_from_public_key(public_key: &[u8]) -> [u8; 16] {
    let hash = hash32(public_key);
    let mut peer_id = [0u8; 16];
    peer_id.copy_from_slice(&hash[..16]);
    peer_id
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::admission::{
        create_admission_envelope_v1, decode_admission_envelope_v1, HASH_LEN, NONCE_LEN,
    };
    use crate::encoding::encode_deterministic;
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    struct Packet0Fixture {
        sender: SigningKey,
        receiver: SigningKey,
        wrong_receiver: SigningKey,
        envelope: Vec<u8>,
        payload: Vec<u8>,
        parent_ref: Vec<u8>,
    }

    fn fixture() -> Packet0Fixture {
        let mut rng = OsRng;
        let sender = SigningKey::generate(&mut rng);
        let receiver = SigningKey::generate(&mut rng);
        let wrong_receiver = SigningKey::generate(&mut rng);
        let payload = b"packet zero payload".to_vec();
        let session_id = hash32(b"session transcript");
        let nonce = [9u8; NONCE_LEN];
        let parent_ref = hash32(b"parent").to_vec();
        let envelope = create_admission_envelope_v1(
            &sender,
            receiver.verifying_key().as_bytes(),
            &session_id,
            &nonce,
            &payload,
            "packet0.admission",
            &[parent_ref.clone()],
            "direct-ed25519",
        )
        .expect("fixture envelope should encode");

        Packet0Fixture {
            sender,
            receiver,
            wrong_receiver,
            envelope,
            payload,
            parent_ref,
        }
    }

    #[test]
    fn valid_packet0_appends_one_dag_admission_node() {
        let f = fixture();
        let mut dag = LocalAdmissionDag::new();

        assert!(dag.is_empty());
        let node_id = dag
            .admit_packet0(
                &f.envelope,
                &f.payload,
                f.receiver.verifying_key().as_bytes(),
            )
            .unwrap();

        assert_eq!(dag.len(), 1);
        assert_eq!(dag.nodes()[0].node_id, node_id);
        assert_eq!(
            dag.nodes()[0].event.sender_public_key,
            f.sender.verifying_key().as_bytes()
        );
        assert_eq!(dag.nodes()[0].dag_node.op_type, PACKET0_ADMISSION_OP);
    }

    #[test]
    fn returned_admission_hash_is_stable_for_same_packet0_input() {
        let f = fixture();
        let mut left = LocalAdmissionDag::new();
        let mut right = LocalAdmissionDag::new();

        let left_id = left
            .admit_packet0(
                &f.envelope,
                &f.payload,
                f.receiver.verifying_key().as_bytes(),
            )
            .unwrap();
        let right_id = right
            .admit_packet0(
                &f.envelope,
                &f.payload,
                f.receiver.verifying_key().as_bytes(),
            )
            .unwrap();

        assert_eq!(left_id, right_id);
    }

    #[test]
    fn tampered_payload_rejects_without_append() {
        let f = fixture();
        let mut dag = LocalAdmissionDag::new();

        assert!(dag
            .admit_packet0(
                &f.envelope,
                b"tampered",
                f.receiver.verifying_key().as_bytes(),
            )
            .is_err());
        assert!(dag.is_empty());
    }

    #[test]
    fn wrong_receiver_rejects_without_append() {
        let f = fixture();
        let mut dag = LocalAdmissionDag::new();

        assert!(dag
            .admit_packet0(
                &f.envelope,
                &f.payload,
                f.wrong_receiver.verifying_key().as_bytes(),
            )
            .is_err());
        assert!(dag.is_empty());
    }

    #[test]
    fn malformed_envelope_rejects_without_append() {
        let f = fixture();
        let mut decoded = decode_admission_envelope_v1(&f.envelope).unwrap();
        decoded.sender_public_key = vec![0u8; HASH_LEN - 1];
        let malformed = encode_deterministic(&decoded).unwrap();
        let mut dag = LocalAdmissionDag::new();

        assert!(dag
            .admit_packet0(
                &malformed,
                &f.payload,
                f.receiver.verifying_key().as_bytes(),
            )
            .is_err());
        assert!(dag.is_empty());
    }

    #[test]
    fn packet0_parent_refs_are_preserved_in_admitted_event() {
        let f = fixture();
        let mut dag = LocalAdmissionDag::new();

        dag.admit_packet0(
            &f.envelope,
            &f.payload,
            f.receiver.verifying_key().as_bytes(),
        )
        .unwrap();

        assert_eq!(dag.nodes()[0].event.dag_parent_refs, vec![f.parent_ref]);
    }
}
