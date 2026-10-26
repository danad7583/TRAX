//! Local in-memory DAG admission path for verified Packet 0 envelopes.

use crate::admission::{decode_admission_envelope_v1, verify_admission_envelope_v1_for_receiver};
use crate::config::SegmentConfig;
use crate::crypto::hash32;
use crate::dag::{receiver_id, TrustedSessionContext};
use crate::encoding::encode_deterministic;
use crate::errors::TraxError;
use crate::types::DagNode;
use ed25519_dalek::VerifyingKey;
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

#[derive(Debug)]
pub struct LocalAdmissionDag {
    config: SegmentConfig,
    nodes: Vec<AdmittedPacket0Node>,
    tip_hash: [u8; 32],
}

impl LocalAdmissionDag {
    pub fn new(config: SegmentConfig) -> Self {
        Self {
            config,
            nodes: Vec::new(),
            tip_hash: [0; 32],
        }
    }

    pub fn config(&self) -> SegmentConfig {
        self.config
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

    /// Derives authoritative post-genesis lineage state from the most recently
    /// verified Packet 0. Packet 0 itself remains immediately admitted.
    pub fn trusted_context_from_latest_packet0(&self) -> Result<TrustedSessionContext, TraxError> {
        let node = self
            .nodes
            .last()
            .ok_or(TraxError::InvalidInput("no verified Packet 0"))?;
        let session_id: [u8; 32] = node
            .event
            .session_id
            .as_slice()
            .try_into()
            .map_err(|_| TraxError::InvalidInput("session_id must be 32 bytes"))?;
        let sender_key_bytes: [u8; 32] = node
            .event
            .sender_public_key
            .as_slice()
            .try_into()
            .map_err(|_| TraxError::InvalidInput("sender_public_key must be 32 bytes"))?;
        let receiver_key_bytes: [u8; 32] = node
            .event
            .receiver_public_key
            .as_slice()
            .try_into()
            .map_err(|_| TraxError::InvalidInput("receiver_public_key must be 32 bytes"))?;
        let lineage_key =
            VerifyingKey::from_bytes(&sender_key_bytes).map_err(|_| TraxError::Crypto)?;
        let receiver_key =
            VerifyingKey::from_bytes(&receiver_key_bytes).map_err(|_| TraxError::Crypto)?;
        Ok(TrustedSessionContext::from_verified_state(
            self.config,
            session_id,
            receiver_id(&receiver_key),
            lineage_key,
            node.node_id,
            0,
            0,
        ))
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
        let index = u64::try_from(self.nodes.len()).map_err(|_| TraxError::ArithmeticOverflow)?;
        index.checked_add(1).ok_or(TraxError::ArithmeticOverflow)?;
        let dag_node = DagNode {
            prev_tip_hash: self.tip_hash,
            segment_anchor: node_id,
            index,
            ts: 0,
            op_type: PACKET0_ADMISSION_OP,
            peer_id: peer_id_from_public_key(&event.sender_public_key),
            counter: index,
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
            std::slice::from_ref(&parent_ref),
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
        let mut dag = LocalAdmissionDag::new(SegmentConfig::new(8).unwrap());

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
        let mut left = LocalAdmissionDag::new(SegmentConfig::new(8).unwrap());
        let mut right = LocalAdmissionDag::new(SegmentConfig::new(8).unwrap());

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
        let mut dag = LocalAdmissionDag::new(SegmentConfig::new(8).unwrap());

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
        let mut dag = LocalAdmissionDag::new(SegmentConfig::new(8).unwrap());

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
        let mut dag = LocalAdmissionDag::new(SegmentConfig::new(8).unwrap());

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
        let mut dag = LocalAdmissionDag::new(SegmentConfig::new(8).unwrap());

        dag.admit_packet0(
            &f.envelope,
            &f.payload,
            f.receiver.verifying_key().as_bytes(),
        )
        .unwrap();

        assert_eq!(dag.nodes()[0].event.dag_parent_refs, vec![f.parent_ref]);
    }

    #[test]
    fn verified_packet0_derives_trusted_post_genesis_context() {
        let f = fixture();
        let mut dag = LocalAdmissionDag::new(SegmentConfig::new(8).unwrap());
        let node_id = dag
            .admit_packet0(
                &f.envelope,
                &f.payload,
                f.receiver.verifying_key().as_bytes(),
            )
            .unwrap();
        let context = dag.trusted_context_from_latest_packet0().unwrap();
        assert_eq!(context.config(), dag.config());
        assert_eq!(context.committed_tip(), node_id);
        assert_eq!(context.lineage_key(), &f.sender.verifying_key());
        assert_eq!(
            context.receiver_id(),
            receiver_id(&f.receiver.verifying_key())
        );
        assert_eq!(context.segment_index(), 0);
        assert_eq!(context.next_counter(), 0);
    }
}
