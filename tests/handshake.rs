use ed25519_dalek::SigningKey;
use trax::config::{HashAlgorithm, ProtocolConfig, SigningAlgorithm, DEFAULT_K};
use trax::crypto::ed25519_sign;
use trax::exchange::PrefixAcknowledgment;
use trax::graph::{
    participant_id, AuthorityId, BranchId, GraphEvent, GraphOperation, GraphSegmentProof, NodeId,
    PairDag, PairGenesis, ParticipantAuthority, ParticipantId, PendingSegment,
};

struct Fixture {
    config: ProtocolConfig,
    a: SigningKey,
    b: SigningKey,
    next: SigningKey,
    a_id: ParticipantId,
    b_id: ParticipantId,
}

impl Fixture {
    fn new(config: ProtocolConfig) -> Self {
        let a = SigningKey::from_bytes(&[101; 32]);
        let b = SigningKey::from_bytes(&[102; 32]);
        let next = SigningKey::from_bytes(&[103; 32]);
        Self {
            config,
            a_id: participant_id(&a.verifying_key().to_bytes()),
            b_id: participant_id(&b.verifying_key().to_bytes()),
            a,
            b,
            next,
        }
    }

    fn dag(&self, nonce: [u8; 32]) -> PairDag {
        let genesis = PairGenesis::new(
            self.config,
            nonce,
            &self.a.verifying_key(),
            &self.b.verifying_key(),
        )
        .unwrap();
        PairDag::from_verified_genesis(self.config, genesis).unwrap()
    }
}

fn config(k: usize) -> ProtocolConfig {
    ProtocolConfig::new(k, SigningAlgorithm::Ed25519, HashAlgorithm::Sha512256).unwrap()
}

#[derive(Debug, PartialEq, Eq)]
struct CommittedState {
    config: ProtocolConfig,
    nodes: usize,
    events: u64,
    checkpoint: NodeId,
    proofs: Vec<GraphSegmentProof>,
    authorities: Vec<ParticipantAuthority>,
}

fn committed(dag: &PairDag) -> CommittedState {
    CommittedState {
        config: dag.config(),
        nodes: dag.len(),
        events: dag.event_count(),
        checkpoint: dag.checkpoint_tip(),
        proofs: dag.proofs().to_vec(),
        authorities: dag
            .genesis()
            .initial_public_keys
            .iter()
            .map(|key| dag.authority(&participant_id(key)).unwrap().clone())
            .collect(),
    }
}

fn rotation_prefix(
    f: &Fixture,
    dag: &PairDag,
    branch: BranchId,
) -> (NodeId, Vec<GraphEvent>, PrefixAcknowledgment) {
    let mut pending = dag.begin_segment();
    let proposal = pending
        .rotate(f.a_id, dag.genesis_id(), branch, &f.a, &f.next)
        .unwrap();
    let acknowledgment = pending.acknowledge_and_pad(f.b_id, &f.b).unwrap();
    (proposal, pending.events().to_vec(), acknowledgment)
}

fn replay<'a>(dag: &'a PairDag, events: &[GraphEvent]) -> PendingSegment<'a> {
    let mut pending = dag.begin_segment();
    for event in events {
        pending.stage(event.clone()).unwrap();
    }
    pending
}

fn rotation_proof(f: &Fixture, dag: &PairDag, branch: BranchId, close: bool) -> GraphSegmentProof {
    let (_, events, acknowledgment) = rotation_prefix(f, dag, branch);
    let mut pending = replay(dag, &events);
    pending.accept_ack(&acknowledgment).unwrap();
    if close {
        pending.finish_close().unwrap();
    } else {
        pending
            .append(f.a_id, branch, b"next real request".to_vec())
            .unwrap();
    }
    pending.seal(f.a_id, &f.next).unwrap()
}

#[test]
fn default_k8_rotation_has_exact_peer_prefix_and_initiator_confirmation() {
    let profile =
        ProtocolConfig::with_default_k(SigningAlgorithm::Ed25519, HashAlgorithm::Sha512256)
            .unwrap();
    let f = Fixture::new(profile);
    let mut receiver = f.dag([1; 32]);
    let before = committed(&receiver);
    let branch = [31; 32];
    let (proposal, prefix, acknowledgment) = rotation_prefix(&f, &receiver, branch);

    assert_eq!(profile.k(), DEFAULT_K);
    assert_eq!(prefix.len(), 7);
    assert!(matches!(prefix[0].operation, GraphOperation::Rotate { .. }));
    assert!(prefix[0].authorization.is_some());
    assert!(prefix[0].new_key_signature.is_some());
    assert!(prefix[1..6].iter().all(|event| {
        event.author == f.b_id && matches!(event.operation, GraphOperation::Padding)
    }));
    assert!(matches!(
        prefix[6].operation,
        GraphOperation::Acknowledge { proposal: id } if id == proposal
    ));
    assert_eq!(prefix[6].author, f.b_id);
    assert_eq!(acknowledgment.commitment.prefix_len, 7);
    assert_eq!(acknowledgment.commitment.expected_final_counter, 8);
    acknowledgment
        .verify(
            &acknowledgment.commitment.context,
            &prefix,
            &AuthorityId {
                participant: f.b_id,
                key_epoch: 0,
            },
            &f.b.verifying_key(),
        )
        .unwrap();
    assert_eq!(committed(&receiver), before);

    let mut pending = replay(&receiver, &prefix);
    assert!(pending.finish_close().is_err());
    pending.accept_ack(&acknowledgment).unwrap();
    assert!(pending.commitment().is_err());
    assert!(pending.seal(f.a_id, &f.next).is_err());
    assert_eq!(committed(&receiver), before);
    let final_id = pending.finish_close().unwrap();
    assert!(matches!(
        pending.events()[7].operation,
        GraphOperation::CloseConfirm { proposal: id, acknowledgment: ack }
            if id == proposal && ack == acknowledgment.node_id().unwrap()
    ));
    assert_eq!(pending.events()[7].author, f.a_id);
    assert_eq!(pending.events()[7].key_epoch, 1);
    assert!(pending.seal(f.a_id, &f.a).is_err());
    assert!(pending.seal(f.b_id, &f.b).is_err());
    let proof = pending.seal(f.a_id, &f.next).unwrap();
    drop(pending);
    assert!(proof.checkpoint.commitment.session_closing);
    assert_eq!(
        proof.checkpoint.commitment.acknowledgment_hash,
        Some(acknowledgment.node_id().unwrap())
    );
    let mut partial = proof.clone();
    partial.events.pop();
    assert!(receiver.verify_and_commit(&partial).is_err());
    assert_eq!(committed(&receiver), before);
    receiver.verify_and_commit(&proof).unwrap();
    assert_eq!(receiver.event_count(), 8);
    assert!(receiver.contains(&final_id));
    assert_eq!(receiver.authority(&f.a_id).unwrap().key_epoch, 1);
    assert_eq!(receiver.authority(&f.b_id).unwrap().key_epoch, 0);
    assert_eq!(
        receiver.acknowledgment_for(&proposal),
        Some(&acknowledgment)
    );
    receiver.verify_history().unwrap();
}

#[test]
fn replacement_key_proof_never_substitutes_for_current_identity_authorization() {
    let f = Fixture::new(config(5));
    let dag = f.dag([2; 32]);
    let before = committed(&dag);
    let (_, prefix, _) = rotation_prefix(&f, &dag, [32; 32]);
    let valid = &prefix[0];
    let mut variants = Vec::new();
    let mut bad = valid.clone();
    bad.authorization = None;
    variants.push(bad);
    let mut bad = valid.clone();
    bad.authorization = Some(ed25519_sign(
        &f.next,
        &bad.authorization_signing_bytes().unwrap(),
    ));
    variants.push(bad);
    let mut bad = valid.clone();
    bad.new_key_signature = None;
    variants.push(bad);
    let mut bad = valid.clone();
    bad.new_key_signature.as_mut().unwrap()[0] ^= 1;
    variants.push(bad);
    let mut bad = valid.clone();
    bad.new_key_signature = Some(ed25519_sign(&f.a, &bad.new_key_signing_bytes().unwrap()));
    variants.push(bad);
    for bad in variants {
        let mut pending = dag.begin_segment();
        assert!(pending.stage(bad).is_err());
        assert!(pending.events().is_empty());
        assert_eq!(committed(&dag), before);
    }
}

#[test]
fn peer_or_retired_key_cannot_forge_the_final_exchange_checkpoint() {
    let f = Fixture::new(config(5));
    let mut dag = f.dag([3; 32]);
    let valid = rotation_proof(&f, &dag, [33; 32], true);
    let before = committed(&dag);
    for (participant, key) in [(f.a_id, &f.a), (f.b_id, &f.b)] {
        let mut forged = valid.clone();
        forged.checkpoint = forged
            .checkpoint
            .commitment
            .sign(
                AuthorityId {
                    participant,
                    key_epoch: 0,
                },
                key,
            )
            .unwrap();
        assert!(dag.verify_and_commit(&forged).is_err());
        assert_eq!(committed(&dag), before);
    }
    let mut missing_ack = valid.clone();
    missing_ack.acknowledgment = None;
    assert!(dag.verify_and_commit(&missing_ack).is_err());
    assert_eq!(committed(&dag), before);
    let mut changed_ack = valid.clone();
    changed_ack.acknowledgment.as_mut().unwrap().signature[0] ^= 1;
    assert!(dag.verify_and_commit(&changed_ack).is_err());
    assert_eq!(committed(&dag), before);
    dag.verify_and_commit(&valid).unwrap();
}

#[test]
fn prefix_ack_rejects_tamper_other_branch_other_graph_and_replay() {
    let f = Fixture::new(config(8));
    let mut dag = f.dag([4; 32]);
    let (_, prefix, valid_ack) = rotation_prefix(&f, &dag, [34; 32]);
    let (_, _, other_branch_ack) = rotation_prefix(&f, &dag, [35; 32]);
    let other_graph = f.dag([5; 32]);
    let (_, _, other_graph_ack) = rotation_prefix(&f, &other_graph, [34; 32]);
    let before = committed(&dag);
    let mut changed_signature = valid_ack.clone();
    changed_signature.signature[0] ^= 1;
    let mut changed_prefix_tip = valid_ack.clone();
    changed_prefix_tip.commitment.prefix_tip[0] ^= 1;
    let mut changed_counter = valid_ack.clone();
    changed_counter.commitment.expected_final_counter += 1;
    for bad in [
        changed_signature,
        changed_prefix_tip,
        changed_counter,
        other_branch_ack,
        other_graph_ack,
    ] {
        let mut pending = replay(&dag, &prefix);
        assert!(pending.accept_ack(&bad).is_err());
        assert!(pending.finish_close().is_err());
        assert_eq!(committed(&dag), before);
    }
    let valid = rotation_proof(&f, &dag, [34; 32], false);
    dag.verify_and_commit(&valid).unwrap();
    let after = committed(&dag);
    assert!(dag.verify_and_commit(&valid).is_err());
    let mut pending = dag.begin_segment();
    assert!(pending.accept_ack(&valid_ack).is_err());
    assert!(pending.stage(prefix[0].clone()).is_err());
    assert_eq!(committed(&dag), after);
}

#[test]
fn real_final_request_continues_after_rotation_without_a_close_confirmation() {
    let f = Fixture::new(config(5));
    let mut dag = f.dag([6; 32]);
    let branch = [36; 32];
    let proof = rotation_proof(&f, &dag, branch, false);
    assert_eq!(proof.events.len(), 5);
    assert!(!proof.checkpoint.commitment.session_closing);
    assert!(matches!(
        &proof.events[4].operation,
        GraphOperation::Append { payload } if payload == b"next real request"
    ));
    dag.verify_and_commit(&proof).unwrap();
    let mut pending = dag.begin_segment();
    for _ in 0..5 {
        pending
            .append(f.a_id, branch, b"later request".to_vec())
            .unwrap();
    }
    let continued = pending.seal(f.a_id, &f.next).unwrap();
    drop(pending);
    dag.verify_and_commit(&continued).unwrap();
    assert_eq!(dag.event_count(), 10);
    dag.verify_history().unwrap();
}

#[test]
fn normal_boundary_needs_no_padding_and_close_requires_three_remaining_slots() {
    let f = Fixture::new(config(5));
    let mut dag = f.dag([7; 32]);
    let main = dag.main_branch();
    let mut pending = dag.begin_segment();
    for _ in 0..3 {
        pending.append(f.a_id, main, vec![]).unwrap();
    }
    assert!(pending.request_close(f.a_id, main).is_err());
    assert_eq!(pending.events().len(), 3);
    for _ in 3..5 {
        pending.append(f.b_id, main, vec![]).unwrap();
    }
    assert_eq!(pending.events().len(), 5);
    assert!(pending.request_close(f.a_id, main).is_err());
    let normal = pending.seal(f.b_id, &f.b).unwrap();
    assert!(normal.acknowledgment.is_none());
    assert!(!normal.checkpoint.commitment.session_closing);
    assert!(normal
        .events
        .iter()
        .all(|event| matches!(event.operation, GraphOperation::Append { .. })));
    drop(pending);
    dag.verify_and_commit(&normal).unwrap();
    let mut close = dag.begin_segment();
    close.request_close(f.a_id, main).unwrap();
    assert_eq!(close.events().len(), 1);
    close.acknowledge_and_pad(f.b_id, &f.b).unwrap();
    assert_eq!(close.events().len(), 4);
    assert_eq!(
        close
            .events()
            .iter()
            .filter(|event| matches!(event.operation, GraphOperation::Padding))
            .count(),
        2
    );
    close.finish_close().unwrap();
    let proof = close.seal(f.a_id, &f.a).unwrap();
    drop(close);
    dag.verify_and_commit(&proof).unwrap();
    assert_eq!(dag.event_count(), 10);
}

#[test]
fn configuration_exchange_uses_new_k_for_prefix_and_final_checkpoint() {
    let f = Fixture::new(config(8));
    let mut dag = f.dag([8; 32]);
    let before = committed(&dag);
    let next = config(5);
    let branch = [37; 32];
    let mut pending = dag.begin_segment();
    pending
        .configure(f.a_id, dag.genesis_id(), branch, next, &f.a)
        .unwrap();
    assert_eq!(pending.effective_config(), next);
    assert_eq!(dag.config(), f.config);
    let acknowledgment = pending.acknowledge_and_pad(f.b_id, &f.b).unwrap();
    assert_eq!(pending.events().len(), 4);
    assert_eq!(acknowledgment.commitment.context.config, next);
    assert_eq!(acknowledgment.commitment.prefix_len, 4);
    assert_eq!(committed(&dag), before);
    pending.finish_close().unwrap();
    let proof = pending.seal(f.a_id, &f.a).unwrap();
    drop(pending);
    assert_eq!(proof.events.len(), 5);
    assert!(proof.events.iter().all(|event| event.config == next));
    assert_eq!(proof.checkpoint.commitment.config, next);
    dag.verify_and_commit(&proof).unwrap();
    assert_eq!(dag.config(), next);
    assert_eq!(dag.event_count(), 5);
    dag.verify_history().unwrap();
}
