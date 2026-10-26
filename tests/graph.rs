use std::collections::BTreeSet;

use ed25519_dalek::SigningKey;
use trax::config::{HashAlgorithm, ProtocolConfig, SigningAlgorithm};
use trax::crypto::hash32;
use trax::graph::{
    participant_id, AuthorityId, BranchId, GraphEvent, GraphOperation, GraphSegmentProof, NodeId,
    PairDag, PairGenesis, ParticipantAuthority, ParticipantId,
};
use trax::TraxError;

fn config(k: usize) -> ProtocolConfig {
    let hash = if cfg!(feature = "hash-blake3") {
        HashAlgorithm::Blake3
    } else {
        HashAlgorithm::Sha512256
    };
    ProtocolConfig::new(k, SigningAlgorithm::Ed25519, hash).unwrap()
}

struct Fixture {
    a: SigningKey,
    b: SigningKey,
    a_next: SigningKey,
    a_id: ParticipantId,
    b_id: ParticipantId,
}

impl Fixture {
    fn new() -> Self {
        let a = SigningKey::from_bytes(&[11; 32]);
        let b = SigningKey::from_bytes(&[22; 32]);
        let a_next = SigningKey::from_bytes(&[33; 32]);
        Self {
            a_id: participant_id(&a.verifying_key().to_bytes()),
            b_id: participant_id(&b.verifying_key().to_bytes()),
            a,
            b,
            a_next,
        }
    }
    fn dag(&self, k: usize) -> PairDag {
        self.dag_with_nonce(k, hash32(b"shared test relationship"))
    }
    fn dag_with_nonce(&self, k: usize, nonce: [u8; 32]) -> PairDag {
        let genesis = PairGenesis::new(
            config(k),
            nonce,
            &self.a.verifying_key(),
            &self.b.verifying_key(),
        )
        .unwrap();
        PairDag::from_verified_genesis(config(k), genesis).unwrap()
    }
}

fn append_batch(
    dag: &mut PairDag,
    author: ParticipantId,
    key: &SigningKey,
    branch: BranchId,
    payload: &[u8],
) -> NodeId {
    let mut pending = dag.begin_segment();
    let mut ids = Vec::new();
    for _ in 0..dag.config().k() {
        ids.push(pending.append(author, branch, payload.to_vec()).unwrap());
    }
    let proof = pending.seal(author, key).unwrap();
    drop(pending);
    assert_eq!(dag.verify_and_commit(&proof).unwrap(), ids);
    *ids.last().unwrap()
}

fn rotate_a(dag: &mut PairDag, f: &Fixture, parent: NodeId, branch: BranchId) -> NodeId {
    let mut pending = dag.begin_segment();
    let id = pending
        .rotate(f.a_id, parent, branch, &f.a, &f.a_next)
        .unwrap();
    pending.acknowledge_and_pad(f.b_id, &f.b).unwrap();
    pending
        .append(f.a_id, branch, b"continue after rotation".to_vec())
        .unwrap();
    let proof = pending.seal(f.a_id, &f.a_next).unwrap();
    drop(pending);
    assert_eq!(dag.verify_and_commit(&proof).unwrap()[0], id);
    id
}

#[derive(Debug, PartialEq, Eq)]
struct Snapshot {
    config: ProtocolConfig,
    genesis: PairGenesis,
    len: usize,
    checkpoint: NodeId,
    segment_index: u64,
    proofs: Vec<GraphSegmentProof>,
    nodes: Vec<(NodeId, Option<GraphEvent>, Vec<NodeId>)>,
    branches: Vec<(BranchId, NodeId, NodeId)>,
    authorities: Vec<ParticipantAuthority>,
}

fn snapshot(dag: &PairDag) -> Snapshot {
    let ids: BTreeSet<_> = std::iter::once(dag.genesis_id())
        .chain(
            dag.proofs()
                .iter()
                .flat_map(|proof| &proof.events)
                .map(|event| event.node_id().unwrap()),
        )
        .collect();
    Snapshot {
        config: dag.config(),
        genesis: dag.genesis().clone(),
        len: dag.len(),
        checkpoint: dag.checkpoint_tip(),
        segment_index: dag.segment_index(),
        proofs: dag.proofs().to_vec(),
        nodes: ids
            .into_iter()
            .map(|id| {
                (
                    id,
                    dag.node(&id).cloned(),
                    dag.children(&id).unwrap().to_vec(),
                )
            })
            .collect(),
        branches: dag
            .branches()
            .map(|(branch, tip)| (*branch, *tip, dag.branch_origin(branch).unwrap()))
            .collect(),
        authorities: dag
            .genesis()
            .initial_public_keys
            .iter()
            .map(|key| dag.authority(&participant_id(key)).unwrap().clone())
            .collect(),
    }
}

fn assert_shared_history(left: &PairDag, right: &PairDag) {
    let left = snapshot(left);
    let right = snapshot(right);
    assert_eq!(left.genesis, right.genesis);
    assert_eq!(left.config, right.config);
    assert_eq!(left.len, right.len);
    assert_eq!(left.checkpoint, right.checkpoint);
    assert_eq!(left.segment_index, right.segment_index);
    assert_eq!(left.nodes, right.nodes);
    assert_eq!(left.branches, right.branches);
    assert_eq!(left.authorities, right.authorities);
}

#[test]
fn common_genesis_sorts_participants_and_binds_negotiated_configuration() {
    let f = Fixture::new();
    let profile = config(5);
    let nonce = hash32(b"shared test relationship");
    let left =
        PairGenesis::new(profile, nonce, &f.a.verifying_key(), &f.b.verifying_key()).unwrap();
    let right =
        PairGenesis::new(profile, nonce, &f.b.verifying_key(), &f.a.verifying_key()).unwrap();
    assert_eq!(left, right);
    let left = PairDag::from_verified_genesis(profile, left).unwrap();
    let right = PairDag::from_verified_genesis(profile, right).unwrap();
    assert_shared_history(&left, &right);
    assert_eq!(left.parent(&left.genesis_id()).unwrap(), None);
    assert_eq!(left.len(), 1);
    assert!(!left.is_empty());
    assert_ne!(left.genesis_id(), f.dag(7).genesis_id());
    assert_ne!(
        left.genesis_id(),
        f.dag_with_nonce(5, hash32(b"other relationship"))
            .genesis_id()
    );
    let alternate =
        ProtocolConfig::new(5, SigningAlgorithm::Ed25519, HashAlgorithm::Sha512256).unwrap();
    let alternate_genesis =
        PairGenesis::new(alternate, nonce, &f.a.verifying_key(), &f.b.verifying_key()).unwrap();
    if profile.hash_algorithm() != alternate.hash_algorithm() {
        assert_ne!(left.genesis_id(), alternate_genesis.node_id().unwrap());
    } else {
        assert_eq!(left.genesis_id(), alternate_genesis.node_id().unwrap());
    }
    assert!(matches!(
        PairDag::from_verified_genesis(config(7), left.genesis().clone()),
        Err(TraxError::GraphContextMismatch)
    ));
    assert!(PairGenesis::new(profile, nonce, &f.a.verifying_key(), &f.a.verifying_key()).is_err());
    let mut unsorted = left.genesis().clone();
    unsorted.initial_public_keys.swap(0, 1);
    assert!(PairDag::from_verified_genesis(profile, unsorted).is_err());
}

#[test]
fn mixed_events_commit_at_explicit_k_with_either_single_participant_signature() {
    let f = Fixture::new();
    for k in [5, 7, 8, 14] {
        let mut left = f.dag(k);
        let mut right = f.dag(k);
        let original = snapshot(&left);
        let mut pending = left.begin_segment();
        assert!(matches!(
            pending.commitment(),
            Err(TraxError::IncompleteSegment)
        ));
        let mut ids = Vec::new();
        for index in 0..k {
            let author = if index % 2 == 0 { f.a_id } else { f.b_id };
            let id = pending
                .append(
                    author,
                    left.main_branch(),
                    format!("payload-{index}").into_bytes(),
                )
                .unwrap();
            ids.push(id);
            assert_eq!(snapshot(&left), original);
            assert!(!left.contains(&id));
            if index + 1 < k {
                assert!(!pending.is_complete());
                assert!(matches!(
                    pending.commitment(),
                    Err(TraxError::IncompleteSegment)
                ));
            }
        }
        assert!(pending.is_complete());
        assert!(matches!(
            pending.append(f.a_id, left.main_branch(), b"extra".to_vec()),
            Err(TraxError::SegmentAlreadySealed)
        ));
        let proof_a = pending.seal(f.a_id, &f.a).unwrap();
        let proof_b = pending.seal(f.b_id, &f.b).unwrap();
        drop(pending);
        assert_eq!(proof_a.checkpoint.commitment, proof_b.checkpoint.commitment);
        assert_ne!(proof_a.checkpoint.signature, proof_b.checkpoint.signature);
        assert_eq!(left.verify_and_commit(&proof_a).unwrap(), ids);
        assert_eq!(right.verify_and_commit(&proof_b).unwrap(), ids);
        assert_shared_history(&left, &right);
        assert_eq!(left.len(), k + 1);
        for (index, id) in ids.iter().enumerate() {
            assert_eq!(left.node(id).unwrap().counter, index as u64 + 1);
            assert_eq!(
                left.node(id).unwrap().parent,
                if index == 0 {
                    left.genesis_id()
                } else {
                    ids[index - 1]
                }
            );
        }
        let accepted = snapshot(&left);
        assert!(left.verify_and_commit(&proof_a).is_err());
        assert_eq!(snapshot(&left), accepted);
        left.verify_history().unwrap();
        right.verify_history().unwrap();
    }
}

#[test]
fn forks_keep_one_parent_while_all_branches_share_checkpoint_counters() {
    let f = Fixture::new();
    let mut dag = f.dag(5);
    let main = dag.main_branch();
    let genesis = dag.genesis_id();
    let fork_branch = hash32(b"new fork branch");
    let mut pending = dag.begin_segment();
    let first = pending.append(f.a_id, main, b"first".to_vec()).unwrap();
    let main_second = pending
        .append(f.b_id, main, b"main second".to_vec())
        .unwrap();
    let fork_first = pending
        .fork(f.a_id, first, fork_branch, b"fork first".to_vec())
        .unwrap();
    let other_branch = hash32(b"other independent fork");
    pending.fork(f.b_id, genesis, other_branch, vec![]).unwrap();
    pending.append(f.b_id, other_branch, vec![]).unwrap();
    let proof = pending.seal(f.b_id, &f.b).unwrap();
    drop(pending);
    dag.verify_and_commit(&proof).unwrap();
    let first_record = dag.node(&first).unwrap().clone();
    assert_eq!(dag.node(&fork_first).unwrap().counter, 3);
    assert_eq!(dag.node(&fork_first).unwrap().sequence, 2);
    let mut pending = dag.begin_segment();
    let fork_second = pending
        .append(f.a_id, fork_branch, b"fork second".to_vec())
        .unwrap();
    let main_third = pending
        .append(f.b_id, main, b"main third".to_vec())
        .unwrap();
    let fork_third = pending
        .append(f.b_id, fork_branch, b"fork third".to_vec())
        .unwrap();
    pending.append(f.b_id, other_branch, vec![]).unwrap();
    pending.append(f.b_id, other_branch, vec![]).unwrap();
    let proof = pending.seal(f.a_id, &f.a).unwrap();
    drop(pending);
    dag.verify_and_commit(&proof).unwrap();
    assert_eq!(dag.node(&first).unwrap(), &first_record);
    assert_eq!(dag.branch_tip(&main).unwrap(), main_third);
    assert_eq!(dag.branch_tip(&fork_branch).unwrap(), fork_third);
    assert_eq!(dag.branch_origin(&main).unwrap(), genesis);
    assert_eq!(dag.branch_origin(&fork_branch).unwrap(), first);
    assert_eq!(dag.children(&first).unwrap(), &[main_second, fork_first]);
    assert_eq!(
        dag.ancestors(&fork_third).unwrap(),
        vec![fork_third, fork_second, fork_first, first, genesis]
    );
    assert_eq!(
        dag.ancestors(&main_third).unwrap(),
        vec![main_third, main_second, first, genesis]
    );
    assert_eq!(dag.node(&fork_third).unwrap().counter, 8);
    let original = snapshot(&dag);
    let mut pending = dag.begin_segment();
    assert!(matches!(
        pending.fork(f.a_id, first, fork_branch, vec![]),
        Err(TraxError::BranchExists)
    ));
    let mut cannot_merge = dag.node(&main_third).unwrap().clone();
    cannot_merge.parent = fork_third;
    cannot_merge.sequence = dag.node(&fork_third).unwrap().sequence + 1;
    cannot_merge.counter = 11;
    assert!(matches!(
        pending.stage(cannot_merge),
        Err(TraxError::BranchTipMismatch)
    ));
    assert!(pending.events().is_empty());
    assert_eq!(snapshot(&dag), original);
    dag.verify_history().unwrap();
}

#[test]
fn rotation_requires_individual_authorization_and_peer_prefix_acknowledgment() {
    let f = Fixture::new();
    let mut dag = f.dag(5);
    let genesis = dag.genesis_id();
    let original = snapshot(&dag);
    let mut pending = dag.begin_segment();
    assert!(pending
        .rotate(f.a_id, genesis, hash32(b"fake rotation"), &f.b, &f.a_next)
        .is_err());
    assert!(pending.events().is_empty());
    let rotation = pending
        .rotate(f.a_id, genesis, hash32(b"valid rotation"), &f.a, &f.a_next)
        .unwrap();
    assert_eq!(dag.authority(&f.a_id).unwrap().key_epoch, 0);
    pending.acknowledge_and_pad(f.b_id, &f.b).unwrap();
    pending
        .append(f.a_id, hash32(b"valid rotation"), b"continue".to_vec())
        .unwrap();
    assert!(pending.seal(f.b_id, &f.b).is_err());
    let valid = pending.seal(f.a_id, &f.a_next).unwrap();
    drop(pending);
    let mut forged = valid.clone();
    forged.events[0].authorization.as_mut().unwrap()[0] ^= 1;
    assert!(dag.verify_and_commit(&forged).is_err());
    assert_eq!(snapshot(&dag), original);
    dag.verify_and_commit(&valid).unwrap();
    assert_eq!(dag.authority(&f.a_id).unwrap().rotation_tip, rotation);
    assert_eq!(dag.authority(&f.a_id).unwrap().key_epoch, 1);
    assert_eq!(dag.authority(&f.b_id).unwrap().key_epoch, 0);
    dag.verify_history().unwrap();
}

#[test]
fn retired_keys_are_identifiable_but_cannot_extend_or_seal_new_history() {
    let f = Fixture::new();
    let mut dag = f.dag(5);
    let main = dag.main_branch();
    let before = append_batch(&mut dag, f.a_id, &f.a, main, b"before rotation");
    let old_record = dag.node(&before).unwrap().clone();
    let b_authority = dag.authority(&f.b_id).unwrap().clone();
    let rotation_branch = hash32(b"a rotation branch");
    let rotation = rotate_a(&mut dag, &f, before, rotation_branch);
    assert_eq!(dag.authority(&f.b_id).unwrap(), &b_authority);
    let retired = dag.identify_key(&f.a.verifying_key().to_bytes()).unwrap();
    assert_eq!(
        retired.authority,
        AuthorityId {
            participant: f.a_id,
            key_epoch: 0
        }
    );
    assert!(!retired.is_current);
    assert!(
        dag.identify_key(&f.a_next.verifying_key().to_bytes())
            .unwrap()
            .is_current
    );
    let original = snapshot(&dag);
    for (branch, parent) in [(main, before), (rotation_branch, rotation)] {
        let mut candidate = old_record.clone();
        candidate.branch = branch;
        candidate.parent = parent;
        candidate.sequence = dag.node(&parent).unwrap().sequence + 1;
        candidate.counter = dag.event_count() + 1;
        candidate.operation = GraphOperation::Append {
            payload: b"retired extension".to_vec(),
        };
        assert!(matches!(
            dag.begin_segment().stage(candidate),
            Err(TraxError::RetiredKey)
        ));
        assert_eq!(snapshot(&dag), original);
    }
    let mut pending = dag.begin_segment();
    for _ in 0..5 {
        pending
            .append(f.b_id, main, b"valid B event".to_vec())
            .unwrap();
    }
    assert!(pending.seal(f.a_id, &f.a).is_err());
    let valid = pending.seal(f.b_id, &f.b).unwrap();
    drop(pending);
    dag.verify_and_commit(&valid).unwrap();
    let current = append_batch(
        &mut dag,
        f.a_id,
        &f.a_next,
        main,
        b"current key on old branch",
    );
    assert_eq!(dag.node(&current).unwrap().authority_tip, rotation);
    assert_eq!(dag.node(&before).unwrap(), &old_record);
    dag.verify_history().unwrap();
}

#[test]
fn stale_authority_and_pre_rotation_draft_do_not_mutate_history() {
    let f = Fixture::new();
    let mut dag = f.dag(5);
    let main = dag.main_branch();
    let mut pending = dag.begin_segment();
    for _ in 0..5 {
        pending
            .append(f.a_id, main, b"prepared before rotation".to_vec())
            .unwrap();
    }
    let stale_proof = pending.seal(f.a_id, &f.a).unwrap();
    drop(pending);
    let genesis = dag.genesis_id();
    rotate_a(
        &mut dag,
        &f,
        genesis,
        hash32(b"rotation before draft commit"),
    );
    let original = snapshot(&dag);
    assert!(dag.verify_and_commit(&stale_proof).is_err());
    assert_eq!(snapshot(&dag), original);
    let mut pending = dag.begin_segment();
    pending
        .append(f.a_id, main, b"current epoch event".to_vec())
        .unwrap();
    let mut stale_tip = pending.events()[0].clone();
    stale_tip.authority_tip = genesis;
    drop(pending);
    assert!(matches!(
        dag.begin_segment().stage(stale_tip),
        Err(TraxError::AuthorityMismatch)
    ));
    assert_eq!(snapshot(&dag), original);
}

#[test]
fn copied_current_epoch_metadata_does_not_allow_old_key_checkpoint_forgery() {
    let f = Fixture::new();
    let mut dag = f.dag(5);
    let genesis = dag.genesis_id();
    rotate_a(&mut dag, &f, genesis, hash32(b"a rotation"));
    let original = snapshot(&dag);
    let mut pending = dag.begin_segment();
    for _ in 0..5 {
        pending
            .append(f.a_id, dag.main_branch(), b"claimed current epoch".to_vec())
            .unwrap();
    }
    let forged_attestation = pending
        .commitment()
        .unwrap()
        .sign(
            AuthorityId {
                participant: f.a_id,
                key_epoch: 1,
            },
            &f.a,
        )
        .unwrap();
    let forged = pending.proof(forged_attestation).unwrap();
    let valid = pending.seal(f.a_id, &f.a_next).unwrap();
    drop(pending);
    assert!(matches!(
        dag.verify_and_commit(&forged),
        Err(TraxError::SegmentSignatureFailure)
    ));
    assert_eq!(snapshot(&dag), original);
    dag.verify_and_commit(&valid).unwrap();
    dag.verify_history().unwrap();
}

#[test]
fn rotations_cannot_reuse_historical_or_other_participant_keys() {
    let f = Fixture::new();
    let mut dag = f.dag(5);
    let genesis = dag.genesis_id();
    rotate_a(&mut dag, &f, genesis, hash32(b"first rotation"));
    let original = snapshot(&dag);
    for (author, key, signing_key) in [
        (f.a_id, &f.a, &f.a_next),
        (f.a_id, &f.a_next, &f.a_next),
        (f.a_id, &f.b, &f.a_next),
        (f.b_id, &f.a_next, &f.b),
    ] {
        let mut pending = dag.begin_segment();
        assert!(matches!(
            pending.rotate(author, genesis, hash32(b"reuse rotation"), signing_key, key),
            Err(TraxError::KeyReuse)
        ));
        assert!(pending.events().is_empty());
        assert_eq!(snapshot(&dag), original);
    }
}

#[test]
fn wrong_relationship_proof_and_foreign_parent_are_rejected_atomically() {
    let f = Fixture::new();
    let mut source = f.dag(5);
    let mut pending = source.begin_segment();
    let foreign_parent = pending
        .append(f.a_id, source.main_branch(), b"source only".to_vec())
        .unwrap();
    for _ in 1..5 {
        pending
            .append(f.a_id, source.main_branch(), vec![])
            .unwrap();
    }
    let proof = pending.seal(f.a_id, &f.a).unwrap();
    drop(pending);
    source.verify_and_commit(&proof).unwrap();
    let mut destination = f.dag_with_nonce(5, hash32(b"different relationship"));
    let original = snapshot(&destination);
    assert!(matches!(
        destination.verify_and_commit(&proof),
        Err(TraxError::GraphContextMismatch)
    ));
    let mut candidate = proof.events[0].clone();
    candidate.dag_id = destination.genesis_id();
    candidate.branch = destination.main_branch();
    candidate.parent = foreign_parent;
    candidate.sequence = 2;
    candidate.authority_tip = destination.genesis_id();
    candidate.configuration_tip = destination.genesis_id();
    assert!(matches!(
        destination.begin_segment().stage(candidate),
        Err(TraxError::UnknownNode)
    ));
    assert_eq!(snapshot(&destination), original);
}

#[test]
fn bad_checkpoint_or_tampered_event_does_not_advance_accepted_history() {
    let f = Fixture::new();
    let mut dag = f.dag(5);
    for segment in 0..2 {
        let mut pending = dag.begin_segment();
        for i in 0..5 {
            pending
                .append(
                    f.a_id,
                    dag.main_branch(),
                    format!("{segment}-{i}").into_bytes(),
                )
                .unwrap();
        }
        let valid = pending.seal(f.b_id, &f.b).unwrap();
        drop(pending);
        if segment == 0 {
            dag.verify_and_commit(&valid).unwrap();
            continue;
        }
        let original = snapshot(&dag);
        let mut variants = Vec::new();
        let mut bad = valid.clone();
        bad.checkpoint.signature[0] ^= 1;
        variants.push(bad);
        let mut bad = valid.clone();
        bad.checkpoint.commitment.previous_checkpoint[0] ^= 1;
        variants.push(bad);
        let mut bad = valid.clone();
        bad.checkpoint.commitment.ordered_merkle_root[0] ^= 1;
        variants.push(bad);
        let mut bad = valid.clone();
        bad.events[2].operation = GraphOperation::Append {
            payload: b"tampered".to_vec(),
        };
        variants.push(bad);
        let mut bad = valid.clone();
        bad.events.swap(0, 1);
        variants.push(bad);
        let mut bad = valid.clone();
        bad.events.pop();
        variants.push(bad);
        let mut bad = valid.clone();
        bad.checkpoint.signer.participant =
            participant_id(&SigningKey::from_bytes(&[44; 32]).verifying_key().to_bytes());
        variants.push(bad);
        let mut bad = valid.clone();
        bad.checkpoint.signer.participant = f.a_id;
        variants.push(bad);
        for bad in variants {
            assert!(dag.verify_and_commit(&bad).is_err());
            assert_eq!(snapshot(&dag), original);
        }
        dag.verify_and_commit(&valid).unwrap();
    }
    assert_eq!(dag.len(), 11);
    dag.verify_history().unwrap();
}

#[test]
fn transition_requires_a_fresh_segment_peer_ack_and_new_key_final_seal() {
    let f = Fixture::new();
    let mut first = f.dag(5);
    let mut second = f.dag(5);
    let original = snapshot(&first);
    let mut pending = first.begin_segment();
    pending
        .append(f.a_id, first.main_branch(), b"old epoch".to_vec())
        .unwrap();
    assert!(pending
        .rotate(
            f.a_id,
            first.genesis_id(),
            hash32(b"mid-segment rotation"),
            &f.a,
            &f.a_next,
        )
        .is_err());
    assert_eq!(pending.events().len(), 1);
    drop(pending);
    let branch = hash32(b"fresh rotation segment");
    let mut pending = first.begin_segment();
    let rotation = pending
        .rotate(f.a_id, first.genesis_id(), branch, &f.a, &f.a_next)
        .unwrap();
    pending.acknowledge_and_pad(f.b_id, &f.b).unwrap();
    pending
        .append(f.a_id, branch, b"new epoch".to_vec())
        .unwrap();
    assert_eq!(pending.events().last().unwrap().authority_tip, rotation);
    assert_eq!(snapshot(&first), original);
    assert!(pending.seal(f.a_id, &f.a).is_err());
    assert!(pending.seal(f.b_id, &f.b).is_err());
    let proof_new = pending.seal(f.a_id, &f.a_next).unwrap();
    drop(pending);
    first.verify_and_commit(&proof_new).unwrap();
    second.verify_and_commit(&proof_new).unwrap();
    assert_shared_history(&first, &second);
    first.verify_history().unwrap();
    second.verify_history().unwrap();
}

#[test]
fn detached_historical_attestation_is_retrievable_without_new_shared_nodes() {
    let f = Fixture::new();
    let mut dag = f.dag(5);
    let mut pending = dag.begin_segment();
    let mut ids = Vec::new();
    for i in 0..5 {
        ids.push(pending.append(f.a_id, dag.main_branch(), vec![i]).unwrap());
    }
    let proof_a = pending.seal(f.a_id, &f.a).unwrap();
    let proof_b = pending.seal(f.b_id, &f.b).unwrap();
    drop(pending);
    dag.verify_and_commit(&proof_b).unwrap();
    for id in &ids {
        assert!(dag.checkpoint_for(&f.a_id, id).is_none());
        assert_eq!(
            dag.checkpoint_for(&f.b_id, id).unwrap(),
            &proof_b.checkpoint
        );
    }
    let original = snapshot(&dag);
    let mut bad = proof_a.checkpoint.clone();
    bad.signature[0] ^= 1;
    assert!(dag.record_attestation(&bad).is_err());
    assert_eq!(snapshot(&dag), original);
    dag.record_attestation(&proof_a.checkpoint).unwrap();
    assert_eq!(snapshot(&dag), original);
    for id in &ids {
        assert_eq!(
            dag.checkpoint_for(&f.a_id, id).unwrap(),
            &proof_a.checkpoint
        );
        assert_eq!(
            dag.checkpoint_for(&f.b_id, id).unwrap(),
            &proof_b.checkpoint
        );
    }
    dag.verify_history().unwrap();
}

#[test]
fn close_padding_is_explicit_minimal_and_counts_control_messages_as_events() {
    let f = Fixture::new();
    for k in [5, 7, 8] {
        for used in 0..=k {
            let mut dag = f.dag(k);
            let mut pending = dag.begin_segment();
            for i in 0..used {
                let author = if i % 2 == 0 { f.a_id } else { f.b_id };
                pending
                    .append(
                        author,
                        dag.main_branch(),
                        format!("request-{i}").into_bytes(),
                    )
                    .unwrap();
            }
            assert_eq!(pending.events().len(), used);
            assert_eq!(dag.len(), 1);
            if used > k - 3 {
                assert!(pending.request_close(f.a_id, dag.main_branch()).is_err());
                assert_eq!(pending.events().len(), used);
                continue;
            }
            let proposal = pending.request_close(f.a_id, dag.main_branch()).unwrap();
            assert_eq!(pending.events().len(), used + 1);
            pending.acknowledge_and_pad(f.b_id, &f.b).unwrap();
            assert_eq!(pending.events().len(), k - 1);
            let padding = pending
                .events()
                .iter()
                .filter(|event| matches!(event.operation, GraphOperation::Padding))
                .count();
            assert_eq!(padding, k - used - 3);
            pending.finish_close().unwrap();
            assert!(matches!(
                pending.events().last().unwrap().operation,
                GraphOperation::CloseConfirm { proposal: id, .. } if id == proposal
            ));
            let proof = pending.seal(f.a_id, &f.a).unwrap();
            assert!(proof.checkpoint.commitment.session_closing);
            drop(pending);
            dag.verify_and_commit(&proof).unwrap();
            assert_eq!(dag.len(), k + 1);
            dag.verify_history().unwrap();
        }
    }
}

#[test]
fn ordinary_mode_rejects_padding_and_checkpoint_authenticates_close_flag() {
    let f = Fixture::new();
    let mut dag = f.dag(5);
    let mut closing = dag.begin_segment();
    closing.request_close(f.a_id, dag.main_branch()).unwrap();
    closing.acknowledge_and_pad(f.b_id, &f.b).unwrap();
    closing.finish_close().unwrap();
    let events = closing.events().to_vec();
    let valid = closing.seal(f.a_id, &f.a).unwrap();
    drop(closing);
    let mut ordinary = dag.begin_segment();
    assert!(ordinary.stage(events[1].clone()).is_err());
    assert!(ordinary.events().is_empty());
    drop(ordinary);
    let original = snapshot(&dag);
    let mut tampered = valid.clone();
    tampered.checkpoint.commitment.session_closing = false;
    assert!(dag.verify_and_commit(&tampered).is_err());
    assert_eq!(snapshot(&dag), original);
    dag.verify_and_commit(&valid).unwrap();
}

#[test]
fn configuration_change_uses_new_k_immediately_then_activates_after_full_exchange() {
    let f = Fixture::new();
    let mut dag = f.dag(8);
    let mut mirror = f.dag(8);
    let main = dag.main_branch();
    let next = ProtocolConfig::new(5, SigningAlgorithm::Ed25519, HashAlgorithm::Sha512256).unwrap();
    let original = snapshot(&dag);
    let mut pending = dag.begin_segment();
    let change = pending
        .configure(
            f.a_id,
            dag.genesis_id(),
            hash32(b"configuration branch"),
            next,
            &f.a,
        )
        .unwrap();
    pending.acknowledge_and_pad(f.b_id, &f.b).unwrap();
    pending
        .append(
            f.a_id,
            hash32(b"configuration branch"),
            b"continue".to_vec(),
        )
        .unwrap();
    assert_eq!(dag.config(), config(8));
    assert!(pending.events().iter().all(|event| event.config == next));
    let valid = pending.seal(f.a_id, &f.a).unwrap();
    drop(pending);
    let mut tampered = valid.clone();
    tampered.events[0].authorization.as_mut().unwrap()[0] ^= 1;
    assert!(dag.verify_and_commit(&tampered).is_err());
    assert_eq!(snapshot(&dag), original);
    dag.verify_and_commit(&valid).unwrap();
    mirror.verify_and_commit(&valid).unwrap();
    assert_eq!(dag.config(), next);
    let mut pending = dag.begin_segment();
    for i in 0..5 {
        pending.append(f.b_id, main, vec![i]).unwrap();
    }
    assert!(pending
        .events()
        .iter()
        .all(|event| event.config == next && event.configuration_tip == change));
    let proof = pending.seal(f.a_id, &f.a).unwrap();
    drop(pending);
    dag.verify_and_commit(&proof).unwrap();
    mirror.verify_and_commit(&proof).unwrap();
    assert_eq!(dag.len(), 11);
    assert_shared_history(&dag, &mirror);
    dag.verify_history().unwrap();
    mirror.verify_history().unwrap();
}
