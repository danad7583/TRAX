use std::fs;
use std::path::{Path, PathBuf};

use ed25519_dalek::SigningKey;
use serde::Serialize;
use trax::config::{HashAlgorithm, ProtocolConfig, SigningAlgorithm};
use trax::crypto::hash32;
use trax::encoding::encode_deterministic;
use trax::graph::{participant_id, AuthorityId, GraphSegmentProof, PairDag, PairGenesis};
use trax::profile::hash_bytes;
use trax::storage::DurableDag;
use trax::TraxError;

const HEADER_LENGTH: usize = b"TRAX:PAIR-DAG:JOURNAL\0".len() + 4;

struct TempJournal(PathBuf);

impl TempJournal {
    fn new() -> Self {
        Self(std::env::temp_dir().join(format!(
            "trax-journal-test-{}-{:016x}.log",
            std::process::id(),
            rand::random::<u64>()
        )))
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempJournal {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

fn config(k: usize) -> ProtocolConfig {
    ProtocolConfig::new(k, SigningAlgorithm::Ed25519, HashAlgorithm::Sha512256).unwrap()
}

fn fixture(k: usize) -> (ProtocolConfig, PairGenesis, SigningKey) {
    let config = config(k);
    let sender = SigningKey::from_bytes(&[1; 32]);
    let receiver = SigningKey::from_bytes(&[2; 32]);
    let genesis = PairGenesis::new(
        config,
        [3; 32],
        &sender.verifying_key(),
        &receiver.verifying_key(),
    )
    .unwrap();
    (config, genesis, sender)
}

fn append_proof(dag: &PairDag, key: &SigningKey, epoch: u64) -> GraphSegmentProof {
    let author = participant_id(&SigningKey::from_bytes(&[1; 32]).verifying_key().to_bytes());
    let mut pending = dag.begin_segment();
    for index in 0..dag.config().k() {
        pending
            .append(
                author,
                dag.main_branch(),
                format!("event {index}").into_bytes(),
            )
            .unwrap();
    }
    let signature = pending
        .commitment()
        .unwrap()
        .sign(
            AuthorityId {
                participant: author,
                key_epoch: epoch,
            },
            key,
        )
        .unwrap();
    pending.proof(signature).unwrap()
}

fn rotation_proof(
    dag: &PairDag,
    old: &SigningKey,
    new: &SigningKey,
) -> ([u8; 32], GraphSegmentProof) {
    let author = participant_id(&old.verifying_key().to_bytes());
    let peer = SigningKey::from_bytes(&[2; 32]);
    let peer_id = participant_id(&peer.verifying_key().to_bytes());
    let mut pending = dag.begin_segment();
    let parent = dag.branch_tip(&dag.main_branch()).unwrap();
    let proposal = pending
        .rotate(author, parent, hash32(b"rotation branch"), old, new)
        .unwrap();
    pending.acknowledge_and_pad(peer_id, &peer).unwrap();
    pending.finish_close().unwrap();
    (proposal, pending.seal(author, new).unwrap())
}

#[test]
fn committed_checkpoints_are_reverified_and_preserved_on_reopen() {
    let path = TempJournal::new();
    let (config, genesis, key) = fixture(8);
    let anchor = genesis.node_id().unwrap();
    let mut journal = DurableDag::create_new(path.path(), config, genesis.clone()).unwrap();
    for expected_index in 1..=2 {
        let proof = append_proof(journal.graph(), &key, 0);
        let ids = journal.verify_and_commit(&proof).unwrap();
        assert_eq!(ids.len(), config.k());
        assert_eq!(journal.graph().segment_index(), expected_index);
    }
    let expected_proofs = journal.graph().proofs().to_vec();
    let expected_tip = journal.graph().checkpoint_tip();
    drop(journal);

    let reopened = DurableDag::open(path.path(), config, anchor).unwrap();
    assert_eq!(reopened.graph().genesis(), &genesis);
    assert_eq!(reopened.graph().proofs(), expected_proofs);
    assert_eq!(reopened.graph().checkpoint_tip(), expected_tip);
    assert_eq!(reopened.graph().len(), 1 + 2 * config.k());
}

#[test]
fn rotations_replay_with_old_and_new_key_authorities() {
    let path = TempJournal::new();
    let (config, genesis, old_key) = fixture(5);
    let anchor = genesis.node_id().unwrap();
    let author = participant_id(&old_key.verifying_key().to_bytes());
    let new_key = SigningKey::from_bytes(&[4; 32]);
    let mut journal = DurableDag::create_new(path.path(), config, genesis).unwrap();
    let proof = append_proof(journal.graph(), &old_key, 0);
    journal.verify_and_commit(&proof).unwrap();

    let (rotation, transition) = rotation_proof(journal.graph(), &old_key, &new_key);
    let acknowledgment = transition.acknowledgment.clone().unwrap();
    journal.verify_and_commit(&transition).unwrap();

    let proof = append_proof(journal.graph(), &new_key, 1);
    journal.verify_and_commit(&proof).unwrap();
    let tip = journal.graph().checkpoint_tip();
    drop(journal);

    let reopened = DurableDag::open(path.path(), config, anchor).unwrap();
    assert_eq!(reopened.graph().segment_index(), 3);
    assert_eq!(reopened.graph().checkpoint_tip(), tip);
    let authority = reopened.graph().authority(&author).unwrap();
    assert_eq!(authority.key_epoch, 1);
    assert_eq!(authority.public_key, new_key.verifying_key().to_bytes());
    assert_eq!(authority.rotation_tip, rotation);
    assert_eq!(
        reopened.graph().acknowledgment_for(&rotation),
        Some(&acknowledgment)
    );
}

#[test]
fn independent_attestations_are_durable_without_duplicate_events() {
    let path = TempJournal::new();
    let (config, genesis, key) = fixture(5);
    let anchor = genesis.node_id().unwrap();
    let peer = SigningKey::from_bytes(&[2; 32]);
    let mut writer = DurableDag::create_new(path.path(), config, genesis).unwrap();
    let proof = append_proof(writer.graph(), &key, 0);
    writer.verify_and_commit(&proof).unwrap();
    let attestation = proof
        .checkpoint
        .commitment
        .sign(
            AuthorityId {
                participant: participant_id(&peer.verifying_key().to_bytes()),
                key_epoch: 0,
            },
            &peer,
        )
        .unwrap();
    let length = fs::metadata(path.path()).unwrap().len();
    let checkpoint = writer.graph().checkpoint_tip();
    writer.record_attestation(&attestation).unwrap();
    assert!(fs::metadata(path.path()).unwrap().len() > length);
    assert_eq!(writer.graph().checkpoint_tip(), checkpoint);
    assert_eq!(writer.graph().segment_index(), 1);
    assert_eq!(writer.graph().len(), 1 + config.k());
    assert_eq!(writer.graph().attestations().count(), 2);
    drop(writer);
    let reopened = DurableDag::open(path.path(), config, anchor).unwrap();
    assert_eq!(reopened.graph().checkpoint_tip(), checkpoint);
    assert_eq!(reopened.graph().segment_index(), 1);
    assert_eq!(reopened.graph().len(), 1 + config.k());
    assert_eq!(reopened.graph().attestations().count(), 2);
    reopened.graph().verify_history().unwrap();
}

#[test]
fn rejected_attestation_writes_nothing() {
    let path = TempJournal::new();
    let (config, genesis, key) = fixture(5);
    let mut writer = DurableDag::create_new(path.path(), config, genesis).unwrap();
    let proof = append_proof(writer.graph(), &key, 0);
    writer.verify_and_commit(&proof).unwrap();
    let peer = SigningKey::from_bytes(&[2; 32]);
    let mut attestation = proof
        .checkpoint
        .commitment
        .sign(
            AuthorityId {
                participant: participant_id(&peer.verifying_key().to_bytes()),
                key_epoch: 0,
            },
            &peer,
        )
        .unwrap();
    attestation.signature[0] ^= 1;
    let length = fs::metadata(path.path()).unwrap().len();
    let checkpoint = writer.graph().checkpoint_tip();
    assert!(writer.record_attestation(&attestation).is_err());
    assert_eq!(fs::metadata(path.path()).unwrap().len(), length);
    assert_eq!(writer.graph().checkpoint_tip(), checkpoint);
}

#[test]
fn external_anchor_and_configuration_must_match_the_journal() {
    let path = TempJournal::new();
    let (config, genesis, _) = fixture(8);
    let anchor = genesis.node_id().unwrap();
    drop(DurableDag::create_new(path.path(), config, genesis).unwrap());
    assert!(matches!(
        DurableDag::open(path.path(), self::config(7), anchor),
        Err(TraxError::GraphContextMismatch)
    ));
    assert!(matches!(
        DurableDag::open(path.path(), config, hash32(b"different genesis")),
        Err(TraxError::GraphContextMismatch)
    ));
    #[cfg(feature = "hash-blake3")]
    assert!(matches!(
        DurableDag::open(
            path.path(),
            ProtocolConfig::new(config.k(), SigningAlgorithm::Ed25519, HashAlgorithm::Blake3)
                .unwrap(),
            anchor,
        ),
        Err(TraxError::GraphContextMismatch)
    ));
}

#[test]
fn configuration_transitions_replay_from_the_external_genesis_profile() {
    let path = TempJournal::new();
    let (initial, genesis, key) = fixture(8);
    let anchor = genesis.node_id().unwrap();
    let next = config(5);
    let author = participant_id(&key.verifying_key().to_bytes());
    let mut writer = DurableDag::create_new(path.path(), initial, genesis).unwrap();
    let mut pending = writer.graph().begin_segment();
    pending
        .configure(author, anchor, hash32(b"configuration branch"), next, &key)
        .unwrap();
    let peer = SigningKey::from_bytes(&[2; 32]);
    pending
        .acknowledge_and_pad(participant_id(&peer.verifying_key().to_bytes()), &peer)
        .unwrap();
    pending.finish_close().unwrap();
    let proof = pending.seal(author, &key).unwrap();
    writer.verify_and_commit(&proof).unwrap();
    assert_eq!(writer.graph().config(), next);
    let proof = append_proof(writer.graph(), &key, 0);
    writer.verify_and_commit(&proof).unwrap();
    let checkpoint = writer.graph().checkpoint_tip();
    drop(writer);
    let reopened = DurableDag::open(path.path(), initial, anchor).unwrap();
    assert_eq!(reopened.graph().config(), next);
    assert_eq!(reopened.graph().checkpoint_tip(), checkpoint);
    assert_eq!(reopened.graph().segment_index(), 2);
    assert_eq!(reopened.graph().event_count(), (next.k() * 2) as u64);
}

#[test]
fn create_new_never_overwrites_an_existing_journal() {
    let path = TempJournal::new();
    let (config, genesis, _) = fixture(5);
    drop(DurableDag::create_new(path.path(), config, genesis.clone()).unwrap());
    let before = fs::read(path.path()).unwrap();
    assert!(DurableDag::create_new(path.path(), config, genesis).is_err());
    assert_eq!(fs::read(path.path()).unwrap(), before);
}

#[test]
fn one_writer_holds_the_lock_until_drop() {
    let path = TempJournal::new();
    let (config, genesis, _) = fixture(5);
    let anchor = genesis.node_id().unwrap();
    let writer = DurableDag::create_new(path.path(), config, genesis).unwrap();
    assert!(matches!(
        DurableDag::open(path.path(), config, anchor),
        Err(TraxError::Storage(error)) if error.kind() == std::io::ErrorKind::WouldBlock
    ));
    drop(writer);
    assert!(DurableDag::open(path.path(), config, anchor).is_ok());
}

#[test]
fn rejected_proof_writes_nothing_and_does_not_poison_the_writer() {
    let path = TempJournal::new();
    let (config, genesis, key) = fixture(5);
    let mut journal = DurableDag::create_new(path.path(), config, genesis).unwrap();
    let valid = append_proof(journal.graph(), &key, 0);
    let mut invalid = valid.clone();
    invalid.checkpoint.signature[0] ^= 1;
    let initial_length = fs::metadata(path.path()).unwrap().len();
    let initial_tip = journal.graph().checkpoint_tip();
    assert!(journal.verify_and_commit(&invalid).is_err());
    assert_eq!(fs::metadata(path.path()).unwrap().len(), initial_length);
    assert_eq!(journal.graph().checkpoint_tip(), initial_tip);
    assert_eq!(journal.graph().segment_index(), 0);
    journal.verify_and_commit(&valid).unwrap();
}

fn populated_journal(path: &Path) -> (ProtocolConfig, [u8; 32], Vec<u8>) {
    let (config, genesis, key) = fixture(5);
    let anchor = genesis.node_id().unwrap();
    let mut journal = DurableDag::create_new(path, config, genesis).unwrap();
    let proof = append_proof(journal.graph(), &key, 0);
    journal.verify_and_commit(&proof).unwrap();
    drop(journal);
    (config, anchor, fs::read(path).unwrap())
}

#[test]
fn corruption_and_partial_frames_are_never_silently_repaired() {
    let path = TempJournal::new();
    let (config, anchor, good) = populated_journal(path.path());
    for length in [
        0,
        HEADER_LENGTH - 1,
        HEADER_LENGTH,
        HEADER_LENGTH + 1,
        good.len() - 1,
    ] {
        fs::write(path.path(), &good[..length]).unwrap();
        assert!(
            matches!(
                DurableDag::open(path.path(), config, anchor),
                Err(TraxError::CorruptJournal)
            ),
            "accepted truncated length {length}"
        );
        assert_eq!(fs::metadata(path.path()).unwrap().len(), length as u64);
    }
    for index in [0, HEADER_LENGTH - 1, HEADER_LENGTH + 8, good.len() - 1] {
        let mut corrupt = good.clone();
        corrupt[index] ^= 1;
        fs::write(path.path(), &corrupt).unwrap();
        assert!(
            DurableDag::open(path.path(), config, anchor).is_err(),
            "accepted corruption at {index}"
        );
        assert_eq!(fs::read(path.path()).unwrap(), corrupt);
    }
}

#[test]
fn impossible_frame_lengths_are_rejected_before_allocation() {
    let path = TempJournal::new();
    let (config, anchor, good) = populated_journal(path.path());
    for length in [0, u64::MAX, good.len() as u64] {
        let mut corrupt = good.clone();
        corrupt[HEADER_LENGTH..HEADER_LENGTH + 8].copy_from_slice(&length.to_be_bytes());
        fs::write(path.path(), &corrupt).unwrap();
        assert!(matches!(
            DurableDag::open(path.path(), config, anchor),
            Err(TraxError::CorruptJournal)
        ));
    }
}

// Mirrors the private serialized enum without exposing storage internals.
#[derive(Serialize)]
enum DiskRecord<'a> {
    Segment(&'a GraphSegmentProof),
}

fn replace_last_frame(good: &[u8], record: &[u8]) -> Vec<u8> {
    let genesis_length =
        u64::from_be_bytes(good[HEADER_LENGTH..HEADER_LENGTH + 8].try_into().unwrap()) as usize;
    let segment_start = HEADER_LENGTH + 8 + genesis_length + 32;
    let mut output = good[..segment_start].to_vec();
    output.extend_from_slice(&(record.len() as u64).to_be_bytes());
    output.extend_from_slice(record);
    output.extend_from_slice(&hash_bytes(HashAlgorithm::Sha512256, record).unwrap());
    output
}

#[test]
fn checksummed_but_unauthenticated_checkpoint_is_rejected_on_replay() {
    let path = TempJournal::new();
    let (config, genesis, key) = fixture(5);
    let anchor = genesis.node_id().unwrap();
    let mut writer = DurableDag::create_new(path.path(), config, genesis).unwrap();
    let mut proof = append_proof(writer.graph(), &key, 0);
    writer.verify_and_commit(&proof).unwrap();
    drop(writer);
    let good = fs::read(path.path()).unwrap();
    proof.checkpoint.signature[0] ^= 1;
    let record = encode_deterministic(&DiskRecord::Segment(&proof)).unwrap();
    fs::write(path.path(), replace_last_frame(&good, &record)).unwrap();
    assert!(DurableDag::open(path.path(), config, anchor).is_err());
}

#[test]
fn tampered_peer_prefix_signature_is_rejected_before_write_and_on_replay() {
    let path = TempJournal::new();
    let (config, genesis, key) = fixture(5);
    let anchor = genesis.node_id().unwrap();
    let new_key = SigningKey::from_bytes(&[4; 32]);
    let mut writer = DurableDag::create_new(path.path(), config, genesis).unwrap();
    let (_, valid) = rotation_proof(writer.graph(), &key, &new_key);
    let mut invalid = valid.clone();
    invalid.acknowledgment.as_mut().unwrap().signature[0] ^= 1;
    let length = fs::metadata(path.path()).unwrap().len();
    assert!(writer.verify_and_commit(&invalid).is_err());
    assert_eq!(fs::metadata(path.path()).unwrap().len(), length);
    assert_eq!(writer.graph().checkpoint_tip(), anchor);
    assert_eq!(writer.graph().len(), 1);
    writer.verify_and_commit(&valid).unwrap();
    drop(writer);
    let good = fs::read(path.path()).unwrap();
    let record = encode_deterministic(&DiskRecord::Segment(&invalid)).unwrap();
    fs::write(path.path(), replace_last_frame(&good, &record)).unwrap();
    assert!(DurableDag::open(path.path(), config, anchor).is_err());
}

#[test]
fn noncanonical_record_is_rejected_even_with_a_valid_checksum() {
    let path = TempJournal::new();
    let (config, genesis, key) = fixture(5);
    let anchor = genesis.node_id().unwrap();
    let mut writer = DurableDag::create_new(path.path(), config, genesis).unwrap();
    let proof = append_proof(writer.graph(), &key, 0);
    writer.verify_and_commit(&proof).unwrap();
    drop(writer);
    let good = fs::read(path.path()).unwrap();
    let record = DiskRecord::Segment(&proof);
    let mut raw = Vec::new();
    ciborium::ser::into_writer(&record, &mut raw).unwrap();
    assert_ne!(raw, encode_deterministic(&record).unwrap());
    fs::write(path.path(), replace_last_frame(&good, &raw)).unwrap();
    assert!(matches!(
        DurableDag::open(path.path(), config, anchor),
        Err(TraxError::CorruptJournal)
    ));
}
