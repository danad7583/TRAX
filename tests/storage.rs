use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};
use std::{
    fs,
    path::{Path, PathBuf},
};
use trax::config::TransmissionProfile;
use trax::crypto::hash_domain;
use trax::encoding::{decode_strict, encode_deterministic};
use trax::genesis::{
    accept_genesis_offer, confirm_genesis, create_genesis_offer, GenesisNode, VerifiedGenesis,
};
use trax::session::{HistoryKind, Relationship};
use trax::storage::DurableRelationship;
use trax::transmission::{Packet, SessionTerminal};
use trax::HashAlgorithm;

const MAGIC: &[u8] = b"TRAX:RELATIONSHIP:JOURNAL:V3\0";
struct Temp(PathBuf);
impl Temp {
    fn new() -> Self {
        Self(std::env::temp_dir().join(format!(
            "trax-history-{}-{}.log",
            std::process::id(),
            rand::random::<u64>()
        )))
    }
    fn path(&self) -> &Path {
        &self.0
    }
}
impl Drop for Temp {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}
struct Fixture {
    a: SigningKey,
    b: SigningKey,
    nodes: [GenesisNode; 3],
}
impl Fixture {
    fn new() -> Self {
        let a = SigningKey::from_bytes(&[1; 32]);
        let b = SigningKey::from_bytes(&[2; 32]);
        let offer = create_genesis_offer(&a, [3; 32], TransmissionProfile::default()).unwrap();
        let accept =
            accept_genesis_offer(&offer, &b, |key| *key == a.verifying_key().to_bytes()).unwrap();
        let confirm = confirm_genesis(&offer, &accept, &a, |key| {
            *key == b.verifying_key().to_bytes()
        })
        .unwrap();
        Self {
            a,
            b,
            nodes: [offer, accept, confirm],
        }
    }
    fn genesis(&self) -> VerifiedGenesis {
        VerifiedGenesis::verify(self.nodes.clone(), |key| {
            *key == self.a.verifying_key().to_bytes() || *key == self.b.verifying_key().to_bytes()
        })
        .unwrap()
    }
    fn relationship(&self) -> Relationship {
        Relationship::new(self.genesis()).unwrap()
    }
    fn writer(&self, path: &Path) -> DurableRelationship {
        DurableRelationship::create_new(path, self.relationship()).unwrap()
    }
}
fn admit(writer: &mut DurableRelationship, packets: &[Packet]) -> Vec<u8> {
    let before = writer.checkpoint();
    writer.start_receive().unwrap();
    let mut payload = Vec::new();
    for (index, packet) in packets.iter().enumerate() {
        let result = writer
            .stage_encoded_packet(&encode_deterministic(packet).unwrap())
            .unwrap();
        if index + 1 < packets.len() {
            assert!(result.is_none());
            assert_eq!(writer.checkpoint(), before);
        } else {
            payload = result.unwrap().payload();
        }
    }
    payload
}
fn round(writer: &mut DurableRelationship, initiator: &SigningKey, responder: &SigningKey) {
    for (key, count) in [(initiator, 3), (responder, 2)] {
        let packets = writer
            .relationship()
            .build_transmission(key, "task", &vec![vec![7; 100]; count])
            .unwrap();
        assert_eq!(admit(writer, &packets), vec![7; count * 100]);
    }
}

#[test]
fn fresh_genesis_and_exact_pin_reopen_without_session_reset() {
    let f = Fixture::new();
    let p = Temp::new();
    let writer = f.writer(p.path());
    let pin = writer.checkpoint();
    assert_eq!(pin.record_count, 0);
    assert_eq!(writer.relationship().history().len(), 1);
    drop(writer);
    let reopened = DurableRelationship::open(p.path(), f.genesis(), &pin).unwrap();
    assert_eq!(reopened.checkpoint(), pin);
    assert!(reopened.relationship().record(&pin.tip).is_some());
}

#[test]
fn two_closed_sessions_replay_continuously_with_both_initiators() {
    let f = Fixture::new();
    let p = Temp::new();
    let mut writer = f.writer(p.path());
    writer
        .begin_session(f.a.verifying_key().to_bytes(), [4; 32])
        .unwrap();
    round(&mut writer, &f.a, &f.b);
    let terminal = writer.relationship().create_close(&f.a).unwrap();
    writer.verify_and_close(&terminal).unwrap();
    let first = writer.checkpoint();
    writer
        .begin_session(f.b.verifying_key().to_bytes(), [5; 32])
        .unwrap();
    assert_eq!(writer.checkpoint(), first);
    round(&mut writer, &f.b, &f.a);
    let terminal = writer.relationship().create_close(&f.b).unwrap();
    writer.verify_and_close(&terminal).unwrap();
    let pin = writer.checkpoint();
    let history = writer.relationship().history().to_vec();
    assert_eq!(pin.completed_sessions, 2);
    assert!(
        matches!(&writer.relationship().record(&pin.tip).unwrap().kind,HistoryKind::SessionTerminal{terminal:original}if original==&terminal)
    );
    drop(writer);
    let restored = DurableRelationship::open(p.path(), f.genesis(), &pin).unwrap();
    assert_eq!(restored.relationship().history(), history);
    assert_eq!(
        restored.relationship().ancestors(&pin.tip).unwrap().len(),
        pin.record_count as usize
    );
}

#[test]
fn active_session_reopens_and_requires_its_response_before_another_session() {
    let f = Fixture::new();
    let p = Temp::new();
    let mut writer = f.writer(p.path());
    writer
        .begin_session(f.a.verifying_key().to_bytes(), [4; 32])
        .unwrap();
    let packets = writer
        .relationship()
        .build_transmission(&f.a, "task", &[vec![1], vec![2]])
        .unwrap();
    admit(&mut writer, &packets);
    let pin = writer.checkpoint();
    drop(writer);
    let mut restored = DurableRelationship::open(p.path(), f.genesis(), &pin).unwrap();
    assert!(restored
        .begin_session(f.b.verifying_key().to_bytes(), [5; 32])
        .is_err());
    let response = restored
        .relationship()
        .build_transmission(&f.b, "result", &[vec![9]])
        .unwrap();
    assert_eq!(admit(&mut restored, &response), vec![9]);
}

#[test]
fn old_complete_prefix_and_old_pins_fail_against_current_authority() {
    let f = Fixture::new();
    let p = Temp::new();
    let mut writer = f.writer(p.path());
    let initial = writer.checkpoint();
    let initial_len = fs::metadata(p.path()).unwrap().len();
    writer
        .begin_session(f.a.verifying_key().to_bytes(), [4; 32])
        .unwrap();
    round(&mut writer, &f.a, &f.b);
    let terminal = writer.relationship().create_close(&f.a).unwrap();
    writer.verify_and_close(&terminal).unwrap();
    let latest = writer.checkpoint();
    drop(writer);
    assert!(DurableRelationship::open(p.path(), f.genesis(), &initial).is_err());
    let bytes = fs::read(p.path()).unwrap();
    fs::write(p.path(), &bytes[..initial_len as usize]).unwrap();
    assert!(DurableRelationship::open(p.path(), f.genesis(), &latest).is_err());
    assert!(DurableRelationship::open(p.path(), f.genesis(), &initial).is_ok());
}

#[test]
fn duplicate_writers_and_create_new_cannot_replace_authority() {
    let f = Fixture::new();
    let p = Temp::new();
    let writer = f.writer(p.path());
    let length = fs::metadata(p.path()).unwrap().len();
    let pin = writer.checkpoint();
    assert!(DurableRelationship::open(p.path(), f.genesis(), &pin).is_err());
    assert!(DurableRelationship::create_new(p.path(), f.relationship()).is_err());
    assert_eq!(fs::metadata(p.path()).unwrap().len(), length);
    drop(writer);
    assert!(DurableRelationship::open(p.path(), f.genesis(), &pin).is_ok());
}

#[test]
fn provisional_or_rejected_transmissions_never_change_file_or_authority() {
    let f = Fixture::new();
    let p = Temp::new();
    let mut writer = f.writer(p.path());
    writer
        .begin_session(f.a.verifying_key().to_bytes(), [4; 32])
        .unwrap();
    let packets = writer
        .relationship()
        .build_transmission(&f.a, "task", &[vec![1], vec![2]])
        .unwrap();
    let before = writer.checkpoint();
    let length = fs::metadata(p.path()).unwrap().len();
    writer.start_receive().unwrap();
    assert!(writer.stage_packet(packets[0].clone()).unwrap().is_none());
    assert_eq!(fs::metadata(p.path()).unwrap().len(), length);
    let mut bad = packets[1].clone();
    bad.authentication.as_mut().unwrap().signature[0] ^= 1;
    assert!(writer.stage_packet(bad).is_err());
    assert_eq!(writer.checkpoint(), before);
    assert_eq!(fs::metadata(p.path()).unwrap().len(), length);
    assert!(!writer.is_poisoned());
    admit(&mut writer, &packets);
}

#[derive(Serialize, Deserialize)]
enum Record {
    Packet(Box<Packet>),
    Terminal(Box<SessionTerminal>),
}
fn frame<T: Serialize>(value: &T) -> Vec<u8> {
    let bytes = encode_deterministic(value).unwrap();
    let mut out = (bytes.len() as u64).to_be_bytes().to_vec();
    out.extend_from_slice(&bytes);
    out.extend_from_slice(
        &hash_domain(
            HashAlgorithm::Sha512256,
            b"TRAX:JOURNAL:FRAME:V3\0",
            &[&bytes],
        )
        .unwrap(),
    );
    out
}

#[test]
fn interrupted_frames_and_complete_unsigned_transactions_fail_closed() {
    let f = Fixture::new();
    let p = Temp::new();
    let mut writer = f.writer(p.path());
    let initial = writer.checkpoint();
    let header_len = fs::metadata(p.path()).unwrap().len() as usize;
    writer
        .begin_session(f.a.verifying_key().to_bytes(), [4; 32])
        .unwrap();
    let packets = writer
        .relationship()
        .build_transmission(&f.a, "task", &[vec![1], vec![2]])
        .unwrap();
    admit(&mut writer, &packets);
    let pin = writer.checkpoint();
    drop(writer);
    let full = fs::read(p.path()).unwrap();
    fs::write(p.path(), &full[..full.len() - 1]).unwrap();
    assert!(DurableRelationship::open(p.path(), f.genesis(), &pin).is_err());
    let mut unsealed = full[..header_len].to_vec();
    unsealed.extend_from_slice(&frame(&Record::Packet(Box::new(packets[0].clone()))));
    fs::write(p.path(), unsealed).unwrap();
    assert!(DurableRelationship::open(p.path(), f.genesis(), &initial).is_err());
}

#[test]
fn recomputed_frame_checksums_cannot_authorize_modified_payload_or_signature() {
    let f = Fixture::new();
    let p = Temp::new();
    let mut writer = f.writer(p.path());
    writer
        .begin_session(f.a.verifying_key().to_bytes(), [4; 32])
        .unwrap();
    let packets = writer
        .relationship()
        .build_transmission(&f.a, "task", &[vec![1]])
        .unwrap();
    let header_len = fs::metadata(p.path()).unwrap().len() as usize;
    let pin_before = writer.checkpoint();
    admit(&mut writer, &packets);
    let latest = writer.checkpoint();
    drop(writer);
    let header = fs::read(p.path()).unwrap()[..header_len].to_vec();
    for signature in [false, true] {
        let mut forged = packets[0].clone();
        if signature {
            forged.authentication.as_mut().unwrap().signature[0] ^= 1;
        } else {
            forged.payload[0] ^= 1;
        }
        let mut bytes = header.clone();
        bytes.extend_from_slice(&frame(&Record::Packet(Box::new(forged))));
        fs::write(p.path(), bytes).unwrap();
        assert!(DurableRelationship::open(p.path(), f.genesis(), &latest).is_err());
        assert!(DurableRelationship::open(p.path(), f.genesis(), &pin_before).is_err());
    }
}

#[test]
fn invalid_lengths_encoding_checksums_genesis_and_external_fields_fail() {
    let f = Fixture::new();
    let p = Temp::new();
    let writer = f.writer(p.path());
    let pin = writer.checkpoint();
    drop(writer);
    let valid = fs::read(p.path()).unwrap();
    for tail in [vec![0; 1], u64::MAX.to_be_bytes().to_vec(), vec![0; 40]] {
        let mut bad = valid.clone();
        bad.extend_from_slice(&tail);
        fs::write(p.path(), bad).unwrap();
        assert!(DurableRelationship::open(p.path(), f.genesis(), &pin).is_err());
    }
    let mut bad = valid.clone();
    *bad.last_mut().unwrap() ^= 1;
    fs::write(p.path(), bad).unwrap();
    assert!(DurableRelationship::open(p.path(), f.genesis(), &pin).is_err());
    fs::write(p.path(), &valid).unwrap();
    let mut bad_pin = pin.clone();
    bad_pin.tip[0] ^= 1;
    assert!(DurableRelationship::open(p.path(), f.genesis(), &bad_pin).is_err());
    let mut bad_pin = pin.clone();
    bad_pin.relationship_id[0] ^= 1;
    assert!(DurableRelationship::open(p.path(), f.genesis(), &bad_pin).is_err());
    let nodes = f.nodes.clone();
    let mut v: ciborium::Value =
        decode_strict(&encode_deterministic(&nodes).unwrap(), 65536).unwrap();
    if let ciborium::Value::Array(ref mut values) = v {
        values.swap(0, 1);
    }
    assert!(VerifiedGenesis::verify(
        decode_strict(&encode_deterministic(&v).unwrap(), 65536).unwrap(),
        |_| true
    )
    .is_err());
    assert_eq!(&valid[..MAGIC.len()], MAGIC);
}

#[test]
fn stale_session_start_and_duplicate_terminal_do_not_write() {
    let f = Fixture::new();
    let p = Temp::new();
    let mut writer = f.writer(p.path());
    writer
        .begin_session(f.a.verifying_key().to_bytes(), [4; 32])
        .unwrap();
    let packets = writer
        .relationship()
        .build_transmission(&f.a, "task", &[vec![1]])
        .unwrap();
    admit(&mut writer, &packets);
    let response = writer
        .relationship()
        .build_transmission(&f.b, "result", &[vec![2]])
        .unwrap();
    admit(&mut writer, &response);
    let terminal = writer.relationship().create_close(&f.a).unwrap();
    writer.verify_and_close(&terminal).unwrap();
    let pin = writer.checkpoint();
    let length = fs::metadata(p.path()).unwrap().len();
    assert!(writer.verify_and_close(&terminal).is_err());
    writer.start_receive().unwrap();
    assert!(writer.stage_packet(packets[0].clone()).is_err());
    assert_eq!(writer.checkpoint(), pin);
    assert_eq!(fs::metadata(p.path()).unwrap().len(), length);
}

#[test]
fn durable_creation_rejects_prior_drafts_or_admission() {
    let f = Fixture::new();
    let p = Temp::new();
    let mut relationship = f.relationship();
    relationship
        .begin_session(f.a.verifying_key().to_bytes(), [4; 32])
        .unwrap();
    assert!(DurableRelationship::create_new(p.path(), relationship).is_err());
    assert!(!p.path().exists());
}

#[test]
fn every_external_pin_field_including_active_session_is_enforced() {
    let f = Fixture::new();
    let p = Temp::new();
    let mut writer = f.writer(p.path());
    writer
        .begin_session(f.a.verifying_key().to_bytes(), [4; 32])
        .unwrap();
    let packets = writer
        .relationship()
        .build_transmission(&f.a, "task", &[vec![1]])
        .unwrap();
    admit(&mut writer, &packets);
    let pin = writer.checkpoint();
    drop(writer);
    let mutations: Vec<fn(&mut trax::transmission::RelationshipCheckpoint)> = vec![
        |p| p.relationship_id[0] ^= 1,
        |p| p.tip[0] ^= 1,
        |p| p.history_hash[0] ^= 1,
        |p| p.record_count += 1,
        |p| p.completed_sessions += 1,
        |p| p.last_session_id = None,
        |p| p.active_session = None,
        |p| p.active_session.as_mut().unwrap().session_id[0] ^= 1,
        |p| p.active_session.as_mut().unwrap().session_index += 1,
        |p| p.active_session.as_mut().unwrap().tip[0] ^= 1,
        |p| p.active_session.as_mut().unwrap().history_hash[0] ^= 1,
        |p| p.active_session.as_mut().unwrap().packet_count += 1,
        |p| p.active_session.as_mut().unwrap().transmission_id += 1,
        |p| p.active_session.as_mut().unwrap().closed = true,
    ];
    for mutation in mutations {
        let mut bad = pin.clone();
        mutation(&mut bad);
        assert!(matches!(
            DurableRelationship::open(p.path(), f.genesis(), &bad),
            Err(trax::TraxError::CheckpointMismatch)
        ));
    }
    assert!(DurableRelationship::open(p.path(), f.genesis(), &pin).is_ok());
}
