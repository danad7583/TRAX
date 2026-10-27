use std::fs;
use std::path::{Path, PathBuf};

use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};
use trax::encoding::{decode_strict, encode_deterministic};
use trax::genesis::{
    accept_genesis_offer, confirm_genesis, create_genesis_offer, GenesisNodeV2,
    TransmissionProfileV2, VerifiedGenesisV2,
};
use trax::transmission::{PacketV2, SessionCheckpointV2, SessionTerminalV2, SessionV2};
use trax::transmission_crypto::hash_v2;
use trax::transmission_storage::DurableSessionV2;
use trax::{HashAlgorithm, TraxError};

const MAGIC: &[u8] = b"TRAX:TRANSMISSION:JOURNAL:V2\0";
const CHECKSUM_DOMAIN: &[u8] = b"TRAX:JOURNAL:FRAME:V2\0";

struct TempJournal(PathBuf);
impl TempJournal {
    fn new() -> Self {
        Self(std::env::temp_dir().join(format!(
            "trax-v2-journal-test-{}-{:016x}.log",
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

struct Fixture {
    a: SigningKey,
    b: SigningKey,
    nodes: [GenesisNodeV2; 3],
}
impl Fixture {
    fn new() -> Self {
        let a = SigningKey::from_bytes(&[71; 32]);
        let b = SigningKey::from_bytes(&[83; 32]);
        let offer = create_genesis_offer(&a, [91; 32], TransmissionProfileV2::default()).unwrap();
        let acceptance = accept_genesis_offer(&offer, &b, |_| true).unwrap();
        let confirmation = confirm_genesis(&offer, &acceptance, &a, |_| true).unwrap();
        Self {
            a,
            b,
            nodes: [offer, acceptance, confirmation],
        }
    }
    fn genesis(&self) -> VerifiedGenesisV2 {
        VerifiedGenesisV2::verify(self.nodes.clone(), |key| {
            key == self.a.verifying_key().as_bytes() || key == self.b.verifying_key().as_bytes()
        })
        .unwrap()
    }
    fn session(&self) -> SessionV2 {
        SessionV2::new(self.genesis(), self.a.verifying_key().to_bytes(), [92; 32]).unwrap()
    }
}

fn admit(writer: &mut DurableSessionV2, packets: &[PacketV2]) -> Vec<u8> {
    let before = writer.checkpoint();
    writer.start_receive().unwrap();
    let mut released = Vec::new();
    for (index, packet) in packets.iter().enumerate() {
        let verified = writer
            .stage_encoded_packet(&encode_deterministic(packet).unwrap())
            .unwrap();
        if index + 1 < packets.len() {
            assert!(verified.is_none());
            assert_eq!(writer.checkpoint(), before);
        } else {
            let verified = verified.unwrap();
            assert_eq!(verified.packets(), packets);
            released = verified.payload();
        }
    }
    assert!(!writer.session().has_pending());
    released
}

fn complete_pair(writer: &mut DurableSessionV2, f: &Fixture) {
    for (key, count) in [(&f.a, 3), (&f.b, 2)] {
        let packets = writer
            .session()
            .build_transmission(key, "task", &vec![vec![7; 100]; count])
            .unwrap();
        assert_eq!(admit(writer, &packets), vec![7; count * 100]);
    }
}

#[derive(Serialize, Deserialize)]
enum Record {
    Packet(Box<PacketV2>),
    Terminal(Box<SessionTerminalV2>),
}

#[derive(Clone, Copy)]
struct Frame {
    start: usize,
    payload: usize,
    length: usize,
    end: usize,
}
fn frames(bytes: &[u8]) -> Vec<Frame> {
    assert!(bytes.starts_with(MAGIC));
    let mut result = Vec::new();
    let mut start = MAGIC.len();
    while start < bytes.len() {
        let length = usize::try_from(u64::from_be_bytes(
            bytes[start..start + 8].try_into().unwrap(),
        ))
        .unwrap();
        let payload = start + 8;
        let end = payload + length + 32;
        assert!(end <= bytes.len());
        result.push(Frame {
            start,
            payload,
            length,
            end,
        });
        start = end;
    }
    result
}
fn encoded_frame(bytes: &[u8]) -> Vec<u8> {
    let mut frame = (bytes.len() as u64).to_be_bytes().to_vec();
    frame.extend_from_slice(bytes);
    frame.extend_from_slice(&hash_v2(HashAlgorithm::Sha512256, CHECKSUM_DOMAIN, &[bytes]).unwrap());
    frame
}
fn replace_frame(journal: &[u8], frame: Frame, payload: &[u8]) -> Vec<u8> {
    let mut modified = journal[..frame.start].to_vec();
    modified.extend_from_slice(&encoded_frame(payload));
    modified.extend_from_slice(&journal[frame.end..]);
    modified
}

#[test]
fn fresh_journal_reopens_against_exact_genesis_and_initial_checkpoint() {
    let f = Fixture::new();
    let path = TempJournal::new();
    let writer = DurableSessionV2::create_new(path.path(), f.session()).unwrap();
    let pin = writer.checkpoint();
    assert_eq!(pin.event_count, 0);
    assert!(!writer.is_poisoned());
    let context = writer.session().context().clone();
    drop(writer);
    let reopened = DurableSessionV2::open(path.path(), f.genesis(), &pin).unwrap();
    assert_eq!(reopened.checkpoint(), pin);
    assert_eq!(reopened.session().context(), &context);
    assert!(reopened.session().nodes().is_empty());
}

#[test]
fn request_response_rounds_and_original_terminal_reverify_on_reopen() {
    let f = Fixture::new();
    let path = TempJournal::new();
    let mut writer = DurableSessionV2::create_new(path.path(), f.session()).unwrap();
    for _ in 0..2 {
        complete_pair(&mut writer, &f);
        let pin = writer.checkpoint();
        let original_seals: Vec<_> = writer
            .session()
            .nodes()
            .iter()
            .filter_map(|node| node.authentication().cloned())
            .collect();
        drop(writer);
        writer = DurableSessionV2::open(path.path(), f.genesis(), &pin).unwrap();
        let replayed_seals: Vec<_> = writer
            .session()
            .nodes()
            .iter()
            .filter_map(|node| node.authentication().cloned())
            .collect();
        assert_eq!(original_seals, replayed_seals);
    }
    let terminal = writer.session().create_close(&f.a).unwrap();
    let before = writer.checkpoint();
    writer
        .verify_encoded_close(&encode_deterministic(&terminal).unwrap())
        .unwrap();
    let pin = writer.checkpoint();
    assert!(pin.closed);
    assert_eq!(pin.event_count, before.event_count + 1);
    drop(writer);
    let mut reopened = DurableSessionV2::open(path.path(), f.genesis(), &pin).unwrap();
    assert_eq!(reopened.session().terminal(), Some(&terminal));
    assert_eq!(reopened.checkpoint(), pin);
    assert!(reopened.start_receive().is_err());
    assert!(reopened.verify_and_close(&terminal).is_err());
}

#[test]
fn exclusive_writer_lock_and_create_new_prevent_duplicate_writers_and_overwrite() {
    let f = Fixture::new();
    let path = TempJournal::new();
    let writer = DurableSessionV2::create_new(path.path(), f.session()).unwrap();
    let pin = writer.checkpoint();
    let length = fs::metadata(path.path()).unwrap().len();
    assert!(
        matches!(DurableSessionV2::open(path.path(), f.genesis(), &pin), Err(TraxError::Storage(error)) if error.kind() == std::io::ErrorKind::WouldBlock)
    );
    assert!(DurableSessionV2::create_new(path.path(), f.session()).is_err());
    assert_eq!(fs::metadata(path.path()).unwrap().len(), length);
    drop(writer);
    DurableSessionV2::open(path.path(), f.genesis(), &pin).unwrap();
}

#[test]
fn old_checkpoint_or_old_complete_prefix_cannot_satisfy_current_external_pin() {
    let f = Fixture::new();
    let path = TempJournal::new();
    let mut writer = DurableSessionV2::create_new(path.path(), f.session()).unwrap();
    let old_pin = writer.checkpoint();
    // Read only after releasing the OS lock for portability across platforms.
    drop(writer);
    let old_journal = fs::read(path.path()).unwrap();
    writer = DurableSessionV2::open(path.path(), f.genesis(), &old_pin).unwrap();
    complete_pair(&mut writer, &f);
    let latest = writer.checkpoint();
    drop(writer);
    assert!(DurableSessionV2::open(path.path(), f.genesis(), &old_pin).is_err());
    DurableSessionV2::open(path.path(), f.genesis(), &latest).unwrap();
    fs::write(path.path(), &old_journal).unwrap();
    assert!(DurableSessionV2::open(path.path(), f.genesis(), &latest).is_err());
    // An externally stale pin plus its matching old journal cannot prove
    // freshness; pin storage/side-effect coupling is explicitly host-owned.
    DurableSessionV2::open(path.path(), f.genesis(), &old_pin).unwrap();
}

#[test]
fn provisional_or_rejected_packets_are_neither_persisted_nor_released() {
    let f = Fixture::new();
    let path = TempJournal::new();
    let mut writer = DurableSessionV2::create_new(path.path(), f.session()).unwrap();
    let initial = writer.checkpoint();
    let length = fs::metadata(path.path()).unwrap().len();
    let packets = writer
        .session()
        .build_transmission(&f.a, "task", &[vec![1; 20], vec![2; 20], vec![3; 20]])
        .unwrap();
    writer.start_receive().unwrap();
    for packet in &packets[..2] {
        assert!(writer.stage_packet(packet.clone()).unwrap().is_none());
        assert_eq!(writer.checkpoint(), initial);
        assert_eq!(fs::metadata(path.path()).unwrap().len(), length);
    }
    assert!(writer.abort_receive());
    writer.start_receive().unwrap();
    assert!(writer.stage_packet(packets[0].clone()).unwrap().is_none());
    assert!(writer.stage_encoded_packet(b"malformed CBOR").is_err());
    assert!(!writer.session().has_pending());
    writer.start_receive().unwrap();
    for packet in &packets[..2] {
        writer.stage_packet(packet.clone()).unwrap();
    }
    let mut bad = packets[2].clone();
    bad.authentication.as_mut().unwrap().signature[0] ^= 1;
    assert!(writer.stage_packet(bad).is_err());
    assert!(!writer.session().has_pending());
    assert_eq!(writer.checkpoint(), initial);
    assert!(!writer.is_poisoned());
    assert_eq!(fs::metadata(path.path()).unwrap().len(), length);
    drop(writer);
    DurableSessionV2::open(path.path(), f.genesis(), &initial).unwrap();
}

#[test]
fn durable_creation_rejects_preexisting_admission_or_pending_work_without_creating_file() {
    let f = Fixture::new();
    let path = TempJournal::new();
    let mut session = f.session();
    session.start_receive().unwrap();
    assert!(DurableSessionV2::create_new(path.path(), session).is_err());
    assert!(!path.path().exists());
    let mut session = f.session();
    let packets = session
        .build_transmission(&f.a, "task", &[vec![1]])
        .unwrap();
    session.start_receive().unwrap();
    assert!(session.stage_packet(packets[0].clone()).unwrap().is_some());
    assert!(DurableSessionV2::create_new(path.path(), session).is_err());
    assert!(!path.path().exists());
}

#[test]
fn interrupted_frame_and_complete_nonfinal_packet_transaction_fail_closed() {
    let f = Fixture::new();
    let source = TempJournal::new();
    let mut writer = DurableSessionV2::create_new(source.path(), f.session()).unwrap();
    let initial = writer.checkpoint();
    let packets = writer
        .session()
        .build_transmission(&f.a, "task", &[vec![4; 30], vec![5; 30]])
        .unwrap();
    admit(&mut writer, &packets);
    let latest = writer.checkpoint();
    drop(writer);
    let bytes = fs::read(source.path()).unwrap();
    let frames = frames(&bytes);
    assert_eq!(frames.len(), 3);
    let final_frame = frames[2];
    for end in [
        MAGIC.len() - 1,
        MAGIC.len() + 1,
        final_frame.start,
        final_frame.start + 1,
        final_frame.payload + final_frame.length - 1,
        bytes.len() - 1,
    ] {
        let path = TempJournal::new();
        fs::write(path.path(), &bytes[..end]).unwrap();
        assert!(DurableSessionV2::open(path.path(), f.genesis(), &latest).is_err());
        assert!(DurableSessionV2::open(path.path(), f.genesis(), &initial).is_err());
    }
    // Whole, checksummed packet frames without their final signature are
    // still incomplete; replay must not silently recover to the old pin.
    let path = TempJournal::new();
    fs::write(path.path(), &bytes[..frames[1].end]).unwrap();
    assert!(matches!(
        DurableSessionV2::open(path.path(), f.genesis(), &initial),
        Err(TraxError::CorruptJournal)
    ));
}

#[test]
fn recomputed_checksums_do_not_authorize_payload_or_signature_substitution() {
    let f = Fixture::new();
    let source = TempJournal::new();
    let mut writer = DurableSessionV2::create_new(source.path(), f.session()).unwrap();
    let packets = writer
        .session()
        .build_transmission(&f.a, "task", &[vec![6; 50]])
        .unwrap();
    admit(&mut writer, &packets);
    let pin = writer.checkpoint();
    drop(writer);
    let bytes = fs::read(source.path()).unwrap();
    let packet_frame = frames(&bytes)[1];
    for tamper_payload in [true, false] {
        let mut record: Record = decode_strict(
            &bytes[packet_frame.payload..packet_frame.payload + packet_frame.length],
            8192,
        )
        .unwrap();
        let Record::Packet(packet) = &mut record else {
            panic!("expected packet")
        };
        if tamper_payload {
            packet.payload[0] ^= 1;
        } else {
            packet.authentication.as_mut().unwrap().signature[0] ^= 1;
        }
        let modified = replace_frame(
            &bytes,
            packet_frame,
            &encode_deterministic(&record).unwrap(),
        );
        let path = TempJournal::new();
        fs::write(path.path(), modified).unwrap();
        assert!(DurableSessionV2::open(path.path(), f.genesis(), &pin).is_err());
    }
}

#[test]
fn checksum_parser_and_declared_length_corruption_are_rejected_before_replay() {
    let f = Fixture::new();
    let source = TempJournal::new();
    let writer = DurableSessionV2::create_new(source.path(), f.session()).unwrap();
    let pin = writer.checkpoint();
    drop(writer);
    let original = fs::read(source.path()).unwrap();
    let mut invalid_checksum = original.clone();
    *invalid_checksum.last_mut().unwrap() ^= 1;
    let mut oversized_length = original.clone();
    oversized_length[MAGIC.len()..MAGIC.len() + 8].copy_from_slice(&u64::MAX.to_be_bytes());
    let header = frames(&original)[0];
    let invalid_schema = replace_frame(
        &original,
        header,
        &encode_deterministic(&"not a header").unwrap(),
    );
    for modified in [invalid_checksum, oversized_length, invalid_schema] {
        let path = TempJournal::new();
        fs::write(path.path(), modified).unwrap();
        assert!(matches!(
            DurableSessionV2::open(path.path(), f.genesis(), &pin),
            Err(TraxError::CorruptJournal)
        ));
    }
}

#[test]
fn legacy_format_wrong_genesis_and_wrong_session_pins_cannot_restore_v2() {
    let f = Fixture::new();
    let path = TempJournal::new();
    let writer = DurableSessionV2::create_new(path.path(), f.session()).unwrap();
    let pin = writer.checkpoint();
    drop(writer);
    let offer = create_genesis_offer(&f.a, [1; 32], TransmissionProfileV2::default()).unwrap();
    let acceptance = accept_genesis_offer(&offer, &f.b, |_| true).unwrap();
    let confirmation = confirm_genesis(&offer, &acceptance, &f.a, |_| true).unwrap();
    let wrong = VerifiedGenesisV2::verify([offer, acceptance, confirmation], |_| true).unwrap();
    assert!(DurableSessionV2::open(path.path(), wrong, &pin).is_err());
    let other = SessionV2::new(f.genesis(), f.a.verifying_key().to_bytes(), [7; 32]).unwrap();
    assert!(DurableSessionV2::open(path.path(), f.genesis(), &other.checkpoint()).is_err());
    let legacy = TempJournal::new();
    fs::write(legacy.path(), b"TRAX:PAIR-DAG:JOURNAL\0\0\0\0\x03").unwrap();
    assert!(matches!(
        DurableSessionV2::open(legacy.path(), f.genesis(), &pin),
        Err(TraxError::CorruptJournal)
    ));
}

#[test]
fn invalid_terminal_changes_neither_durable_length_nor_trusted_checkpoint() {
    let f = Fixture::new();
    let path = TempJournal::new();
    let mut writer = DurableSessionV2::create_new(path.path(), f.session()).unwrap();
    complete_pair(&mut writer, &f);
    let pin = writer.checkpoint();
    let length = fs::metadata(path.path()).unwrap().len();
    let mut terminal = writer.session().create_close(&f.a).unwrap();
    terminal.signature[0] ^= 1;
    assert!(writer.verify_and_close(&terminal).is_err());
    assert_eq!(writer.checkpoint(), pin);
    assert_eq!(fs::metadata(path.path()).unwrap().len(), length);
    assert!(!writer.is_poisoned());
}

#[test]
fn every_external_checkpoint_field_is_required_exactly() {
    let f = Fixture::new();
    let path = TempJournal::new();
    let mut writer = DurableSessionV2::create_new(path.path(), f.session()).unwrap();
    complete_pair(&mut writer, &f);
    let pin = writer.checkpoint();
    drop(writer);
    let mutations: [fn(&mut SessionCheckpointV2); 6] = [
        |c| c.session_id[0] ^= 1,
        |c| c.tip[0] ^= 1,
        |c| c.history_hash[0] ^= 1,
        |c| c.event_count += 1,
        |c| c.transmission_id += 1,
        |c| c.closed = true,
    ];
    for mutation in mutations {
        let mut wrong = pin.clone();
        mutation(&mut wrong);
        assert!(DurableSessionV2::open(path.path(), f.genesis(), &wrong).is_err());
    }
    DurableSessionV2::open(path.path(), f.genesis(), &pin).unwrap();
}
