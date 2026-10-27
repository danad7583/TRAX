//! Locked, fsync-before-release persistence for transmission-profile sessions.
//!
//! Each verified transmission is written as bounded packet frames, then synced
//! once. Replay does not admit an incomplete transmission. An external exact
//! latest checkpoint is required at open; its authenticated freshness and atomic
//! coupling to application side effects are host responsibilities.

use std::fs::{File, OpenOptions, TryLockError};
use std::io::{self, Read, Seek, Write};
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::encoding::{decode_strict, encode_deterministic};
use crate::genesis::{GenesisNodeV2, VerifiedGenesisV2};
use crate::transmission::{
    PacketV2, SessionCheckpointV2, SessionContextV2, SessionTerminalV2, SessionV2,
    VerifiedTransmissionV2,
};
use crate::transmission_crypto::hash_v2;
use crate::{HashAlgorithm, TraxError};

const MAGIC: &[u8] = b"TRAX:TRANSMISSION:JOURNAL:V2\0";
const HEADER_LIMIT: usize = 65536;
const CHECKSUM_DOMAIN: &[u8] = b"TRAX:JOURNAL:FRAME:V2\0";

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Header {
    genesis: [GenesisNodeV2; 3],
    context: SessionContextV2,
}

#[derive(Serialize, Deserialize)]
enum Record {
    Packet(Box<PacketV2>),
    Terminal(Box<SessionTerminalV2>),
}

pub struct DurableSessionV2 {
    file: File,
    session: SessionV2,
    end: u64,
    poisoned: bool,
}

impl DurableSessionV2 {
    /// The supplied memory session must be fresh and have no provisional work.
    pub fn create_new(path: impl AsRef<Path>, session: SessionV2) -> Result<Self, TraxError> {
        if session.checkpoint().event_count != 0 || session.has_pending() {
            return Err(TraxError::UnexpectedState);
        }
        let header = Header {
            genesis: session.genesis().nodes().clone(),
            context: session.context().clone(),
        };
        let frame = frame(&header)?;
        let mut file = OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .open(path)?;
        lock(&file)?;
        file.write_all(MAGIC)?;
        file.write_all(&frame)?;
        file.sync_all()?;
        let end = file.stream_position()?;
        Ok(Self {
            file,
            session,
            end,
            poisoned: false,
        })
    }

    /// Replays against explicitly accepted genesis and an authenticated latest
    /// state pin. An older complete journal is rejected if its pin differs.
    pub fn open(
        path: impl AsRef<Path>,
        genesis: VerifiedGenesisV2,
        expected: &SessionCheckpointV2,
    ) -> Result<Self, TraxError> {
        let mut file = OpenOptions::new().read(true).write(true).open(path)?;
        lock(&file)?;
        let end = file.metadata()?.len();
        let mut magic = vec![0; MAGIC.len()];
        read_exact(&mut file, &mut magic)?;
        if magic != MAGIC {
            return Err(TraxError::CorruptJournal);
        }
        let header: Header =
            read_frame(&mut file, end, HEADER_LIMIT)?.ok_or(TraxError::CorruptJournal)?;
        if &header.genesis != genesis.nodes() {
            return Err(TraxError::GraphContextMismatch);
        }
        let mut session = SessionV2::new(genesis, header.context.initiator, header.context.nonce)?;
        if session.context() != &header.context {
            return Err(TraxError::GraphContextMismatch);
        }
        let record_limit = session.context().profile.limits.max_wire_packet_bytes as usize + 128;
        while let Some(record) = read_frame::<Record>(&mut file, end, record_limit)? {
            match record {
                Record::Packet(packet) => {
                    if !session.has_pending() {
                        session.start_replay()?;
                    }
                    session.stage_packet(*packet)?;
                }
                Record::Terminal(terminal) => {
                    session.verify_and_close(&terminal)?;
                }
            }
        }
        if session.has_pending() {
            return Err(TraxError::CorruptJournal);
        }
        if &session.checkpoint() != expected {
            return Err(TraxError::GraphContextMismatch);
        }
        Ok(Self {
            file,
            session,
            end,
            poisoned: false,
        })
    }

    pub fn session(&self) -> &SessionV2 {
        &self.session
    }
    pub fn checkpoint(&self) -> SessionCheckpointV2 {
        self.session.checkpoint()
    }
    pub fn is_poisoned(&self) -> bool {
        self.poisoned
    }

    fn check_writer(&self) -> Result<(), TraxError> {
        if self.poisoned {
            Err(TraxError::JournalPoisoned)
        } else {
            Ok(())
        }
    }

    pub fn start_receive(&mut self) -> Result<(), TraxError> {
        self.check_writer()?;
        self.session.start_receive()
    }
    pub fn abort_receive(&mut self) -> bool {
        self.session.abort_receive()
    }
    pub fn expire_receive(&mut self) -> bool {
        self.session.expire_receive()
    }

    pub fn stage_encoded_packet(
        &mut self,
        bytes: &[u8],
    ) -> Result<Option<VerifiedTransmissionV2>, TraxError> {
        self.check_writer()?;
        let packet = match decode_strict(
            bytes,
            self.session.context().profile.limits.max_wire_packet_bytes as usize,
        ) {
            Ok(packet) => packet,
            Err(error) => {
                self.session.abort_receive();
                return Err(error);
            }
        };
        self.stage_packet(packet)
    }

    pub fn stage_packet(
        &mut self,
        packet: PacketV2,
    ) -> Result<Option<VerifiedTransmissionV2>, TraxError> {
        self.check_writer()?;
        let Some(prepared) = self.session.prepare_packet(packet)? else {
            return Ok(None);
        };
        // Encode only one bounded packet at a time, not the whole payload batch.
        // A failed write never releases VerifiedTransmission or advances memory.
        let result = (|| {
            self.check_position()?;
            for packet in prepared.packets() {
                self.file
                    .write_all(&frame(&Record::Packet(Box::new(packet.clone())))?)?;
            }
            self.file.sync_all()?;
            self.end = self.file.stream_position()?;
            Ok::<_, TraxError>(())
        })();
        if let Err(error) = result {
            self.poisoned = true;
            return Err(error);
        }
        Ok(Some(self.session.apply_prepared(prepared)))
    }

    pub fn verify_and_close(&mut self, terminal: &SessionTerminalV2) -> Result<(), TraxError> {
        self.check_writer()?;
        let (tip, hash) = self.session.prepare_close(terminal)?;
        let encoded = frame(&Record::Terminal(Box::new(terminal.clone())))?;
        if let Err(error) = (|| {
            self.check_position()?;
            self.file.write_all(&encoded)?;
            self.file.sync_all()?;
            self.end = self.file.stream_position()?;
            Ok::<_, TraxError>(())
        })() {
            self.poisoned = true;
            return Err(error);
        }
        self.session.apply_close(terminal.clone(), tip, hash);
        Ok(())
    }

    pub fn verify_encoded_close(&mut self, bytes: &[u8]) -> Result<(), TraxError> {
        let terminal = decode_strict(
            bytes,
            self.session.context().profile.limits.max_wire_packet_bytes as usize,
        )?;
        self.verify_and_close(&terminal)
    }

    fn check_position(&mut self) -> Result<(), TraxError> {
        if self.file.metadata()?.len() != self.end || self.file.stream_position()? != self.end {
            return Err(TraxError::CorruptJournal);
        }
        Ok(())
    }
}

fn lock(file: &File) -> Result<(), TraxError> {
    file.try_lock().map_err(|error| match error {
        TryLockError::WouldBlock => TraxError::Storage(io::Error::new(
            io::ErrorKind::WouldBlock,
            "session journal already locked",
        )),
        TryLockError::Error(error) => TraxError::Storage(error),
    })
}

fn frame<T: Serialize>(record: &T) -> Result<Vec<u8>, TraxError> {
    let bytes = encode_deterministic(record)?;
    let mut frame = Vec::with_capacity(
        bytes
            .len()
            .checked_add(40)
            .ok_or(TraxError::ArithmeticOverflow)?,
    );
    frame.extend_from_slice(
        &u64::try_from(bytes.len())
            .map_err(|_| TraxError::ArithmeticOverflow)?
            .to_be_bytes(),
    );
    frame.extend_from_slice(&bytes);
    frame.extend_from_slice(&hash_v2(
        HashAlgorithm::Sha512256,
        CHECKSUM_DOMAIN,
        &[&bytes],
    )?);
    Ok(frame)
}

fn read_frame<T: serde::de::DeserializeOwned + Serialize>(
    file: &mut File,
    end: u64,
    cap: usize,
) -> Result<Option<T>, TraxError> {
    let offset = file.stream_position()?;
    if offset == end {
        return Ok(None);
    }
    let remaining = end.checked_sub(offset).ok_or(TraxError::CorruptJournal)?;
    if remaining < 40 {
        return Err(TraxError::CorruptJournal);
    }
    let mut length = [0; 8];
    read_exact(file, &mut length)?;
    let len = u64::from_be_bytes(length);
    if len == 0 || len > cap as u64 || len > remaining - 40 {
        return Err(TraxError::CorruptJournal);
    }
    let mut bytes = vec![0; usize::try_from(len).map_err(|_| TraxError::ArithmeticOverflow)?];
    read_exact(file, &mut bytes)?;
    let mut checksum = [0; 32];
    read_exact(file, &mut checksum)?;
    if hash_v2(HashAlgorithm::Sha512256, CHECKSUM_DOMAIN, &[&bytes])? != checksum {
        return Err(TraxError::CorruptJournal);
    }
    decode_strict(&bytes, cap)
        .map(Some)
        .map_err(|_| TraxError::CorruptJournal)
}

fn read_exact(file: &mut File, bytes: &mut [u8]) -> Result<(), TraxError> {
    file.read_exact(bytes).map_err(|error| {
        if error.kind() == io::ErrorKind::UnexpectedEof {
            TraxError::CorruptJournal
        } else {
            TraxError::Storage(error)
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::SeekFrom;
    use std::path::PathBuf;

    use crate::genesis::{
        accept_genesis_offer, confirm_genesis, create_genesis_offer, TransmissionProfileV2,
    };
    use ed25519_dalek::SigningKey;

    struct TestPath(PathBuf);
    impl TestPath {
        fn new() -> Self {
            Self(std::env::temp_dir().join(format!(
                "trax-v2-io-fault-{}-{:016x}.log",
                std::process::id(),
                rand::random::<u64>()
            )))
        }
    }
    impl Drop for TestPath {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }

    fn fixture() -> (SessionV2, SigningKey, SigningKey) {
        let a = SigningKey::from_bytes(&[101; 32]);
        let b = SigningKey::from_bytes(&[102; 32]);
        let offer = create_genesis_offer(&a, [103; 32], TransmissionProfileV2::default()).unwrap();
        let acceptance = accept_genesis_offer(&offer, &b, |_| true).unwrap();
        let confirmation = confirm_genesis(&offer, &acceptance, &a, |_| true).unwrap();
        let genesis =
            VerifiedGenesisV2::verify([offer, acceptance, confirmation], |_| true).unwrap();
        let session = SessionV2::new(genesis, a.verifying_key().to_bytes(), [104; 32]).unwrap();
        (session, a, b)
    }

    // White-box fault injection changes only this test's file handle. It adds
    // no production hooks and reliably makes write_all fail on both Windows
    // and Unix, after normal verification and position checks have succeeded.
    fn inject_read_only_handle(writer: &mut DurableSessionV2, path: &Path) {
        let mut read_only = File::open(path).unwrap();
        read_only.seek(SeekFrom::End(0)).unwrap();
        writer.file = read_only;
    }

    #[test]
    fn failed_transmission_write_releases_nothing_preserves_memory_and_poisons_writer() {
        let path = TestPath::new();
        let (session, a, _) = fixture();
        let genesis = session.genesis().clone();
        let mut writer = DurableSessionV2::create_new(&path.0, session).unwrap();
        let before = writer.checkpoint();
        let length = writer.file.metadata().unwrap().len();
        let packets = writer
            .session()
            .build_transmission(&a, "task", &[vec![1], vec![2], vec![3]])
            .unwrap();
        writer.start_receive().unwrap();
        for packet in &packets[..2] {
            assert!(writer.stage_packet(packet.clone()).unwrap().is_none());
        }
        inject_read_only_handle(&mut writer, &path.0);
        assert!(matches!(
            writer.stage_packet(packets[2].clone()),
            Err(TraxError::Storage(_))
        ));
        assert_eq!(writer.checkpoint(), before);
        assert!(writer.session().nodes().is_empty());
        assert!(!writer.session().has_pending());
        assert_eq!(writer.file.metadata().unwrap().len(), length);
        assert!(writer.is_poisoned());
        assert!(matches!(
            writer.start_receive(),
            Err(TraxError::JournalPoisoned)
        ));
        assert!(matches!(
            writer.stage_packet(packets[0].clone()),
            Err(TraxError::JournalPoisoned)
        ));
        drop(writer);
        assert_eq!(
            DurableSessionV2::open(&path.0, genesis, &before)
                .unwrap()
                .checkpoint(),
            before
        );
    }

    #[test]
    fn failed_terminal_write_does_not_close_memory_and_poison_is_sticky() {
        let path = TestPath::new();
        let (session, a, b) = fixture();
        let genesis = session.genesis().clone();
        let mut writer = DurableSessionV2::create_new(&path.0, session).unwrap();
        for key in [&a, &b] {
            let packet = writer
                .session()
                .build_transmission(key, "task", &[vec![4]])
                .unwrap()
                .remove(0);
            writer.start_receive().unwrap();
            assert!(writer.stage_packet(packet).unwrap().is_some());
        }
        let terminal = writer.session().create_close(&a).unwrap();
        let before = writer.checkpoint();
        let length = writer.file.metadata().unwrap().len();
        inject_read_only_handle(&mut writer, &path.0);
        assert!(matches!(
            writer.verify_and_close(&terminal),
            Err(TraxError::Storage(_))
        ));
        assert_eq!(writer.checkpoint(), before);
        assert!(!writer.checkpoint().closed);
        assert!(writer.session().terminal().is_none());
        assert_eq!(writer.file.metadata().unwrap().len(), length);
        assert!(writer.is_poisoned());
        assert!(matches!(
            writer.verify_and_close(&terminal),
            Err(TraxError::JournalPoisoned)
        ));
        drop(writer);
        assert_eq!(
            DurableSessionV2::open(&path.0, genesis, &before)
                .unwrap()
                .checkpoint(),
            before
        );
    }

    #[test]
    fn unexpected_file_position_cannot_overwrite_existing_journal() {
        let path = TestPath::new();
        let (session, a, _) = fixture();
        let mut writer = DurableSessionV2::create_new(&path.0, session).unwrap();
        let before = writer.checkpoint();
        let length = writer.file.metadata().unwrap().len();
        let packet = writer
            .session()
            .build_transmission(&a, "task", &[vec![5]])
            .unwrap()
            .remove(0);
        writer.start_receive().unwrap();
        writer.file.seek(SeekFrom::Start(0)).unwrap();
        assert!(matches!(
            writer.stage_packet(packet),
            Err(TraxError::CorruptJournal)
        ));
        assert_eq!(writer.checkpoint(), before);
        assert_eq!(writer.file.metadata().unwrap().len(), length);
        assert!(writer.is_poisoned());
    }
}
