//! Durable authority for a complete relationship across application sessions.
//! Verification precedes writes; synchronization precedes trusted state and
//! payload release. Restore requires accepted genesis and a fresh external pin.
use crate::crypto::hash_domain;
use crate::encoding::{decode_strict, encode_deterministic};
use crate::genesis::{GenesisNode, VerifiedGenesis};
use crate::session::Relationship;
use crate::transmission::{Packet, RelationshipCheckpoint, SessionTerminal, VerifiedTransmission};
use crate::{HashAlgorithm, TraxError};
use serde::{Deserialize, Serialize};
use std::fs::{File, OpenOptions, TryLockError};
use std::io::{self, Read, Seek, Write};
use std::path::Path;

const MAGIC: &[u8] = b"TRAX:RELATIONSHIP:JOURNAL:V3\0";
const HEADER_LIMIT: usize = 65536;
const CHECKSUM_DOMAIN: &[u8] = b"TRAX:JOURNAL:FRAME:V3\0";

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Header {
    genesis: [GenesisNode; 3],
}
#[derive(Serialize, Deserialize)]
enum Record {
    Packet(Box<Packet>),
    Terminal(Box<SessionTerminal>),
}

pub struct DurableRelationship {
    file: File,
    relationship: Relationship,
    end: u64,
    poisoned: bool,
    #[cfg(test)]
    fail_sync: bool,
}

impl DurableRelationship {
    /// No session or provisional work may predate durable ownership.
    pub fn create_new(
        path: impl AsRef<Path>,
        relationship: Relationship,
    ) -> Result<Self, TraxError> {
        if relationship.checkpoint().record_count != 0
            || relationship.session().is_some()
            || relationship.has_pending()
        {
            return Err(TraxError::UnexpectedState);
        }
        let header = Header {
            genesis: relationship.genesis().nodes().clone(),
        };
        let bytes = frame(&header)?;
        let mut file = OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .open(path)?;
        lock(&file)?;
        file.write_all(MAGIC)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        let end = file.stream_position()?;
        Ok(Self {
            file,
            relationship,
            end,
            poisoned: false,
            #[cfg(test)]
            fail_sync: false,
        })
    }

    /// Replays every signed transaction against explicitly accepted genesis.
    /// A valid stale prefix cannot satisfy a current exact external state pin.
    pub fn open(
        path: impl AsRef<Path>,
        genesis: VerifiedGenesis,
        expected: &RelationshipCheckpoint,
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
            return Err(TraxError::RelationshipMismatch);
        }
        let mut relationship = Relationship::new(genesis)?;
        let cap = relationship
            .genesis()
            .profile()
            .limits
            .max_wire_packet_bytes as usize
            + 128;
        while let Some(record) = read_frame::<Record>(&mut file, end, cap)? {
            match record {
                Record::Packet(packet) => {
                    if !relationship.has_pending() {
                        relationship.start_replay()?;
                    }
                    // No application release during replay; all cryptographic
                    // checks remain, without live receive elapsed-time limits.
                    relationship.stage_packet(*packet)?;
                }
                Record::Terminal(terminal) => relationship.verify_and_close(&terminal)?,
            }
        }
        if relationship.has_pending() {
            return Err(TraxError::CorruptJournal);
        }
        if &relationship.checkpoint() != expected {
            return Err(TraxError::CheckpointMismatch);
        }
        Ok(Self {
            file,
            relationship,
            end,
            poisoned: false,
            #[cfg(test)]
            fail_sync: false,
        })
    }
    pub fn relationship(&self) -> &Relationship {
        &self.relationship
    }
    pub fn checkpoint(&self) -> RelationshipCheckpoint {
        self.relationship.checkpoint()
    }
    pub fn is_poisoned(&self) -> bool {
        self.poisoned
    }
    pub fn begin_session(&mut self, initiator: [u8; 32], nonce: [u8; 32]) -> Result<(), TraxError> {
        self.check_writer()?;
        self.relationship.begin_session(initiator, nonce)
    }
    pub fn start_receive(&mut self) -> Result<(), TraxError> {
        self.check_writer()?;
        self.relationship.start_receive()
    }
    pub fn abort_receive(&mut self) -> bool {
        self.relationship.abort_receive()
    }
    /// Clears only an unadmitted intent; accepted history cannot be discarded.
    pub fn abort_draft_session(&mut self) -> bool {
        self.relationship.abort_draft_session()
    }
    pub fn expire_receive(&mut self) -> bool {
        self.relationship.expire_receive()
    }
    pub fn stage_encoded_packet(
        &mut self,
        bytes: &[u8],
    ) -> Result<Option<VerifiedTransmission>, TraxError> {
        self.check_writer()?;
        let cap = self
            .relationship
            .genesis()
            .profile()
            .limits
            .max_wire_packet_bytes as usize;
        let packet = match decode_strict(bytes, cap) {
            Ok(packet) => packet,
            Err(error) => {
                self.relationship.abort_receive();
                return Err(error);
            }
        };
        self.stage_packet(packet)
    }
    pub fn stage_packet(
        &mut self,
        packet: Packet,
    ) -> Result<Option<VerifiedTransmission>, TraxError> {
        self.check_writer()?;
        let Some(prepared) = self.relationship.prepare_packet(packet)? else {
            return Ok(None);
        };
        let result = (|| {
            self.check_position()?;
            for packet in prepared.packets() {
                self.file
                    .write_all(&frame(&Record::Packet(Box::new(packet.clone())))?)?;
            }
            self.sync()?;
            self.end = self.file.stream_position()?;
            Ok::<_, TraxError>(())
        })();
        if let Err(error) = result {
            self.poisoned = true;
            return Err(error);
        }
        Ok(Some(self.relationship.apply_prepared(prepared)))
    }
    pub fn verify_and_close(&mut self, terminal: &SessionTerminal) -> Result<(), TraxError> {
        self.check_writer()?;
        let prepared = self.relationship.prepare_close(terminal)?;
        let bytes = frame(&Record::Terminal(Box::new(terminal.clone())))?;
        if let Err(error) = (|| {
            self.check_position()?;
            self.file.write_all(&bytes)?;
            self.sync()?;
            self.end = self.file.stream_position()?;
            Ok::<_, TraxError>(())
        })() {
            self.poisoned = true;
            return Err(error);
        }
        self.relationship.apply_close(prepared);
        Ok(())
    }
    pub fn verify_encoded_close(&mut self, bytes: &[u8]) -> Result<(), TraxError> {
        self.check_writer()?;
        let terminal = decode_strict(
            bytes,
            self.relationship
                .genesis()
                .profile()
                .limits
                .max_wire_packet_bytes as usize,
        )?;
        self.verify_and_close(&terminal)
    }
    fn check_writer(&self) -> Result<(), TraxError> {
        if self.poisoned {
            Err(TraxError::JournalPoisoned)
        } else {
            Ok(())
        }
    }
    fn sync(&self) -> Result<(), TraxError> {
        #[cfg(test)]
        if self.fail_sync {
            return Err(io::Error::other("injected sync failure").into());
        }
        self.file.sync_all()?;
        Ok(())
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
            "relationship journal already locked",
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
    frame.extend_from_slice(&hash_domain(
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
    let mut len = [0; 8];
    read_exact(file, &mut len)?;
    let len = u64::from_be_bytes(len);
    if len == 0 || len > cap as u64 || len > remaining - 40 {
        return Err(TraxError::CorruptJournal);
    }
    let mut bytes = vec![0; usize::try_from(len).map_err(|_| TraxError::ArithmeticOverflow)?];
    read_exact(file, &mut bytes)?;
    let mut checksum = [0; 32];
    read_exact(file, &mut checksum)?;
    if hash_domain(HashAlgorithm::Sha512256, CHECKSUM_DOMAIN, &[&bytes])? != checksum {
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
    use crate::config::TransmissionProfile;
    use crate::genesis::{accept_genesis_offer, confirm_genesis, create_genesis_offer};
    use ed25519_dalek::SigningKey;
    use std::io::SeekFrom;

    struct Temp(std::path::PathBuf);
    impl Temp {
        fn new() -> Self {
            Self(std::env::temp_dir().join(format!(
                "trax-write-failure-{}-{}.log",
                std::process::id(),
                rand::random::<u64>()
            )))
        }
    }
    impl Drop for Temp {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }
    fn fixture(path: &Path) -> (SigningKey, SigningKey, DurableRelationship) {
        let a = SigningKey::from_bytes(&[1; 32]);
        let b = SigningKey::from_bytes(&[2; 32]);
        let offer = create_genesis_offer(&a, [3; 32], TransmissionProfile::default()).unwrap();
        let accept = accept_genesis_offer(&offer, &b, |_| true).unwrap();
        let confirm = confirm_genesis(&offer, &accept, &a, |_| true).unwrap();
        let relationship =
            Relationship::new(VerifiedGenesis::verify([offer, accept, confirm], |_| true).unwrap())
                .unwrap();
        (
            a,
            b,
            DurableRelationship::create_new(path, relationship).unwrap(),
        )
    }
    fn packet(writer: &DurableRelationship, key: &SigningKey) -> Packet {
        writer
            .relationship()
            .build_transmission(key, "task", &[vec![1]])
            .unwrap()
            .remove(0)
    }
    fn admit(writer: &mut DurableRelationship, key: &SigningKey) {
        let packet = packet(writer, key);
        writer.start_receive().unwrap();
        assert!(writer.stage_packet(packet).unwrap().is_some());
    }

    #[test]
    fn failed_write_never_admits_or_releases_and_writer_is_poisoned() {
        let p = Temp::new();
        let (a, _, mut writer) = fixture(&p.0);
        writer
            .begin_session(a.verifying_key().to_bytes(), [4; 32])
            .unwrap();
        let packet = packet(&writer, &a);
        let before = writer.checkpoint();
        let mut readonly = OpenOptions::new().read(true).open(&p.0).unwrap();
        readonly.seek(SeekFrom::End(0)).unwrap();
        writer.file = readonly;
        writer.start_receive().unwrap();
        assert!(matches!(
            writer.stage_packet(packet.clone()),
            Err(TraxError::Storage(_))
        ));
        assert_eq!(writer.checkpoint(), before);
        assert_eq!(writer.relationship().history().len(), 1);
        assert!(writer.is_poisoned());
        assert!(matches!(
            writer.stage_packet(packet),
            Err(TraxError::JournalPoisoned)
        ));
        assert!(matches!(
            writer.start_receive(),
            Err(TraxError::JournalPoisoned)
        ));
    }
    #[test]
    fn failed_sync_never_admits_or_releases_a_complete_verified_transmission() {
        let p = Temp::new();
        let (a, _, mut writer) = fixture(&p.0);
        writer
            .begin_session(a.verifying_key().to_bytes(), [4; 32])
            .unwrap();
        let packet = packet(&writer, &a);
        let before = writer.checkpoint();
        writer.fail_sync = true;
        writer.start_receive().unwrap();
        assert!(matches!(
            writer.stage_packet(packet),
            Err(TraxError::Storage(_))
        ));
        assert_eq!(writer.checkpoint(), before);
        assert_eq!(writer.relationship().history().len(), 1);
        assert!(writer.is_poisoned());
    }
    #[test]
    fn failed_terminal_sync_keeps_original_authority_and_does_not_close() {
        let p = Temp::new();
        let (a, b, mut writer) = fixture(&p.0);
        writer
            .begin_session(a.verifying_key().to_bytes(), [4; 32])
            .unwrap();
        admit(&mut writer, &a);
        admit(&mut writer, &b);
        let terminal = writer.relationship().create_close(&a).unwrap();
        let before = writer.checkpoint();
        writer.fail_sync = true;
        assert!(matches!(
            writer.verify_and_close(&terminal),
            Err(TraxError::Storage(_))
        ));
        assert_eq!(writer.checkpoint(), before);
        assert!(!writer.relationship().session().unwrap().closed());
        assert!(writer.is_poisoned());
    }
    #[test]
    fn unexpected_file_position_cannot_overwrite_accepted_history() {
        let p = Temp::new();
        let (a, _, mut writer) = fixture(&p.0);
        writer
            .begin_session(a.verifying_key().to_bytes(), [4; 32])
            .unwrap();
        let packet = packet(&writer, &a);
        let length = writer.file.metadata().unwrap().len();
        let before = writer.checkpoint();
        writer.file.seek(SeekFrom::Start(0)).unwrap();
        writer.start_receive().unwrap();
        assert!(matches!(
            writer.stage_packet(packet),
            Err(TraxError::CorruptJournal)
        ));
        assert_eq!(writer.file.metadata().unwrap().len(), length);
        assert_eq!(writer.checkpoint(), before);
        assert!(writer.is_poisoned());
    }
}
