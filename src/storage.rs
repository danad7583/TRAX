//! Locked, append-only persistence for a verified relationship DAG.
//!
//! Opening a journal requires an independently established genesis ID and full
//! genesis protocol configuration (K, signing algorithm and graph hash algorithm);
//! checksums never establish identity or replace checkpoint authentication.
//! Every complete checkpoint is reverified during replay. Partial/corrupt tails
//! are errors and are never repaired or silently admitted.
//! A valid older prefix cannot be distinguished from the latest history using
//! only a genesis anchor; rollback detection needs an external latest checkpoint.
//!
//! The private file owns an exclusive operating-system lock until drop. Locks
//! coordinate cooperating users of this API, not arbitrary external file edits.
//! Successful commits call `sync_all` before advancing the in-memory DAG. The
//! host remains responsible for filesystem/directory durability and backups.

use std::fs::{File, OpenOptions, TryLockError};
use std::io::{self, Read, Seek, Write};
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::config::{HashAlgorithm, ProtocolConfig};
use crate::encoding::{decode, encode_deterministic};
use crate::graph::{CheckpointAttestation, GraphSegmentProof, NodeId, PairDag, PairGenesis};
use crate::profile::hash_bytes;
use crate::TraxError;

const MAGIC: &[u8] = b"TRAX:PAIR-DAG:JOURNAL\0";
// Version 3 persists proposal/prefix-ACK/final exchange proofs. Frame checksums
// remain SHA-512/256 independently of the negotiated graph hash.
const VERSION: u32 = 3;
const FRAME_OVERHEAD: u64 = 8 + 32;

#[derive(Deserialize)]
enum JournalRecord {
    Genesis(PairGenesis),
    Segment(Box<GraphSegmentProof>),
    Attestation(CheckpointAttestation),
}

#[derive(Serialize)]
enum JournalRecordRef<'a> {
    Genesis(&'a PairGenesis),
    Segment(&'a GraphSegmentProof),
    Attestation(&'a CheckpointAttestation),
}

/// Verified state backed by a journal. There is no mutable graph/file accessor:
/// a checkpoint must be durably written before it can become trusted state.
pub struct DurableDag {
    file: File,
    graph: PairDag,
    end: u64,
    poisoned: bool,
}

impl DurableDag {
    /// Creates a new journal without overwriting an existing path.
    /// `genesis` must come from the host's independently verified handshake.
    pub fn create_new(
        path: impl AsRef<Path>,
        config: ProtocolConfig,
        genesis: PairGenesis,
    ) -> Result<Self, TraxError> {
        let graph = PairDag::from_verified_genesis(config, genesis)?;
        let frame = encode_frame(&JournalRecordRef::Genesis(graph.genesis()))?;
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(path)?;
        lock(&file)?;
        file.write_all(MAGIC)?;
        file.write_all(&VERSION.to_be_bytes())?;
        file.write_all(&frame)?;
        file.sync_all()?;
        let end = file.stream_position()?;
        Ok(Self {
            file,
            graph,
            end,
            poisoned: false,
        })
    }

    /// Opens and exclusively locks a journal, replaying all checkpoints against
    /// the external trust anchor. Missing/corrupt/truncated records are errors.
    pub fn open(
        path: impl AsRef<Path>,
        config: ProtocolConfig,
        expected_genesis_id: NodeId,
    ) -> Result<Self, TraxError> {
        let mut file = OpenOptions::new().read(true).write(true).open(path)?;
        lock(&file)?;
        let end = file.metadata()?.len();
        read_header(&mut file)?;
        let genesis = match read_frame(&mut file, end)? {
            Some(JournalRecord::Genesis(genesis)) => genesis,
            _ => return Err(TraxError::CorruptJournal),
        };
        let mut graph = PairDag::from_verified_genesis(config, genesis)?;
        if graph.genesis_id() != expected_genesis_id {
            return Err(TraxError::GraphContextMismatch);
        }
        while let Some(record) = read_frame(&mut file, end)? {
            match record {
                JournalRecord::Segment(proof) => {
                    graph.verify_and_commit(&proof)?;
                }
                JournalRecord::Attestation(attestation) => {
                    graph.record_attestation(&attestation)?;
                }
                JournalRecord::Genesis(_) => return Err(TraxError::CorruptJournal),
            }
        }
        Ok(Self {
            file,
            graph,
            end,
            poisoned: false,
        })
    }

    pub fn graph(&self) -> &PairDag {
        &self.graph
    }

    /// Authenticates and prepares a full batch before writing.
    /// A write/sync failure poisons this handle and leaves trusted memory intact.
    /// Reopening revalidates whatever complete bytes reached durable storage.
    pub fn verify_and_commit(
        &mut self,
        proof: &GraphSegmentProof,
    ) -> Result<Vec<NodeId>, TraxError> {
        if self.poisoned {
            return Err(TraxError::JournalPoisoned);
        }
        let prepared = self.graph.prepare_commit(proof)?;
        self.append_record(&JournalRecordRef::Segment(proof))?;
        Ok(self.graph.commit_prepared(prepared))
    }

    /// Persists another participant's independent signature for an already
    /// verified checkpoint without appending duplicate graph events.
    pub fn record_attestation(
        &mut self,
        attestation: &CheckpointAttestation,
    ) -> Result<(), TraxError> {
        if self.poisoned {
            return Err(TraxError::JournalPoisoned);
        }
        self.graph.verify_recorded_attestation(attestation)?;
        self.append_record(&JournalRecordRef::Attestation(attestation))?;
        self.graph.commit_attestation(attestation.clone());
        Ok(())
    }

    fn append_record(&mut self, record: &JournalRecordRef<'_>) -> Result<(), TraxError> {
        let frame = encode_frame(record)?;
        let new_end = self
            .end
            .checked_add(u64::try_from(frame.len()).map_err(|_| TraxError::ArithmeticOverflow)?)
            .ok_or(TraxError::ArithmeticOverflow)?;
        if let Err(error) = self.write_frame(&frame) {
            self.poisoned = true;
            return Err(error);
        }
        self.end = new_end;
        Ok(())
    }

    fn write_frame(&mut self, frame: &[u8]) -> Result<(), TraxError> {
        // Detect accidental edits even when another program ignores the lock.
        if self.file.metadata()?.len() != self.end || self.file.stream_position()? != self.end {
            return Err(TraxError::CorruptJournal);
        }
        self.file.write_all(frame)?;
        self.file.sync_all()?;
        Ok(())
    }
}

fn lock(file: &File) -> Result<(), TraxError> {
    file.try_lock().map_err(|error| match error {
        TryLockError::WouldBlock => TraxError::Storage(io::Error::new(
            io::ErrorKind::WouldBlock,
            "journal is already locked",
        )),
        TryLockError::Error(error) => TraxError::Storage(error),
    })
}

fn encode_frame(record: &JournalRecordRef<'_>) -> Result<Vec<u8>, TraxError> {
    let bytes = encode_deterministic(record)?;
    let length = u64::try_from(bytes.len()).map_err(|_| TraxError::ArithmeticOverflow)?;
    let frame_length = bytes
        .len()
        .checked_add(FRAME_OVERHEAD as usize)
        .ok_or(TraxError::ArithmeticOverflow)?;
    let mut frame = Vec::new();
    frame
        .try_reserve_exact(frame_length)
        .map_err(io::Error::other)?;
    frame.extend_from_slice(&length.to_be_bytes());
    frame.extend_from_slice(&bytes);
    frame.extend_from_slice(&hash_bytes(HashAlgorithm::Sha512256, &bytes)?);
    Ok(frame)
}

fn read_header(file: &mut File) -> Result<(), TraxError> {
    let mut magic = vec![0; MAGIC.len()];
    read_exact(file, &mut magic)?;
    let mut version = [0; 4];
    read_exact(file, &mut version)?;
    if magic != MAGIC || u32::from_be_bytes(version) != VERSION {
        return Err(TraxError::CorruptJournal);
    }
    Ok(())
}

fn read_frame(file: &mut File, end: u64) -> Result<Option<JournalRecord>, TraxError> {
    let offset = file.stream_position()?;
    if offset == end {
        return Ok(None);
    }
    let remaining = end.checked_sub(offset).ok_or(TraxError::CorruptJournal)?;
    if remaining < FRAME_OVERHEAD {
        return Err(TraxError::CorruptJournal);
    }
    let mut length = [0; 8];
    read_exact(file, &mut length)?;
    let length = u64::from_be_bytes(length);
    // Bound attacker-controlled lengths against actual remaining file bytes
    // before any conversion/allocation; no arbitrary application payload cap.
    if length == 0 || length > remaining - FRAME_OVERHEAD {
        return Err(TraxError::CorruptJournal);
    }
    let length = usize::try_from(length).map_err(|_| TraxError::ArithmeticOverflow)?;
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(length).map_err(io::Error::other)?;
    bytes.resize(length, 0);
    read_exact(file, &mut bytes)?;
    let mut digest = [0; 32];
    read_exact(file, &mut digest)?;
    if hash_bytes(HashAlgorithm::Sha512256, &bytes)? != digest {
        return Err(TraxError::CorruptJournal);
    }
    decode(&bytes)
        .map(Some)
        .map_err(|_| TraxError::CorruptJournal)
}

fn read_exact(file: &mut File, buffer: &mut [u8]) -> Result<(), TraxError> {
    file.read_exact(buffer).map_err(|error| {
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
    use crate::config::SigningAlgorithm;
    use crate::graph::{participant_id, AuthorityId};
    use ed25519_dalek::SigningKey;
    use std::io::SeekFrom;

    #[test]
    fn failed_write_preserves_memory_and_poisons_the_writer() {
        let path = std::env::temp_dir().join(format!(
            "trax-journal-write-failure-{}-{:016x}.log",
            std::process::id(),
            rand::random::<u64>()
        ));
        let config =
            ProtocolConfig::new(5, SigningAlgorithm::Ed25519, HashAlgorithm::Sha512256).unwrap();
        let key = SigningKey::from_bytes(&[1; 32]);
        let peer = SigningKey::from_bytes(&[2; 32]);
        let author = participant_id(&key.verifying_key().to_bytes());
        let genesis =
            PairGenesis::new(config, [3; 32], &key.verifying_key(), &peer.verifying_key()).unwrap();
        let anchor = genesis.node_id().unwrap();
        let mut journal = DurableDag::create_new(&path, config, genesis).unwrap();
        let mut pending = journal.graph().begin_segment();
        for _ in 0..config.k() {
            pending
                .append(author, journal.graph().main_branch(), b"payload".to_vec())
                .unwrap();
        }
        let signature = pending
            .commitment()
            .unwrap()
            .sign(
                AuthorityId {
                    participant: author,
                    key_epoch: 0,
                },
                &key,
            )
            .unwrap();
        let proof = pending.proof(signature).unwrap();

        // Inject a genuine OS write failure without exposing any mutable file
        // accessor or changing the production persistence path.
        let mut readonly = File::open(&path).unwrap();
        readonly.seek(SeekFrom::Start(journal.end)).unwrap();
        journal.file = readonly;
        assert!(matches!(
            journal.verify_and_commit(&proof),
            Err(TraxError::Storage(_))
        ));
        assert_eq!(journal.graph().checkpoint_tip(), anchor);
        assert_eq!(journal.graph().segment_index(), 0);
        assert!(matches!(
            journal.verify_and_commit(&proof),
            Err(TraxError::JournalPoisoned)
        ));
        drop(journal);
        let reopened = DurableDag::open(&path, config, anchor).unwrap();
        assert_eq!(reopened.graph().segment_index(), 0);
        drop(reopened);
        std::fs::remove_file(path).unwrap();
    }
}
