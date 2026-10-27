//! K-free logical transmissions. Receipt and hash linkage are never admission.
//!
//! See `docs/TRANSMISSION_V2.md`. Legacy graph/segment proofs cannot enter these
//! APIs. A mutable session owns at most one provisional transmission, and is not
//! cloneable. Memory-only state is not a crash-safe replay ledger.

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use ed25519_dalek::{SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::crypto::{ed25519_sign, ed25519_verify};
use crate::encoding::{decode_strict, encode_deterministic};
use crate::genesis::{TransmissionProfileV2, VerifiedGenesisV2};
use crate::transmission_crypto::{hash_v2, MerkleAccumulatorV2};
use crate::TraxError;

pub type Hash = [u8; 32];
const TRANSMISSION_DOMAIN: &[u8] = b"TRAX:TRANSMISSION:V2\0";
const CLOSE_DOMAIN: &[u8] = b"TRAX:SESSION:CLOSE:V2\0";
const MAX_MESSAGE_TYPE: usize = 64;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum TransmissionKindV2 {
    #[serde(rename = "request")]
    Request,
    #[serde(rename = "response")]
    Response,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionContextV2 {
    pub version: u8,
    #[serde(with = "serde_bytes")]
    pub relationship_id: Hash,
    pub profile: TransmissionProfileV2,
    #[serde(with = "serde_bytes")]
    pub initiator: Hash,
    #[serde(with = "serde_bytes")]
    pub responder: Hash,
    #[serde(with = "serde_bytes")]
    pub nonce: Hash,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PacketEventV2 {
    pub version: u8,
    #[serde(with = "serde_bytes")]
    pub relationship_id: Hash,
    #[serde(with = "serde_bytes")]
    pub session_id: Hash,
    pub transmission_id: u64,
    #[serde(with = "serde_bytes")]
    pub initiator: Hash,
    #[serde(with = "serde_bytes")]
    pub sender: Hash,
    #[serde(with = "serde_bytes")]
    pub receiver: Hash,
    pub key_epoch: u64,
    pub kind: TransmissionKindV2,
    pub message_type: String,
    pub packet_index: u32,
    pub counter: u64,
    #[serde(with = "serde_bytes")]
    pub previous_tip: Hash,
    #[serde(with = "serde_bytes")]
    pub payload_hash: Hash,
    pub payload_len: u32,
    pub is_final: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransmissionCommitmentV2 {
    pub version: u8,
    pub purpose: String,
    #[serde(with = "serde_bytes")]
    pub relationship_id: Hash,
    #[serde(with = "serde_bytes")]
    pub session_id: Hash,
    pub transmission_id: u64,
    #[serde(with = "serde_bytes")]
    pub initiator: Hash,
    #[serde(with = "serde_bytes")]
    pub sender: Hash,
    #[serde(with = "serde_bytes")]
    pub receiver: Hash,
    pub key_epoch: u64,
    pub kind: TransmissionKindV2,
    pub message_type: String,
    #[serde(with = "serde_bytes")]
    pub starting_tip: Hash,
    pub first_counter: u64,
    pub last_counter: u64,
    pub packet_count: u32,
    pub payload_bytes: u64,
    #[serde(with = "serde_bytes")]
    pub merkle_root: Hash,
    #[serde(with = "serde_bytes")]
    pub final_event_tip: Hash,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransmissionSealV2 {
    pub commitment: TransmissionCommitmentV2,
    #[serde(with = "serde_bytes")]
    pub signature: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PacketV2 {
    pub event: PacketEventV2,
    #[serde(with = "serde_bytes")]
    pub payload: Vec<u8>,
    pub authentication: Option<TransmissionSealV2>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionCloseCommitmentV2 {
    pub version: u8,
    pub purpose: String,
    #[serde(with = "serde_bytes")]
    pub relationship_id: Hash,
    #[serde(with = "serde_bytes")]
    pub session_id: Hash,
    #[serde(with = "serde_bytes")]
    pub initiator: Hash,
    #[serde(with = "serde_bytes")]
    pub responder: Hash,
    #[serde(with = "serde_bytes")]
    pub final_data_tip: Hash,
    #[serde(with = "serde_bytes")]
    pub history_hash: Hash,
    pub first_counter: u64,
    pub last_counter: u64,
    pub event_count: u64,
    pub transmission_id: u64,
    pub terminal_counter: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionTerminalV2 {
    pub commitment: SessionCloseCommitmentV2,
    #[serde(with = "serde_bytes")]
    pub signature: Vec<u8>,
}

/// External latest-state pin. Its freshness/authenticity is the host's duty.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionCheckpointV2 {
    #[serde(with = "serde_bytes")]
    pub session_id: Hash,
    #[serde(with = "serde_bytes")]
    pub tip: Hash,
    #[serde(with = "serde_bytes")]
    pub history_hash: Hash,
    pub event_count: u64,
    pub transmission_id: u64,
    pub closed: bool,
}

#[derive(Debug)]
pub struct CommittedNodeV2 {
    event: PacketEventV2,
    tip: Hash,
    authentication: Option<TransmissionSealV2>,
}

impl CommittedNodeV2 {
    pub fn event(&self) -> &PacketEventV2 {
        &self.event
    }
    pub fn tip(&self) -> Hash {
        self.tip
    }
    pub fn authentication(&self) -> Option<&TransmissionSealV2> {
        self.authentication.as_ref()
    }
}

/// Only constructed after Rust admission (and fsync in the durable wrapper).
#[derive(Debug)]
pub struct VerifiedTransmissionV2 {
    packets: Vec<PacketV2>,
}

impl VerifiedTransmissionV2 {
    pub fn packets(&self) -> &[PacketV2] {
        &self.packets
    }
    pub fn commitment(&self) -> &TransmissionCommitmentV2 {
        &self
            .packets
            .last()
            .expect("verified nonempty transmission")
            .authentication
            .as_ref()
            .expect("verified final seal")
            .commitment
    }
    pub fn payload(&self) -> Vec<u8> {
        self.packets
            .iter()
            .flat_map(|packet| packet.payload.iter().copied())
            .collect()
    }
    pub fn payload_chunks(&self) -> impl Iterator<Item = &[u8]> {
        self.packets.iter().map(|packet| packet.payload.as_slice())
    }
}

struct PendingTransmission {
    // Only private durable replay may omit a live network deadline.
    started: Option<Instant>,
    packets: Vec<PacketV2>,
    tip: Hash,
    payload_bytes: u64,
    merkle: MerkleAccumulatorV2,
    history_hash: Hash,
}

pub(crate) struct PreparedTransmission {
    verified: VerifiedTransmissionV2,
    history_hash: Hash,
    tip: Hash,
    event_count: u64,
}

impl PreparedTransmission {
    pub(crate) fn packets(&self) -> &[PacketV2] {
        self.verified.packets()
    }
}

/// One authoritative ordered session. No public unchecked restore/Clone exists.
pub struct SessionV2 {
    genesis: VerifiedGenesisV2,
    context: SessionContextV2,
    session_id: Hash,
    tip: Hash,
    history_hash: Hash,
    event_count: u64,
    transmission_id: u64,
    next_kind: TransmissionKindV2,
    terminal: Option<SessionTerminalV2>,
    nodes: Vec<CommittedNodeV2>,
    index: BTreeMap<Hash, usize>,
    pending: Option<PendingTransmission>,
}

impl SessionV2 {
    pub fn new(
        genesis: VerifiedGenesisV2,
        initiator: Hash,
        nonce: Hash,
    ) -> Result<Self, TraxError> {
        let responder = if initiator == genesis.initiator_key() {
            genesis.responder_key()
        } else if initiator == genesis.responder_key() {
            genesis.initiator_key()
        } else {
            return Err(TraxError::UnknownParticipant);
        };
        let context = SessionContextV2 {
            version: 2,
            relationship_id: genesis.anchor(),
            profile: genesis.profile().clone(),
            initiator,
            responder,
            nonce,
        };
        let bytes = encode_deterministic(&context)?;
        let hash = context.profile.hash_algorithm;
        let session_id = hash_v2(hash, b"TRAX:SESSION:ID:V2\0", &[&bytes])?;
        let history_hash = hash_v2(hash, b"TRAX:HISTORY:INIT:V2\0", &[&bytes])?;
        let tip = hash_v2(
            hash,
            b"TRAX:SESSION:ANCHOR:V2\0",
            &[&session_id, &genesis.anchor()],
        )?;
        Ok(Self {
            genesis,
            context,
            session_id,
            tip,
            history_hash,
            event_count: 0,
            transmission_id: 0,
            next_kind: TransmissionKindV2::Request,
            terminal: None,
            nodes: Vec::new(),
            index: BTreeMap::new(),
            pending: None,
        })
    }

    pub fn context(&self) -> &SessionContextV2 {
        &self.context
    }
    pub fn genesis(&self) -> &VerifiedGenesisV2 {
        &self.genesis
    }
    pub fn session_id(&self) -> Hash {
        self.session_id
    }
    pub fn checkpoint(&self) -> SessionCheckpointV2 {
        SessionCheckpointV2 {
            session_id: self.session_id,
            tip: self.tip,
            history_hash: self.history_hash,
            event_count: self.event_count,
            transmission_id: self.transmission_id,
            closed: self.terminal.is_some(),
        }
    }
    pub fn nodes(&self) -> &[CommittedNodeV2] {
        &self.nodes
    }
    pub fn node(&self, tip: &Hash) -> Option<&CommittedNodeV2> {
        self.index.get(tip).and_then(|index| self.nodes.get(*index))
    }
    pub fn terminal(&self) -> Option<&SessionTerminalV2> {
        self.terminal.as_ref()
    }
    pub fn has_pending(&self) -> bool {
        self.pending.is_some()
    }
    pub fn next_kind(&self) -> TransmissionKindV2 {
        self.next_kind
    }
    pub fn expected_sender(&self) -> Hash {
        match self.next_kind {
            TransmissionKindV2::Request => self.context.initiator,
            TransmissionKindV2::Response => self.context.responder,
        }
    }
    fn expected_receiver(&self) -> Hash {
        if self.expected_sender() == self.context.initiator {
            self.context.responder
        } else {
            self.context.initiator
        }
    }

    pub fn start_receive(&mut self) -> Result<(), TraxError> {
        self.start_receive_inner(true)
    }
    pub(crate) fn start_replay(&mut self) -> Result<(), TraxError> {
        self.start_receive_inner(false)
    }
    fn start_receive_inner(&mut self, live: bool) -> Result<(), TraxError> {
        if self.pending.is_some() || self.terminal.is_some() {
            return Err(TraxError::UnexpectedState);
        }
        self.pending = Some(PendingTransmission {
            started: live.then(Instant::now),
            packets: Vec::new(),
            tip: self.tip,
            payload_bytes: 0,
            merkle: MerkleAccumulatorV2::new(self.context.profile.hash_algorithm)?,
            history_hash: self.history_hash,
        });
        Ok(())
    }
    pub fn abort_receive(&mut self) -> bool {
        self.pending.take().is_some()
    }
    pub fn expire_receive(&mut self) -> bool {
        let expired = self.pending.as_ref().is_some_and(|p| {
            p.started.is_some_and(|started| {
                started.elapsed() >= Duration::from_millis(self.context.profile.limits.timeout_ms)
            })
        });
        if expired {
            self.pending = None;
        }
        expired
    }

    pub fn stage_encoded_packet(
        &mut self,
        bytes: &[u8],
    ) -> Result<Option<VerifiedTransmissionV2>, TraxError> {
        let packet = match decode_strict(
            bytes,
            self.context.profile.limits.max_wire_packet_bytes as usize,
        ) {
            Ok(packet) => packet,
            Err(error) => {
                self.abort_receive();
                return Err(error);
            }
        };
        self.stage_packet(packet)
    }

    pub fn stage_packet(
        &mut self,
        packet: PacketV2,
    ) -> Result<Option<VerifiedTransmissionV2>, TraxError> {
        Ok(self
            .prepare_packet(packet)?
            .map(|prepared| self.apply_prepared(prepared)))
    }

    /// Takes provisional ownership first: every error discards all staged data.
    pub(crate) fn prepare_packet(
        &mut self,
        packet: PacketV2,
    ) -> Result<Option<PreparedTransmission>, TraxError> {
        let mut pending = self.pending.take().ok_or(TraxError::UnexpectedState)?;
        if pending.started.is_some_and(|started| {
            started.elapsed() >= Duration::from_millis(self.context.profile.limits.timeout_ms)
        }) {
            return Err(TraxError::TransmissionExpired);
        }
        let limits = &self.context.profile.limits;
        if pending.packets.len() >= limits.max_packets as usize
            || packet.payload.len() > limits.max_packet_payload_bytes as usize
            || packet.event.message_type.len() > MAX_MESSAGE_TYPE
            || packet.event.message_type.is_empty()
            || encode_deterministic(&packet)?.len() > limits.max_wire_packet_bytes as usize
        {
            return Err(TraxError::TransmissionLimit);
        }
        let e = &packet.event;
        let count =
            u32::try_from(pending.packets.len()).map_err(|_| TraxError::ArithmeticOverflow)?;
        let expected_counter = self
            .event_count
            .checked_add(u64::from(count))
            .and_then(|n| n.checked_add(1))
            .ok_or(TraxError::ArithmeticOverflow)?;
        let transmission_id = self
            .transmission_id
            .checked_add(1)
            .ok_or(TraxError::ArithmeticOverflow)?;
        if e.version != 2
            || e.relationship_id != self.context.relationship_id
            || e.session_id != self.session_id
            || e.transmission_id != transmission_id
            || e.initiator != self.context.initiator
            || e.sender != self.expected_sender()
            || e.receiver != self.expected_receiver()
            || e.key_epoch != 0
            || e.kind != self.next_kind
            || e.packet_index != count
            || e.counter != expected_counter
            || e.previous_tip != pending.tip
            || pending
                .packets
                .first()
                .is_some_and(|first| first.event.message_type != e.message_type)
        {
            return Err(TraxError::SegmentContextMismatch);
        }
        if usize::try_from(e.payload_len).map_err(|_| TraxError::ArithmeticOverflow)?
            != packet.payload.len()
            || e.payload_hash
                != hash_v2(
                    self.context.profile.hash_algorithm,
                    b"TRAX:PAYLOAD:V2\0",
                    &[&packet.payload],
                )?
        {
            return Err(TraxError::PayloadHashMismatch);
        }
        if e.is_final != packet.authentication.is_some() {
            return Err(TraxError::InvalidInput(
                "only final packet must carry authentication",
            ));
        }
        let payload_bytes = pending
            .payload_bytes
            .checked_add(u64::from(e.payload_len))
            .ok_or(TraxError::ArithmeticOverflow)?;
        if payload_bytes > limits.max_payload_bytes {
            return Err(TraxError::TransmissionLimit);
        }
        let event_bytes = encode_deterministic(e)?;
        pending.merkle.push(&event_bytes)?;
        pending.tip = event_tip_v2(self.context.profile.hash_algorithm, e)?;
        pending.payload_bytes = payload_bytes;
        pending.history_hash = hash_v2(
            self.context.profile.hash_algorithm,
            b"TRAX:HISTORY:EVENT:V2\0",
            &[&pending.history_hash, &event_bytes],
        )?;
        if !e.is_final {
            pending.packets.push(packet);
            self.pending = Some(pending);
            return Ok(None);
        }
        let expected = self.commitment(
            e,
            count.checked_add(1).ok_or(TraxError::ArithmeticOverflow)?,
            payload_bytes,
            pending.tip,
            pending.merkle.root()?,
        )?;
        let seal = packet
            .authentication
            .as_ref()
            .ok_or(TraxError::BadSignature)?;
        if seal.commitment != expected {
            return Err(TraxError::SegmentContextMismatch);
        }
        let key =
            VerifyingKey::from_bytes(&self.expected_sender()).map_err(|_| TraxError::Crypto)?;
        if !ed25519_verify(
            &key,
            &signing_bytes(TRANSMISSION_DOMAIN, &expected)?,
            &seal.signature,
        ) {
            return Err(TraxError::BadSignature);
        }
        pending.history_hash = hash_v2(
            self.context.profile.hash_algorithm,
            b"TRAX:HISTORY:AUTH:V2\0",
            &[&pending.history_hash, &encode_deterministic(seal)?],
        )?;
        pending.packets.push(packet);
        Ok(Some(PreparedTransmission {
            verified: VerifiedTransmissionV2 {
                packets: pending.packets,
            },
            history_hash: pending.history_hash,
            tip: pending.tip,
            event_count: expected_counter,
        }))
    }

    pub(crate) fn apply_prepared(
        &mut self,
        prepared: PreparedTransmission,
    ) -> VerifiedTransmissionV2 {
        for packet in prepared.verified.packets() {
            // All fallible encoding/hashing was completed before durable write.
            let tip = event_tip_v2(self.context.profile.hash_algorithm, &packet.event)
                .expect("prepared event hash");
            self.index.insert(tip, self.nodes.len());
            self.nodes.push(CommittedNodeV2 {
                event: packet.event.clone(),
                tip,
                authentication: packet.authentication.clone(),
            });
        }
        self.tip = prepared.tip;
        self.history_hash = prepared.history_hash;
        self.event_count = prepared.event_count;
        self.transmission_id += 1;
        self.next_kind = match self.next_kind {
            TransmissionKindV2::Request => TransmissionKindV2::Response,
            TransmissionKindV2::Response => TransmissionKindV2::Request,
        };
        prepared.verified
    }

    fn commitment(
        &self,
        final_event: &PacketEventV2,
        count: u32,
        bytes: u64,
        tip: Hash,
        root: Hash,
    ) -> Result<TransmissionCommitmentV2, TraxError> {
        Ok(TransmissionCommitmentV2 {
            version: 2,
            purpose: "logical-transmission".into(),
            relationship_id: self.context.relationship_id,
            session_id: self.session_id,
            transmission_id: self
                .transmission_id
                .checked_add(1)
                .ok_or(TraxError::ArithmeticOverflow)?,
            initiator: self.context.initiator,
            sender: self.expected_sender(),
            receiver: self.expected_receiver(),
            key_epoch: 0,
            kind: self.next_kind,
            message_type: final_event.message_type.clone(),
            starting_tip: self.tip,
            first_counter: self
                .event_count
                .checked_add(1)
                .ok_or(TraxError::ArithmeticOverflow)?,
            last_counter: final_event.counter,
            packet_count: count,
            payload_bytes: bytes,
            merkle_root: root,
            final_event_tip: tip,
        })
    }

    /// Creates packets but does not admit or expose them as a verified result.
    /// The original sender can mirror them through the same admission path.
    pub fn build_transmission(
        &self,
        key: &SigningKey,
        message_type: &str,
        chunks: &[Vec<u8>],
    ) -> Result<Vec<PacketV2>, TraxError> {
        if self.terminal.is_some() || self.pending.is_some() {
            return Err(TraxError::UnexpectedState);
        }
        if key.verifying_key().to_bytes() != self.expected_sender() {
            return Err(TraxError::SignerMismatch);
        }
        let limits = &self.context.profile.limits;
        if chunks.is_empty()
            || chunks.len() > limits.max_packets as usize
            || message_type.is_empty()
            || message_type.len() > MAX_MESSAGE_TYPE
        {
            return Err(TraxError::TransmissionLimit);
        }
        let mut tip = self.tip;
        let mut bytes = 0u64;
        let mut merkle = MerkleAccumulatorV2::new(self.context.profile.hash_algorithm)?;
        let mut packets = Vec::with_capacity(chunks.len());
        for (index, payload) in chunks.iter().enumerate() {
            if payload.len() > limits.max_packet_payload_bytes as usize {
                return Err(TraxError::TransmissionLimit);
            }
            let len = u32::try_from(payload.len()).map_err(|_| TraxError::ArithmeticOverflow)?;
            bytes = bytes
                .checked_add(u64::from(len))
                .ok_or(TraxError::ArithmeticOverflow)?;
            if bytes > limits.max_payload_bytes {
                return Err(TraxError::TransmissionLimit);
            }
            let event = PacketEventV2 {
                version: 2,
                relationship_id: self.context.relationship_id,
                session_id: self.session_id,
                transmission_id: self
                    .transmission_id
                    .checked_add(1)
                    .ok_or(TraxError::ArithmeticOverflow)?,
                initiator: self.context.initiator,
                sender: self.expected_sender(),
                receiver: self.expected_receiver(),
                key_epoch: 0,
                kind: self.next_kind,
                message_type: message_type.into(),
                packet_index: u32::try_from(index).map_err(|_| TraxError::ArithmeticOverflow)?,
                counter: self
                    .event_count
                    .checked_add(index as u64)
                    .and_then(|n| n.checked_add(1))
                    .ok_or(TraxError::ArithmeticOverflow)?,
                previous_tip: tip,
                payload_hash: hash_v2(
                    self.context.profile.hash_algorithm,
                    b"TRAX:PAYLOAD:V2\0",
                    &[payload],
                )?,
                payload_len: len,
                is_final: index + 1 == chunks.len(),
            };
            merkle.push(&encode_deterministic(&event)?)?;
            tip = event_tip_v2(self.context.profile.hash_algorithm, &event)?;
            packets.push(PacketV2 {
                event,
                payload: payload.clone(),
                authentication: None,
            });
        }
        let final_packet = packets.last_mut().ok_or(TraxError::IncompleteSegment)?;
        let commitment = self.commitment(
            &final_packet.event,
            chunks.len() as u32,
            bytes,
            tip,
            merkle.root()?,
        )?;
        let signature = ed25519_sign(key, &signing_bytes(TRANSMISSION_DOMAIN, &commitment)?);
        final_packet.authentication = Some(TransmissionSealV2 {
            commitment,
            signature,
        });
        for packet in &packets {
            if encode_deterministic(packet)?.len() > limits.max_wire_packet_bytes as usize {
                return Err(TraxError::TransmissionLimit);
            }
        }
        Ok(packets)
    }

    /// Fragments bytes using the actual full-wire overhead (including final seal).
    pub fn fragment_transmission(
        &self,
        key: &SigningKey,
        message_type: &str,
        payload: &[u8],
    ) -> Result<Vec<PacketV2>, TraxError> {
        if payload.len() as u64 > self.context.profile.limits.max_payload_bytes {
            return Err(TraxError::TransmissionLimit);
        }
        // Derive a conservative capacity from a fully signed empty final packet.
        // Reserve integer/byte-string header growth, independent of data values.
        let empty = self.build_transmission(key, message_type, &[Vec::new()])?;
        if payload.is_empty() {
            return Ok(empty);
        }
        let overhead = encode_deterministic(&empty[0])?
            .len()
            .checked_add(96)
            .ok_or(TraxError::ArithmeticOverflow)?;
        let budget = self.context.profile.limits.max_wire_packet_bytes as usize;
        let capacity = budget
            .checked_sub(overhead)
            .ok_or(TraxError::TransmissionLimit)?
            .min(self.context.profile.limits.max_packet_payload_bytes as usize);
        if capacity == 0
            || payload.len().div_ceil(capacity) > self.context.profile.limits.max_packets as usize
        {
            return Err(TraxError::TransmissionLimit);
        }
        let chunks = payload
            .chunks(capacity)
            .map(<[u8]>::to_vec)
            .collect::<Vec<_>>();
        self.build_transmission(key, message_type, &chunks)
    }

    fn close_commitment(&self) -> Result<SessionCloseCommitmentV2, TraxError> {
        if self.pending.is_some()
            || self.terminal.is_some()
            || self.next_kind != TransmissionKindV2::Request
            || self.transmission_id < 2
        {
            return Err(TraxError::UnexpectedState);
        }
        Ok(SessionCloseCommitmentV2 {
            version: 2,
            purpose: "session-close".into(),
            relationship_id: self.context.relationship_id,
            session_id: self.session_id,
            initiator: self.context.initiator,
            responder: self.context.responder,
            final_data_tip: self.tip,
            history_hash: self.history_hash,
            first_counter: 1,
            last_counter: self.event_count,
            event_count: self.event_count,
            transmission_id: self.transmission_id,
            terminal_counter: self
                .event_count
                .checked_add(1)
                .ok_or(TraxError::ArithmeticOverflow)?,
        })
    }

    pub fn create_close(&self, key: &SigningKey) -> Result<SessionTerminalV2, TraxError> {
        if key.verifying_key().to_bytes() != self.context.initiator {
            return Err(TraxError::SignerMismatch);
        }
        let commitment = self.close_commitment()?;
        let signature = ed25519_sign(key, &signing_bytes(CLOSE_DOMAIN, &commitment)?);
        Ok(SessionTerminalV2 {
            commitment,
            signature,
        })
    }

    pub(crate) fn prepare_close(
        &self,
        terminal: &SessionTerminalV2,
    ) -> Result<(Hash, Hash), TraxError> {
        let expected = self.close_commitment()?;
        if terminal.commitment != expected {
            return Err(TraxError::SegmentContextMismatch);
        }
        let bytes = encode_deterministic(terminal)?;
        if bytes.len() > self.context.profile.limits.max_wire_packet_bytes as usize {
            return Err(TraxError::TransmissionLimit);
        }
        let key =
            VerifyingKey::from_bytes(&self.context.initiator).map_err(|_| TraxError::Crypto)?;
        if !ed25519_verify(
            &key,
            &signing_bytes(CLOSE_DOMAIN, &expected)?,
            &terminal.signature,
        ) {
            return Err(TraxError::BadSignature);
        }
        Ok((
            hash_v2(
                self.context.profile.hash_algorithm,
                b"TRAX:SESSION:TERMINAL:V2\0",
                &[&bytes],
            )?,
            hash_v2(
                self.context.profile.hash_algorithm,
                b"TRAX:HISTORY:TERMINAL:V2\0",
                &[&self.history_hash, &bytes],
            )?,
        ))
    }

    pub(crate) fn apply_close(
        &mut self,
        terminal: SessionTerminalV2,
        tip: Hash,
        history_hash: Hash,
    ) {
        self.event_count = terminal.commitment.terminal_counter;
        self.tip = tip;
        self.history_hash = history_hash;
        self.terminal = Some(terminal);
    }

    pub fn verify_and_close(&mut self, terminal: &SessionTerminalV2) -> Result<(), TraxError> {
        let (tip, hash) = self.prepare_close(terminal)?;
        self.apply_close(terminal.clone(), tip, hash);
        Ok(())
    }

    pub fn verify_encoded_close(&mut self, bytes: &[u8]) -> Result<(), TraxError> {
        let terminal = decode_strict(
            bytes,
            self.context.profile.limits.max_wire_packet_bytes as usize,
        )?;
        self.verify_and_close(&terminal)
    }
}

pub fn event_tip_v2(
    algorithm: crate::HashAlgorithm,
    event: &PacketEventV2,
) -> Result<Hash, TraxError> {
    hash_v2(
        algorithm,
        b"TRAX:EVENT:V2\0",
        &[&encode_deterministic(event)?],
    )
}

fn signing_bytes<T: Serialize>(domain: &[u8], commitment: &T) -> Result<Vec<u8>, TraxError> {
    let mut bytes = domain.to_vec();
    bytes.extend_from_slice(&encode_deterministic(commitment)?);
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::genesis::{accept_genesis_offer, confirm_genesis, create_genesis_offer};

    fn fixture(profile: TransmissionProfileV2) -> (SigningKey, SessionV2) {
        let a = SigningKey::from_bytes(&[1; 32]);
        let b = SigningKey::from_bytes(&[2; 32]);
        let offer = create_genesis_offer(&a, [3; 32], profile).unwrap();
        let accept = accept_genesis_offer(&offer, &b, |_| true).unwrap();
        let confirm = confirm_genesis(&offer, &accept, &a, |_| true).unwrap();
        let genesis = VerifiedGenesisV2::verify([offer, accept, confirm], |_| true).unwrap();
        let session = SessionV2::new(genesis, a.verifying_key().to_bytes(), [4; 32]).unwrap();
        (a, session)
    }

    #[test]
    fn restored_history_does_not_expire_on_live_network_deadline() {
        let mut profile = TransmissionProfileV2::default();
        profile.limits.timeout_ms = 1;
        let (key, mut session) = fixture(profile);
        let packet = session
            .build_transmission(&key, "task", &[vec![1]])
            .unwrap()
            .remove(0);
        session.start_replay().unwrap();
        std::thread::sleep(Duration::from_millis(3));
        assert!(session.stage_packet(packet).unwrap().is_some());
        assert_eq!(session.checkpoint().event_count, 1);
    }

    #[test]
    fn arithmetic_overflow_discards_provisional_state_without_committing() {
        let (key, mut session) = fixture(TransmissionProfileV2::default());
        let packet = session
            .build_transmission(&key, "task", &[vec![1]])
            .unwrap()
            .remove(0);
        session.event_count = u64::MAX;
        let before = session.checkpoint();
        assert!(matches!(
            session.build_transmission(&key, "task", &[vec![1]]),
            Err(TraxError::ArithmeticOverflow)
        ));
        session.start_receive().unwrap();
        assert!(matches!(
            session.stage_packet(packet),
            Err(TraxError::ArithmeticOverflow)
        ));
        assert_eq!(session.checkpoint(), before);
        assert!(!session.has_pending());
    }

    #[test]
    fn fragmentation_rejects_excessive_packet_count_before_chunk_allocation() {
        let mut profile = TransmissionProfileV2::default();
        profile.limits.max_packets = 1;
        profile.limits.max_packet_payload_bytes = 1;
        profile.limits.max_payload_bytes = 1024 * 1024;
        let (key, session) = fixture(profile);
        assert!(matches!(
            session.fragment_transmission(&key, "task", &vec![0; 1024 * 1024]),
            Err(TraxError::TransmissionLimit)
        ));
        assert_eq!(session.checkpoint().event_count, 0);
    }
}
