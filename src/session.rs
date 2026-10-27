//! Continuous authenticated relationship history and final-only admission.
use crate::config::{HashAlgorithm, SESSION_SCHEMA_VERSION};
use crate::crypto::{ed25519_sign, ed25519_verify, hash_domain, Hash};
use crate::encoding::{decode_strict, encode_deterministic};
use crate::genesis::{GenesisNode, VerifiedGenesis};
use crate::merkle::MerkleAccumulator;
use crate::transmission::{
    event_tip, signing_bytes, Packet, PacketEvent, RelationshipCheckpoint, SessionCheckpoint,
    SessionCloseCommitment, SessionContext, SessionTerminal, TransmissionCommitment,
    TransmissionKind, TransmissionSeal, VerifiedTransmission,
};
use crate::TraxError;
use ed25519_dalek::{SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::time::{Duration, Instant};
const TRANSMISSION_DOMAIN: &[u8] = b"TRAX:TRANSMISSION:V3\0";
const CLOSE_DOMAIN: &[u8] = b"TRAX:SESSION:CLOSE:V3\0";
const MAX_MESSAGE_TYPE: usize = 64;

/// Original signed data is retained without introducing extra seal nodes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum HistoryKind {
    Genesis {
        transcript: [GenesisNode; 3],
    },
    SessionStart {
        context: SessionContext,
    },
    Packet {
        event: PacketEvent,
        authentication: Option<TransmissionSeal>,
    },
    SessionTerminal {
        terminal: SessionTerminal,
    },
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoryRecord {
    #[serde(with = "serde_bytes")]
    pub id: Hash,
    #[serde(with = "crate::genesis::optional_bytes32")]
    pub parent: Option<Hash>,
    pub position: u64,
    pub kind: HistoryKind,
}

/// Read-only state. Sessions can only be created by their relationship owner.
pub struct Session {
    context: SessionContext,
    id: Hash,
    tip: Hash,
    history_hash: Hash,
    packet_count: u64,
    transmission_id: u64,
    next_kind: TransmissionKind,
    terminal: Option<SessionTerminal>,
    admitted: bool,
    receiving: bool,
}
impl Session {
    fn from_context(context: SessionContext) -> Result<Self, TraxError> {
        let bytes = encode_deterministic(&context)?;
        let hash = context.profile.hash_algorithm;
        Ok(Self {
            id: hash_domain(hash, b"TRAX:SESSION:ID:V3\0", &[&bytes])?,
            tip: session_start_id(&context)?,
            history_hash: hash_domain(hash, b"TRAX:HISTORY:INIT:V3\0", &[&bytes])?,
            context,
            packet_count: 0,
            transmission_id: 0,
            next_kind: TransmissionKind::Request,
            terminal: None,
            admitted: false,
            receiving: false,
        })
    }
    pub fn context(&self) -> &SessionContext {
        &self.context
    }
    pub fn session_id(&self) -> Hash {
        self.id
    }
    pub fn checkpoint(&self) -> SessionCheckpoint {
        SessionCheckpoint {
            session_id: self.id,
            session_index: self.context.session_index,
            tip: self.tip,
            history_hash: self.history_hash,
            packet_count: self.packet_count,
            transmission_id: self.transmission_id,
            closed: self.closed(),
        }
    }
    pub fn closed(&self) -> bool {
        self.terminal.is_some()
    }
    pub fn terminal(&self) -> Option<&SessionTerminal> {
        self.terminal.as_ref()
    }
    pub fn has_pending(&self) -> bool {
        self.receiving
    }
    pub fn next_kind(&self) -> TransmissionKind {
        self.next_kind
    }
    pub fn expected_sender(&self) -> Hash {
        match self.next_kind {
            TransmissionKind::Request => self.context.initiator,
            TransmissionKind::Response => self.context.responder,
        }
    }
    fn expected_receiver(&self) -> Hash {
        match self.next_kind {
            TransmissionKind::Request => self.context.responder,
            TransmissionKind::Response => self.context.initiator,
        }
    }
}
struct PendingTransmission {
    started: Option<Instant>,
    candidate: Option<Session>,
    packets: Vec<Packet>,
    tip: Option<Hash>,
    payload_bytes: u64,
    merkle: Option<MerkleAccumulator>,
    session_history_hash: Option<Hash>,
}
pub(crate) struct PreparedTransmission {
    verified: VerifiedTransmission,
    candidate: Option<Session>,
    records: Vec<HistoryRecord>,
    history_hash: Hash,
    session_history_hash: Hash,
    packet_count: u64,
    transmission_id: u64,
}
impl PreparedTransmission {
    pub(crate) fn packets(&self) -> &[Packet] {
        self.verified.packets()
    }
}
pub(crate) struct PreparedClose {
    record: HistoryRecord,
    history_hash: Hash,
    session_history_hash: Hash,
    terminal: SessionTerminal,
}

/// One mirrored authoritative history, across any number of closed sessions.
/// Draft session starts remain provisional until their first request verifies.
pub struct Relationship {
    genesis: VerifiedGenesis,
    history: Vec<HistoryRecord>,
    index: BTreeMap<Hash, usize>,
    child_index: BTreeMap<Hash, Vec<Hash>>,
    tip: Hash,
    history_hash: Hash,
    record_count: u64,
    completed_sessions: u64,
    last_session_id: Option<Hash>,
    active: Option<Session>,
    last_closed: Option<Session>,
    pending: Option<PendingTransmission>,
}
impl Relationship {
    pub fn new(genesis: VerifiedGenesis) -> Result<Self, TraxError> {
        let record = HistoryRecord {
            id: genesis.anchor(),
            parent: None,
            position: 0,
            kind: HistoryKind::Genesis {
                transcript: genesis.nodes().clone(),
            },
        };
        let history_hash = hash_domain(
            genesis.profile().hash_algorithm,
            b"TRAX:HISTORY:ROOT:V3\0",
            &[&encode_deterministic(&record)?],
        )?;
        let tip = record.id;
        Ok(Self {
            genesis,
            history: vec![record],
            index: BTreeMap::from([(tip, 0)]),
            child_index: BTreeMap::new(),
            tip,
            history_hash,
            record_count: 0,
            completed_sessions: 0,
            last_session_id: None,
            active: None,
            last_closed: None,
            pending: None,
        })
    }
    pub fn genesis(&self) -> &VerifiedGenesis {
        &self.genesis
    }
    pub fn session(&self) -> Option<&Session> {
        self.active.as_ref().or(self.last_closed.as_ref())
    }
    pub fn active_session(&self) -> Option<&Session> {
        self.active.as_ref()
    }
    pub fn has_pending(&self) -> bool {
        self.pending.is_some()
    }
    pub fn history(&self) -> &[HistoryRecord] {
        &self.history
    }
    pub fn record(&self, id: &Hash) -> Option<&HistoryRecord> {
        self.index.get(id).and_then(|i| self.history.get(*i))
    }
    pub fn children(&self, id: &Hash) -> Vec<&HistoryRecord> {
        self.child_index
            .get(id)
            .into_iter()
            .flatten()
            .filter_map(|id| self.record(id))
            .collect()
    }
    /// Ancestors nearest-parent-first, excluding the selected record.
    pub fn ancestors(&self, id: &Hash) -> Result<Vec<&HistoryRecord>, TraxError> {
        let mut parent = self.record(id).ok_or(TraxError::UnknownNode)?.parent;
        let mut result = Vec::new();
        while let Some(id) = parent {
            let record = self.record(&id).ok_or(TraxError::UnknownNode)?;
            result.push(record);
            parent = record.parent;
        }
        Ok(result)
    }
    pub fn checkpoint(&self) -> RelationshipCheckpoint {
        RelationshipCheckpoint {
            relationship_id: self.genesis.anchor(),
            tip: self.tip,
            history_hash: self.history_hash,
            record_count: self.record_count,
            completed_sessions: self.completed_sessions,
            last_session_id: self.last_session_id,
            active_session: self
                .active
                .as_ref()
                .filter(|s| s.admitted)
                .map(Session::checkpoint),
        }
    }
    fn context(&self, initiator: Hash, nonce: Hash) -> Result<SessionContext, TraxError> {
        let responder = if initiator == self.genesis.initiator_key() {
            self.genesis.responder_key()
        } else if initiator == self.genesis.responder_key() {
            self.genesis.initiator_key()
        } else {
            return Err(TraxError::UnknownParticipant);
        };
        Ok(SessionContext {
            version: SESSION_SCHEMA_VERSION,
            relationship_id: self.genesis.anchor(),
            profile: self.genesis.profile().clone(),
            initiator,
            responder,
            nonce,
            session_index: self
                .completed_sessions
                .checked_add(1)
                .ok_or(TraxError::ArithmeticOverflow)?,
            previous_tip: self.tip,
            previous_history_hash: self.history_hash,
            previous_record_count: self.record_count,
        })
    }
    fn validate_context(&self, context: &SessionContext) -> Result<(), TraxError> {
        if *context != self.context(context.initiator, context.nonce)? {
            return Err(TraxError::RelationshipMismatch);
        }
        Ok(())
    }
    pub fn begin_session(&mut self, initiator: Hash, nonce: Hash) -> Result<(), TraxError> {
        let context = self.context(initiator, nonce)?;
        self.begin_session_from_context(&context)
    }
    pub fn begin_session_from_context(
        &mut self,
        context: &SessionContext,
    ) -> Result<(), TraxError> {
        if self.active.is_some() || self.pending.is_some() {
            return Err(TraxError::UnexpectedState);
        }
        self.validate_context(context)?;
        self.active = Some(Session::from_context(context.clone())?);
        Ok(())
    }
    /// Discards only an unadmitted local intent. Accepted history cannot reset.
    pub fn abort_draft_session(&mut self) -> bool {
        if self.pending.is_none() && self.active.as_ref().is_some_and(|s| !s.admitted) {
            self.active = None;
            true
        } else {
            false
        }
    }
    pub fn start_receive(&mut self) -> Result<(), TraxError> {
        self.start_receive_inner(true)
    }
    pub(crate) fn start_replay(&mut self) -> Result<(), TraxError> {
        self.start_receive_inner(false)
    }
    fn start_receive_inner(&mut self, live: bool) -> Result<(), TraxError> {
        if self.pending.is_some() {
            return Err(TraxError::UnexpectedState);
        }
        self.pending = Some(PendingTransmission {
            started: live.then(Instant::now),
            candidate: None,
            packets: Vec::new(),
            tip: None,
            payload_bytes: 0,
            merkle: None,
            session_history_hash: None,
        });
        if let Some(session) = &mut self.active {
            session.receiving = true;
        }
        Ok(())
    }
    pub fn abort_receive(&mut self) -> bool {
        if let Some(session) = &mut self.active {
            session.receiving = false;
        }
        self.pending.take().is_some()
    }
    pub fn expire_receive(&mut self) -> bool {
        let expired = self.pending.as_ref().is_some_and(|p| {
            p.started.is_some_and(|started| {
                started.elapsed() >= Duration::from_millis(self.genesis.profile().limits.timeout_ms)
            })
        });
        if expired {
            self.abort_receive();
        }
        expired
    }
    pub fn stage_encoded_packet(
        &mut self,
        bytes: &[u8],
    ) -> Result<Option<VerifiedTransmission>, TraxError> {
        let packet = match decode_strict(
            bytes,
            self.genesis.profile().limits.max_wire_packet_bytes as usize,
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
        packet: Packet,
    ) -> Result<Option<VerifiedTransmission>, TraxError> {
        Ok(self.prepare_packet(packet)?.map(|p| self.apply_prepared(p)))
    }
    pub(crate) fn prepare_packet(
        &mut self,
        packet: Packet,
    ) -> Result<Option<PreparedTransmission>, TraxError> {
        let pending = self.pending.take().ok_or(TraxError::UnexpectedState)?;
        if let Some(session) = &mut self.active {
            session.receiving = false;
        }
        let result = self.prepare_packet_inner(pending, packet);
        if let Ok(None) = &result {
            if let Some(session) = &mut self.active {
                session.receiving = true;
            }
        }
        result
    }
    fn prepare_packet_inner(
        &mut self,
        mut pending: PendingTransmission,
        packet: Packet,
    ) -> Result<Option<PreparedTransmission>, TraxError> {
        let profile = self.genesis.profile();
        let limits = &profile.limits;
        if pending
            .started
            .is_some_and(|s| s.elapsed() >= Duration::from_millis(limits.timeout_ms))
        {
            return Err(TraxError::TransmissionExpired);
        }
        if pending.packets.len() >= limits.max_packets as usize
            || packet.payload.len() > limits.max_packet_payload_bytes as usize
            || packet.event.message_type.is_empty()
            || packet.event.message_type.len() > MAX_MESSAGE_TYPE
            || encode_deterministic(&packet)?.len() > limits.max_wire_packet_bytes as usize
        {
            return Err(TraxError::TransmissionLimit);
        }
        if self.active.is_none() && pending.candidate.is_none() {
            let context = packet
                .session_start
                .as_ref()
                .ok_or(TraxError::TransmissionContextMismatch)?;
            self.validate_context(context)?;
            pending.candidate = Some(Session::from_context(context.clone())?);
        }
        let session = self
            .active
            .as_ref()
            .or(pending.candidate.as_ref())
            .ok_or(TraxError::UnexpectedState)?;
        let first_request = session.transmission_id == 0;
        let count =
            u32::try_from(pending.packets.len()).map_err(|_| TraxError::ArithmeticOverflow)?;
        if count == 0 && first_request {
            if packet.session_start.as_ref() != Some(&session.context) {
                return Err(TraxError::TransmissionContextMismatch);
            }
        } else if packet.session_start.is_some() {
            return Err(TraxError::TransmissionContextMismatch);
        }
        if count == 0 {
            pending.tip = Some(session.tip);
            pending.merkle = Some(MerkleAccumulator::new(profile.hash_algorithm)?);
            pending.session_history_hash = Some(session.history_hash);
        }
        let extra = u64::from(first_request);
        let counter = self
            .record_count
            .checked_add(extra)
            .and_then(|n| n.checked_add(u64::from(count)))
            .and_then(|n| n.checked_add(1))
            .ok_or(TraxError::ArithmeticOverflow)?;
        let transmission_id = session
            .transmission_id
            .checked_add(1)
            .ok_or(TraxError::ArithmeticOverflow)?;
        let e = &packet.event;
        if e.version != SESSION_SCHEMA_VERSION
            || e.relationship_id != self.genesis.anchor()
            || e.session_id != session.id
            || e.transmission_id != transmission_id
            || e.initiator != session.context.initiator
            || e.sender != session.expected_sender()
            || e.receiver != session.expected_receiver()
            || e.key_epoch != 0
            || e.kind != session.next_kind
            || e.packet_index != count
            || e.counter != counter
            || Some(e.previous_tip) != pending.tip
            || pending
                .packets
                .first()
                .is_some_and(|p| p.event.message_type != e.message_type)
        {
            return Err(TraxError::TransmissionContextMismatch);
        }
        if e.payload_len as usize != packet.payload.len()
            || e.payload_hash
                != hash_domain(
                    profile.hash_algorithm,
                    b"TRAX:PAYLOAD:V3\0",
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
        pending.payload_bytes = pending
            .payload_bytes
            .checked_add(u64::from(e.payload_len))
            .ok_or(TraxError::ArithmeticOverflow)?;
        if pending.payload_bytes > limits.max_payload_bytes {
            return Err(TraxError::TransmissionLimit);
        }
        let event_bytes = encode_deterministic(e)?;
        pending
            .merkle
            .as_mut()
            .expect("initialized")
            .push(&event_bytes)?;
        let tip = event_tip(profile.hash_algorithm, e)?;
        pending.tip = Some(tip);
        let mut session_history = hash_domain(
            profile.hash_algorithm,
            b"TRAX:HISTORY:EVENT:V3\0",
            &[
                &pending.session_history_hash.expect("initialized"),
                &event_bytes,
            ],
        )?;
        pending.session_history_hash = Some(session_history);
        if !e.is_final {
            pending.packets.push(packet);
            self.pending = Some(pending);
            return Ok(None);
        }
        let expected = self.commitment(
            session,
            e,
            count.checked_add(1).ok_or(TraxError::ArithmeticOverflow)?,
            pending.payload_bytes,
            tip,
            pending.merkle.as_ref().expect("initialized").root()?,
        )?;
        let seal = packet
            .authentication
            .as_ref()
            .ok_or(TraxError::BadSignature)?;
        if seal.commitment != expected {
            return Err(TraxError::TransmissionContextMismatch);
        }
        let key =
            VerifyingKey::from_bytes(&session.expected_sender()).map_err(|_| TraxError::Crypto)?;
        if !ed25519_verify(
            &key,
            &signing_bytes(TRANSMISSION_DOMAIN, &expected)?,
            &seal.signature,
        ) {
            return Err(TraxError::BadSignature);
        }
        session_history = hash_domain(
            profile.hash_algorithm,
            b"TRAX:HISTORY:AUTH:V3\0",
            &[&session_history, &encode_deterministic(seal)?],
        )?;
        let packet_count = session
            .packet_count
            .checked_add(u64::from(count) + 1)
            .ok_or(TraxError::ArithmeticOverflow)?;
        pending.packets.push(packet);
        let mut records = Vec::with_capacity(pending.packets.len() + extra as usize);
        let mut parent = self.tip;
        let mut position = self.record_count;
        if first_request {
            position = position
                .checked_add(1)
                .ok_or(TraxError::ArithmeticOverflow)?;
            let record = HistoryRecord {
                id: session_start_id(&session.context)?,
                parent: Some(parent),
                position,
                kind: HistoryKind::SessionStart {
                    context: session.context.clone(),
                },
            };
            parent = record.id;
            records.push(record);
        }
        for packet in &pending.packets {
            position = position
                .checked_add(1)
                .ok_or(TraxError::ArithmeticOverflow)?;
            let record = HistoryRecord {
                id: event_tip(profile.hash_algorithm, &packet.event)?,
                parent: Some(parent),
                position,
                kind: HistoryKind::Packet {
                    event: packet.event.clone(),
                    authentication: packet.authentication.clone(),
                },
            };
            parent = record.id;
            records.push(record);
        }
        let mut history_hash = self.history_hash;
        for record in &records {
            history_hash = fold_record(profile.hash_algorithm, history_hash, record)?;
        }
        Ok(Some(PreparedTransmission {
            verified: VerifiedTransmission::from_packets(pending.packets),
            candidate: pending.candidate,
            records,
            history_hash,
            session_history_hash: session_history,
            packet_count,
            transmission_id,
        }))
    }
    pub(crate) fn apply_prepared(
        &mut self,
        prepared: PreparedTransmission,
    ) -> VerifiedTransmission {
        if self.active.is_none() {
            self.active = prepared.candidate;
        }
        for record in prepared.records {
            self.insert_record(record);
        }
        self.history_hash = prepared.history_hash;
        let session = self.active.as_mut().expect("prepared active session");
        session.tip = self.tip;
        session.history_hash = prepared.session_history_hash;
        session.packet_count = prepared.packet_count;
        session.transmission_id = prepared.transmission_id;
        session.admitted = true;
        session.receiving = false;
        session.next_kind = match session.next_kind {
            TransmissionKind::Request => TransmissionKind::Response,
            TransmissionKind::Response => TransmissionKind::Request,
        };
        self.last_session_id = Some(session.id);
        prepared.verified
    }
    fn insert_record(&mut self, record: HistoryRecord) {
        if let Some(parent) = record.parent {
            self.child_index.entry(parent).or_default().push(record.id);
        }
        self.tip = record.id;
        self.record_count = record.position;
        self.index.insert(record.id, self.history.len());
        self.history.push(record);
    }
    fn commitment(
        &self,
        session: &Session,
        event: &PacketEvent,
        count: u32,
        bytes: u64,
        tip: Hash,
        root: Hash,
    ) -> Result<TransmissionCommitment, TraxError> {
        Ok(TransmissionCommitment {
            version: SESSION_SCHEMA_VERSION,
            purpose: "logical-transmission".into(),
            relationship_id: self.genesis.anchor(),
            session_id: session.id,
            transmission_id: session
                .transmission_id
                .checked_add(1)
                .ok_or(TraxError::ArithmeticOverflow)?,
            initiator: session.context.initiator,
            sender: session.expected_sender(),
            receiver: session.expected_receiver(),
            key_epoch: 0,
            kind: session.next_kind,
            message_type: event.message_type.clone(),
            starting_tip: session.tip,
            first_counter: self
                .record_count
                .checked_add(u64::from(session.transmission_id == 0))
                .and_then(|n| n.checked_add(1))
                .ok_or(TraxError::ArithmeticOverflow)?,
            last_counter: event.counter,
            packet_count: count,
            payload_bytes: bytes,
            merkle_root: root,
            final_event_tip: tip,
        })
    }
    /// Produces untrusted wire packets. Mirror through the same admission API.
    pub fn build_transmission(
        &self,
        key: &SigningKey,
        message_type: &str,
        chunks: &[Vec<u8>],
    ) -> Result<Vec<Packet>, TraxError> {
        let session = self.active.as_ref().ok_or(TraxError::UnexpectedState)?;
        if self.pending.is_some() {
            return Err(TraxError::UnexpectedState);
        }
        if key.verifying_key().to_bytes() != session.expected_sender() {
            return Err(TraxError::SignerMismatch);
        }
        let profile = self.genesis.profile();
        let limits = &profile.limits;
        if chunks.is_empty()
            || chunks.len() > limits.max_packets as usize
            || message_type.is_empty()
            || message_type.len() > MAX_MESSAGE_TYPE
        {
            return Err(TraxError::TransmissionLimit);
        }
        let mut tip = session.tip;
        let mut bytes = 0u64;
        let mut merkle = MerkleAccumulator::new(profile.hash_algorithm)?;
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
            let event = PacketEvent {
                version: SESSION_SCHEMA_VERSION,
                relationship_id: self.genesis.anchor(),
                session_id: session.id,
                transmission_id: session
                    .transmission_id
                    .checked_add(1)
                    .ok_or(TraxError::ArithmeticOverflow)?,
                initiator: session.context.initiator,
                sender: session.expected_sender(),
                receiver: session.expected_receiver(),
                key_epoch: 0,
                kind: session.next_kind,
                message_type: message_type.into(),
                packet_index: u32::try_from(index).map_err(|_| TraxError::ArithmeticOverflow)?,
                counter: self
                    .record_count
                    .checked_add(u64::from(session.transmission_id == 0))
                    .and_then(|n| n.checked_add(index as u64))
                    .and_then(|n| n.checked_add(1))
                    .ok_or(TraxError::ArithmeticOverflow)?,
                previous_tip: tip,
                payload_hash: hash_domain(
                    profile.hash_algorithm,
                    b"TRAX:PAYLOAD:V3\0",
                    &[payload],
                )?,
                payload_len: len,
                is_final: index + 1 == chunks.len(),
            };
            merkle.push(&encode_deterministic(&event)?)?;
            tip = event_tip(profile.hash_algorithm, &event)?;
            packets.push(Packet {
                event,
                payload: payload.clone(),
                authentication: None,
                session_start: if index == 0 && session.transmission_id == 0 {
                    Some(session.context.clone())
                } else {
                    None
                },
            });
        }
        let final_packet = packets.last_mut().ok_or(TraxError::UnexpectedState)?;
        let commitment = self.commitment(
            session,
            &final_packet.event,
            chunks.len() as u32,
            bytes,
            tip,
            merkle.root()?,
        )?;
        final_packet.authentication = Some(TransmissionSeal {
            signature: ed25519_sign(key, &signing_bytes(TRANSMISSION_DOMAIN, &commitment)?),
            commitment,
        });
        for packet in &packets {
            if encode_deterministic(packet)?.len() > limits.max_wire_packet_bytes as usize {
                return Err(TraxError::TransmissionLimit);
            }
        }
        Ok(packets)
    }
    pub fn fragment_transmission(
        &self,
        key: &SigningKey,
        message_type: &str,
        payload: &[u8],
    ) -> Result<Vec<Packet>, TraxError> {
        let session = self.active.as_ref().ok_or(TraxError::UnexpectedState)?;
        if self.pending.is_some() {
            return Err(TraxError::UnexpectedState);
        }
        if key.verifying_key().to_bytes() != session.expected_sender() {
            return Err(TraxError::SignerMismatch);
        }
        let limits = &self.genesis.profile().limits;
        if payload.len() as u64 > limits.max_payload_bytes
            || message_type.is_empty()
            || message_type.len() > MAX_MESSAGE_TYPE
        {
            return Err(TraxError::TransmissionLimit);
        }
        let bytes = payload.len() as u64;
        if self
            .packet_capacity(session, message_type, 0, 1, bytes, true)?
            .is_some_and(|capacity| payload.len() <= capacity)
        {
            return self.build_transmission(key, message_type, &[payload.to_vec()]);
        }
        if limits.max_packets < 2 {
            return Err(TraxError::TransmissionLimit);
        }
        let mut count = 2u32;
        let (first, middle, last) = loop {
            let first = self
                .packet_capacity(session, message_type, 0, count, bytes, false)?
                .ok_or(TraxError::TransmissionLimit)?;
            let last = self
                .packet_capacity(session, message_type, count - 1, count, bytes, true)?
                .ok_or(TraxError::TransmissionLimit)?;
            if !payload.is_empty() && last == 0 {
                return Err(TraxError::TransmissionLimit);
            }
            let remaining = payload.len().saturating_sub(first + last);
            if remaining == 0 {
                break (first, 0, last);
            }
            // The largest middle index/counter bounds every middle packet's
            // integer overhead. Recompute only when count crosses a boundary.
            let middle = self
                .packet_capacity(
                    session,
                    message_type,
                    (count - 2).max(1),
                    count,
                    bytes,
                    false,
                )?
                .ok_or(TraxError::TransmissionLimit)?;
            if middle == 0 {
                return Err(TraxError::TransmissionLimit);
            }
            let needed = remaining
                .div_ceil(middle)
                .checked_add(2)
                .ok_or(TraxError::ArithmeticOverflow)?;
            if needed > limits.max_packets as usize {
                return Err(TraxError::TransmissionLimit);
            }
            if needed <= count as usize {
                break (first, middle, last);
            }
            count = u32::try_from(needed).map_err(|_| TraxError::ArithmeticOverflow)?;
        };
        // All count/byte/counter limits were checked before chunk allocation.
        // A context-only first packet is allowed when first+seal cannot fit in
        // one packet; the final packet carries data for a nonempty payload.
        let mut chunks = Vec::with_capacity(count as usize);
        let mut offset = first.min(
            payload
                .len()
                .saturating_sub(usize::from(!payload.is_empty())),
        );
        chunks.push(payload[..offset].to_vec());
        for _ in 0..count - 2 {
            let take = middle.min(payload.len().saturating_sub(offset + 1));
            chunks.push(payload[offset..offset + take].to_vec());
            offset += take;
        }
        if payload.len() - offset > last {
            return Err(TraxError::TransmissionLimit);
        }
        chunks.push(payload[offset..].to_vec());
        self.build_transmission(key, message_type, &chunks)
    }

    fn packet_capacity(
        &self,
        session: &Session,
        message_type: &str,
        index: u32,
        count: u32,
        bytes: u64,
        is_final: bool,
    ) -> Result<Option<usize>, TraxError> {
        let limits = &self.genesis.profile().limits;
        let event = PacketEvent {
            version: SESSION_SCHEMA_VERSION,
            relationship_id: self.genesis.anchor(),
            session_id: session.id,
            transmission_id: session
                .transmission_id
                .checked_add(1)
                .ok_or(TraxError::ArithmeticOverflow)?,
            initiator: session.context.initiator,
            sender: session.expected_sender(),
            receiver: session.expected_receiver(),
            key_epoch: 0,
            kind: session.next_kind,
            message_type: message_type.into(),
            packet_index: index,
            counter: self
                .record_count
                .checked_add(u64::from(session.transmission_id == 0))
                .and_then(|n| n.checked_add(u64::from(index)))
                .and_then(|n| n.checked_add(1))
                .ok_or(TraxError::ArithmeticOverflow)?,
            previous_tip: [0; 32],
            payload_hash: [0; 32],
            payload_len: 0,
            is_final,
        };
        let authentication = if is_final {
            Some(TransmissionSeal {
                commitment: self.commitment(session, &event, count, bytes, [0; 32], [0; 32])?,
                // Signature bytes have a fixed size; sizing never signs.
                signature: vec![0; 64],
            })
        } else {
            None
        };
        let packet = Packet {
            event,
            payload: Vec::new(),
            authentication,
            session_start: if index == 0 && session.transmission_id == 0 {
                Some(session.context.clone())
            } else {
                None
            },
        };
        let empty_size = encode_deterministic(&packet)?.len();
        let budget = limits.max_wire_packet_bytes as usize;
        if empty_size > budget {
            return Ok(None);
        }
        let mut low = 0usize;
        let mut high = limits.max_packet_payload_bytes as usize;
        while low < high {
            let middle = low + (high - low).div_ceil(2);
            // Replacing zero payload_len and an empty byte string changes
            // exactly these two CBOR headers, in addition to the data bytes.
            let size = empty_size + middle + 2 * (cbor_header_len(middle as u64) - 1);
            if size <= budget {
                low = middle;
            } else {
                high = middle - 1;
            }
        }
        Ok(Some(low))
    }
    fn close_commitment(&self) -> Result<SessionCloseCommitment, TraxError> {
        let session = self.active.as_ref().ok_or(TraxError::UnexpectedState)?;
        if self.pending.is_some()
            || !session.admitted
            || session.next_kind != TransmissionKind::Request
            || session.transmission_id < 2
        {
            return Err(TraxError::UnexpectedState);
        }
        Ok(SessionCloseCommitment {
            version: SESSION_SCHEMA_VERSION,
            purpose: "session-close".into(),
            relationship_id: self.genesis.anchor(),
            session_id: session.id,
            session_index: session.context.session_index,
            initiator: session.context.initiator,
            responder: session.context.responder,
            final_data_tip: self.tip,
            session_history_hash: session.history_hash,
            relationship_history_hash: self.history_hash,
            first_counter: session
                .context
                .previous_record_count
                .checked_add(2)
                .ok_or(TraxError::ArithmeticOverflow)?,
            last_counter: self.record_count,
            packet_count: session.packet_count,
            transmission_id: session.transmission_id,
            terminal_counter: self
                .record_count
                .checked_add(1)
                .ok_or(TraxError::ArithmeticOverflow)?,
        })
    }
    pub fn create_close(&self, key: &SigningKey) -> Result<SessionTerminal, TraxError> {
        let session = self.active.as_ref().ok_or(TraxError::UnexpectedState)?;
        if key.verifying_key().to_bytes() != session.context.initiator {
            return Err(TraxError::SignerMismatch);
        }
        let commitment = self.close_commitment()?;
        Ok(SessionTerminal {
            signature: ed25519_sign(key, &signing_bytes(CLOSE_DOMAIN, &commitment)?),
            commitment,
        })
    }
    pub(crate) fn prepare_close(
        &self,
        terminal: &SessionTerminal,
    ) -> Result<PreparedClose, TraxError> {
        let expected = self.close_commitment()?;
        if terminal.commitment != expected {
            return Err(TraxError::TransmissionContextMismatch);
        }
        let bytes = encode_deterministic(terminal)?;
        let profile = self.genesis.profile();
        if bytes.len() > profile.limits.max_wire_packet_bytes as usize {
            return Err(TraxError::TransmissionLimit);
        }
        let key = VerifyingKey::from_bytes(&expected.initiator).map_err(|_| TraxError::Crypto)?;
        if !ed25519_verify(
            &key,
            &signing_bytes(CLOSE_DOMAIN, &expected)?,
            &terminal.signature,
        ) {
            return Err(TraxError::BadSignature);
        }
        self.completed_sessions
            .checked_add(1)
            .ok_or(TraxError::ArithmeticOverflow)?;
        let record = HistoryRecord {
            id: hash_domain(
                profile.hash_algorithm,
                b"TRAX:SESSION:TERMINAL:V3\0",
                &[&bytes],
            )?,
            parent: Some(self.tip),
            position: expected.terminal_counter,
            kind: HistoryKind::SessionTerminal {
                terminal: terminal.clone(),
            },
        };
        Ok(PreparedClose {
            history_hash: fold_record(profile.hash_algorithm, self.history_hash, &record)?,
            session_history_hash: hash_domain(
                profile.hash_algorithm,
                b"TRAX:HISTORY:TERMINAL:V3\0",
                &[&expected.session_history_hash, &bytes],
            )?,
            record,
            terminal: terminal.clone(),
        })
    }
    pub(crate) fn apply_close(&mut self, prepared: PreparedClose) {
        self.insert_record(prepared.record);
        self.history_hash = prepared.history_hash;
        let mut session = self.active.take().expect("prepared active session");
        session.tip = self.tip;
        session.history_hash = prepared.session_history_hash;
        session.terminal = Some(prepared.terminal);
        self.completed_sessions += 1;
        self.last_session_id = Some(session.id);
        self.last_closed = Some(session);
    }
    pub fn verify_and_close(&mut self, terminal: &SessionTerminal) -> Result<(), TraxError> {
        let prepared = self.prepare_close(terminal)?;
        self.apply_close(prepared);
        Ok(())
    }
    pub fn verify_encoded_close(&mut self, bytes: &[u8]) -> Result<(), TraxError> {
        let terminal = decode_strict(
            bytes,
            self.genesis.profile().limits.max_wire_packet_bytes as usize,
        )?;
        self.verify_and_close(&terminal)
    }
}
pub fn session_start_id(context: &SessionContext) -> Result<Hash, TraxError> {
    hash_domain(
        context.profile.hash_algorithm,
        b"TRAX:SESSION:START:V3\0",
        &[&encode_deterministic(context)?],
    )
}
fn fold_record(
    algorithm: HashAlgorithm,
    previous: Hash,
    record: &HistoryRecord,
) -> Result<Hash, TraxError> {
    hash_domain(
        algorithm,
        b"TRAX:HISTORY:RECORD:V3\0",
        &[&previous, &encode_deterministic(record)?],
    )
}

fn cbor_header_len(value: u64) -> usize {
    match value {
        0..=23 => 1,
        24..=255 => 2,
        256..=65535 => 3,
        65536..=0xffff_ffff => 5,
        _ => 9,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::genesis::{accept_genesis_offer, confirm_genesis, create_genesis_offer};
    use crate::TransmissionProfile;

    fn fixture(profile: TransmissionProfile) -> (SigningKey, Relationship) {
        let a = SigningKey::from_bytes(&[1; 32]);
        let b = SigningKey::from_bytes(&[2; 32]);
        let offer = create_genesis_offer(&a, [3; 32], profile).unwrap();
        let accept = accept_genesis_offer(&offer, &b, |_| true).unwrap();
        let confirm = confirm_genesis(&offer, &accept, &a, |_| true).unwrap();
        let genesis = VerifiedGenesis::verify([offer, accept, confirm], |_| true).unwrap();
        let mut relationship = Relationship::new(genesis).unwrap();
        relationship
            .begin_session(a.verifying_key().to_bytes(), [4; 32])
            .unwrap();
        (a, relationship)
    }
    #[test]
    fn durable_replay_omits_only_the_live_network_deadline() {
        let mut profile = TransmissionProfile::default();
        profile.limits.timeout_ms = 1;
        let (key, mut relationship) = fixture(profile);
        let packet = relationship
            .build_transmission(&key, "task", &[vec![1]])
            .unwrap()
            .remove(0);
        relationship.start_replay().unwrap();
        std::thread::sleep(Duration::from_millis(3));
        assert!(relationship.stage_packet(packet).unwrap().is_some());
        assert_eq!(relationship.checkpoint().record_count, 2);
    }
    #[test]
    fn counter_overflow_discards_provisional_state_without_committing() {
        let (key, mut relationship) = fixture(TransmissionProfile::default());
        let packet = relationship
            .build_transmission(&key, "task", &[vec![1]])
            .unwrap()
            .remove(0);
        relationship.record_count = u64::MAX;
        let before = relationship.checkpoint();
        assert!(matches!(
            relationship.build_transmission(&key, "task", &[vec![1]]),
            Err(TraxError::ArithmeticOverflow)
        ));
        relationship.start_receive().unwrap();
        assert!(matches!(
            relationship.stage_packet(packet),
            Err(TraxError::ArithmeticOverflow)
        ));
        assert_eq!(relationship.checkpoint(), before);
        assert!(!relationship.has_pending());
        assert!(!relationship.active_session().unwrap().has_pending());
    }
    #[test]
    fn transmission_and_session_indices_never_wrap() {
        let (key, mut relationship) = fixture(TransmissionProfile::default());
        let mut packet = relationship
            .build_transmission(&key, "task", &[vec![1]])
            .unwrap()
            .remove(0);
        packet.session_start = None;
        relationship.active.as_mut().unwrap().transmission_id = u64::MAX;
        let before = relationship.checkpoint();
        assert!(matches!(
            relationship.build_transmission(&key, "task", &[vec![1]]),
            Err(TraxError::ArithmeticOverflow)
        ));
        relationship.start_receive().unwrap();
        assert!(matches!(
            relationship.stage_packet(packet),
            Err(TraxError::ArithmeticOverflow)
        ));
        assert_eq!(relationship.checkpoint(), before);
        relationship.active = None;
        relationship.completed_sessions = u64::MAX;
        let before = relationship.checkpoint();
        assert!(matches!(
            relationship.begin_session(key.verifying_key().to_bytes(), [9; 32]),
            Err(TraxError::ArithmeticOverflow)
        ));
        assert_eq!(relationship.checkpoint(), before);
    }
    #[test]
    fn fragmentation_checks_packet_count_before_allocating_chunks() {
        let mut profile = TransmissionProfile::default();
        profile.limits.max_packets = 1;
        profile.limits.max_packet_payload_bytes = 1;
        profile.limits.max_payload_bytes = 1024 * 1024;
        let (key, relationship) = fixture(profile);
        assert!(matches!(
            relationship.fragment_transmission(&key, "task", &vec![0; 1024 * 1024]),
            Err(TraxError::TransmissionLimit)
        ));
        assert_eq!(relationship.checkpoint().record_count, 0);
    }
}
