//! Ordered, signed K-window admission for post-genesis TRAX lineage.

use crate::crypto::{ed25519_sign, ed25519_verify, hash32, merkle_root_k8};
use crate::encoding::encode_deterministic;
use crate::errors::TraxError;
use crate::types::{PostGenesisEventV1, SegmentCommitmentV1, SegmentProof, SegmentSealV1};
use ed25519_dalek::{SigningKey, VerifyingKey};

pub const DEFAULT_SEGMENT_K: usize = 8;
pub const POST_GENESIS_EVENT_VERSION: u8 = 1;
pub const SEGMENT_COMMITMENT_VERSION: u8 = 1;
const EVENT_DOMAIN: &[u8] = b"TRAX:POST-GENESIS-EVENT:V1\0";
const COMMITMENT_DOMAIN: &[u8] = b"TRAX:SEGMENT-COMMITMENT:V1\0";
const RECEIVER_ID_DOMAIN: &[u8] = b"TRAX:RECEIVER-ID:V1\0";

pub fn lineage_key_id(key: &VerifyingKey) -> [u8; 32] {
    hash32(key.as_bytes())
}

/// Stable receiver trust identity. This is derived from the receiver's
/// lineage public key, never an ephemeral transmission key.
pub fn receiver_id(receiver_lineage_key: &VerifyingKey) -> [u8; 32] {
    let mut material = Vec::with_capacity(RECEIVER_ID_DOMAIN.len() + 32);
    material.extend_from_slice(RECEIVER_ID_DOMAIN);
    material.extend_from_slice(receiver_lineage_key.as_bytes());
    hash32(&material)
}

/// Authoritative state that has already crossed the Packet 0/session trust
/// boundary. Fields are private so they can only advance through admission.
#[derive(Debug, Clone)]
pub struct TrustedSessionContext {
    session_id: [u8; 32],
    receiver_id: [u8; 32],
    lineage_key: VerifyingKey,
    committed_tip: [u8; 32],
    segment_index: u64,
    next_counter: u64,
}

impl TrustedSessionContext {
    /// Constructs context from state the caller has independently verified.
    /// Prefer `LocalAdmissionDag::trusted_context_from_latest_packet0` when
    /// Packet 0 was admitted by this crate.
    pub fn from_verified_state(
        session_id: [u8; 32],
        receiver_id: [u8; 32],
        lineage_key: VerifyingKey,
        committed_tip: [u8; 32],
        segment_index: u64,
        next_counter: u64,
    ) -> Self {
        Self {
            session_id,
            receiver_id,
            lineage_key,
            committed_tip,
            segment_index,
            next_counter,
        }
    }

    pub fn session_id(&self) -> [u8; 32] {
        self.session_id
    }
    pub fn receiver_id(&self) -> [u8; 32] {
        self.receiver_id
    }
    pub fn lineage_key(&self) -> &VerifyingKey {
        &self.lineage_key
    }
    pub fn committed_tip(&self) -> [u8; 32] {
        self.committed_tip
    }
    pub fn segment_index(&self) -> u64 {
        self.segment_index
    }
    pub fn next_counter(&self) -> u64 {
        self.next_counter
    }
}

pub fn event_bytes(event: &PostGenesisEventV1) -> Result<Vec<u8>, TraxError> {
    encode_deterministic(event)
}

pub fn event_tip(event: &PostGenesisEventV1) -> Result<[u8; 32], TraxError> {
    let encoded = event_bytes(event)?;
    let mut material = Vec::with_capacity(EVENT_DOMAIN.len() + encoded.len());
    material.extend_from_slice(EVENT_DOMAIN);
    material.extend_from_slice(&encoded);
    Ok(hash32(&material))
}

pub fn ordered_merkle_root(events: &[PostGenesisEventV1]) -> Result<[u8; 32], TraxError> {
    let messages = events
        .iter()
        .map(event_bytes)
        .collect::<Result<Vec<_>, _>>()?;
    merkle_root_k8(&messages)
}

pub fn commitment_signing_bytes(commitment: &SegmentCommitmentV1) -> Result<Vec<u8>, TraxError> {
    let encoded = encode_deterministic(commitment)?;
    let mut bytes = Vec::with_capacity(COMMITMENT_DOMAIN.len() + encoded.len());
    bytes.extend_from_slice(COMMITMENT_DOMAIN);
    bytes.extend_from_slice(&encoded);
    Ok(bytes)
}

pub fn create_segment_seal_k8(
    signing_key: &SigningKey,
    events: &[PostGenesisEventV1],
) -> Result<SegmentSealV1, TraxError> {
    validate_ordered_events(events, DEFAULT_SEGMENT_K)?;
    let first = &events[0];
    let last = &events[events.len() - 1];
    if first.lineage_key_id != lineage_key_id(&signing_key.verifying_key()) {
        return Err(TraxError::SegmentContextMismatch);
    }
    let commitment = SegmentCommitmentV1 {
        version: SEGMENT_COMMITMENT_VERSION,
        k: DEFAULT_SEGMENT_K as u32,
        session_id: first.session_id,
        segment_index: first.segment_index,
        first_counter: first.counter,
        last_counter: last.counter,
        starting_committed_tip: first.previous_tip,
        final_provisional_tip: event_tip(last)?,
        ordered_merkle_root: ordered_merkle_root(events)?,
        lineage_key_id: first.lineage_key_id,
        receiver_id: first.receiver_id,
    };
    let signature = ed25519_sign(signing_key, &commitment_signing_bytes(&commitment)?);
    Ok(SegmentSealV1 {
        commitment,
        signature,
    })
}

/// Verifies internal cryptographic consistency only. Success does not admit
/// the proof into any particular trusted session.
pub fn verify_segment_proof_intrinsic(
    proof: &SegmentProof,
    expected_key: &VerifyingKey,
) -> Result<(), TraxError> {
    verify_seal_against_events(&proof.events, &proof.seal, expected_key)
}

/// Verifies both intrinsic validity and membership in the authoritative
/// receiver session context. This is the admission-grade verifier.
pub fn verify_segment_proof_for_context(
    proof: &SegmentProof,
    context: &TrustedSessionContext,
) -> Result<(), TraxError> {
    verify_segment_proof_intrinsic(proof, context.lineage_key())?;
    let c = &proof.seal.commitment;
    if c.session_id != context.session_id {
        return Err(TraxError::SessionMismatch);
    }
    if c.receiver_id != context.receiver_id {
        return Err(TraxError::ReceiverMismatch);
    }
    if c.lineage_key_id != lineage_key_id(context.lineage_key())
        || c.segment_index != context.segment_index
        || c.starting_committed_tip != context.committed_tip
        || c.first_counter != context.next_counter
    {
        return Err(TraxError::SegmentContextMismatch);
    }
    Ok(())
}

fn verify_seal_against_events(
    events: &[PostGenesisEventV1],
    seal: &SegmentSealV1,
    expected_key: &VerifyingKey,
) -> Result<(), TraxError> {
    validate_ordered_events(events, DEFAULT_SEGMENT_K)?;
    let first = &events[0];
    let last = &events[events.len() - 1];
    let c = &seal.commitment;
    if c.version != SEGMENT_COMMITMENT_VERSION || c.k as usize != DEFAULT_SEGMENT_K {
        return Err(TraxError::InvalidSegmentSize);
    }
    if c.session_id != first.session_id
        || c.segment_index != first.segment_index
        || c.first_counter != first.counter
        || c.last_counter != last.counter
        || c.starting_committed_tip != first.previous_tip
        || c.final_provisional_tip != event_tip(last)?
        || c.lineage_key_id != first.lineage_key_id
        || c.receiver_id != first.receiver_id
        || c.lineage_key_id != lineage_key_id(expected_key)
    {
        return Err(TraxError::SegmentContextMismatch);
    }
    if c.ordered_merkle_root != ordered_merkle_root(events)? {
        return Err(TraxError::SegmentRootMismatch);
    }
    if !ed25519_verify(expected_key, &commitment_signing_bytes(c)?, &seal.signature) {
        return Err(TraxError::SegmentSignatureFailure);
    }
    Ok(())
}

fn validate_ordered_events(events: &[PostGenesisEventV1], k: usize) -> Result<(), TraxError> {
    if events.len() != k {
        return Err(if events.len() < k {
            TraxError::IncompleteSegment
        } else {
            TraxError::InvalidSegmentSize
        });
    }
    for (index, event) in events.iter().enumerate() {
        if event.version != POST_GENESIS_EVENT_VERSION {
            return Err(TraxError::SegmentContextMismatch);
        }
        if index > 0 {
            let previous = &events[index - 1];
            if event.previous_tip != event_tip(previous)? {
                return Err(TraxError::ProvisionalTipMismatch);
            }
            if event.counter
                != previous
                    .counter
                    .checked_add(1)
                    .ok_or(TraxError::CounterDiscontinuity)?
            {
                return Err(TraxError::CounterDiscontinuity);
            }
            if event.session_id != previous.session_id
                || event.lineage_key_id != previous.lineage_key_id
                || event.receiver_id != previous.receiver_id
                || event.segment_index != previous.segment_index
            {
                return Err(TraxError::SegmentContextMismatch);
            }
        }
    }
    Ok(())
}

/// Receiver-owned state separating staged data from trusted history.
#[derive(Debug)]
pub struct ReceiveAdmissionWindow {
    k: usize,
    context: TrustedSessionContext,
    provisional_tip: [u8; 32],
    provisional: Vec<PostGenesisEventV1>,
    committed_count: u64,
}

impl ReceiveAdmissionWindow {
    pub fn new_k8(context: TrustedSessionContext) -> Self {
        let provisional_tip = context.committed_tip;
        let committed_count = context
            .segment_index
            .saturating_mul(DEFAULT_SEGMENT_K as u64);
        Self {
            k: DEFAULT_SEGMENT_K,
            context,
            provisional_tip,
            provisional: Vec::with_capacity(DEFAULT_SEGMENT_K),
            committed_count,
        }
    }

    /// Validates the received payload before the event can enter provisional state.
    pub fn stage_with_payload(
        &mut self,
        event: PostGenesisEventV1,
        payload: &[u8],
    ) -> Result<[u8; 32], TraxError> {
        if hash32(payload) != event.payload_hash {
            return Err(TraxError::PayloadHashMismatch);
        }
        self.stage_payload_validated(event)
    }

    fn stage_payload_validated(
        &mut self,
        event: PostGenesisEventV1,
    ) -> Result<[u8; 32], TraxError> {
        if self.provisional.len() == self.k {
            return Err(TraxError::SegmentAlreadySealed);
        }
        if event.session_id != self.context.session_id {
            return Err(TraxError::SessionMismatch);
        }
        if event.receiver_id != self.context.receiver_id {
            return Err(TraxError::ReceiverMismatch);
        }
        if event.lineage_key_id != lineage_key_id(&self.context.lineage_key)
            || event.segment_index != self.context.segment_index
        {
            return Err(TraxError::SegmentContextMismatch);
        }
        let expected_counter = self
            .context
            .next_counter
            .checked_add(self.provisional.len() as u64)
            .ok_or(TraxError::CounterDiscontinuity)?;
        if event.counter != expected_counter {
            return Err(TraxError::CounterDiscontinuity);
        }
        if event.previous_tip != self.provisional_tip {
            return Err(TraxError::ProvisionalTipMismatch);
        }
        let tip = event_tip(&event)?;
        self.provisional.push(event);
        self.provisional_tip = tip;
        Ok(tip)
    }

    pub fn verify_and_commit(
        &mut self,
        seal: &SegmentSealV1,
    ) -> Result<Vec<PostGenesisEventV1>, TraxError> {
        if self.provisional.len() != self.k {
            return Err(TraxError::IncompleteSegment);
        }
        let proof = SegmentProof {
            events: self.provisional.clone(),
            seal: seal.clone(),
        };
        let result = verify_segment_proof_for_context(&proof, &self.context).and_then(|_| {
            if seal.commitment.final_provisional_tip != self.provisional_tip {
                return Err(TraxError::ProvisionalTipMismatch);
            }
            Ok(())
        });
        if let Err(error) = result {
            self.provisional.clear();
            self.provisional_tip = self.context.committed_tip;
            return Err(error);
        }
        let admitted = std::mem::take(&mut self.provisional);
        self.context.committed_tip = self.provisional_tip;
        self.context.segment_index += 1;
        self.context.next_counter += self.k as u64;
        self.committed_count += self.k as u64;
        Ok(admitted)
    }

    pub fn committed_tip(&self) -> [u8; 32] {
        self.context.committed_tip
    }
    pub fn provisional_tip(&self) -> [u8; 32] {
        self.provisional_tip
    }
    pub fn provisional_count(&self) -> usize {
        self.provisional.len()
    }
    pub fn committed_count(&self) -> u64 {
        self.committed_count
    }
    pub fn segment_index(&self) -> u64 {
        self.context.segment_index
    }
    pub fn next_counter(&self) -> u64 {
        self.context.next_counter
    }
    pub fn trusted_context(&self) -> &TrustedSessionContext {
        &self.context
    }
}
