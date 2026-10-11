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

pub fn lineage_key_id(key: &VerifyingKey) -> [u8; 32] {
    hash32(key.as_bytes())
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

pub fn verify_segment_proof(
    proof: &SegmentProof,
    expected_key: &VerifyingKey,
) -> Result<(), TraxError> {
    verify_seal_against_events(&proof.events, &proof.seal, expected_key)
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
    expected_session: [u8; 32],
    expected_receiver: [u8; 32],
    expected_key: VerifyingKey,
    committed_tip: [u8; 32],
    provisional_tip: [u8; 32],
    segment_index: u64,
    next_counter: u64,
    provisional: Vec<PostGenesisEventV1>,
    committed: Vec<PostGenesisEventV1>,
}

impl ReceiveAdmissionWindow {
    pub fn new_k8(
        expected_session: [u8; 32],
        expected_receiver: [u8; 32],
        expected_key: VerifyingKey,
        committed_tip: [u8; 32],
        segment_index: u64,
        next_counter: u64,
    ) -> Self {
        Self {
            k: DEFAULT_SEGMENT_K,
            expected_session,
            expected_receiver,
            expected_key,
            committed_tip,
            provisional_tip: committed_tip,
            segment_index,
            next_counter,
            provisional: Vec::with_capacity(DEFAULT_SEGMENT_K),
            committed: Vec::new(),
        }
    }

    pub fn stage(&mut self, event: PostGenesisEventV1) -> Result<[u8; 32], TraxError> {
        if self.provisional.len() == self.k {
            return Err(TraxError::SegmentAlreadySealed);
        }
        if event.session_id != self.expected_session {
            return Err(TraxError::SessionMismatch);
        }
        if event.receiver_id != self.expected_receiver {
            return Err(TraxError::ReceiverMismatch);
        }
        if event.lineage_key_id != lineage_key_id(&self.expected_key)
            || event.segment_index != self.segment_index
        {
            return Err(TraxError::SegmentContextMismatch);
        }
        let expected_counter = self
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
        let result = verify_seal_against_events(&self.provisional, seal, &self.expected_key)
            .and_then(|_| {
                let c = &seal.commitment;
                if c.session_id != self.expected_session {
                    return Err(TraxError::SessionMismatch);
                }
                if c.receiver_id != self.expected_receiver {
                    return Err(TraxError::ReceiverMismatch);
                }
                if c.segment_index != self.segment_index
                    || c.starting_committed_tip != self.committed_tip
                    || c.first_counter != self.next_counter
                    || c.final_provisional_tip != self.provisional_tip
                {
                    return Err(TraxError::SegmentContextMismatch);
                }
                Ok(())
            });
        if let Err(error) = result {
            self.provisional.clear();
            self.provisional_tip = self.committed_tip;
            return Err(error);
        }
        let admitted = std::mem::take(&mut self.provisional);
        self.committed_tip = self.provisional_tip;
        self.segment_index += 1;
        self.next_counter += self.k as u64;
        self.committed.extend(admitted.iter().cloned());
        Ok(admitted)
    }

    pub fn committed_tip(&self) -> [u8; 32] {
        self.committed_tip
    }
    pub fn provisional_tip(&self) -> [u8; 32] {
        self.provisional_tip
    }
    pub fn provisional_count(&self) -> usize {
        self.provisional.len()
    }
    pub fn committed_count(&self) -> usize {
        self.committed.len()
    }
    pub fn segment_index(&self) -> u64 {
        self.segment_index
    }
    pub fn committed_events(&self) -> &[PostGenesisEventV1] {
        &self.committed
    }
}
