//! Detached acknowledgments of a K-1 event prefix.
//!
//! This proof authenticates the exact prefix and its acknowledgment metadata;
//! it does not admit partial DAG history. The graph verifies ancestry, current
//! key authority, proposal flow and the final K-event checkpoint separately.
//! Signatures remain outside GraphEvent, avoiding a self-referential ACK hash.

use ed25519_dalek::{SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::crypto::{ed25519_sign, ed25519_verify};
use crate::encoding::encode_deterministic;
use crate::graph::{AuthorityId, BranchId, GraphEvent, GraphOperation, NodeId};
use crate::profile::{domain_hash, merkle_root_for_count};
use crate::{ProtocolConfig, TraxError};

const ACK_DOMAIN: &[u8] = b"TRAX:PREFIX-ACK:V2\0";
const ACK_ID_DOMAIN: &[u8] = b"TRAX:PREFIX-ACK-ID:V2\0";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrefixContext {
    pub dag_id: NodeId,
    pub config: ProtocolConfig,
    pub configuration_tip: NodeId,
    pub previous_checkpoint: NodeId,
    pub segment_index: u64,
    pub proposal: NodeId,
    pub branch: BranchId,
    pub first_counter: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrefixCommitment {
    pub context: PrefixContext,
    pub prefix_len: u32,
    pub last_counter: u64,
    pub expected_final_counter: u64,
    pub ordered_merkle_root: NodeId,
    pub prefix_tip: NodeId,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrefixAcknowledgment {
    pub commitment: PrefixCommitment,
    pub signer: AuthorityId,
    pub signature: Vec<u8>,
}

impl PrefixAcknowledgment {
    /// Creates detached evidence using the caller's authorized current key.
    /// A stable participant ID is not the current public key after rotation;
    /// authority resolution remains the caller's graph responsibility.
    pub fn create(
        context: PrefixContext,
        events: &[GraphEvent],
        signer: AuthorityId,
        key: &SigningKey,
    ) -> Result<Self, TraxError> {
        if key.verifying_key().is_weak() {
            return Err(TraxError::Crypto);
        }
        let commitment = prefix_commitment(context, events, &signer)?;
        let signature = ed25519_sign(key, &signing_bytes(&commitment, &signer)?);
        Ok(Self {
            commitment,
            signer,
            signature,
        })
    }

    /// Verifies against external context, events, signer identity and trusted
    /// verification key. Success alone never advances a committed DAG tip.
    pub fn verify(
        &self,
        expected: &PrefixContext,
        events: &[GraphEvent],
        expected_signer: &AuthorityId,
        key: &VerifyingKey,
    ) -> Result<(), TraxError> {
        if self.commitment.context != *expected {
            return Err(TraxError::GraphContextMismatch);
        }
        if self.signer != *expected_signer {
            return Err(TraxError::SignerMismatch);
        }
        if key.is_weak() {
            return Err(TraxError::Crypto);
        }
        let recomputed = prefix_commitment(*expected, events, expected_signer)?;
        if self.commitment != recomputed {
            return Err(TraxError::GraphContextMismatch);
        }
        if !ed25519_verify(
            key,
            &signing_bytes(&self.commitment, &self.signer)?,
            &self.signature,
        ) {
            return Err(TraxError::BadSignature);
        }
        Ok(())
    }

    pub fn node_id(&self) -> Result<NodeId, TraxError> {
        domain_hash(
            self.commitment.context.config,
            ACK_ID_DOMAIN,
            &encode_deterministic(self)?,
        )
    }
}

fn signing_bytes(
    commitment: &PrefixCommitment,
    signer: &AuthorityId,
) -> Result<Vec<u8>, TraxError> {
    let mut bytes = ACK_DOMAIN.to_vec();
    bytes.extend_from_slice(&encode_deterministic(&(commitment, signer))?);
    Ok(bytes)
}

fn prefix_commitment(
    context: PrefixContext,
    events: &[GraphEvent],
    signer: &AuthorityId,
) -> Result<PrefixCommitment, TraxError> {
    context.config.validate()?;
    let k = context.config.k();
    if k < 5 {
        return Err(TraxError::InvalidInput(
            "prefix acknowledgment requires K >= 5",
        ));
    }
    if events.len() != k - 1 {
        return Err(TraxError::InvalidSegmentSize);
    }
    for (index, event) in events.iter().enumerate() {
        if event.version != 2
            || event.dag_id != context.dag_id
            || event.config != context.config
            || event.configuration_tip != context.configuration_tip
        {
            return Err(TraxError::GraphContextMismatch);
        }
        let expected = context
            .first_counter
            .checked_add(u64::try_from(index).map_err(|_| TraxError::ArithmeticOverflow)?)
            .ok_or(TraxError::ArithmeticOverflow)?;
        if event.counter != expected {
            return Err(TraxError::CounterDiscontinuity);
        }
    }
    let last = &events[events.len() - 1];
    if !matches!(last.operation, GraphOperation::Acknowledge { proposal } if proposal == context.proposal)
        || last.branch != context.branch
    {
        return Err(TraxError::GraphContextMismatch);
    }
    if last.author != signer.participant || last.key_epoch != signer.key_epoch {
        return Err(TraxError::SignerMismatch);
    }
    let expected_final_counter = last
        .counter
        .checked_add(1)
        .ok_or(TraxError::ArithmeticOverflow)?;
    let encoded = events
        .iter()
        .map(encode_deterministic)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(PrefixCommitment {
        context,
        prefix_len: u32::try_from(events.len()).map_err(|_| TraxError::ArithmeticOverflow)?,
        last_counter: last.counter,
        expected_final_counter,
        ordered_merkle_root: merkle_root_for_count(context.config, k - 1, &encoded)?,
        prefix_tip: last.node_id()?,
    })
}
