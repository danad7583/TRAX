//! Shared immutable history with an explicit negotiated cadence. Either
//! participant can seal an ordinary full segment. Transition and close exchanges
//! bind a peer's prefix acknowledgment to the initiator's final checkpoint.
use crate::crypto::{ed25519_sign, ed25519_verify};
use crate::encoding::encode_deterministic;
use crate::exchange::{PrefixAcknowledgment, PrefixContext};
use crate::profile::{domain_hash, merkle_root};
use crate::{ProtocolConfig, TraxError};
use ed25519_dalek::{SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub type NodeId = [u8; 32];
pub type BranchId = [u8; 32];
pub type ParticipantId = [u8; 32];
const VERSION: u8 = 2;

fn digest<T: Serialize>(
    config: ProtocolConfig,
    domain: &[u8],
    value: &T,
) -> Result<NodeId, TraxError> {
    domain_hash(config, domain, &encode_deterministic(value)?)
}
fn signing_bytes<T: Serialize>(domain: &[u8], value: &T) -> Result<Vec<u8>, TraxError> {
    let mut bytes = domain.to_vec();
    bytes.extend_from_slice(&encode_deterministic(value)?);
    Ok(bytes)
}
/// Initial public key, stable across key and hash-algorithm rotations.
pub fn participant_id(initial_public_key: &[u8; 32]) -> ParticipantId {
    *initial_public_key
}
fn check_key(bytes: &[u8; 32]) -> Result<VerifyingKey, TraxError> {
    let key = VerifyingKey::from_bytes(bytes).map_err(|_| TraxError::Crypto)?;
    if key.is_weak() {
        return Err(TraxError::Crypto);
    }
    Ok(key)
}

/// The host's authenticated negotiation result. Both ends agree on these keys,
/// nonce, K, signing algorithm and hash algorithm before constructing the DAG.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PairGenesis {
    pub version: u8,
    pub config: ProtocolConfig,
    pub relationship_nonce: [u8; 32],
    pub initial_public_keys: [[u8; 32]; 2],
}
impl PairGenesis {
    pub fn new(
        config: ProtocolConfig,
        relationship_nonce: [u8; 32],
        first: &VerifyingKey,
        second: &VerifyingKey,
    ) -> Result<Self, TraxError> {
        config.validate()?;
        check_key(&first.to_bytes())?;
        check_key(&second.to_bytes())?;
        let mut keys = [first.to_bytes(), second.to_bytes()];
        keys.sort();
        if keys[0] == keys[1] {
            return Err(TraxError::InvalidInput(
                "participants must have distinct keys",
            ));
        }
        Ok(Self {
            version: VERSION,
            config,
            relationship_nonce,
            initial_public_keys: keys,
        })
    }
    pub fn node_id(&self) -> Result<NodeId, TraxError> {
        digest(self.config, b"TRAX:PAIR-GENESIS:V2\0", self)
    }
}

/// Only one structural parent; no merge operation exists.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum GraphOperation {
    Append {
        payload: Vec<u8>,
    },
    Fork {
        payload: Vec<u8>,
    },
    Rotate {
        new_public_key: [u8; 32],
    },
    Configure {
        new_config: ProtocolConfig,
    },
    CloseRequest,
    Acknowledge {
        proposal: NodeId,
    },
    CloseConfirm {
        proposal: NodeId,
        acknowledgment: NodeId,
    },
    Padding,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GraphEvent {
    pub version: u8,
    pub dag_id: NodeId,
    pub config: ProtocolConfig,
    pub configuration_tip: NodeId,
    pub branch: BranchId,
    pub parent: NodeId,
    /// Structural depth; sibling branches may share depths.
    pub sequence: u64,
    /// Shared insertion order across participants and branches.
    pub counter: u64,
    pub author: ParticipantId,
    pub key_epoch: u64,
    pub authority_tip: NodeId,
    pub operation: GraphOperation,
    /// Only Rotate/Configure have a per-event current-key authorization.
    pub authorization: Option<Vec<u8>>,
    /// Rotation additionally proves possession of the replacement private key.
    pub new_key_signature: Option<Vec<u8>>,
}
impl GraphEvent {
    pub fn node_id(&self) -> Result<NodeId, TraxError> {
        digest(self.config, b"TRAX:GRAPH-EVENT:V2\0", self)
    }
    pub fn authorization_signing_bytes(&self) -> Result<Vec<u8>, TraxError> {
        let mut unsigned = self.clone();
        unsigned.authorization = None;
        unsigned.new_key_signature = None;
        signing_bytes(b"TRAX:GRAPH-TRANSITION:V2\0", &unsigned)
    }
    pub fn new_key_signing_bytes(&self) -> Result<Vec<u8>, TraxError> {
        let mut unsigned = self.clone();
        unsigned.authorization = None;
        unsigned.new_key_signature = None;
        signing_bytes(b"TRAX:GRAPH-NEW-KEY:V2\0", &unsigned)
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GraphCommitment {
    pub version: u8,
    pub dag_id: NodeId,
    pub config: ProtocolConfig,
    pub configuration_tip: NodeId,
    pub segment_index: u64,
    pub previous_checkpoint: NodeId,
    pub first_counter: u64,
    pub last_counter: u64,
    pub ordered_merkle_root: NodeId,
    pub final_event: NodeId,
    pub session_closing: bool,
    pub acknowledgment_hash: Option<NodeId>,
}
impl GraphCommitment {
    /// Excludes the signer: either end can attest the same checkpoint identity.
    pub fn checkpoint_id(&self) -> Result<NodeId, TraxError> {
        digest(self.config, b"TRAX:GRAPH-CHECKPOINT-ID:V2\0", self)
    }
    pub fn sign(
        &self,
        signer: AuthorityId,
        key: &SigningKey,
    ) -> Result<CheckpointAttestation, TraxError> {
        let bytes = signing_bytes(b"TRAX:GRAPH-CHECKPOINT:V2\0", &(self, &signer))?;
        Ok(CheckpointAttestation {
            commitment: self.clone(),
            signer,
            signature: ed25519_sign(key, &bytes),
        })
    }
}
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityId {
    pub participant: ParticipantId,
    pub key_epoch: u64,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CheckpointAttestation {
    pub commitment: GraphCommitment,
    pub signer: AuthorityId,
    pub signature: Vec<u8>,
}
impl CheckpointAttestation {
    pub fn signing_bytes(&self) -> Result<Vec<u8>, TraxError> {
        signing_bytes(
            b"TRAX:GRAPH-CHECKPOINT:V2\0",
            &(&self.commitment, &self.signer),
        )
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GraphSegmentProof {
    pub events: Vec<GraphEvent>,
    pub checkpoint: CheckpointAttestation,
    pub acknowledgment: Option<PrefixAcknowledgment>,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParticipantAuthority {
    pub participant: ParticipantId,
    pub key_epoch: u64,
    pub public_key: [u8; 32],
    pub rotation_tip: NodeId,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyIdentity {
    pub authority: AuthorityId,
    pub is_current: bool,
}
#[derive(Debug, Clone)]
struct CheckpointRecord {
    proof_index: usize,
    eligible_keys: BTreeMap<AuthorityId, [u8; 32]>,
    attestations: BTreeMap<AuthorityId, CheckpointAttestation>,
}

/// Accepted history has no mutation/delete API. Unsigned events can be used in
/// PendingSegment while a session proceeds, without advancing trusted history.
#[derive(Debug, Clone)]
pub struct PairDag {
    config: ProtocolConfig,
    configuration_tip: NodeId,
    genesis: PairGenesis,
    genesis_id: NodeId,
    main_branch: BranchId,
    nodes: BTreeMap<NodeId, GraphEvent>,
    children: BTreeMap<NodeId, Vec<NodeId>>,
    branches: BTreeMap<BranchId, NodeId>,
    origins: BTreeMap<BranchId, NodeId>,
    authorities: BTreeMap<ParticipantId, ParticipantAuthority>,
    historical_keys: BTreeMap<[u8; 32], AuthorityId>,
    checkpoint_tip: NodeId,
    event_count: u64,
    proofs: Vec<GraphSegmentProof>,
    checkpoints: BTreeMap<NodeId, CheckpointRecord>,
    event_checkpoints: BTreeMap<NodeId, NodeId>,
}
pub(crate) struct PreparedCommit {
    base_checkpoint: NodeId,
    proof: GraphSegmentProof,
    ids: Vec<NodeId>,
    checkpoint_id: NodeId,
    eligible_keys: BTreeMap<AuthorityId, [u8; 32]>,
    new_config: Option<(NodeId, ProtocolConfig)>,
    event_count: u64,
}
impl PairDag {
    pub fn from_verified_genesis(
        config: ProtocolConfig,
        genesis: PairGenesis,
    ) -> Result<Self, TraxError> {
        config.validate()?;
        if genesis.version != VERSION || genesis.config != config {
            return Err(TraxError::GraphContextMismatch);
        }
        if genesis.initial_public_keys[0] >= genesis.initial_public_keys[1] {
            return Err(TraxError::InvalidInput(
                "genesis keys must be distinct and sorted",
            ));
        }
        let genesis_id = genesis.node_id()?;
        let main_branch = digest(config, b"TRAX:MAIN-BRANCH:V2\0", &genesis_id)?;
        let mut authorities = BTreeMap::new();
        let mut historical_keys = BTreeMap::new();
        for key in genesis.initial_public_keys {
            check_key(&key)?;
            let participant = participant_id(&key);
            authorities.insert(
                participant,
                ParticipantAuthority {
                    participant,
                    key_epoch: 0,
                    public_key: key,
                    rotation_tip: genesis_id,
                },
            );
            historical_keys.insert(
                key,
                AuthorityId {
                    participant,
                    key_epoch: 0,
                },
            );
        }
        Ok(Self {
            config,
            configuration_tip: genesis_id,
            genesis,
            genesis_id,
            main_branch,
            nodes: BTreeMap::new(),
            children: BTreeMap::from([(genesis_id, vec![])]),
            branches: BTreeMap::from([(main_branch, genesis_id)]),
            origins: BTreeMap::from([(main_branch, genesis_id)]),
            authorities,
            historical_keys,
            checkpoint_tip: genesis_id,
            event_count: 0,
            proofs: vec![],
            checkpoints: BTreeMap::new(),
            event_checkpoints: BTreeMap::new(),
        })
    }
    pub fn config(&self) -> ProtocolConfig {
        self.config
    }
    pub fn configuration_tip(&self) -> NodeId {
        self.configuration_tip
    }
    pub fn genesis(&self) -> &PairGenesis {
        &self.genesis
    }
    pub fn genesis_id(&self) -> NodeId {
        self.genesis_id
    }
    pub fn main_branch(&self) -> BranchId {
        self.main_branch
    }
    pub fn checkpoint_tip(&self) -> NodeId {
        self.checkpoint_tip
    }
    pub fn segment_index(&self) -> u64 {
        self.proofs.len() as u64
    }
    pub fn event_count(&self) -> u64 {
        self.event_count
    }
    /// Includes genesis.
    pub fn len(&self) -> usize {
        self.nodes.len() + 1
    }
    pub fn is_empty(&self) -> bool {
        false
    }
    pub fn proofs(&self) -> &[GraphSegmentProof] {
        &self.proofs
    }
    pub fn node(&self, id: &NodeId) -> Option<&GraphEvent> {
        self.nodes.get(id)
    }
    pub fn contains(&self, id: &NodeId) -> bool {
        *id == self.genesis_id || self.nodes.contains_key(id)
    }
    pub fn authority(&self, id: &ParticipantId) -> Option<&ParticipantAuthority> {
        self.authorities.get(id)
    }
    pub fn identify_key(&self, key: &[u8; 32]) -> Option<KeyIdentity> {
        let authority = self.historical_keys.get(key)?.clone();
        let is_current = self.authority(&authority.participant)?.key_epoch == authority.key_epoch;
        Some(KeyIdentity {
            authority,
            is_current,
        })
    }
    pub fn branch_tip(&self, branch: &BranchId) -> Result<NodeId, TraxError> {
        self.branches
            .get(branch)
            .copied()
            .ok_or(TraxError::UnknownBranch)
    }
    pub fn branch_origin(&self, branch: &BranchId) -> Result<NodeId, TraxError> {
        self.origins
            .get(branch)
            .copied()
            .ok_or(TraxError::UnknownBranch)
    }
    pub fn branches(&self) -> impl Iterator<Item = (&BranchId, &NodeId)> {
        self.branches.iter()
    }
    pub fn parent(&self, id: &NodeId) -> Result<Option<NodeId>, TraxError> {
        if *id == self.genesis_id {
            return Ok(None);
        }
        self.node(id)
            .map(|node| Some(node.parent))
            .ok_or(TraxError::UnknownNode)
    }
    pub fn children(&self, id: &NodeId) -> Result<&[NodeId], TraxError> {
        self.children
            .get(id)
            .map(Vec::as_slice)
            .ok_or(TraxError::UnknownNode)
    }
    pub fn ancestors(&self, id: &NodeId) -> Result<Vec<NodeId>, TraxError> {
        let mut result = vec![*id];
        let mut cursor = *id;
        while let Some(parent) = self.parent(&cursor)? {
            result.push(parent);
            cursor = parent;
        }
        Ok(result)
    }
    pub fn begin_segment(&self) -> PendingSegment<'_> {
        let eligible_keys = self
            .authorities
            .values()
            .map(|a| {
                (
                    AuthorityId {
                        participant: a.participant,
                        key_epoch: a.key_epoch,
                    },
                    a.public_key,
                )
            })
            .collect();
        PendingSegment {
            base: self,
            events: vec![],
            node_indexes: BTreeMap::new(),
            branch_tips: BTreeMap::new(),
            authorities: self.authorities.clone(),
            new_keys: BTreeMap::new(),
            eligible_keys,
            new_config: None,
            proposal: None,
            acknowledgment: None,
        }
    }
    pub fn verify_and_commit(
        &mut self,
        proof: &GraphSegmentProof,
    ) -> Result<Vec<NodeId>, TraxError> {
        let prepared = self.prepare_commit(proof)?;
        Ok(self.commit_prepared(prepared))
    }
    pub(crate) fn prepare_commit(
        &self,
        proof: &GraphSegmentProof,
    ) -> Result<PreparedCommit, TraxError> {
        let mut pending = self.begin_segment();
        for event in &proof.events {
            if pending.events.len() == pending.effective_config().k() - 1 {
                if let Some(acknowledgment) = &proof.acknowledgment {
                    pending.accept_ack(acknowledgment)?;
                }
            }
            pending.stage(event.clone())?;
        }
        if proof.acknowledgment != pending.acknowledgment {
            return Err(TraxError::GraphContextMismatch);
        }
        if proof.checkpoint.commitment != pending.commitment()? {
            return Err(TraxError::GraphContextMismatch);
        }
        let eligible_keys = pending.checkpoint_keys()?;
        verify_attestation(&proof.checkpoint, &eligible_keys)?;
        let checkpoint_id = proof.checkpoint.commitment.checkpoint_id()?;
        self.segment_index()
            .checked_add(1)
            .ok_or(TraxError::ArithmeticOverflow)?;
        let event_count = self
            .event_count
            .checked_add(proof.events.len() as u64)
            .ok_or(TraxError::ArithmeticOverflow)?;
        let ids = pending
            .events
            .iter()
            .map(GraphEvent::node_id)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(PreparedCommit {
            base_checkpoint: self.checkpoint_tip,
            proof: proof.clone(),
            ids,
            checkpoint_id,
            eligible_keys,
            new_config: pending.new_config,
            event_count,
        })
    }
    pub(crate) fn commit_prepared(&mut self, prepared: PreparedCommit) -> Vec<NodeId> {
        assert_eq!(
            self.checkpoint_tip, prepared.base_checkpoint,
            "private transaction must not outlive its base state"
        );
        for (id, event) in prepared.ids.iter().zip(&prepared.proof.events) {
            self.children.entry(event.parent).or_default().push(*id);
            self.children.insert(*id, vec![]);
            self.branches.insert(event.branch, *id);
            if matches!(
                event.operation,
                GraphOperation::Fork { .. }
                    | GraphOperation::Rotate { .. }
                    | GraphOperation::Configure { .. }
            ) {
                self.origins.insert(event.branch, event.parent);
            }
            if let GraphOperation::Rotate { new_public_key } = event.operation {
                let authority = self
                    .authorities
                    .get_mut(&event.author)
                    .expect("validated participant");
                authority.key_epoch += 1;
                authority.public_key = new_public_key;
                authority.rotation_tip = *id;
                self.historical_keys.insert(
                    new_public_key,
                    AuthorityId {
                        participant: event.author,
                        key_epoch: authority.key_epoch,
                    },
                );
            }
            self.nodes.insert(*id, event.clone());
            self.event_checkpoints.insert(*id, prepared.checkpoint_id);
        }
        if let Some((id, config)) = prepared.new_config {
            self.config = config;
            self.configuration_tip = id;
        }
        self.checkpoints.insert(
            prepared.checkpoint_id,
            CheckpointRecord {
                proof_index: self.proofs.len(),
                eligible_keys: prepared.eligible_keys,
                attestations: BTreeMap::from([(
                    prepared.proof.checkpoint.signer.clone(),
                    prepared.proof.checkpoint.clone(),
                )]),
            },
        );
        self.checkpoint_tip = prepared.checkpoint_id;
        self.event_count = prepared.event_count;
        self.proofs.push(prepared.proof);
        prepared.ids
    }
    /// Fetch a participant's known checkpoint proof covering this event.
    pub fn checkpoint_for(
        &self,
        participant: &ParticipantId,
        event: &NodeId,
    ) -> Option<&CheckpointAttestation> {
        let checkpoint = self.checkpoints.get(self.event_checkpoints.get(event)?)?;
        checkpoint
            .attestations
            .values()
            .find(|a| &a.signer.participant == participant)
    }
    pub fn attestations(&self) -> impl Iterator<Item = &CheckpointAttestation> {
        self.checkpoints
            .values()
            .flat_map(|c| c.attestations.values())
    }
    /// The peer's committed K-1 prefix agreement for a transition/close proposal.
    pub fn acknowledgment_for(&self, proposal: &NodeId) -> Option<&PrefixAcknowledgment> {
        let checkpoint = self
            .checkpoints
            .get(self.event_checkpoints.get(proposal)?)?;
        self.proofs
            .get(checkpoint.proof_index)?
            .acknowledgment
            .as_ref()
            .filter(|acknowledgment| &acknowledgment.commitment.context.proposal == proposal)
    }
    /// Historical proof verification does not grant authority for new extensions.
    pub fn record_attestation(
        &mut self,
        attestation: &CheckpointAttestation,
    ) -> Result<(), TraxError> {
        self.verify_recorded_attestation(attestation)?;
        self.commit_attestation(attestation.clone());
        Ok(())
    }
    pub(crate) fn verify_recorded_attestation(
        &self,
        attestation: &CheckpointAttestation,
    ) -> Result<(), TraxError> {
        let id = attestation.commitment.checkpoint_id()?;
        let record = self.checkpoints.get(&id).ok_or(TraxError::UnknownNode)?;
        if self.proofs[record.proof_index].checkpoint.commitment != attestation.commitment {
            return Err(TraxError::GraphContextMismatch);
        }
        verify_attestation(attestation, &record.eligible_keys)
    }
    pub(crate) fn commit_attestation(&mut self, attestation: CheckpointAttestation) {
        let id = attestation
            .commitment
            .checkpoint_id()
            .expect("previously validated checkpoint");
        self.checkpoints
            .get_mut(&id)
            .expect("previously validated checkpoint")
            .attestations
            .insert(attestation.signer.clone(), attestation);
    }
    pub fn verify_history(&self) -> Result<(), TraxError> {
        let mut verified = Self::from_verified_genesis(self.genesis.config, self.genesis.clone())?;
        for proof in &self.proofs {
            verified.verify_and_commit(proof)?;
        }
        for attestation in self.attestations() {
            verified.record_attestation(attestation)?;
        }
        Ok(())
    }
}
fn verify_attestation(
    attestation: &CheckpointAttestation,
    eligible: &BTreeMap<AuthorityId, [u8; 32]>,
) -> Result<(), TraxError> {
    let key = eligible.get(&attestation.signer).ok_or_else(|| {
        if eligible.keys().any(|id| {
            id.participant == attestation.signer.participant
                && id.key_epoch > attestation.signer.key_epoch
        }) {
            TraxError::RetiredKey
        } else {
            TraxError::AuthorityMismatch
        }
    })?;
    if !ed25519_verify(
        &check_key(key)?,
        &attestation.signing_bytes()?,
        &attestation.signature,
    ) {
        return Err(TraxError::SegmentSignatureFailure);
    }
    Ok(())
}

/// Only candidate events and changed tips are staged. Cloning this overlay
/// copies at most the current segment; the immutable base history stays borrowed.
#[derive(Clone)]
pub struct PendingSegment<'a> {
    base: &'a PairDag,
    events: Vec<GraphEvent>,
    node_indexes: BTreeMap<NodeId, usize>,
    branch_tips: BTreeMap<BranchId, NodeId>,
    authorities: BTreeMap<ParticipantId, ParticipantAuthority>,
    new_keys: BTreeMap<[u8; 32], AuthorityId>,
    eligible_keys: BTreeMap<AuthorityId, [u8; 32]>,
    new_config: Option<(NodeId, ProtocolConfig)>,
    proposal: Option<Proposal>,
    acknowledgment: Option<PrefixAcknowledgment>,
}

#[derive(Clone, Copy)]
enum ProposalKind {
    Rotation,
    Configuration,
    Close,
}

#[derive(Clone)]
struct Proposal {
    id: NodeId,
    initiator: ParticipantId,
    branch: BranchId,
    kind: ProposalKind,
}

impl PendingSegment<'_> {
    pub fn events(&self) -> &[GraphEvent] {
        &self.events
    }
    /// A validated first-event configuration proposal selects the profile for
    /// its entire transition batch, before becoming the live graph profile.
    pub fn effective_config(&self) -> ProtocolConfig {
        self.new_config
            .map(|(_, config)| config)
            .unwrap_or(self.base.config)
    }
    pub fn is_complete(&self) -> bool {
        self.events.len() == self.effective_config().k()
    }

    pub fn append(
        &mut self,
        author: ParticipantId,
        branch: BranchId,
        payload: Vec<u8>,
    ) -> Result<NodeId, TraxError> {
        let parent = self.branch_tip(&branch)?;
        let event = self.candidate(author, branch, parent, GraphOperation::Append { payload })?;
        self.stage(event)
    }
    pub fn fork(
        &mut self,
        author: ParticipantId,
        parent: NodeId,
        branch: BranchId,
        payload: Vec<u8>,
    ) -> Result<NodeId, TraxError> {
        let event = self.candidate(author, branch, parent, GraphOperation::Fork { payload })?;
        self.stage(event)
    }
    /// Starts a fresh transition branch. Both identity continuity and possession
    /// of the new private key are independently proven before provisional use.
    pub fn rotate(
        &mut self,
        author: ParticipantId,
        parent: NodeId,
        branch: BranchId,
        old_key: &SigningKey,
        new_key: &SigningKey,
    ) -> Result<NodeId, TraxError> {
        let mut event = self.candidate(
            author,
            branch,
            parent,
            GraphOperation::Rotate {
                new_public_key: new_key.verifying_key().to_bytes(),
            },
        )?;
        event.authorization = Some(ed25519_sign(old_key, &event.authorization_signing_bytes()?));
        event.new_key_signature = Some(ed25519_sign(new_key, &event.new_key_signing_bytes()?));
        self.stage(event)
    }
    /// The proposal itself and its complete bilateral exchange use the proposed
    /// new K/hash profile; activation of the live graph waits for final admission.
    pub fn configure(
        &mut self,
        author: ParticipantId,
        parent: NodeId,
        branch: BranchId,
        new_config: ProtocolConfig,
        key: &SigningKey,
    ) -> Result<NodeId, TraxError> {
        new_config.validate()?;
        let mut event = self.candidate(
            author,
            branch,
            parent,
            GraphOperation::Configure { new_config },
        )?;
        event.config = new_config;
        event.authorization = Some(ed25519_sign(key, &event.authorization_signing_bytes()?));
        self.stage(event)
    }
    /// A close proposal reserves its own slot, the peer's K-1 ACK and the
    /// initiator's final decision. It does not irreversibly close the session.
    pub fn request_close(
        &mut self,
        author: ParticipantId,
        branch: BranchId,
    ) -> Result<NodeId, TraxError> {
        let parent = self.branch_tip(&branch)?;
        let event = self.candidate(author, branch, parent, GraphOperation::CloseRequest)?;
        self.stage(event)
    }
    /// Fills unused peer slots, records the K-1 ACK and signs the exact prefix.
    /// A failed multi-record operation leaves the original overlay unchanged.
    pub fn acknowledge_and_pad(
        &mut self,
        peer: ParticipantId,
        key: &SigningKey,
    ) -> Result<PrefixAcknowledgment, TraxError> {
        let proposal = self
            .proposal
            .clone()
            .ok_or(TraxError::InvalidInput("no open exchange proposal"))?;
        if peer != self.peer(&proposal)? {
            return Err(TraxError::SignerMismatch);
        }
        if self.acknowledgment.is_some() || self.events.len() >= self.effective_config().k() - 1 {
            return Err(TraxError::InvalidInput(
                "prefix acknowledgment is already staged",
            ));
        }
        let authority = self
            .authorities
            .get(&peer)
            .ok_or(TraxError::UnknownParticipant)?;
        if key.verifying_key().to_bytes() != authority.public_key {
            return Err(TraxError::BadSignature);
        }
        let signer = AuthorityId {
            participant: peer,
            key_epoch: authority.key_epoch,
        };
        let mut draft = self.clone();
        while draft.events.len() < draft.effective_config().k() - 2 {
            let parent = draft.branch_tip(&proposal.branch)?;
            let event = draft.candidate(peer, proposal.branch, parent, GraphOperation::Padding)?;
            draft.stage(event)?;
        }
        let parent = draft.branch_tip(&proposal.branch)?;
        let event = draft.candidate(
            peer,
            proposal.branch,
            parent,
            GraphOperation::Acknowledge {
                proposal: proposal.id,
            },
        )?;
        draft.stage(event)?;
        let acknowledgment =
            PrefixAcknowledgment::create(draft.prefix_context()?, &draft.events, signer, key)?;
        draft.accept_ack(&acknowledgment)?;
        *self = draft;
        Ok(acknowledgment)
    }
    /// A detached ACK is meaningful only for this exact staged K-1 prefix.
    /// It never admits those provisional records.
    pub fn accept_ack(&mut self, acknowledgment: &PrefixAcknowledgment) -> Result<(), TraxError> {
        let proposal = self
            .proposal
            .as_ref()
            .ok_or(TraxError::InvalidInput("no open exchange proposal"))?;
        if self.events.len() != self.effective_config().k() - 1 {
            return Err(TraxError::InvalidInput(
                "acknowledgment requires the exact K-1 prefix",
            ));
        }
        let peer = self.peer(proposal)?;
        let authority = self
            .authorities
            .get(&peer)
            .ok_or(TraxError::UnknownParticipant)?;
        let signer = AuthorityId {
            participant: peer,
            key_epoch: authority.key_epoch,
        };
        acknowledgment.verify(
            &self.prefix_context()?,
            &self.events,
            &signer,
            &check_key(&authority.public_key)?,
        )?;
        if self
            .acknowledgment
            .as_ref()
            .is_some_and(|prior| prior != acknowledgment)
        {
            return Err(TraxError::GraphContextMismatch);
        }
        self.acknowledgment = Some(acknowledgment.clone());
        Ok(())
    }
    /// The initiator can confirm closure, or append a real request in this same
    /// final slot instead. The final checkpoint authenticates that choice.
    pub fn finish_close(&mut self) -> Result<NodeId, TraxError> {
        let proposal = self
            .proposal
            .clone()
            .ok_or(TraxError::InvalidInput("no open exchange proposal"))?;
        let acknowledgment = self
            .acknowledgment
            .as_ref()
            .ok_or(TraxError::InvalidInput("peer acknowledgment is required"))?
            .node_id()?;
        let parent = self.branch_tip(&proposal.branch)?;
        let event = self.candidate(
            proposal.initiator,
            proposal.branch,
            parent,
            GraphOperation::CloseConfirm {
                proposal: proposal.id,
                acknowledgment,
            },
        )?;
        self.stage(event)
    }
    fn peer(&self, proposal: &Proposal) -> Result<ParticipantId, TraxError> {
        self.authorities
            .keys()
            .copied()
            .find(|id| *id != proposal.initiator)
            .ok_or(TraxError::UnknownParticipant)
    }
    fn prefix_context(&self) -> Result<PrefixContext, TraxError> {
        let proposal = self
            .proposal
            .as_ref()
            .ok_or(TraxError::InvalidInput("no open exchange proposal"))?;
        Ok(PrefixContext {
            dag_id: self.base.genesis_id,
            config: self.effective_config(),
            configuration_tip: self.base.configuration_tip,
            previous_checkpoint: self.base.checkpoint_tip,
            segment_index: self.base.segment_index(),
            proposal: proposal.id,
            branch: proposal.branch,
            first_counter: self
                .base
                .event_count
                .checked_add(1)
                .ok_or(TraxError::ArithmeticOverflow)?,
        })
    }
    fn node(&self, id: &NodeId) -> Option<&GraphEvent> {
        self.node_indexes
            .get(id)
            .map(|i| &self.events[*i])
            .or_else(|| self.base.node(id))
    }
    fn branch_tip(&self, branch: &BranchId) -> Result<NodeId, TraxError> {
        self.branch_tips
            .get(branch)
            .or_else(|| self.base.branches.get(branch))
            .copied()
            .ok_or(TraxError::UnknownBranch)
    }
    fn candidate(
        &self,
        author: ParticipantId,
        branch: BranchId,
        parent: NodeId,
        operation: GraphOperation,
    ) -> Result<GraphEvent, TraxError> {
        let authority = self
            .authorities
            .get(&author)
            .ok_or(TraxError::UnknownParticipant)?;
        Ok(GraphEvent {
            version: VERSION,
            dag_id: self.base.genesis_id,
            config: self.effective_config(),
            configuration_tip: self.base.configuration_tip,
            branch,
            parent,
            sequence: self.next_sequence(&parent)?,
            counter: self.next_counter()?,
            author,
            key_epoch: authority.key_epoch,
            authority_tip: authority.rotation_tip,
            operation,
            authorization: None,
            new_key_signature: None,
        })
    }
    fn next_sequence(&self, parent: &NodeId) -> Result<u64, TraxError> {
        if *parent == self.base.genesis_id {
            return Ok(1);
        }
        self.node(parent)
            .ok_or(TraxError::UnknownNode)?
            .sequence
            .checked_add(1)
            .ok_or(TraxError::ArithmeticOverflow)
    }
    fn next_counter(&self) -> Result<u64, TraxError> {
        self.base
            .event_count
            .checked_add(self.events.len() as u64)
            .and_then(|v| v.checked_add(1))
            .ok_or(TraxError::ArithmeticOverflow)
    }
    /// Returns an opening proposal kind, or validates the allowed next action
    /// for an existing exchange without modifying provisional state.
    fn validate_flow(&self, event: &GraphEvent) -> Result<Option<ProposalKind>, TraxError> {
        let k = event.config.k();
        if let Some(proposal) = &self.proposal {
            if event.branch != proposal.branch {
                return Err(TraxError::InvalidInput(
                    "exchange events must remain on the proposal branch",
                ));
            }
            if self.events.len() == k - 1 {
                let acknowledgment =
                    self.acknowledgment.as_ref().ok_or(TraxError::InvalidInput(
                        "peer prefix acknowledgment is required before the final event",
                    ))?;
                if event.author != proposal.initiator {
                    return Err(TraxError::SignerMismatch);
                }
                match event.operation {
                    GraphOperation::Append { .. } => {}
                    GraphOperation::CloseConfirm {
                        proposal: id,
                        acknowledgment: hash,
                    } if id == proposal.id && hash == acknowledgment.node_id()? => {}
                    _ => {
                        return Err(TraxError::InvalidInput(
                            "the final event must be the initiator's request or close confirmation",
                        ))
                    }
                }
            } else {
                if event.author != self.peer(proposal)? {
                    return Err(TraxError::SignerMismatch);
                }
                if self.events.len() == k - 2 {
                    if !matches!(event.operation, GraphOperation::Acknowledge { proposal: id } if id == proposal.id)
                    {
                        return Err(TraxError::InvalidInput(
                            "the peer acknowledgment must occupy K-1",
                        ));
                    }
                } else if !matches!(
                    event.operation,
                    GraphOperation::Append { .. } | GraphOperation::Padding
                ) {
                    return Err(TraxError::InvalidInput(
                        "only peer records or filler may precede acknowledgment",
                    ));
                }
            }
            return Ok(None);
        }
        match event.operation {
            GraphOperation::Rotate { .. } | GraphOperation::Configure { .. } => {
                if !self.events.is_empty() {
                    return Err(TraxError::InvalidInput(
                        "transitions must begin a fresh segment",
                    ));
                }
                if k < 5 {
                    return Err(TraxError::InvalidInput("an exchange requires K >= 5"));
                }
                Ok(Some(
                    if matches!(event.operation, GraphOperation::Rotate { .. }) {
                        ProposalKind::Rotation
                    } else {
                        ProposalKind::Configuration
                    },
                ))
            }
            GraphOperation::CloseRequest => {
                if k - self.events.len() < 3 {
                    return Err(TraxError::InvalidInput(
                        "close proposal needs three remaining slots",
                    ));
                }
                Ok(Some(ProposalKind::Close))
            }
            GraphOperation::Append { .. } | GraphOperation::Fork { .. } => Ok(None),
            _ => Err(TraxError::InvalidInput(
                "control records require an open exchange",
            )),
        }
    }
    pub fn stage(&mut self, event: GraphEvent) -> Result<NodeId, TraxError> {
        if self.is_complete() {
            return Err(TraxError::SegmentAlreadySealed);
        }
        let expected_config = if self.events.is_empty() {
            match event.operation {
                GraphOperation::Configure { new_config } => new_config,
                _ => self.effective_config(),
            }
        } else {
            self.effective_config()
        };
        expected_config.validate()?;
        if event.version != VERSION
            || event.dag_id != self.base.genesis_id
            || event.config != expected_config
            || event.configuration_tip != self.base.configuration_tip
        {
            return Err(TraxError::GraphContextMismatch);
        }
        let authority = self
            .authorities
            .get(&event.author)
            .ok_or(TraxError::UnknownParticipant)?;
        if event.key_epoch < authority.key_epoch {
            return Err(TraxError::RetiredKey);
        }
        if event.key_epoch != authority.key_epoch || event.authority_tip != authority.rotation_tip {
            return Err(TraxError::AuthorityMismatch);
        }
        if event.sequence != self.next_sequence(&event.parent)?
            || event.counter != self.next_counter()?
        {
            return Err(TraxError::CounterDiscontinuity);
        }
        let proposal_kind = self.validate_flow(&event)?;
        match event.operation {
            GraphOperation::Fork { .. }
            | GraphOperation::Rotate { .. }
            | GraphOperation::Configure { .. } => {
                if self.branch_tips.contains_key(&event.branch)
                    || self.base.branches.contains_key(&event.branch)
                {
                    return Err(TraxError::BranchExists);
                }
            }
            _ => {
                if self.branch_tip(&event.branch)? != event.parent {
                    return Err(TraxError::BranchTipMismatch);
                }
            }
        }
        if matches!(
            event.operation,
            GraphOperation::Rotate { .. } | GraphOperation::Configure { .. }
        ) {
            let signature = event
                .authorization
                .as_ref()
                .ok_or(TraxError::BadSignature)?;
            if !ed25519_verify(
                &check_key(&authority.public_key)?,
                &event.authorization_signing_bytes()?,
                signature,
            ) {
                return Err(TraxError::BadSignature);
            }
        } else if event.authorization.is_some() {
            return Err(TraxError::InvalidInput(
                "ordinary events must not carry transition authorization",
            ));
        }
        match &event.operation {
            GraphOperation::Rotate { new_public_key } => {
                let new_key = check_key(new_public_key)?;
                let possession = event
                    .new_key_signature
                    .as_ref()
                    .ok_or(TraxError::BadSignature)?;
                if !ed25519_verify(&new_key, &event.new_key_signing_bytes()?, possession) {
                    return Err(TraxError::BadSignature);
                }
                if self.base.historical_keys.contains_key(new_public_key)
                    || self.new_keys.contains_key(new_public_key)
                {
                    return Err(TraxError::KeyReuse);
                }
                authority
                    .key_epoch
                    .checked_add(1)
                    .ok_or(TraxError::ArithmeticOverflow)?;
            }
            _ if event.new_key_signature.is_some() => {
                return Err(TraxError::InvalidInput(
                    "only rotation may carry new-key possession proof",
                ))
            }
            _ => {}
        }
        let id = event.node_id()?;
        if self.node_indexes.contains_key(&id) || self.base.contains(&id) {
            return Err(TraxError::DuplicateNode);
        }
        // Every fallible check precedes mutation, including both rotation proofs.
        if let Some(kind) = proposal_kind {
            self.proposal = Some(Proposal {
                id,
                initiator: event.author,
                branch: event.branch,
                kind,
            });
        }
        if let GraphOperation::Rotate { new_public_key } = event.operation {
            let mut next = authority.clone();
            next.key_epoch += 1;
            next.public_key = new_public_key;
            next.rotation_tip = id;
            let identity = AuthorityId {
                participant: event.author,
                key_epoch: next.key_epoch,
            };
            self.new_keys.insert(new_public_key, identity.clone());
            self.eligible_keys.insert(identity, new_public_key);
            self.authorities.insert(event.author, next);
        }
        if let GraphOperation::Configure { new_config } = event.operation {
            self.new_config = Some((id, new_config));
        }
        self.branch_tips.insert(event.branch, id);
        self.node_indexes.insert(id, self.events.len());
        self.events.push(event);
        Ok(id)
    }
    fn checkpoint_keys(&self) -> Result<BTreeMap<AuthorityId, [u8; 32]>, TraxError> {
        if let Some(proposal) = &self.proposal {
            let current = self
                .authorities
                .get(&proposal.initiator)
                .ok_or(TraxError::UnknownParticipant)?;
            if matches!(proposal.kind, ProposalKind::Rotation)
                && current.rotation_tip != proposal.id
            {
                return Err(TraxError::AuthorityMismatch);
            }
            Ok(BTreeMap::from([(
                AuthorityId {
                    participant: current.participant,
                    key_epoch: current.key_epoch,
                },
                current.public_key,
            )]))
        } else {
            Ok(self.eligible_keys.clone())
        }
    }
    pub fn commitment(&self) -> Result<GraphCommitment, TraxError> {
        if !self.is_complete() {
            return Err(TraxError::IncompleteSegment);
        }
        if self.proposal.is_some() && self.acknowledgment.is_none() {
            return Err(TraxError::InvalidInput(
                "exchange checkpoint requires peer acknowledgment",
            ));
        }
        let config = self.effective_config();
        let encoded = self
            .events
            .iter()
            .map(encode_deterministic)
            .collect::<Result<Vec<_>, _>>()?;
        let first = &self.events[0];
        let last = &self.events[self.events.len() - 1];
        Ok(GraphCommitment {
            version: VERSION,
            dag_id: self.base.genesis_id,
            config,
            configuration_tip: self.base.configuration_tip,
            segment_index: self.base.segment_index(),
            previous_checkpoint: self.base.checkpoint_tip,
            first_counter: first.counter,
            last_counter: last.counter,
            ordered_merkle_root: merkle_root(config, &encoded)?,
            final_event: last.node_id()?,
            session_closing: matches!(last.operation, GraphOperation::CloseConfirm { .. }),
            acknowledgment_hash: self
                .acknowledgment
                .as_ref()
                .map(PrefixAcknowledgment::node_id)
                .transpose()?,
        })
    }
    pub fn proof(&self, checkpoint: CheckpointAttestation) -> Result<GraphSegmentProof, TraxError> {
        if checkpoint.commitment != self.commitment()? {
            return Err(TraxError::GraphContextMismatch);
        }
        Ok(GraphSegmentProof {
            events: self.events.clone(),
            checkpoint,
            acknowledgment: self.acknowledgment.clone(),
        })
    }
    /// Ordinary batches permit either participant. A transition/close exchange
    /// requires the initiator's final current key, including a new rotation key.
    pub fn seal(
        &self,
        participant: ParticipantId,
        key: &SigningKey,
    ) -> Result<GraphSegmentProof, TraxError> {
        let eligible = self.checkpoint_keys()?;
        let signer = eligible
            .iter()
            .find(|(id, bytes)| {
                id.participant == participant && **bytes == key.verifying_key().to_bytes()
            })
            .map(|(id, _)| id.clone())
            .ok_or_else(|| {
                if self
                    .base
                    .identify_key(&key.verifying_key().to_bytes())
                    .is_some_and(|id| !id.is_current)
                {
                    TraxError::RetiredKey
                } else {
                    TraxError::BadSignature
                }
            })?;
        self.proof(self.commitment()?.sign(signer, key)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{HashAlgorithm, SigningAlgorithm};

    fn fixture() -> (PairDag, SigningKey, SigningKey) {
        let a = SigningKey::from_bytes(&[1; 32]);
        let b = SigningKey::from_bytes(&[2; 32]);
        let config =
            ProtocolConfig::new(8, SigningAlgorithm::Ed25519, HashAlgorithm::Sha512256).unwrap();
        let genesis =
            PairGenesis::new(config, [3; 32], &a.verifying_key(), &b.verifying_key()).unwrap();
        (
            PairDag::from_verified_genesis(config, genesis).unwrap(),
            a,
            b,
        )
    }
    #[test]
    fn counter_overflow_never_stages_a_candidate() {
        let (mut dag, a, _) = fixture();
        dag.event_count = u64::MAX;
        let mut pending = dag.begin_segment();
        assert!(matches!(
            pending.append(
                participant_id(&a.verifying_key().to_bytes()),
                dag.main_branch(),
                vec![]
            ),
            Err(TraxError::ArithmeticOverflow)
        ));
        assert!(pending.events().is_empty());
        assert_eq!(dag.len(), 1);
    }
    #[test]
    fn acknowledge_padding_is_atomic_when_counter_arithmetic_overflows() {
        let (mut dag, a, b) = fixture();
        dag.event_count = u64::MAX - 3;
        let mut pending = dag.begin_segment();
        let proposal = pending
            .request_close(
                participant_id(&a.verifying_key().to_bytes()),
                dag.main_branch(),
            )
            .unwrap();
        let before = pending.events().to_vec();
        assert!(matches!(
            pending.acknowledge_and_pad(participant_id(&b.verifying_key().to_bytes()), &b),
            Err(TraxError::ArithmeticOverflow)
        ));
        assert_eq!(pending.events(), before);
        assert_eq!(pending.proposal.as_ref().unwrap().id, proposal);
        assert!(pending.acknowledgment.is_none());
    }
}
