//! Legacy wire containers. Operational current-key rotation validation and
//! fork creation are implemented by `crate::graph::PendingSegment::rotate`.
#[derive(Debug, Clone)]
pub struct RotationProof<'a> {
    pub new_pubkey: &'a [u8],
    pub signed_by_old: &'a [u8],
}

#[derive(Default)]
pub enum QuarantineState {
    #[default]
    Normal,
    Quarantined,
}
