//! Key rotation & compromise handling per §6.1
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
