//! Key rotation & compromise handling per §6.1
#[derive(Debug, Clone)]
pub struct RotationProof<'a> {
    pub new_pubkey: &'a [u8],
    pub signed_by_old: &'a [u8],
}

pub enum QuarantineState {
    Normal,
    Quarantined,
}

impl Default for QuarantineState {
    fn default() -> Self { QuarantineState::Normal }
}
