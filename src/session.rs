//! Handshake and session binding per §4.1
use crate::crypto::hkdf_extract_expand;
pub struct Session {
    pub session_id: [u8;32],
}

pub fn derive_session_id(context: &[u8], nonce_a: &[u8], nonce_b: &[u8], ecdh_opt: Option<&[u8]>) -> [u8;32] {
    let ikm = match ecdh_opt {
        Some(s) => [nonce_a, nonce_b, s].concat(),
        None => [nonce_a, nonce_b].concat(),
    };
    let th = hkdf_extract_expand(b"trax:th:salt", &ikm, context, 32);
    let mut id = [0u8;32];
    id.copy_from_slice(&th);
    id
}
