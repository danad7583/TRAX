//! Crypto profile: Ed25519 (sig), optional X25519 (ECDH), BLAKE3 or SHA-512/256, HKDF.

#[cfg(feature = "crypto-ed25519")]
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};

use crate::config::SegmentConfig;
use crate::errors::TraxError;

pub const K8_MERKLE_DEPTH: usize = 3;
pub type MerkleProof = Vec<[u8; 32]>;
pub type MerkleProofs = Vec<MerkleProof>;
const SEGMENT_LEAF_DOMAIN: &[u8] = b"TRAX:SEGMENT:LEAF:V1\0";
const SEGMENT_NODE_DOMAIN: &[u8] = b"TRAX:SEGMENT:NODE:V1\0";

#[cfg(feature = "hash-blake3")]
pub fn hash32(data: &[u8]) -> [u8; 32] {
    blake3::hash(data).into()
}

#[cfg(all(not(feature = "hash-blake3"), feature = "hash-sha2"))]
pub fn hash32(data: &[u8]) -> [u8; 32] {
    #[cfg(feature = "hash-sha2")]
    use sha2::{Digest, Sha512_256};
    let mut h = Sha512_256::new();
    h.update(data);
    let out = h.finalize();
    let mut a = [0u8; 32];
    a.copy_from_slice(&out);
    a
}

pub fn hkdf_extract_expand(salt: &[u8], ikm: &[u8], info: &[u8], out_len: usize) -> Vec<u8> {
    use hkdf::Hkdf;
    use sha2::Sha512;
    let hk = Hkdf::<Sha512>::new(Some(salt), ikm);
    let mut okm = vec![0u8; out_len];
    hk.expand(info, &mut okm).expect("HKDF expand");
    okm
}

#[cfg(feature = "crypto-ed25519")]
pub fn ed25519_sign(sk: &SigningKey, msg: &[u8]) -> Vec<u8> {
    sk.sign(msg).to_bytes().to_vec()
}

#[cfg(feature = "crypto-ed25519")]
pub fn ed25519_verify(vk: &VerifyingKey, msg: &[u8], sig: &[u8]) -> bool {
    if let Ok(s) = Signature::from_slice(sig) {
        vk.verify_strict(msg, &s).is_ok()
    } else {
        false
    }
}

#[cfg(feature = "crypto-ed25519")]
/// Signs only a bare Merkle root. This low-level primitive is **not** a
/// TRAX segment seal because it does not bind session or lineage context.
/// Use `crate::dag::create_segment_seal` for protocol admission.
pub fn ed25519_sign_merkle_root_raw(
    config: SegmentConfig,
    sk: &SigningKey,
    messages: &[Vec<u8>],
) -> Result<(Vec<u8>, MerkleProofs), TraxError> {
    let (root_hash, proofs) = root_and_proofs(config, messages)?;
    Ok((sk.sign(&root_hash).to_bytes().to_vec(), proofs))
}

#[cfg(feature = "crypto-ed25519")]
/// Explicit K=8 convenience wrapper for the low-level bare-root primitive.
pub fn ed25519_sign_merkle_root_k8_raw(
    sk: &SigningKey,
    messages: &[Vec<u8>],
) -> Result<(Vec<u8>, MerkleProofs), TraxError> {
    ed25519_sign_merkle_root_raw(SegmentConfig::new(8)?, sk, messages)
}

/// Explicit K=8 convenience wrapper; no default admission cadence is selected.
pub fn merkle_root_k8(messages: &[Vec<u8>]) -> Result<[u8; 32], TraxError> {
    merkle_root(SegmentConfig::new(8)?, messages)
}

pub fn merkle_root_and_proofs_k8(
    messages: &[Vec<u8>],
) -> Result<([u8; 32], MerkleProofs), TraxError> {
    root_and_proofs(SegmentConfig::new(8)?, messages)
}

pub fn merkle_root(config: SegmentConfig, messages: &[Vec<u8>]) -> Result<[u8; 32], TraxError> {
    Ok(root_and_proofs(config, messages)?.0)
}

/// Builds an ordered tree for exactly the configured number of leaves.
///
/// At each level, adjacent left/right nodes are domain-separated and hashed.
/// An unpaired final node is promoted unchanged to the next level; no synthetic
/// or duplicated leaf is introduced. Proofs omit siblings at promotion levels.
/// K=1 therefore has a leaf root and an empty inclusion proof. For K=8 this is
/// byte-for-byte the original balanced tree profile.
pub fn root_and_proofs(
    config: SegmentConfig,
    messages: &[Vec<u8>],
) -> Result<([u8; 32], MerkleProofs), TraxError> {
    if messages.len() != config.k() {
        return Err(TraxError::InvalidSegmentSize);
    }
    let leaves: Vec<[u8; 32]> = messages
        .iter()
        .map(|message| hash_parts(SEGMENT_LEAF_DOMAIN, &[message]))
        .collect();
    let mut tree_levels: Vec<Vec<[u8; 32]>> = vec![leaves];
    while tree_levels.last().unwrap().len() > 1 {
        let prev_level = tree_levels.last().unwrap();
        let mut next_level = Vec::with_capacity(prev_level.len().div_ceil(2));
        for chunk in prev_level.chunks(2) {
            next_level.push(if chunk.len() == 2 {
                hash_parts(SEGMENT_NODE_DOMAIN, &[&chunk[0], &chunk[1]])
            } else {
                chunk[0]
            });
        }
        tree_levels.push(next_level);
    }
    let root_hash = tree_levels.last().unwrap()[0];
    let mut proofs: MerkleProofs = vec![Vec::new(); config.k()];
    for (leaf_idx, proof) in proofs.iter_mut().enumerate() {
        let mut idx = leaf_idx;
        for level in &tree_levels[..tree_levels.len() - 1] {
            let sibling_idx = if idx % 2 == 0 { idx + 1 } else { idx - 1 };
            if let Some(sibling) = level.get(sibling_idx) {
                proof.push(*sibling);
            }
            idx /= 2;
        }
    }
    Ok((root_hash, proofs))
}

pub fn verify_merkle_inclusion_k8(
    message: &[u8],
    leaf_index: usize,
    proof: &[[u8; 32]],
    expected_root: &[u8; 32],
) -> Result<bool, TraxError> {
    verify_merkle_inclusion(
        SegmentConfig::new(8)?,
        message,
        leaf_index,
        proof,
        expected_root,
    )
}

/// Verifies the exact tree path implied by K and the leaf's ordered index.
/// Missing or extra siblings, including siblings at promotion levels, are
/// rejected rather than interpreted as another tree shape.
pub fn verify_merkle_inclusion(
    config: SegmentConfig,
    message: &[u8],
    leaf_index: usize,
    proof: &[[u8; 32]],
    expected_root: &[u8; 32],
) -> Result<bool, TraxError> {
    if leaf_index >= config.k() {
        return Err(TraxError::InvalidSegmentSize);
    }
    let mut current = hash_parts(SEGMENT_LEAF_DOMAIN, &[message]);
    let mut index = leaf_index;
    let mut width = config.k();
    let mut consumed = 0;
    while width > 1 {
        if !index.is_multiple_of(2) || index + 1 < width {
            let sibling = proof.get(consumed).ok_or(TraxError::InvalidSegmentSize)?;
            consumed += 1;
            current = if index.is_multiple_of(2) {
                hash_parts(SEGMENT_NODE_DOMAIN, &[&current, sibling])
            } else {
                hash_parts(SEGMENT_NODE_DOMAIN, &[sibling, &current])
            };
        }
        index /= 2;
        width = width.div_ceil(2);
    }
    if consumed != proof.len() {
        return Err(TraxError::InvalidSegmentSize);
    }
    Ok(&current == expected_root)
}

fn hash_parts(domain: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut bytes = Vec::with_capacity(domain.len() + parts.iter().map(|p| p.len()).sum::<usize>());
    bytes.extend_from_slice(domain);
    for part in parts {
        bytes.extend_from_slice(part);
    }
    hash32(&bytes)
}
