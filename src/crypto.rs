//! Crypto profile: Ed25519 (sig), optional X25519 (ECDH), BLAKE3 or SHA-512/256, HKDF.

#[cfg(feature = "crypto-ed25519")]
use ed25519_dalek::{SigningKey, VerifyingKey, Signature, Signer, Verifier};

#[cfg(feature = "hash-blake3")]
pub fn hash32(data: &[u8]) -> [u8;32] { blake3::hash(data).into() }

#[cfg(all(not(feature = "hash-blake3"), feature = "hash-sha2"))]
pub fn hash32(data: &[u8]) -> [u8;32] {
    #[cfg(feature = "hash-sha2")]
    use sha2::{Digest, Sha512_256};
    let mut h = Sha512_256::new();
    h.update(data);
    let out = h.finalize();
    let mut a = [0u8;32];
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
        vk.verify(msg, &s).is_ok()
    } else { false }
}

#[cfg(feature = "crypto-ed25519")]
pub fn ed25519_sign_batch_k8(
    sk: &SigningKey,
    messages: &[Vec<u8>]
) -> (Vec<u8>, Vec<Vec<[u8; 32]>>) {
    assert_eq!(messages.len(), 8, "Batch size must be exactly 8");

    use blake3::Hasher;

    // 1. Hash each message as a leaf
    let mut leaves = Vec::with_capacity(8);
    for msg in messages {
        let mut h = Hasher::new();
        h.update(b"leaf:");
        h.update(msg);
        let mut leaf_hash = [0u8; 32];
        leaf_hash.copy_from_slice(h.finalize().as_bytes());
        leaves.push(leaf_hash);
    }

    // 2. Build Merkle tree & collect inclusion proofs
    let mut tree_levels: Vec<Vec<[u8; 32]>> = vec![leaves.clone()];
    while tree_levels.last().unwrap().len() > 1 {
        let prev_level = tree_levels.last().unwrap();
        let mut next_level = Vec::with_capacity(prev_level.len() / 2);
        for chunk in prev_level.chunks(2) {
            let mut h = Hasher::new();
            h.update(b"node:");
            h.update(&chunk[0]);
            h.update(&chunk[1]);
            let mut node_hash = [0u8; 32];
            node_hash.copy_from_slice(h.finalize().as_bytes());
            next_level.push(node_hash);
        }
        tree_levels.push(next_level);
    }

    let root_hash = tree_levels.last().unwrap()[0];
    let root_sig = sk.sign(&root_hash).to_bytes().to_vec();

    // 3. Generate inclusion proofs for each leaf
    let mut proofs: Vec<Vec<[u8; 32]>> = vec![Vec::new(); 8];
    for leaf_idx in 0..8 {
        let mut idx = leaf_idx;
        for level in &tree_levels[..tree_levels.len() - 1] {
            let sibling_idx = if idx % 2 == 0 { idx + 1 } else { idx - 1 };
            proofs[leaf_idx].push(level[sibling_idx]);
            idx /= 2;
        }
    }

    (root_sig, proofs)
}
