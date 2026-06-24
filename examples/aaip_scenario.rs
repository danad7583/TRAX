
//! Simulate Agent A ↔ Agent B scenario per TRAX v1.1.0
use rand_core::OsRng;
use ed25519_dalek::{SigningKey, VerifyingKey, Signer, Verifier};
use trax::session::derive_session_id;
use trax::crypto::hash32;
use coset::{CoseSign1, Header, iana};

fn sign_cose(sk: &SigningKey, payload: &[u8]) -> Vec<u8> {
    let mut protected = Header::new();
    protected.alg = Some(iana::Algorithm::EdDSA.into());
    let protected = protected.to_protected().unwrap();
    let mut s1 = CoseSign1{ protected, unprotected: Header::new(), payload: Some(payload.to_vec()), signature: vec![] };
    s1.sign(|m| sk.sign(m).to_vec()).expect("sign");
    let mut out = vec![]; s1.to_writer(&mut out).unwrap(); out
}

fn verify_cose(vk: &VerifyingKey, bytes: &[u8]) -> bool {
    if let Ok(s1) = CoseSign1::from_slice(bytes) {
        if let Some(_payload) = s1.payload.as_ref() {
            return s1.verify(|m, sig| vk.verify(m, &ed25519_dalek::Signature::from_slice(sig).unwrap()).map(|_| ()).map_err(|_| coset::CoseError::Verification)).is_ok();
        }
    }
    false
}

fn main() {
    let nonce_a = b"nonce_A_32_bytes________________";
    let nonce_b = b"nonce_B_32_bytes________________";
    let context = b"trax:demo";
    let session_id = derive_session_id(context, nonce_a, nonce_b, None);
    println!("session_id={:02x?}", session_id);

    let sk_a = SigningKey::generate(&mut OsRng);
    let vk_a = sk_a.verifying_key();
    let sk_b = SigningKey::generate(&mut OsRng);
    let vk_b = sk_b.verifying_key();

    let payload1 = b"{\"msg\":\"hello B\",\"counter\":1}";
    let env1 = sign_cose(&sk_a, payload1);
    println!("A->B COSE len={} bytes", env1.len());
    assert!(verify_cose(&vk_a, &env1));

    let tip_hash = hash32(&env1);
    println!("B tip_hash={:02x?}", tip_hash);

    let _sk_b2 = SigningKey::generate(&mut OsRng);
    println!("B rotated key; entering quarantine until fresh K-window validated");

    println!("Quarantine simulated; complete.");
}
