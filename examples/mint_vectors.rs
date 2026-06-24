
//! Generate Ed25519 keypairs and COSE_Sign1 vectors matching TRAX v1.1.0.
//! Usage:
//!   cargo run --example mint_vectors --features crypto-ed25519,hash-blake3
//! Outputs raw binary vectors into ./vectors/generated/*
use std::fs;
use std::path::PathBuf;
use rand_core::OsRng;
use ed25519_dalek::{SigningKey, VerifyingKey, Signer};
use coset::{CoseSign1, Header, iana};

fn outdir() -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("vectors"); p.push("generated");
    fs::create_dir_all(&p).unwrap();
    p
}

fn save(name: &str, bytes: &[u8]) {
    let mut p = outdir();
    p.push(name);
    fs::write(p, bytes).unwrap();
}

fn cose_sign_payload(sk: &SigningKey, payload: &[u8]) -> Vec<u8> {
    let mut protected = Header::new();
    protected.alg = Some(iana::Algorithm::EdDSA.into());
    let protected = protected.to_protected().unwrap();
    let mut sign1 = CoseSign1 {
        protected,
        unprotected: Header::new(),
        payload: Some(payload.to_vec()),
        signature: vec![],
    };
    sign1.sign(|m| sk.sign(m).to_vec()).expect("sign");
    let mut out = vec![];
    sign1.to_writer(&mut out).expect("serialize cose");
    out
}

fn main() {
    let sk_a = SigningKey::generate(&mut OsRng);
    let vk_a: VerifyingKey = sk_a.verifying_key();
    let sk_b = SigningKey::generate(&mut OsRng);
    let vk_b: VerifyingKey = sk_b.verifying_key();

    save("agent_a_pub.ed25519", vk_a.as_bytes());
    save("agent_b_pub.ed25519", vk_b.as_bytes());

    let payload = b"{\"msg_type\":\"hello\",\"body\":\"test\"}";
    let cose = cose_sign_payload(&sk_a, payload);
    save("req-3.1.2_cose_sign1_valid.cbor", &cose);

    let mut bad = cose.clone();
    if let Some(last) = bad.last_mut() { *last ^= 0xFF; }
    save("req-8.3.1_bad_signature.cbor", &bad);

    println!("Minted vectors in ./vectors/generated");
}
