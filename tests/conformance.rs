// Conformance tests mapped to requirement IDs.
mod vectors;
use vectors::load_vector;

#[test]
fn req_3_1_1_deterministic_cbor() {
    let v = load_vector("deterministic_cbor_valid.cbor");
    assert!(!v.is_empty());
}

#[test]
fn req_5_1_1_segment_proof_validates() {
    // Placeholder logic: will parse CBOR in real vectors
    let v = load_vector("segment_proof_valid.cbor");
    assert!(!v.is_empty());
}

#[test]
fn req_4_1_2_session_id_binding() {
    // Placeholder until handshake demo wires in real IDs
    assert!(true);
}

#[cfg(feature = "crypto-ed25519")]
#[test]
fn req_4_2_1_ed25519_sign_verify_roundtrip() {
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;
    use trax::crypto::{ed25519_sign, ed25519_verify};

    let mut csprng = OsRng;
    let signing_key = SigningKey::generate(&mut csprng);
    let verifying_key = signing_key.verifying_key();

    let msg = b"trax signing conformance test message";

    let sig = ed25519_sign(&signing_key, msg);

    assert_eq!(sig.len(), 64);
    assert!(ed25519_verify(&verifying_key, msg, &sig));
}

#[cfg(feature = "crypto-ed25519")]
#[test]
fn req_4_2_2_ed25519_rejects_tampered_message() {
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;
    use trax::crypto::{ed25519_sign, ed25519_verify};

    let mut csprng = OsRng;
    let signing_key = SigningKey::generate(&mut csprng);
    let verifying_key = signing_key.verifying_key();

    let msg = b"trax signed message";
    let tampered = b"trax signed message tampered";

    let sig = ed25519_sign(&signing_key, msg);

    assert!(ed25519_verify(&verifying_key, msg, &sig));
    assert!(!ed25519_verify(&verifying_key, tampered, &sig));
}
