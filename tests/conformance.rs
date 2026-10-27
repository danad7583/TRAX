use ed25519_dalek::{SigningKey, VerifyingKey};
use std::collections::BTreeMap;
use trax::crypto::{ed25519_sign, ed25519_verify};
use trax::encoding::{decode_strict, encode_deterministic};

#[test]
fn deterministic_cbor_matches_independent_fixed_bytes() {
    let value = BTreeMap::from([("aa", 2_u64), ("z", 1), ("a", 3)]);
    let expected = [0xa3, 0x61, b'a', 3, 0x61, b'z', 1, 0x62, b'a', b'a', 2];
    assert_eq!(encode_deterministic(&value).unwrap(), expected);
    assert_eq!(
        decode_strict::<BTreeMap<String, u64>>(&expected, 64).unwrap(),
        value
            .into_iter()
            .map(|(key, value)| (key.to_owned(), value))
            .collect()
    );
}

#[test]
fn ed25519_signatures_bind_the_message_and_signing_key() {
    let key = SigningKey::from_bytes(&[7; 32]);
    let other = SigningKey::from_bytes(&[8; 32]);
    let message = b"TRAX signing conformance message";
    let signature = ed25519_sign(&key, message);
    assert_eq!(signature.len(), 64);
    assert!(ed25519_verify(&key.verifying_key(), message, &signature));
    assert!(!ed25519_verify(
        &key.verifying_key(),
        b"changed",
        &signature
    ));
    assert!(!ed25519_verify(&other.verifying_key(), message, &signature));
    for length in [0, 32, 63, 65] {
        let mut malformed = signature.clone();
        malformed.resize(length, 0);
        assert!(!ed25519_verify(&key.verifying_key(), message, &malformed));
    }
    let mut changed = signature;
    changed[63] |= 0x80;
    assert!(!ed25519_verify(&key.verifying_key(), message, &changed));
}

#[test]
fn strict_ed25519_rejects_identity_point_forgery() {
    let mut identity = [0; 32];
    identity[0] = 1;
    let key = VerifyingKey::from_bytes(&identity).unwrap();
    assert!(key.is_weak());
    // R = identity, S = 0 satisfies the non-strict group equation for an
    // identity public key. Strict verification must reject this forgery.
    let mut forged = vec![0; 64];
    forged[0] = 1;
    assert!(!ed25519_verify(&key, b"unauthorized", &forged));
}
