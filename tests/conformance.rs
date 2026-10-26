// Conformance tests mapped to requirement IDs.
use trax::config::SegmentConfig;

#[test]
fn req_3_1_1_deterministic_cbor() {
    use std::collections::BTreeMap;
    use trax::encoding::{decode, encode_deterministic};

    // BTreeMap iterates a, aa, z. The wire profile orders encoded keys by
    // length first, then bytes: a, z, aa. Expected CBOR is fixed independently
    // of the serializer's output and any historical placeholder fixture.
    let value = BTreeMap::from([
        ("aa".to_owned(), 2_u64),
        ("z".to_owned(), 1_u64),
        ("a".to_owned(), 3_u64),
    ]);
    let expected = [
        0xa3, 0x61, b'a', 0x03, 0x61, b'z', 0x01, 0x62, b'a', b'a', 0x02,
    ];
    assert_eq!(encode_deterministic(&value).unwrap(), expected);
    let decoded: BTreeMap<String, u64> = decode(&expected).unwrap();
    assert_eq!(decoded, value);
}

#[test]
fn req_5_1_1_segment_proof_is_intrinsically_valid_and_context_admitted() {
    use ed25519_dalek::SigningKey;
    use trax::crypto::hash32;
    use trax::dag::{
        create_segment_seal, event_tip, lineage_key_id, receiver_id,
        verify_segment_proof_for_context, verify_segment_proof_intrinsic, TrustedSessionContext,
    };
    use trax::{PostGenesisEventV1, SegmentProof};
    let key = SigningKey::from_bytes(&[7; 32]);
    let receiver = SigningKey::from_bytes(&[8; 32]);
    let genesis = hash32(b"genesis");
    let mut tip = genesis;
    let events = (0..8)
        .map(|counter| {
            let event = PostGenesisEventV1 {
                version: 1,
                session_id: hash32(b"session"),
                lineage_key_id: lineage_key_id(&key.verifying_key()),
                receiver_id: receiver_id(&receiver.verifying_key()),
                segment_index: 0,
                counter,
                previous_tip: tip,
                content_hash: hash32(&[counter as u8]),
                payload_hash: hash32(&[counter as u8, 1]),
            };
            tip = event_tip(&event).unwrap();
            event
        })
        .collect::<Vec<_>>();
    let seal = create_segment_seal(SegmentConfig::new(8).unwrap(), &key, &events).unwrap();
    let proof = SegmentProof { events, seal };
    verify_segment_proof_intrinsic(SegmentConfig::new(8).unwrap(), &proof, &key.verifying_key())
        .unwrap();
    let trusted = TrustedSessionContext::from_verified_state(
        SegmentConfig::new(8).unwrap(),
        hash32(b"session"),
        receiver_id(&receiver.verifying_key()),
        key.verifying_key(),
        genesis,
        0,
        0,
    );
    verify_segment_proof_for_context(&proof, &trusted).unwrap();
}

#[test]
fn req_4_1_2_session_id_binding() {
    let left = trax::session::derive_session_id(b"context", b"nonce-a", b"nonce-b", None);
    let right = trax::session::derive_session_id(b"other", b"nonce-a", b"nonce-b", None);
    assert_ne!(left, right);
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
