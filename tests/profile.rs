use ciborium::value::Value;
use std::collections::BTreeMap;
use trax::config::{HashAlgorithm, ProtocolConfig, SigningAlgorithm, DEFAULT_K};
use trax::encoding::{decode, encode_deterministic};
use trax::profile::{domain_hash, hash_bytes, merkle_root};
use trax::TraxError;

fn sha_config(k: usize) -> ProtocolConfig {
    ProtocolConfig::new(k, SigningAlgorithm::Ed25519, HashAlgorithm::Sha512256).unwrap()
}

fn config_bytes(k: u64, signing: &str, hash: &str, extra: bool) -> Vec<u8> {
    let mut fields = BTreeMap::from([
        ("k", Value::Integer(k.into())),
        ("signing_algorithm", Value::Text(signing.to_owned())),
        ("hash_algorithm", Value::Text(hash.to_owned())),
    ]);
    if extra {
        fields.insert("ignored_algorithm", Value::Text("not allowed".into()));
    }
    encode_deterministic(&fields).unwrap()
}

#[test]
fn runtime_hashes_match_fixed_vectors_without_algorithm_fallback() {
    assert_eq!(
        hex::encode(hash_bytes(HashAlgorithm::Sha512256, b"").unwrap()),
        "c672b8d1ef56ed28ab87c3622c5114069bdd3ad7b8f9737498d0c01ecef0967a"
    );
    assert_eq!(
        hex::encode(hash_bytes(HashAlgorithm::Sha512256, b"abc").unwrap()),
        "53048e2681941ef99b2e29b76b4c7dabe4c2d0c634fc6d46e0e2f13107e7af23"
    );
    #[cfg(feature = "hash-blake3")]
    {
        let blake = hash_bytes(HashAlgorithm::Blake3, b"").unwrap();
        assert_eq!(
            hex::encode(blake),
            "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262"
        );
        assert_ne!(blake, hash_bytes(HashAlgorithm::Sha512256, b"").unwrap());
    }
    #[cfg(not(feature = "hash-blake3"))]
    assert!(matches!(
        hash_bytes(HashAlgorithm::Blake3, b""),
        Err(TraxError::UnsupportedAlgorithm)
    ));
}

#[test]
fn protocol_config_is_explicit_validated_and_roundtrips() {
    for k in [5, 7, 8, 14] {
        let config = sha_config(k);
        config.validate().unwrap();
        assert_eq!(config.k(), k);
        assert_eq!(config.segment().k(), k);
        assert_eq!(config.signing_algorithm(), SigningAlgorithm::Ed25519);
        assert_eq!(config.hash_algorithm(), HashAlgorithm::Sha512256);
        let encoded = encode_deterministic(&config).unwrap();
        assert_eq!(decode::<ProtocolConfig>(&encoded).unwrap(), config);
    }
    for k in 0..=4 {
        assert!(matches!(
            ProtocolConfig::new(k, SigningAlgorithm::Ed25519, HashAlgorithm::Sha512256),
            Err(TraxError::InvalidSegmentSize)
        ));
    }
    if let Ok(k) = usize::try_from(u64::from(u32::MAX) + 1) {
        assert!(
            ProtocolConfig::new(k, SigningAlgorithm::Ed25519, HashAlgorithm::Sha512256).is_err()
        );
    }
}

#[test]
fn default_cadence_is_opt_in_and_remains_explicit_on_the_wire() {
    let config =
        ProtocolConfig::with_default_k(SigningAlgorithm::Ed25519, HashAlgorithm::Sha512256)
            .unwrap();
    assert_eq!(DEFAULT_K, 8);
    assert_eq!(config.k(), 8);
    assert_eq!(config, sha_config(8));
    assert_eq!(sha_config(5).k(), 5);

    let encoded = encode_deterministic(&config).unwrap();
    assert_eq!(encoded, config_bytes(8, "ed25519", "sha512-256", false));
    assert_eq!(decode::<ProtocolConfig>(&encoded).unwrap(), config);

    let missing_k = BTreeMap::from([
        ("signing_algorithm", Value::Text("ed25519".into())),
        ("hash_algorithm", Value::Text("sha512-256".into())),
    ]);
    assert!(decode::<ProtocolConfig>(&encode_deterministic(&missing_k).unwrap()).is_err());
}

#[test]
fn serialized_configuration_cannot_bypass_validation_or_choose_unknown_algorithms() {
    for bytes in [
        config_bytes(0, "ed25519", "sha512-256", false),
        config_bytes(1, "ed25519", "sha512-256", false),
        config_bytes(2, "ed25519", "sha512-256", false),
        config_bytes(3, "ed25519", "sha512-256", false),
        config_bytes(4, "ed25519", "sha512-256", false),
        config_bytes(u64::from(u32::MAX) + 1, "ed25519", "sha512-256", false),
        config_bytes(5, "rsa", "sha512-256", false),
        config_bytes(5, "ed25519", "sha3-256", false),
        config_bytes(5, "ed25519", "sha512-256", true),
    ] {
        assert!(decode::<ProtocolConfig>(&bytes).is_err());
    }
    let missing = BTreeMap::from([("k", Value::Integer(5.into()))]);
    assert!(decode::<ProtocolConfig>(&encode_deterministic(&missing).unwrap()).is_err());
    #[cfg(not(feature = "hash-blake3"))]
    {
        assert!(matches!(
            ProtocolConfig::new(5, SigningAlgorithm::Ed25519, HashAlgorithm::Blake3),
            Err(TraxError::UnsupportedAlgorithm)
        ));
        assert!(decode::<ProtocolConfig>(&config_bytes(5, "ed25519", "blake3", false)).is_err());
    }
}

#[test]
fn root_supports_positive_and_odd_sizes_without_padding() {
    for k in [5, 7, 8, 14] {
        let config = sha_config(k);
        let messages: Vec<_> = (0..k)
            .map(|i| format!("message-{i}").into_bytes())
            .collect();
        let root = merkle_root(config, &messages).unwrap();
        assert_eq!(merkle_root(config, &messages).unwrap(), root);
        assert!(matches!(
            merkle_root(config, &messages[..k - 1]),
            Err(TraxError::InvalidSegmentSize)
        ));
        let mut changed = messages.clone();
        changed[k - 1].push(b'!');
        assert_ne!(merkle_root(config, &changed).unwrap(), root);
        if k > 1 {
            changed = messages.clone();
            changed.swap(0, k - 1);
            assert_ne!(merkle_root(config, &changed).unwrap(), root);
        }
    }
    let config = sha_config(5);
    let messages = vec![
        b"a".to_vec(),
        b"b".to_vec(),
        b"c".to_vec(),
        b"d".to_vec(),
        b"e".to_vec(),
    ];
    let a = domain_hash(config, b"TRAX:SEGMENT:LEAF:V1\0", b"a").unwrap();
    let b = domain_hash(config, b"TRAX:SEGMENT:LEAF:V1\0", b"b").unwrap();
    let c = domain_hash(config, b"TRAX:SEGMENT:LEAF:V1\0", b"c").unwrap();
    let d = domain_hash(config, b"TRAX:SEGMENT:LEAF:V1\0", b"d").unwrap();
    let e = domain_hash(config, b"TRAX:SEGMENT:LEAF:V1\0", b"e").unwrap();
    let mut ab_bytes = a.to_vec();
    ab_bytes.extend_from_slice(&b);
    let ab = domain_hash(config, b"TRAX:SEGMENT:NODE:V1\0", &ab_bytes).unwrap();
    let mut cd_bytes = c.to_vec();
    cd_bytes.extend_from_slice(&d);
    let cd = domain_hash(config, b"TRAX:SEGMENT:NODE:V1\0", &cd_bytes).unwrap();
    let mut abcd_bytes = ab.to_vec();
    abcd_bytes.extend_from_slice(&cd);
    let abcd = domain_hash(config, b"TRAX:SEGMENT:NODE:V1\0", &abcd_bytes).unwrap();
    let mut root_bytes = abcd.to_vec();
    root_bytes.extend_from_slice(&e);
    let expected = domain_hash(config, b"TRAX:SEGMENT:NODE:V1\0", &root_bytes).unwrap();
    assert_eq!(merkle_root(config, &messages).unwrap(), expected);
    let mut padded = messages.clone();
    padded.push(messages[4].clone());
    assert_ne!(merkle_root(sha_config(6), &padded).unwrap(), expected);
}

#[cfg(feature = "hash-blake3")]
#[test]
fn merkle_root_uses_the_negotiated_runtime_algorithm() {
    let messages = vec![
        b"a".to_vec(),
        b"b".to_vec(),
        b"c".to_vec(),
        b"d".to_vec(),
        b"e".to_vec(),
    ];
    let blake = ProtocolConfig::new(5, SigningAlgorithm::Ed25519, HashAlgorithm::Blake3).unwrap();
    assert_ne!(
        merkle_root(blake, &messages).unwrap(),
        merkle_root(sha_config(5), &messages).unwrap()
    );
    assert_ne!(
        encode_deterministic(&blake).unwrap(),
        encode_deterministic(&sha_config(5)).unwrap()
    );
}
