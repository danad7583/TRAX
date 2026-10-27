use ciborium::value::Value;
use ed25519_dalek::SigningKey;
use trax::config::HashAlgorithm;
use trax::crypto::ed25519_sign;
use trax::encoding::{decode_strict, encode_deterministic};
use trax::genesis::{
    accept_genesis_offer, confirm_genesis, create_genesis_offer, genesis_node_id, GenesisNodeV2,
    GenesisStepV2, TransmissionLimitsV2, TransmissionProfileV2, VerifiedGenesisV2,
    MAX_TRANSMISSION_PACKETS_V2, MAX_TRANSMISSION_PAYLOAD_BYTES_V2, MAX_TRANSMISSION_TIMEOUT_MS_V2,
    MAX_WIRE_PACKET_BYTES_V2,
};
use trax::transmission_crypto::hash_v2;

struct Fixture {
    a: SigningKey,
    b: SigningKey,
    other: SigningKey,
}

impl Fixture {
    fn new() -> Self {
        Self {
            a: SigningKey::from_bytes(&[17; 32]),
            b: SigningKey::from_bytes(&[29; 32]),
            other: SigningKey::from_bytes(&[43; 32]),
        }
    }
    fn nodes(&self, nonce: [u8; 32], profile: TransmissionProfileV2) -> [GenesisNodeV2; 3] {
        let offer = create_genesis_offer(&self.a, nonce, profile).unwrap();
        let acceptance = accept_genesis_offer(&offer, &self.b, |key| {
            key == self.a.verifying_key().as_bytes()
        })
        .unwrap();
        let confirmation = confirm_genesis(&offer, &acceptance, &self.a, |key| {
            key == self.b.verifying_key().as_bytes()
        })
        .unwrap();
        [offer, acceptance, confirmation]
    }
    fn trusted(&self, key: &[u8; 32]) -> bool {
        key == self.a.verifying_key().as_bytes() || key == self.b.verifying_key().as_bytes()
    }
}

fn resign(node: &mut GenesisNodeV2, key: &SigningKey) {
    let mut bytes = b"TRAX:GENESIS:V2\0".to_vec();
    bytes.extend_from_slice(&encode_deterministic(&node.event).unwrap());
    node.signature = ed25519_sign(key, &bytes);
}

fn field_mut<'a>(value: &'a mut Value, name: &str) -> &'a mut Value {
    match value {
        Value::Map(fields) => fields
            .iter_mut()
            .find(|(key, _)| key == &Value::Text(name.to_owned()))
            .map(|(_, value)| value)
            .unwrap(),
        _ => panic!("expected map"),
    }
}

#[test]
fn complete_transcript_is_three_linked_signed_nodes_with_one_shared_anchor() {
    let f = Fixture::new();
    let nodes = f.nodes([5; 32], TransmissionProfileV2::default());
    assert_eq!(nodes[0].event.step, GenesisStepV2::Offer);
    assert_eq!(nodes[0].event.previous_tip, [0; 32]);
    assert_eq!(nodes[0].event.responder_public_key, None);
    assert_eq!(nodes[1].event.step, GenesisStepV2::Accept);
    assert_eq!(
        nodes[1].event.previous_tip,
        genesis_node_id(&nodes[0]).unwrap()
    );
    assert_eq!(nodes[2].event.step, GenesisStepV2::Confirm);
    assert_eq!(
        nodes[2].event.previous_tip,
        genesis_node_id(&nodes[1]).unwrap()
    );
    for node in &nodes {
        assert_eq!(node.signature.len(), 64);
        assert_eq!(node.event.nonce, [5; 32]);
    }
    let left = VerifiedGenesisV2::verify(nodes.clone(), |key| f.trusted(key)).unwrap();
    let mut called = Vec::new();
    let right = VerifiedGenesisV2::verify(nodes.clone(), |key| {
        called.push(*key);
        f.trusted(key)
    })
    .unwrap();
    assert_eq!(
        called,
        vec![
            f.a.verifying_key().to_bytes(),
            f.b.verifying_key().to_bytes()
        ]
    );
    assert_eq!(left.anchor(), right.anchor());
    assert_eq!(left.nodes(), &nodes);
    assert_eq!(left.initiator_key(), f.a.verifying_key().to_bytes());
    assert_eq!(left.responder_key(), f.b.verifying_key().to_bytes());
    assert_eq!(left.profile(), &TransmissionProfileV2::default());
    let encoded = encode_deterministic(&nodes).unwrap();
    assert_eq!(
        left.anchor(),
        hash_v2(
            HashAlgorithm::Sha512256,
            b"TRAX:GENESIS:ANCHOR:V2\0",
            &[&encoded]
        )
        .unwrap()
    );
    for node in &nodes {
        assert_eq!(
            genesis_node_id(node).unwrap(),
            hash_v2(
                HashAlgorithm::Sha512256,
                b"TRAX:GENESIS:NODE:V2\0",
                &[&encode_deterministic(node).unwrap()]
            )
            .unwrap()
        );
    }
}

#[test]
fn trust_policy_is_explicit_at_accept_confirmation_and_final_verification() {
    let f = Fixture::new();
    let nodes = f.nodes([6; 32], TransmissionProfileV2::default());
    assert!(accept_genesis_offer(&nodes[0], &f.b, |_| false).is_err());
    assert!(confirm_genesis(&nodes[0], &nodes[1], &f.a, |_| false).is_err());
    assert!(VerifiedGenesisV2::verify(nodes.clone(), |_| false).is_err());
    assert!(
        VerifiedGenesisV2::verify(nodes.clone(), |key| key != f.b.verifying_key().as_bytes())
            .is_err()
    );
    assert!(VerifiedGenesisV2::verify(nodes, |key| key != f.a.verifying_key().as_bytes()).is_err());
}

#[test]
fn malformed_transcript_never_reaches_the_trust_callback() {
    let f = Fixture::new();
    let nodes = f.nodes([7; 32], TransmissionProfileV2::default());
    for index in 0..3 {
        let mut malformed = nodes.clone();
        malformed[index].signature[0] ^= 1;
        let mut calls = 0;
        assert!(VerifiedGenesisV2::verify(malformed, |_| {
            calls += 1;
            true
        })
        .is_err());
        assert_eq!(calls, 0);
    }
    let mut offer = nodes[0].clone();
    offer.signature[0] ^= 1;
    let mut calls = 0;
    assert!(accept_genesis_offer(&offer, &f.b, |_| {
        calls += 1;
        true
    })
    .is_err());
    assert_eq!(calls, 0);
}

#[test]
fn signatures_are_required_for_each_original_signer_and_have_exact_length() {
    let f = Fixture::new();
    let nodes = f.nodes([8; 32], TransmissionProfileV2::default());
    assert!(confirm_genesis(&nodes[0], &nodes[1], &f.b, |_| true).is_err());
    for index in 0..3 {
        let mut forged = nodes.clone();
        resign(&mut forged[index], &f.other);
        assert!(VerifiedGenesisV2::verify(forged, |_| true).is_err());
        for length in [0, 32, 63, 65] {
            let mut malformed = nodes.clone();
            malformed[index].signature.resize(length, 0);
            assert!(VerifiedGenesisV2::verify(malformed, |_| true).is_err());
        }
    }
}

#[test]
fn signed_link_nonce_step_and_profile_substitutions_are_rejected() {
    let f = Fixture::new();
    let nodes = f.nodes([9; 32], TransmissionProfileV2::default());
    let mut acceptance = nodes[1].clone();
    acceptance.event.previous_tip[0] ^= 1;
    resign(&mut acceptance, &f.b);
    assert!(confirm_genesis(&nodes[0], &acceptance, &f.a, |_| true).is_err());
    acceptance = nodes[1].clone();
    acceptance.event.nonce[0] ^= 1;
    resign(&mut acceptance, &f.b);
    assert!(confirm_genesis(&nodes[0], &acceptance, &f.a, |_| true).is_err());
    acceptance = nodes[1].clone();
    acceptance.event.profile.limits.timeout_ms += 1;
    resign(&mut acceptance, &f.b);
    assert!(confirm_genesis(&nodes[0], &acceptance, &f.a, |_| true).is_err());
    let mut malformed = nodes.clone();
    malformed[2].event.previous_tip[0] ^= 1;
    resign(&mut malformed[2], &f.a);
    assert!(VerifiedGenesisV2::verify(malformed, |_| true).is_err());
    let mut reordered = nodes.clone();
    reordered.swap(0, 1);
    assert!(VerifiedGenesisV2::verify(reordered, |_| true).is_err());
    let duplicated = [nodes[0].clone(), nodes[1].clone(), nodes[1].clone()];
    assert!(VerifiedGenesisV2::verify(duplicated, |_| true).is_err());
}

#[test]
fn advertised_self_signed_replacement_is_not_implicitly_trusted() {
    let f = Fixture::new();
    let offer = create_genesis_offer(&f.a, [10; 32], TransmissionProfileV2::default()).unwrap();
    let other_acceptance = accept_genesis_offer(&offer, &f.other, |_| true).unwrap();
    assert!(confirm_genesis(&offer, &other_acceptance, &f.a, |key| key
        == f.b.verifying_key().as_bytes())
    .is_err());
    let confirmation = confirm_genesis(&offer, &other_acceptance, &f.a, |_| true).unwrap();
    assert!(
        VerifiedGenesisV2::verify([offer.clone(), other_acceptance, confirmation], |key| f
            .trusted(key))
        .is_err()
    );
    assert!(accept_genesis_offer(&offer, &f.a, |_| true).is_err());
    let mut weak = offer;
    weak.event.initiator_public_key = [0; 32];
    assert!(accept_genesis_offer(&weak, &f.b, |_| true).is_err());
}

#[test]
fn profile_and_event_versions_cannot_cross_into_the_v2_trust_token() {
    let f = Fixture::new();
    let bad_profile = TransmissionProfileV2 {
        version: 1,
        ..TransmissionProfileV2::default()
    };
    assert!(create_genesis_offer(&f.a, [11; 32], bad_profile).is_err());
    let nodes = f.nodes([11; 32], TransmissionProfileV2::default());
    for step in [GenesisStepV2::Accept, GenesisStepV2::Confirm] {
        let mut wrong = nodes[0].clone();
        wrong.event.step = step;
        resign(&mut wrong, &f.a);
        assert!(accept_genesis_offer(&wrong, &f.b, |_| true).is_err());
    }
    let mut wrong = nodes[0].clone();
    wrong.event.version = 1;
    resign(&mut wrong, &f.a);
    assert!(accept_genesis_offer(&wrong, &f.b, |_| true).is_err());
    let mut wrong = nodes[0].clone();
    wrong.event.responder_public_key = Some(f.b.verifying_key().to_bytes());
    resign(&mut wrong, &f.a);
    assert!(accept_genesis_offer(&wrong, &f.b, |_| true).is_err());
}

#[test]
fn genesis_nonce_and_full_profile_are_bound_into_the_three_record_anchor() {
    let f = Fixture::new();
    let profile = TransmissionProfileV2::default();
    let base = f.nodes([12; 32], profile.clone());
    assert_eq!(base, f.nodes([12; 32], profile.clone()));
    let base = VerifiedGenesisV2::verify(base, |_| true).unwrap();
    let nonce = VerifiedGenesisV2::verify(f.nodes([13; 32], profile.clone()), |_| true).unwrap();
    let mut changed = profile;
    changed.limits.max_packets -= 1;
    let limits = VerifiedGenesisV2::verify(f.nodes([12; 32], changed), |_| true).unwrap();
    assert_ne!(base.anchor(), nonce.anchor());
    assert_ne!(base.anchor(), limits.anchor());
}

#[test]
fn resource_limits_are_positive_bounded_and_do_not_select_a_k() {
    let limits = TransmissionLimitsV2::default();
    limits.validate().unwrap();
    let cases = [
        TransmissionLimitsV2 {
            max_packets: 0,
            ..limits.clone()
        },
        TransmissionLimitsV2 {
            max_packets: MAX_TRANSMISSION_PACKETS_V2 + 1,
            ..limits.clone()
        },
        TransmissionLimitsV2 {
            max_payload_bytes: 0,
            ..limits.clone()
        },
        TransmissionLimitsV2 {
            max_payload_bytes: MAX_TRANSMISSION_PAYLOAD_BYTES_V2 + 1,
            ..limits.clone()
        },
        TransmissionLimitsV2 {
            max_packet_payload_bytes: 0,
            ..limits.clone()
        },
        TransmissionLimitsV2 {
            max_wire_packet_bytes: 0,
            ..limits.clone()
        },
        TransmissionLimitsV2 {
            max_wire_packet_bytes: MAX_WIRE_PACKET_BYTES_V2 + 1,
            ..limits.clone()
        },
        TransmissionLimitsV2 {
            timeout_ms: 0,
            ..limits.clone()
        },
        TransmissionLimitsV2 {
            timeout_ms: MAX_TRANSMISSION_TIMEOUT_MS_V2 + 1,
            ..limits.clone()
        },
        TransmissionLimitsV2 {
            max_packet_payload_bytes: limits.max_wire_packet_bytes + 1,
            ..limits.clone()
        },
    ];
    for limits in cases {
        assert!(limits.validate().is_err());
        assert!(TransmissionProfileV2 {
            limits,
            ..TransmissionProfileV2::default()
        }
        .validate()
        .is_err());
    }
    TransmissionLimitsV2 {
        max_packets: MAX_TRANSMISSION_PACKETS_V2,
        max_payload_bytes: MAX_TRANSMISSION_PAYLOAD_BYTES_V2,
        max_packet_payload_bytes: MAX_WIRE_PACKET_BYTES_V2,
        max_wire_packet_bytes: MAX_WIRE_PACKET_BYTES_V2,
        timeout_ms: MAX_TRANSMISSION_TIMEOUT_MS_V2,
    }
    .validate()
    .unwrap();
    let profile = Value::serialized(&TransmissionProfileV2::default()).unwrap();
    if let Value::Map(fields) = profile {
        assert!(!fields
            .iter()
            .any(|(key, _)| key == &Value::Text("k".into())));
    } else {
        panic!("expected profile map");
    }
}

#[test]
fn fixed_fields_use_exact_byte_strings_and_strict_bounded_typed_decoding() {
    let f = Fixture::new();
    let nodes = f.nodes([14; 32], TransmissionProfileV2::default());
    for node in &nodes {
        let bytes = encode_deterministic(node).unwrap();
        assert_eq!(
            decode_strict::<GenesisNodeV2>(&bytes, bytes.len()).unwrap(),
            *node
        );
        assert!(decode_strict::<GenesisNodeV2>(&bytes, bytes.len() - 1).is_err());
        let mut value = Value::serialized(node).unwrap();
        assert!(
            matches!(field_mut(&mut value, "signature"), Value::Bytes(bytes) if bytes.len() == 64)
        );
        let event = field_mut(&mut value, "event");
        for field in ["previous_tip", "nonce", "initiator_public_key"] {
            assert!(matches!(field_mut(event, field), Value::Bytes(bytes) if bytes.len() == 32));
        }
    }
    for replacement in [
        Value::Bytes(vec![0; 31]),
        Value::Bytes(vec![0; 33]),
        Value::Array(vec![Value::Integer(0.into()); 32]),
    ] {
        let mut value = Value::serialized(&nodes[0]).unwrap();
        *field_mut(field_mut(&mut value, "event"), "nonce") = replacement;
        let bytes = encode_deterministic(&value).unwrap();
        assert!(decode_strict::<GenesisNodeV2>(&bytes, 4096).is_err());
    }
    let mut value = Value::serialized(&nodes[1]).unwrap();
    *field_mut(field_mut(&mut value, "event"), "responder_public_key") = Value::Bytes(vec![0; 31]);
    assert!(decode_strict::<GenesisNodeV2>(&encode_deterministic(&value).unwrap(), 4096).is_err());
    let mut value = Value::serialized(&nodes[0]).unwrap();
    if let Value::Map(fields) = &mut value {
        fields.push((Value::Text("ignored".into()), Value::Bool(true)));
    }
    assert!(decode_strict::<GenesisNodeV2>(&encode_deterministic(&value).unwrap(), 4096).is_err());
    let mut value = Value::serialized(&nodes[0]).unwrap();
    let profile = field_mut(field_mut(&mut value, "event"), "profile");
    if let Value::Map(fields) = profile {
        fields.push((Value::Text("k".into()), Value::Integer(8.into())));
    }
    assert!(decode_strict::<GenesisNodeV2>(&encode_deterministic(&value).unwrap(), 4096).is_err());
    let mut bytes = encode_deterministic(&nodes[0]).unwrap();
    bytes.push(0);
    assert!(decode_strict::<GenesisNodeV2>(&bytes, 4096).is_err());
}

#[test]
fn hash_selection_is_explicit_and_does_not_fall_back_to_legacy_compile_time_hash() {
    let f = Fixture::new();
    let profile = TransmissionProfileV2 {
        hash_algorithm: HashAlgorithm::Blake3,
        ..TransmissionProfileV2::default()
    };
    #[cfg(feature = "hash-blake3")]
    {
        let nodes = f.nodes([15; 32], profile);
        let token = VerifiedGenesisV2::verify(nodes.clone(), |_| true).unwrap();
        assert_eq!(
            token.anchor(),
            hash_v2(
                HashAlgorithm::Blake3,
                b"TRAX:GENESIS:ANCHOR:V2\0",
                &[&encode_deterministic(&nodes).unwrap()]
            )
            .unwrap()
        );
        let sha =
            VerifiedGenesisV2::verify(f.nodes([15; 32], TransmissionProfileV2::default()), |_| {
                true
            })
            .unwrap();
        assert_ne!(token.anchor(), sha.anchor());
    }
    #[cfg(not(feature = "hash-blake3"))]
    {
        assert!(profile.validate().is_err());
        assert!(create_genesis_offer(&f.a, [15; 32], profile).is_err());
    }
}

#[test]
fn legacy_packet_zero_signature_cannot_replace_v2_genesis_authorization() {
    let f = Fixture::new();
    let bytes = trax::admission::create_admission_envelope_v1(
        &f.a,
        f.b.verifying_key().as_bytes(),
        &[1; 32],
        &[2; 16],
        b"payload",
        "packet0.admission",
        &[],
        "direct-ed25519",
    )
    .unwrap();
    let legacy = trax::admission::decode_admission_envelope_v1(&bytes).unwrap();
    let mut offer = create_genesis_offer(&f.a, [16; 32], TransmissionProfileV2::default()).unwrap();
    offer.signature = legacy.signature;
    assert!(accept_genesis_offer(&offer, &f.b, |_| true).is_err());
}
