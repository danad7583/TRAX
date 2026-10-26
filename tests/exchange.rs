use ciborium::value::Value;
use ed25519_dalek::{SigningKey, VerifyingKey};
use trax::encoding::{decode, encode_deterministic};
use trax::exchange::{PrefixAcknowledgment, PrefixContext};
use trax::graph::{participant_id, AuthorityId, GraphEvent, GraphOperation};
use trax::profile::merkle_root;
use trax::{HashAlgorithm, ProtocolConfig, SigningAlgorithm, TraxError};

fn config(k: usize) -> ProtocolConfig {
    ProtocolConfig::new(k, SigningAlgorithm::Ed25519, HashAlgorithm::Sha512256).unwrap()
}

fn fixture(k: usize) -> (PrefixContext, Vec<GraphEvent>, AuthorityId, SigningKey) {
    assert!(k >= 5);
    let author = SigningKey::from_bytes(&[1; 32]);
    let key = SigningKey::from_bytes(&[2; 32]);
    let signer = AuthorityId {
        participant: participant_id(&key.verifying_key().to_bytes()),
        key_epoch: 0,
    };
    let mut context = PrefixContext {
        dag_id: [3; 32],
        config: config(k),
        configuration_tip: [4; 32],
        previous_checkpoint: [5; 32],
        segment_index: 7,
        proposal: [0; 32],
        branch: [6; 32],
        first_counter: 10,
    };
    let mut events = Vec::new();
    let mut parent = context.dag_id;
    for index in 0..k - 1 {
        let is_ack = index == k - 2;
        let event = GraphEvent {
            version: 2,
            dag_id: context.dag_id,
            config: context.config,
            configuration_tip: context.configuration_tip,
            branch: context.branch,
            parent,
            sequence: index as u64 + 1,
            counter: context.first_counter + index as u64,
            author: if is_ack {
                signer.participant
            } else {
                participant_id(&author.verifying_key().to_bytes())
            },
            key_epoch: 0,
            authority_tip: context.dag_id,
            operation: if is_ack {
                GraphOperation::Acknowledge {
                    proposal: context.proposal,
                }
            } else if index == 0 {
                GraphOperation::CloseRequest
            } else {
                GraphOperation::Append {
                    payload: vec![index as u8],
                }
            },
            authorization: None,
            new_key_signature: None,
        };
        parent = event.node_id().unwrap();
        if index == 0 {
            context.proposal = parent;
        }
        events.push(event);
    }
    (context, events, signer, key)
}

#[test]
fn detached_prefix_proofs_round_trip_and_retain_the_negotiated_k() {
    for k in [5, 6, 8] {
        let (context, events, signer, key) = fixture(k);
        let ack_event_id = events.last().unwrap().node_id().unwrap();
        let proof = PrefixAcknowledgment::create(context, &events, signer.clone(), &key).unwrap();
        proof
            .verify(&context, &events, &signer, &key.verifying_key())
            .unwrap();
        assert_eq!(proof.commitment.context.config.k(), k);
        assert_eq!(proof.commitment.prefix_len as usize, k - 1);
        assert_eq!(proof.commitment.prefix_tip, ack_event_id);
        assert_eq!(
            proof.commitment.expected_final_counter,
            context.first_counter + k as u64 - 1
        );
        assert_eq!(events.last().unwrap().node_id().unwrap(), ack_event_id);
        let bytes = encode_deterministic(&proof).unwrap();
        let decoded: PrefixAcknowledgment = decode(&bytes).unwrap();
        assert_eq!(decoded, proof);
        assert_eq!(decoded.node_id().unwrap(), proof.node_id().unwrap());
        assert_ne!(proof.node_id().unwrap(), ack_event_id);
    }
}

#[test]
fn odd_prefix_root_uses_k_minus_one_without_padding() {
    let (context, events, signer, key) = fixture(6);
    let proof = PrefixAcknowledgment::create(context, &events, signer, &key).unwrap();
    let encoded = events
        .iter()
        .map(encode_deterministic)
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert_eq!(
        proof.commitment.ordered_merkle_root,
        merkle_root(config(5), &encoded).unwrap()
    );
    assert_eq!(proof.commitment.prefix_len, 5);
    assert_eq!(proof.commitment.context.config.k(), 6);
}

#[test]
fn prefix_length_and_minimum_k_are_enforced() {
    let (context, events, signer, key) = fixture(5);
    assert!(PrefixAcknowledgment::create(context, &events[..1], signer.clone(), &key).is_err());
    let mut extra = events.clone();
    extra.push(events[1].clone());
    assert!(PrefixAcknowledgment::create(context, &extra, signer.clone(), &key).is_err());
    for k in [1, 2, 3, 4] {
        assert!(
            ProtocolConfig::new(k, SigningAlgorithm::Ed25519, HashAlgorithm::Sha512256).is_err()
        );
    }
}

#[test]
fn every_event_must_match_the_prefix_context_and_counter_order() {
    let (context, events, signer, key) = fixture(6);
    let mutations: [fn(&mut GraphEvent); 6] = [
        |event| event.dag_id[0] ^= 1,
        |event| event.config = config(5),
        |event| event.configuration_tip[0] ^= 1,
        |event| event.version = 1,
        |event| event.counter += 1,
        |event| event.counter -= 1,
    ];
    for mutation in mutations {
        let mut invalid = events.clone();
        mutation(&mut invalid[0]);
        assert!(PrefixAcknowledgment::create(context, &invalid, signer.clone(), &key).is_err());
    }
    let mut swapped = events.clone();
    swapped.swap(0, 1);
    assert!(PrefixAcknowledgment::create(context, &swapped, signer, &key).is_err());
}

#[test]
fn final_ack_must_bind_the_proposal_branch_and_signer_epoch() {
    let (context, events, signer, key) = fixture(5);
    let mutations: [fn(&mut GraphEvent); 5] = [
        |event| event.operation = GraphOperation::Append { payload: vec![] },
        |event| event.operation = GraphOperation::Acknowledge { proposal: [99; 32] },
        |event| event.branch[0] ^= 1,
        |event| event.author[0] ^= 1,
        |event| event.key_epoch += 1,
    ];
    for mutation in mutations {
        let mut invalid = events.clone();
        mutation(invalid.last_mut().unwrap());
        assert!(PrefixAcknowledgment::create(context, &invalid, signer.clone(), &key).is_err());
    }
}

#[test]
fn verification_requires_external_context_and_authorized_key() {
    let (context, events, signer, key) = fixture(5);
    let proof = PrefixAcknowledgment::create(context, &events, signer.clone(), &key).unwrap();
    let mutations: [fn(&mut PrefixContext); 8] = [
        |context| context.dag_id[0] ^= 1,
        |context| context.config = config(6),
        |context| context.configuration_tip[0] ^= 1,
        |context| context.previous_checkpoint[0] ^= 1,
        |context| context.segment_index += 1,
        |context| context.proposal[0] ^= 1,
        |context| context.branch[0] ^= 1,
        |context| context.first_counter += 1,
    ];
    for mutation in mutations {
        let mut invalid = context;
        mutation(&mut invalid);
        assert!(proof
            .verify(&invalid, &events, &signer, &key.verifying_key())
            .is_err());
    }
    let mut wrong_signer = signer.clone();
    wrong_signer.key_epoch += 1;
    assert!(proof
        .verify(&context, &events, &wrong_signer, &key.verifying_key())
        .is_err());
    let wrong_key = SigningKey::from_bytes(&[9; 32]).verifying_key();
    assert!(proof
        .verify(&context, &events, &signer, &wrong_key)
        .is_err());
    let mut identity = [0; 32];
    identity[0] = 1;
    assert!(proof
        .verify(
            &context,
            &events,
            &signer,
            &VerifyingKey::from_bytes(&identity).unwrap()
        )
        .is_err());
}

#[test]
fn changed_commitment_payload_or_signature_cannot_verify() {
    let (context, events, signer, key) = fixture(6);
    let proof = PrefixAcknowledgment::create(context, &events, signer.clone(), &key).unwrap();
    let mutations: [fn(&mut PrefixAcknowledgment); 6] = [
        |proof| proof.commitment.prefix_len += 1,
        |proof| proof.commitment.last_counter += 1,
        |proof| proof.commitment.expected_final_counter += 1,
        |proof| proof.commitment.ordered_merkle_root[0] ^= 1,
        |proof| proof.commitment.prefix_tip[0] ^= 1,
        |proof| proof.signature[0] ^= 1,
    ];
    for mutation in mutations {
        let mut invalid = proof.clone();
        mutation(&mut invalid);
        assert!(invalid
            .verify(&context, &events, &signer, &key.verifying_key())
            .is_err());
        assert_ne!(invalid.node_id().unwrap(), proof.node_id().unwrap());
    }
    let mut changed = events.clone();
    changed[1].operation = GraphOperation::Append {
        payload: b"different".to_vec(),
    };
    assert!(proof
        .verify(&context, &changed, &signer, &key.verifying_key())
        .is_err());
}

#[test]
fn final_counter_overflow_is_rejected() {
    let (mut context, mut events, signer, key) = fixture(5);
    context.first_counter = u64::MAX - (events.len() - 1) as u64;
    for (index, event) in events.iter_mut().enumerate() {
        event.counter = context.first_counter + index as u64;
    }
    assert!(matches!(
        PrefixAcknowledgment::create(context, &events, signer.clone(), &key),
        Err(TraxError::ArithmeticOverflow)
    ));
    context.first_counter = u64::MAX;
    events[0].counter = u64::MAX;
    assert!(matches!(
        PrefixAcknowledgment::create(context, &events, signer, &key),
        Err(TraxError::ArithmeticOverflow)
    ));
}

#[test]
fn unknown_proof_fields_are_rejected_even_in_canonical_cbor() {
    let (context, events, signer, key) = fixture(5);
    let proof = PrefixAcknowledgment::create(context, &events, signer, &key).unwrap();
    let mut value = Value::serialized(&proof).unwrap();
    value
        .as_map_mut()
        .unwrap()
        .push((Value::Text("unexpected".to_owned()), Value::Null));
    let bytes = encode_deterministic(&value).unwrap();
    assert!(decode::<Value>(&bytes).is_ok());
    assert!(decode::<PrefixAcknowledgment>(&bytes).is_err());
}
