use ciborium::value::Value;
use ed25519_dalek::{SigningKey, VerifyingKey};
use serde::Serialize;
use trax::config::{HashAlgorithm, ProtocolConfig, SigningAlgorithm};
use trax::crypto::{ed25519_sign, ed25519_verify, hash32};
use trax::encoding::{decode, encode_deterministic};
use trax::graph::{
    participant_id, AuthorityId, GraphEvent, GraphOperation, GraphSegmentProof, PairDag,
    PairGenesis,
};
use trax::profile::hash_bytes;
use trax::storage::DurableDag;
use trax::TraxError;

fn fixture() -> (ProtocolConfig, PairGenesis, SigningKey) {
    let config =
        ProtocolConfig::new(5, SigningAlgorithm::Ed25519, HashAlgorithm::Sha512256).unwrap();
    let key = SigningKey::from_bytes(&[1; 32]);
    let peer = SigningKey::from_bytes(&[2; 32]);
    let genesis =
        PairGenesis::new(config, [3; 32], &key.verifying_key(), &peer.verifying_key()).unwrap();
    (config, genesis, key)
}

fn proof(dag: &PairDag, key: &SigningKey) -> GraphSegmentProof {
    let author = participant_id(&key.verifying_key().to_bytes());
    let mut pending = dag.begin_segment();
    for _ in 0..dag.config().k() {
        pending
            .append(author, dag.main_branch(), b"authenticated payload".to_vec())
            .unwrap();
    }
    let signature = pending
        .commitment()
        .unwrap()
        .sign(
            AuthorityId {
                participant: author,
                key_epoch: 0,
            },
            key,
        )
        .unwrap();
    pending.proof(signature).unwrap()
}

fn add_unknown_field(value: &mut Value) {
    let Value::Map(fields) = value else {
        panic!("expected a serialized struct map");
    };
    fields.push((
        Value::Text("unauthenticated_extension".to_owned()),
        Value::Bool(true),
    ));
}

fn with_unknown_field(value: &impl Serialize) -> Vec<u8> {
    let mut value = Value::serialized(value).unwrap();
    add_unknown_field(&mut value);
    encode_deterministic(&value).unwrap()
}

#[test]
fn genesis_event_and_proof_reject_unknown_fields_in_canonical_cbor() {
    let (config, genesis, key) = fixture();
    let dag = PairDag::from_verified_genesis(config, genesis.clone()).unwrap();
    let proof = proof(&dag, &key);
    let genesis_bytes = with_unknown_field(&genesis);
    let event_bytes = with_unknown_field(&proof.events[0]);
    let proof_bytes = with_unknown_field(&proof);
    // They are valid canonical CBOR: rejection must come from the protocol schema.
    assert!(decode::<Value>(&genesis_bytes).is_ok());
    assert!(decode::<Value>(&event_bytes).is_ok());
    assert!(decode::<Value>(&proof_bytes).is_ok());
    assert!(decode::<PairGenesis>(&genesis_bytes).is_err());
    assert!(decode::<GraphEvent>(&event_bytes).is_err());
    assert!(decode::<GraphSegmentProof>(&proof_bytes).is_err());
}

#[test]
fn proof_cannot_hide_unknown_fields_inside_an_event_or_operation() {
    let (config, genesis, key) = fixture();
    let dag = PairDag::from_verified_genesis(config, genesis).unwrap();
    let proof = proof(&dag, &key);
    let mut value = Value::serialized(&proof).unwrap();
    let fields = value.as_map_mut().unwrap();
    let (_, events) = fields
        .iter_mut()
        .find(|(key, _)| key.as_text() == Some("events"))
        .unwrap();
    add_unknown_field(&mut events.as_array_mut().unwrap()[0]);
    let encoded = encode_deterministic(&value).unwrap();
    assert!(decode::<Value>(&encoded).is_ok());
    assert!(decode::<GraphSegmentProof>(&encoded).is_err());

    let mut operation = Value::serialized(&GraphOperation::Append {
        payload: b"data".to_vec(),
    })
    .unwrap();
    add_unknown_field(&mut operation.as_map_mut().unwrap()[0].1);
    let encoded = encode_deterministic(&operation).unwrap();
    assert!(decode::<GraphOperation>(&encoded).is_err());
}

fn identity_key() -> VerifyingKey {
    let mut identity = [0; 32];
    identity[0] = 1;
    let key = VerifyingKey::from_bytes(&identity).unwrap();
    assert!(key.is_weak());
    key
}

#[test]
fn weak_public_key_cannot_authenticate_messages_or_establish_genesis() {
    let (config, genesis, strong) = fixture();
    let weak = identity_key();
    let mut identity_signature = [0; 64];
    identity_signature[0] = 1;
    assert!(!ed25519_verify(
        &weak,
        b"arbitrary checkpoint",
        &identity_signature
    ));
    assert!(matches!(
        PairGenesis::new(config, [3; 32], &strong.verifying_key(), &weak),
        Err(TraxError::Crypto)
    ));
    let mut forged = genesis;
    forged.initial_public_keys = [strong.verifying_key().to_bytes(), weak.to_bytes()];
    forged.initial_public_keys.sort();
    assert!(matches!(
        PairDag::from_verified_genesis(config, forged),
        Err(TraxError::Crypto)
    ));
}

#[test]
fn weak_rotation_key_is_rejected_without_staging_or_admission() {
    let (config, genesis, key) = fixture();
    let mut dag = PairDag::from_verified_genesis(config, genesis).unwrap();
    let author = participant_id(&key.verifying_key().to_bytes());
    let mut pending = dag.begin_segment();
    let new_key = SigningKey::from_bytes(&[4; 32]);
    pending
        .rotate(
            author,
            dag.genesis_id(),
            hash32(b"rotation"),
            &key,
            &new_key,
        )
        .unwrap();
    let mut invalid = pending.events()[0].clone();
    invalid.operation = GraphOperation::Rotate {
        new_public_key: identity_key().to_bytes(),
    };
    invalid.authorization = Some(ed25519_sign(
        &key,
        &invalid.authorization_signing_bytes().unwrap(),
    ));
    drop(pending);
    let mut rejected = dag.begin_segment();
    assert!(rejected.stage(invalid.clone()).is_err());
    assert!(rejected.events().is_empty());
    drop(rejected);
    let mut candidate = proof(&dag, &key);
    candidate.events[0] = invalid;
    let old_tip = dag.checkpoint_tip();
    assert!(dag.verify_and_commit(&candidate).is_err());
    assert_eq!(dag.checkpoint_tip(), old_tip);
    assert_eq!(dag.segment_index(), 0);
}

#[test]
fn journal_open_cannot_bypass_weak_genesis_validation() {
    let (config, mut genesis, key) = fixture();
    genesis.initial_public_keys = [key.verifying_key().to_bytes(), identity_key().to_bytes()];
    genesis.initial_public_keys.sort();
    let anchor = genesis.node_id().unwrap();
    #[derive(Serialize)]
    enum Record {
        Genesis(PairGenesis),
    }
    let record = encode_deterministic(&Record::Genesis(genesis)).unwrap();
    let mut journal = b"TRAX:PAIR-DAG:JOURNAL\0".to_vec();
    journal.extend_from_slice(&3_u32.to_be_bytes());
    journal.extend_from_slice(&(record.len() as u64).to_be_bytes());
    journal.extend_from_slice(&record);
    journal.extend_from_slice(&hash_bytes(HashAlgorithm::Sha512256, &record).unwrap());
    let path = std::env::temp_dir().join(format!(
        "trax-weak-genesis-{}-{:016x}.log",
        std::process::id(),
        rand::random::<u64>()
    ));
    std::fs::write(&path, journal).unwrap();
    assert!(matches!(
        DurableDag::open(&path, config, anchor),
        Err(TraxError::Crypto)
    ));
    std::fs::remove_file(path).unwrap();
}
