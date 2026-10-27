use serde::{Deserialize, Serialize};
use trax::crypto::hash_domain;
use trax::encoding::{decode_strict, encode_deterministic};
use trax::genesis::{GenesisNode, VerifiedGenesis};
use trax::session::{HistoryRecord, Relationship};
use trax::transmission::{
    Packet, RelationshipCheckpoint, SessionCheckpoint, SessionContext, SessionTerminal,
};

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SessionVector {
    context: SessionContext,
    transmissions: Vec<Vec<Packet>>,
    terminal: SessionTerminal,
    checkpoint: SessionCheckpoint,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Transcript {
    genesis: [GenesisNode; 3],
    sessions: Vec<SessionVector>,
    history: Vec<HistoryRecord>,
    checkpoint: RelationshipCheckpoint,
}

#[test]
fn frozen_transcript_reconstructs_two_sessions_and_all_original_signed_records() {
    let bytes = include_bytes!("../vectors/relationship.cbor");
    assert_eq!(
        hex::encode(hash_domain(trax::HashAlgorithm::Sha512256, b"", &[bytes]).unwrap()),
        "f9e1504e0aaa105315455f403500b3995a03e468620cc95df6726e25c7e9e957"
    );
    let vector: Transcript = decode_strict(bytes, 256 * 1024).unwrap();
    assert_eq!(encode_deterministic(&vector).unwrap(), bytes);
    let trusted = [
        vector.genesis[0].event.initiator_public_key,
        vector.genesis[1].event.responder_public_key.unwrap(),
    ];
    let mut relationship = Relationship::new(
        VerifiedGenesis::verify(vector.genesis, |key| trusted.contains(key)).unwrap(),
    )
    .unwrap();
    for entry in vector.sessions {
        for packets in entry.transmissions {
            relationship.start_receive().unwrap();
            for packet in packets {
                relationship.stage_packet(packet).unwrap();
            }
        }
        assert_eq!(relationship.session().unwrap().context(), &entry.context);
        relationship.verify_and_close(&entry.terminal).unwrap();
        assert_eq!(
            relationship.session().unwrap().checkpoint(),
            entry.checkpoint
        );
        assert!(relationship
            .record(&relationship.checkpoint().tip)
            .is_some());
    }
    assert_eq!(relationship.history(), vector.history);
    assert_eq!(relationship.checkpoint(), vector.checkpoint);
    for record in relationship.history() {
        assert_eq!(relationship.record(&record.id).unwrap(), record);
    }
}
