use serde::{Deserialize, Serialize};
use trax::encoding::{decode_strict, encode_deterministic};
use trax::genesis::{GenesisNodeV2, VerifiedGenesisV2};
use trax::transmission::{
    PacketV2, SessionCheckpointV2, SessionContextV2, SessionTerminalV2, SessionV2,
};

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Vector {
    genesis: [GenesisNodeV2; 3],
    context: SessionContextV2,
    request: Vec<PacketV2>,
    response: Vec<PacketV2>,
    terminal: SessionTerminalV2,
    checkpoint: SessionCheckpointV2,
}

#[test]
fn frozen_full_transcript_verifies_without_recreating_any_signature() {
    let bytes = include_bytes!("../vectors/transmission_v2.cbor");
    assert_eq!(
        hex::encode(trax::profile::hash_bytes(trax::HashAlgorithm::Sha512256, bytes).unwrap()),
        "1c524040831fa1f2c43fa1f68e6520fdef0982b1e83fa3dec177e309774dfaff"
    );
    let vector: Vector = decode_strict(bytes, 65536).unwrap();
    assert_eq!(encode_deterministic(&vector).unwrap(), bytes);
    let trusted = [vector.context.initiator, vector.context.responder];
    let genesis = VerifiedGenesisV2::verify(vector.genesis, |key| trusted.contains(key)).unwrap();
    let mut session =
        SessionV2::new(genesis, vector.context.initiator, vector.context.nonce).unwrap();
    assert_eq!(session.context(), &vector.context);
    for packets in [&vector.request, &vector.response] {
        session.start_receive().unwrap();
        for packet in packets {
            session.stage_packet(packet.clone()).unwrap();
        }
    }
    session.verify_and_close(&vector.terminal).unwrap();
    assert_eq!(session.checkpoint(), vector.checkpoint);
}
