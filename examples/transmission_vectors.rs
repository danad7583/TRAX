//! Explicitly regenerate the public, deterministic V2 conformance transcript.
//! These fixed seeds are test data, never deployment keys.
use ed25519_dalek::SigningKey;
use serde::Serialize;
use trax::encoding::encode_deterministic;
use trax::genesis::{
    accept_genesis_offer, confirm_genesis, create_genesis_offer, GenesisNodeV2,
    TransmissionProfileV2, VerifiedGenesisV2,
};
use trax::transmission::{
    PacketV2, SessionCheckpointV2, SessionContextV2, SessionTerminalV2, SessionV2,
};

#[derive(Serialize)]
struct Vector {
    genesis: [GenesisNodeV2; 3],
    context: SessionContextV2,
    request: Vec<PacketV2>,
    response: Vec<PacketV2>,
    terminal: SessionTerminalV2,
    checkpoint: SessionCheckpointV2,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let a = SigningKey::from_bytes(&[1; 32]);
    let b = SigningKey::from_bytes(&[2; 32]);
    let offer = create_genesis_offer(&a, [3; 32], TransmissionProfileV2::default())?;
    let accept = accept_genesis_offer(&offer, &b, |key| *key == a.verifying_key().to_bytes())?;
    let confirm = confirm_genesis(&offer, &accept, &a, |key| {
        *key == b.verifying_key().to_bytes()
    })?;
    let genesis = [offer, accept, confirm];
    let trusted = [a.verifying_key().to_bytes(), b.verifying_key().to_bytes()];
    let mut session = SessionV2::new(
        VerifiedGenesisV2::verify(genesis.clone(), |key| trusted.contains(key))?,
        trusted[0],
        [4; 32],
    )?;
    let context = session.context().clone();
    let request = session.build_transmission(
        &a,
        "document.request",
        &[b"hello ".to_vec(), b"world".to_vec(), b"!".to_vec()],
    )?;
    session.start_receive()?;
    for packet in &request {
        session.stage_packet(packet.clone())?;
    }
    let response = session.build_transmission(
        &b,
        "document.response",
        &[b"received".to_vec(), b" twelve bytes".to_vec()],
    )?;
    session.start_receive()?;
    for packet in &response {
        session.stage_packet(packet.clone())?;
    }
    let terminal = session.create_close(&a)?;
    session.verify_and_close(&terminal)?;
    let checkpoint = session.checkpoint();
    let vector = Vector {
        genesis,
        context,
        request,
        response,
        terminal,
        checkpoint,
    };
    let bytes = encode_deterministic(&vector)?;
    let path =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("vectors/transmission_v2.cbor");
    std::fs::write(&path, &bytes)?;
    println!("{}: {} bytes", path.display(), bytes.len());
    println!(
        "SHA-512/256={}",
        hex::encode(trax::profile::hash_bytes(
            trax::HashAlgorithm::Sha512256,
            &bytes
        )?)
    );
    Ok(())
}
