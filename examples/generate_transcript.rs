//! Regenerate public conformance data explicitly; fixed seeds are test keys.
use ed25519_dalek::SigningKey;
use serde::Serialize;
use trax::config::TransmissionProfile;
use trax::crypto::hash_domain;
use trax::encoding::encode_deterministic;
use trax::genesis::{
    accept_genesis_offer, confirm_genesis, create_genesis_offer, GenesisNode, VerifiedGenesis,
};
use trax::session::{HistoryRecord, Relationship};
use trax::transmission::{
    Packet, RelationshipCheckpoint, SessionCheckpoint, SessionContext, SessionTerminal,
};

#[derive(Serialize)]
struct SessionVector {
    context: SessionContext,
    transmissions: Vec<Vec<Packet>>,
    terminal: SessionTerminal,
    checkpoint: SessionCheckpoint,
}
#[derive(Serialize)]
struct Transcript {
    genesis: [GenesisNode; 3],
    sessions: Vec<SessionVector>,
    history: Vec<HistoryRecord>,
    checkpoint: RelationshipCheckpoint,
}
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let a = SigningKey::from_bytes(&[1; 32]);
    let b = SigningKey::from_bytes(&[2; 32]);
    let offer = create_genesis_offer(&a, [3; 32], TransmissionProfile::default())?;
    let accept = accept_genesis_offer(&offer, &b, |key| *key == a.verifying_key().to_bytes())?;
    let confirm = confirm_genesis(&offer, &accept, &a, |key| {
        *key == b.verifying_key().to_bytes()
    })?;
    let genesis = [offer, accept, confirm];
    let trusted = [a.verifying_key().to_bytes(), b.verifying_key().to_bytes()];
    let mut relationship = Relationship::new(VerifiedGenesis::verify(genesis.clone(), |key| {
        trusted.contains(key)
    })?)?;
    let mut sessions = Vec::new();
    for (index, (initiator, responder)) in [(&a, &b), (&b, &a)].into_iter().enumerate() {
        relationship.begin_session(initiator.verifying_key().to_bytes(), [index as u8 + 4; 32])?;
        let context = relationship.session().unwrap().context().clone();
        let mut transmissions = Vec::new();
        let rounds = if index == 0 { 2 } else { 1 };
        for _ in 0..rounds {
            for (key, kind, chunks) in [
                (
                    initiator,
                    "document.request",
                    vec![b"hello ".to_vec(), b"world".to_vec(), b"!".to_vec()],
                ),
                (
                    responder,
                    "document.response",
                    vec![b"received".to_vec(), b" twelve bytes".to_vec()],
                ),
            ] {
                let packets = relationship.build_transmission(key, kind, &chunks)?;
                relationship.start_receive()?;
                for packet in &packets {
                    relationship.stage_packet(packet.clone())?;
                }
                transmissions.push(packets);
            }
        }
        let terminal = relationship.create_close(initiator)?;
        relationship.verify_and_close(&terminal)?;
        let checkpoint = relationship.session().unwrap().checkpoint();
        sessions.push(SessionVector {
            context,
            transmissions,
            terminal,
            checkpoint,
        });
    }
    let transcript = Transcript {
        genesis,
        sessions,
        history: relationship.history().to_vec(),
        checkpoint: relationship.checkpoint(),
    };
    let bytes = encode_deterministic(&transcript)?;
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("vectors/relationship.cbor");
    std::fs::write(&path, &bytes)?;
    println!("{}: {} bytes", path.display(), bytes.len());
    println!(
        "SHA-512/256={}",
        hex::encode(hash_domain(trax::HashAlgorithm::Sha512256, b"", &[&bytes])?)
    );
    Ok(())
}
