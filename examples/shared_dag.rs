//! Local simulation: each real host keeps its own private keys and exchanges
//! the serialized public events/proofs through the application's transport.
use ed25519_dalek::SigningKey;
use trax::graph::{participant_id, PairDag, PairGenesis};
use trax::{HashAlgorithm, ProtocolConfig, SigningAlgorithm, TraxError};

fn main() -> Result<(), TraxError> {
    let a = SigningKey::generate(&mut rand::rngs::OsRng);
    let a_new = SigningKey::generate(&mut rand::rngs::OsRng);
    let b = SigningKey::generate(&mut rand::rngs::OsRng);
    let a_id = participant_id(&a.verifying_key().to_bytes());
    let b_id = participant_id(&b.verifying_key().to_bytes());
    let config =
        ProtocolConfig::with_default_k(SigningAlgorithm::Ed25519, HashAlgorithm::Sha512256)?;
    let genesis = PairGenesis::new(
        config,
        rand::random(),
        &a.verifying_key(),
        &b.verifying_key(),
    )?;
    let mut a_dag = PairDag::from_verified_genesis(config, genesis.clone())?;
    let mut b_dag = PairDag::from_verified_genesis(config, genesis)?;
    let new_branch = rand::random();

    // Node 1: authorize replacement with A's current key and prove possession
    // with A's new key. Only public information is transmitted to B.
    let mut a_pending = a_dag.begin_segment();
    let rotation = a_pending.rotate(a_id, a_dag.genesis_id(), new_branch, &a, &a_new)?;
    let mut b_pending = b_dag.begin_segment();
    b_pending.stage(a_pending.events()[0].clone())?;

    // Nodes 2..6: explicit filler. Node 7: B's acknowledgment and its detached
    // signature over the exact seven-node prefix. This is not a K checkpoint.
    let ack = b_pending.acknowledge_and_pad(b_id, &b)?;
    assert_eq!(b_pending.events().len(), 7);
    for event in &b_pending.events()[1..] {
        a_pending.stage(event.clone())?;
    }
    a_pending.accept_ack(&ack)?;
    assert_eq!(a_dag.len(), 1);
    assert_eq!(b_dag.len(), 1); // No partial segment entered trusted history.

    // Node 8: A agrees to close and signs the full checkpoint with its new key.
    // Alternatively A can append a real request here, then seal and continue.
    a_pending.finish_close()?;
    let proof = a_pending.seal(a_id, &a_new)?;
    drop(a_pending);
    drop(b_pending);
    let a_nodes = a_dag.verify_and_commit(&proof)?;
    let b_nodes = b_dag.verify_and_commit(&proof)?;
    assert_eq!(a_nodes, b_nodes);
    assert_eq!(a_dag.checkpoint_tip(), b_dag.checkpoint_tip());
    assert_eq!(b_dag.acknowledgment_for(&rotation), Some(&ack));
    a_dag.verify_history()?;
    b_dag.verify_history()?;
    println!("Both mirrors verified A's rotation, B's signed 7-node acknowledgment, and A's new-key checkpoint at node 8.");
    Ok(())
}
