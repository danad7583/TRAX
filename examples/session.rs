//! Two local mirrors of one continuous relationship; no transport is opened.
use ed25519_dalek::SigningKey;
use trax::config::{HashAlgorithm, SigningAlgorithm, TransmissionProfile};
use trax::encoding::encode_deterministic;
use trax::genesis::{accept_genesis_offer, confirm_genesis, create_genesis_offer, VerifiedGenesis};
use trax::session::{HistoryKind, Relationship};
use trax::TraxError;

fn exchange(
    sender: &mut Relationship,
    receiver: &mut Relationship,
    key: &SigningKey,
    kind: &str,
    count: usize,
) -> Result<(), TraxError> {
    let chunks: Vec<_> = (0..count)
        .map(|index| format!("{kind} packet {index}: ").into_bytes())
        .collect();
    let expected: Vec<_> = chunks.iter().flatten().copied().collect();
    let packets = sender.build_transmission(key, kind, &chunks)?;
    sender.start_receive()?;
    receiver.start_receive()?;
    let before = receiver.checkpoint();
    for (index, packet) in packets.into_iter().enumerate() {
        let bytes = encode_deterministic(&packet)?;
        let local = sender.stage_encoded_packet(&bytes)?;
        let remote = receiver.stage_encoded_packet(&bytes)?;
        if index + 1 == count {
            assert_eq!(local.expect("final sender admission").payload(), expected);
            assert_eq!(
                remote.expect("final receiver admission").payload(),
                expected
            );
        } else {
            assert!(local.is_none());
            assert!(remote.is_none());
            assert_eq!(receiver.checkpoint(), before);
        }
    }
    assert_eq!(sender.checkpoint(), receiver.checkpoint());
    println!("Both mirrors admitted a {count}-packet {kind} after its final signature.");
    Ok(())
}

fn close(
    initiator: &mut Relationship,
    responder: &mut Relationship,
    key: &SigningKey,
) -> Result<(), TraxError> {
    let terminal = initiator.create_close(key)?;
    let bytes = encode_deterministic(&terminal)?;
    initiator.verify_encoded_close(&bytes)?;
    responder.verify_encoded_close(&bytes)?;
    assert_eq!(initiator.checkpoint(), responder.checkpoint());
    assert!(matches!(
        responder.record(&responder.checkpoint().tip).unwrap().kind,
        HistoryKind::SessionTerminal { .. }
    ));
    Ok(())
}

fn main() -> Result<(), TraxError> {
    let a = SigningKey::generate(&mut rand::rngs::OsRng);
    let b = SigningKey::generate(&mut rand::rngs::OsRng);
    let a_id = a.verifying_key().to_bytes();
    let b_id = b.verifying_key().to_bytes();
    let profile = TransmissionProfile {
        signing_algorithm: SigningAlgorithm::Ed25519,
        hash_algorithm: HashAlgorithm::Sha512256,
        ..TransmissionProfile::default()
    };
    let offer = create_genesis_offer(&a, rand::random(), profile)?;
    // Each callback is the host's explicit identity-acceptance policy.
    let acceptance = accept_genesis_offer(&offer, &b, |key| key == &a_id)?;
    let confirmation = confirm_genesis(&offer, &acceptance, &a, |key| key == &b_id)?;
    let transcript = [offer, acceptance, confirmation];
    let trust = |key: &[u8; 32]| key == &a_id || key == &b_id;
    let mut a_history = Relationship::new(VerifiedGenesis::verify(transcript.clone(), trust)?)?;
    let mut b_history = Relationship::new(VerifiedGenesis::verify(transcript, trust)?)?;

    a_history.begin_session(a_id, rand::random())?;
    // B learns and verifies the new session from A's first signed transmission.
    exchange(&mut a_history, &mut b_history, &a, "request", 100)?;
    exchange(&mut b_history, &mut a_history, &b, "response", 17)?;
    exchange(&mut a_history, &mut b_history, &a, "request", 3)?;
    exchange(&mut b_history, &mut a_history, &b, "response", 2)?;
    close(&mut a_history, &mut b_history, &a)?;
    let prior_terminal = b_history.checkpoint().tip;

    // The other participant starts the next session from the accepted closure.
    b_history.begin_session(b_id, rand::random())?;
    assert_eq!(
        b_history.session().unwrap().context().previous_tip,
        prior_terminal
    );
    exchange(&mut b_history, &mut a_history, &b, "request", 7)?;
    exchange(&mut a_history, &mut b_history, &a, "response", 1)?;
    close(&mut b_history, &mut a_history, &b)?;

    assert_eq!(a_history.history(), b_history.history());
    let tip = a_history.checkpoint().tip;
    assert_eq!(
        a_history.ancestors(&tip)?.len(),
        a_history.history().len() - 1
    );
    assert_eq!(a_history.checkpoint().completed_sessions, 2);
    println!("Two closed sessions share one traversable history, including both original terminal signatures.");
    Ok(())
}
