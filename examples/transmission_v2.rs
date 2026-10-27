//! Local V2 simulation; real hosts retain their own keys and exchange only
//! canonical public genesis nodes, packets and the initiator's terminal node.
use ed25519_dalek::SigningKey;
use trax::genesis::{
    accept_genesis_offer, confirm_genesis, create_genesis_offer, TransmissionProfileV2,
    VerifiedGenesisV2,
};
use trax::transmission::SessionV2;
use trax::TraxError;

fn exchange(
    sender: &mut SessionV2,
    receiver: &mut SessionV2,
    key: &SigningKey,
    kind: &str,
    count: usize,
) -> Result<(), TraxError> {
    let chunks: Vec<_> = (0..count)
        .map(|index| format!("{kind} packet {index}: ").into_bytes())
        .collect();
    let expected: Vec<_> = chunks.iter().flatten().copied().collect();
    let packets = sender.build_transmission(key, kind, &chunks)?;
    assert_eq!(packets.len(), count);
    sender.start_receive()?;
    receiver.start_receive()?;
    let before = receiver.checkpoint();
    for (index, packet) in packets.into_iter().enumerate() {
        let bytes = trax::encoding::encode_deterministic(&packet)?;
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
    println!("Both peers admitted {count}-packet {kind} after its final signature.");
    Ok(())
}

fn main() -> Result<(), TraxError> {
    let a = SigningKey::generate(&mut rand::rngs::OsRng);
    let b = SigningKey::generate(&mut rand::rngs::OsRng);
    let a_id = a.verifying_key().to_bytes();
    let b_id = b.verifying_key().to_bytes();
    let offer = create_genesis_offer(&a, rand::random(), TransmissionProfileV2::default())?;
    // Each explicit callback represents the host's own trust-acceptance policy.
    let acceptance = accept_genesis_offer(&offer, &b, |key| key == &a_id)?;
    let confirmation = confirm_genesis(&offer, &acceptance, &a, |key| key == &b_id)?;
    let transcript = [offer, acceptance, confirmation];
    let trust = |key: &[u8; 32]| key == &a_id || key == &b_id;
    let nonce = rand::random();
    let mut a_session = SessionV2::new(
        VerifiedGenesisV2::verify(transcript.clone(), trust)?,
        a_id,
        nonce,
    )?;
    let mut b_session = SessionV2::new(VerifiedGenesisV2::verify(transcript, trust)?, a_id, nonce)?;

    exchange(&mut a_session, &mut b_session, &a, "request", 100)?;
    exchange(&mut b_session, &mut a_session, &b, "response", 17)?;
    exchange(&mut a_session, &mut b_session, &a, "request", 3)?;
    exchange(&mut b_session, &mut a_session, &b, "response", 2)?;

    let terminal = a_session.create_close(&a)?;
    let bytes = trax::encoding::encode_deterministic(&terminal)?;
    a_session.verify_encoded_close(&bytes)?;
    b_session.verify_encoded_close(&bytes)?;
    assert_eq!(a_session.checkpoint(), b_session.checkpoint());
    assert!(a_session.checkpoint().closed);
    println!("Both peers mirrored A's original signed terminal node; B added no signature.");
    Ok(())
}
