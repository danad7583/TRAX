use ed25519_dalek::SigningKey;
use trax::crypto::{
    ed25519_sign_merkle_root_k8_raw, hash32, merkle_root_and_proofs_k8, verify_merkle_inclusion_k8,
};
use trax::dag::{
    create_segment_seal_k8, event_bytes, event_tip, lineage_key_id, receiver_id,
    verify_segment_proof_for_context, verify_segment_proof_intrinsic, ReceiveAdmissionWindow,
    TrustedSessionContext,
};
use trax::{PostGenesisEventV1, SegmentProof, TraxError};

struct Fixture {
    events: Vec<PostGenesisEventV1>,
    payloads: Vec<Vec<u8>>,
}

fn fixture(key: &SigningKey, context: &TrustedSessionContext) -> Fixture {
    let mut tip = context.committed_tip();
    let mut payloads = Vec::new();
    let events = (0..8)
        .map(|i| {
            let payload = format!("payload-{i}").into_bytes();
            let event = PostGenesisEventV1 {
                version: 1,
                session_id: context.session_id(),
                lineage_key_id: lineage_key_id(&key.verifying_key()),
                receiver_id: context.receiver_id(),
                segment_index: context.segment_index(),
                counter: context.next_counter() + i,
                previous_tip: tip,
                content_hash: hash32(format!("content-{i}").as_bytes()),
                payload_hash: hash32(&payload),
            };
            tip = event_tip(&event).unwrap();
            payloads.push(payload);
            event
        })
        .collect();
    Fixture { events, payloads }
}

fn context(
    key: &SigningKey,
    receiver_key: &SigningKey,
    session: &[u8],
    tip: [u8; 32],
    segment: u64,
    counter: u64,
) -> TrustedSessionContext {
    TrustedSessionContext::from_verified_state(
        hash32(session),
        receiver_id(&receiver_key.verifying_key()),
        key.verifying_key(),
        tip,
        segment,
        counter,
    )
}

fn stage_all(window: &mut ReceiveAdmissionWindow, f: &Fixture) {
    for (event, payload) in f.events.iter().zip(&f.payloads) {
        window.stage_with_payload(event.clone(), payload).unwrap();
    }
}

#[test]
fn payloads_are_required_and_first_seven_remain_provisional() {
    let key = SigningKey::from_bytes(&[1; 32]);
    let receiver = SigningKey::from_bytes(&[2; 32]);
    let genesis = hash32(b"genesis");
    let context = context(&key, &receiver, b"session", genesis, 0, 10);
    let f = fixture(&key, &context);
    let seal = create_segment_seal_k8(&key, &f.events).unwrap();
    let mut window = ReceiveAdmissionWindow::new_k8(context);

    assert!(matches!(
        window.stage_with_payload(f.events[0].clone(), b"wrong"),
        Err(TraxError::PayloadHashMismatch)
    ));
    assert_eq!(window.provisional_count(), 0);
    for (event, payload) in f.events.iter().zip(&f.payloads).take(7) {
        window.stage_with_payload(event.clone(), payload).unwrap();
    }
    assert_eq!(window.provisional_count(), 7);
    assert_eq!(window.committed_count(), 0);
    assert_eq!(window.committed_tip(), genesis);
    window
        .stage_with_payload(f.events[7].clone(), &f.payloads[7])
        .unwrap();
    assert_eq!(window.verify_and_commit(&seal).unwrap(), f.events);
    assert_eq!(window.committed_count(), 8);
}

#[test]
fn intrinsic_validity_does_not_imply_context_admission() {
    let key = SigningKey::from_bytes(&[3; 32]);
    let receiver = SigningKey::from_bytes(&[4; 32]);
    let base = context(
        &key,
        &receiver,
        b"other-session",
        hash32(b"other-tip"),
        4,
        40,
    );
    let f = fixture(&key, &base);
    let proof = SegmentProof {
        seal: create_segment_seal_k8(&key, &f.events).unwrap(),
        events: f.events,
    };
    verify_segment_proof_intrinsic(&proof, &key.verifying_key()).unwrap();

    let cases = [
        context(
            &key,
            &receiver,
            b"current-session",
            base.committed_tip(),
            4,
            40,
        ),
        context(
            &key,
            &SigningKey::from_bytes(&[5; 32]),
            b"other-session",
            base.committed_tip(),
            4,
            40,
        ),
        context(
            &key,
            &receiver,
            b"other-session",
            hash32(b"wrong-tip"),
            4,
            40,
        ),
        context(
            &key,
            &receiver,
            b"other-session",
            base.committed_tip(),
            5,
            40,
        ),
        context(
            &key,
            &receiver,
            b"other-session",
            base.committed_tip(),
            4,
            41,
        ),
    ];
    for wrong_context in cases {
        assert!(verify_segment_proof_for_context(&proof, &wrong_context).is_err());
    }
}

#[test]
fn tampered_payload_never_enters_provisional_state() {
    let key = SigningKey::from_bytes(&[6; 32]);
    let receiver = SigningKey::from_bytes(&[7; 32]);
    let context = context(&key, &receiver, b"session", hash32(b"g"), 0, 0);
    let f = fixture(&key, &context);
    let mut window = ReceiveAdmissionWindow::new_k8(context);
    let mut changed = f.payloads[0].clone();
    changed[0] ^= 1;
    assert!(matches!(
        window.stage_with_payload(f.events[0].clone(), &changed),
        Err(TraxError::PayloadHashMismatch)
    ));
    assert_eq!(window.provisional_count(), 0);
}

#[test]
fn failed_verification_preserves_every_committed_state_field() {
    let key = SigningKey::from_bytes(&[8; 32]);
    let receiver = SigningKey::from_bytes(&[9; 32]);
    let genesis = hash32(b"g");
    let initial = context(&key, &receiver, b"session", genesis, 0, 0);
    let first = fixture(&key, &initial);
    let mut window = ReceiveAdmissionWindow::new_k8(initial);
    stage_all(&mut window, &first);
    window
        .verify_and_commit(&create_segment_seal_k8(&key, &first.events).unwrap())
        .unwrap();
    let snapshot = (
        window.committed_tip(),
        window.committed_count(),
        window.segment_index(),
        window.next_counter(),
    );

    let second = fixture(&key, window.trusted_context());
    stage_all(&mut window, &second);
    let mut bad = create_segment_seal_k8(&key, &second.events).unwrap();
    bad.signature[0] ^= 1;
    assert!(window.verify_and_commit(&bad).is_err());
    assert_eq!(
        snapshot,
        (
            window.committed_tip(),
            window.committed_count(),
            window.segment_index(),
            window.next_counter(),
        )
    );
    assert_eq!(window.provisional_count(), 0);
}

#[test]
fn every_seal_failure_is_atomic_after_prior_commit() {
    type Mutator = fn(&mut trax::SegmentSealV1);
    let mutations: [Mutator; 7] = [
        |seal| seal.signature[0] ^= 1,
        |seal| seal.commitment.session_id[0] ^= 1,
        |seal| seal.commitment.receiver_id[0] ^= 1,
        |seal| seal.commitment.starting_committed_tip[0] ^= 1,
        |seal| seal.commitment.segment_index += 1,
        |seal| seal.commitment.first_counter += 1,
        |seal| seal.commitment.ordered_merkle_root[0] ^= 1,
    ];

    for (case, mutate) in mutations.into_iter().enumerate() {
        let key = SigningKey::from_bytes(&[20; 32]);
        let receiver = SigningKey::from_bytes(&[21; 32]);
        let initial = context(&key, &receiver, b"session", hash32(b"g"), 0, 0);
        let first = fixture(&key, &initial);
        let mut window = ReceiveAdmissionWindow::new_k8(initial);
        stage_all(&mut window, &first);
        window
            .verify_and_commit(&create_segment_seal_k8(&key, &first.events).unwrap())
            .unwrap();
        let before = (
            window.committed_tip(),
            window.committed_count(),
            window.segment_index(),
            window.next_counter(),
        );
        let second = fixture(&key, window.trusted_context());
        stage_all(&mut window, &second);
        let mut seal = create_segment_seal_k8(&key, &second.events).unwrap();
        mutate(&mut seal);
        assert!(window.verify_and_commit(&seal).is_err(), "case {case}");
        assert_eq!(
            before,
            (
                window.committed_tip(),
                window.committed_count(),
                window.segment_index(),
                window.next_counter(),
            ),
            "case {case}"
        );
        assert_eq!(window.provisional_count(), 0, "case {case}");
    }
}

#[test]
fn committed_count_advances_without_retaining_history() {
    let key = SigningKey::from_bytes(&[10; 32]);
    let receiver = SigningKey::from_bytes(&[11; 32]);
    let context = context(&key, &receiver, b"session", hash32(b"g"), 0, 0);
    let mut window = ReceiveAdmissionWindow::new_k8(context);
    for expected in [8, 16] {
        let f = fixture(&key, window.trusted_context());
        let seal = create_segment_seal_k8(&key, &f.events).unwrap();
        stage_all(&mut window, &f);
        let released = window.verify_and_commit(&seal).unwrap();
        assert_eq!(released.len(), 8);
        assert_eq!(window.committed_count(), expected);
        assert_eq!(window.provisional_count(), 0);
    }
}

#[test]
fn receiver_id_is_deterministic_domain_separated_and_key_bound() {
    let receiver = SigningKey::from_bytes(&[12; 32]);
    let unrelated = SigningKey::from_bytes(&[13; 32]);
    let id = receiver_id(&receiver.verifying_key());
    assert_eq!(id, receiver_id(&receiver.verifying_key()));
    assert_ne!(id, hash32(receiver.verifying_key().as_bytes()));
    assert_ne!(id, receiver_id(&unrelated.verifying_key()));
}

#[test]
fn raw_merkle_signature_is_not_a_segment_seal() {
    let key = SigningKey::from_bytes(&[14; 32]);
    let receiver = SigningKey::from_bytes(&[15; 32]);
    let context = context(&key, &receiver, b"session", hash32(b"g"), 0, 0);
    let f = fixture(&key, &context);
    let messages = f
        .events
        .iter()
        .map(event_bytes)
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    let (raw_signature, _) = ed25519_sign_merkle_root_k8_raw(&key, &messages).unwrap();
    let mut seal = create_segment_seal_k8(&key, &f.events).unwrap();
    seal.signature = raw_signature;
    assert!(matches!(
        verify_segment_proof_intrinsic(
            &SegmentProof {
                events: f.events,
                seal
            },
            &key.verifying_key()
        ),
        Err(TraxError::SegmentSignatureFailure)
    ));
}

#[test]
fn inclusion_proofs_remain_order_sensitive() {
    let key = SigningKey::from_bytes(&[16; 32]);
    let receiver = SigningKey::from_bytes(&[17; 32]);
    let context = context(&key, &receiver, b"session", hash32(b"g"), 0, 0);
    let f = fixture(&key, &context);
    let messages = f
        .events
        .iter()
        .map(event_bytes)
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    let (root, proofs) = merkle_root_and_proofs_k8(&messages).unwrap();
    for i in 0..8 {
        assert!(verify_merkle_inclusion_k8(&messages[i], i, &proofs[i], &root).unwrap());
    }
    let mut corrupt = proofs[0].clone();
    corrupt[0][0] ^= 1;
    assert!(!verify_merkle_inclusion_k8(&messages[0], 0, &corrupt, &root).unwrap());
}
