use ed25519_dalek::SigningKey;
use trax::config::SegmentConfig;
use trax::crypto::{
    ed25519_sign_merkle_root_k8_raw, hash32, merkle_root_and_proofs_k8, verify_merkle_inclusion_k8,
};
use trax::dag::{
    create_segment_seal, event_bytes, event_tip, lineage_key_id, receiver_id,
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
    let events = (0..context.config().k() as u64)
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
        SegmentConfig::new(8).unwrap(),
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
    let seal = create_segment_seal(SegmentConfig::new(8).unwrap(), &key, &f.events).unwrap();
    let mut window = ReceiveAdmissionWindow::new(context).unwrap();

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
        seal: create_segment_seal(SegmentConfig::new(8).unwrap(), &key, &f.events).unwrap(),
        events: f.events,
    };
    verify_segment_proof_intrinsic(SegmentConfig::new(8).unwrap(), &proof, &key.verifying_key())
        .unwrap();

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
    let mut window = ReceiveAdmissionWindow::new(context).unwrap();
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
    let mut window = ReceiveAdmissionWindow::new(initial).unwrap();
    stage_all(&mut window, &first);
    window
        .verify_and_commit(
            &create_segment_seal(SegmentConfig::new(8).unwrap(), &key, &first.events).unwrap(),
        )
        .unwrap();
    let snapshot = (
        window.committed_tip(),
        window.committed_count(),
        window.segment_index(),
        window.next_counter(),
    );

    let second = fixture(&key, window.trusted_context());
    stage_all(&mut window, &second);
    let mut bad =
        create_segment_seal(SegmentConfig::new(8).unwrap(), &key, &second.events).unwrap();
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
        let mut window = ReceiveAdmissionWindow::new(initial).unwrap();
        stage_all(&mut window, &first);
        window
            .verify_and_commit(
                &create_segment_seal(SegmentConfig::new(8).unwrap(), &key, &first.events).unwrap(),
            )
            .unwrap();
        let before = (
            window.committed_tip(),
            window.committed_count(),
            window.segment_index(),
            window.next_counter(),
        );
        let second = fixture(&key, window.trusted_context());
        stage_all(&mut window, &second);
        let mut seal =
            create_segment_seal(SegmentConfig::new(8).unwrap(), &key, &second.events).unwrap();
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
    let mut window = ReceiveAdmissionWindow::new(context).unwrap();
    for expected in [8, 16] {
        let f = fixture(&key, window.trusted_context());
        let seal = create_segment_seal(SegmentConfig::new(8).unwrap(), &key, &f.events).unwrap();
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
    let mut seal = create_segment_seal(SegmentConfig::new(8).unwrap(), &key, &f.events).unwrap();
    seal.signature = raw_signature;
    assert!(matches!(
        verify_segment_proof_intrinsic(
            SegmentConfig::new(8).unwrap(),
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

fn configured_context(
    config: SegmentConfig,
    key: &SigningKey,
    receiver: &SigningKey,
    segment_index: u64,
    next_counter: u64,
) -> TrustedSessionContext {
    TrustedSessionContext::from_verified_state(
        config,
        hash32(b"configured session"),
        receiver_id(&receiver.verifying_key()),
        key.verifying_key(),
        hash32(b"configured genesis"),
        segment_index,
        next_counter,
    )
}

#[test]
fn positive_configured_sizes_admit_only_complete_windows() {
    let key = SigningKey::from_bytes(&[30; 32]);
    let receiver = SigningKey::from_bytes(&[31; 32]);
    for k in [1, 3, 4, 5, 8, 14] {
        let config = SegmentConfig::new(k).unwrap();
        let context = configured_context(config, &key, &receiver, 0, 0);
        let f = fixture(&key, &context);
        let seal = create_segment_seal(config, &key, &f.events).unwrap();
        assert_eq!(seal.commitment.k as usize, k);
        assert!(matches!(
            create_segment_seal(config, &key, &f.events[..k - 1]),
            Err(TraxError::IncompleteSegment)
        ));
        let mut window = ReceiveAdmissionWindow::new(context).unwrap();
        for i in 0..k - 1 {
            window
                .stage_with_payload(f.events[i].clone(), &f.payloads[i])
                .unwrap();
        }
        let before_tip = window.committed_tip();
        assert!(matches!(
            window.verify_and_commit(&seal),
            Err(TraxError::IncompleteSegment)
        ));
        assert_eq!(window.committed_tip(), before_tip);
        assert_eq!(window.committed_count(), 0);
        assert_eq!(window.provisional_count(), k - 1);
        window
            .stage_with_payload(f.events[k - 1].clone(), &f.payloads[k - 1])
            .unwrap();
        assert_eq!(window.verify_and_commit(&seal).unwrap(), f.events);
        assert_eq!(window.committed_count(), k as u64);
        assert_eq!(window.next_counter(), k as u64);
        assert_eq!(window.segment_index(), 1);
        assert_eq!(window.provisional_count(), 0);
    }
}

#[test]
fn verifier_requires_its_explicit_k_and_the_signed_k_to_agree() {
    let key = SigningKey::from_bytes(&[32; 32]);
    let receiver = SigningKey::from_bytes(&[33; 32]);
    for k in [1, 3, 4, 8, 14] {
        let config = SegmentConfig::new(k).unwrap();
        let context = configured_context(config, &key, &receiver, 0, 0);
        let f = fixture(&key, &context);
        let proof = SegmentProof {
            seal: create_segment_seal(config, &key, &f.events).unwrap(),
            events: f.events,
        };
        verify_segment_proof_intrinsic(config, &proof, &key.verifying_key()).unwrap();
        verify_segment_proof_for_context(&proof, &context).unwrap();
        for other_k in [1, 3, 4, 8, 14].into_iter().filter(|other| *other != k) {
            let other = SegmentConfig::new(other_k).unwrap();
            assert!(verify_segment_proof_intrinsic(other, &proof, &key.verifying_key()).is_err());
            let other_context = configured_context(other, &key, &receiver, 0, 0);
            assert!(verify_segment_proof_for_context(&proof, &other_context).is_err());
        }
        let mut changed = proof.clone();
        changed.seal.commitment.k += 1;
        // Even a fresh valid signature must not override the receiver's K.
        changed.seal.signature = trax::crypto::ed25519_sign(
            &key,
            &trax::dag::commitment_signing_bytes(&changed.seal.commitment).unwrap(),
        );
        assert!(matches!(
            verify_segment_proof_for_context(&changed, &context),
            Err(TraxError::InvalidSegmentSize)
        ));
    }
}

#[test]
fn merkle_paths_support_odd_sizes_and_reject_missing_or_extra_siblings() {
    use trax::crypto::{merkle_root, root_and_proofs, verify_merkle_inclusion};
    for k in 1..=32 {
        let config = SegmentConfig::new(k).unwrap();
        let messages: Vec<_> = (0..k)
            .map(|i| format!("ordered message {i}").into_bytes())
            .collect();
        let (root, proofs) = root_and_proofs(config, &messages).unwrap();
        assert_eq!(merkle_root(config, &messages).unwrap(), root);
        assert!(root_and_proofs(config, &messages[..k - 1]).is_err());
        for i in 0..k {
            assert!(verify_merkle_inclusion(config, &messages[i], i, &proofs[i], &root).unwrap());
            assert!(
                !verify_merkle_inclusion(config, b"changed payload", i, &proofs[i], &root).unwrap()
            );
            let mut extra = proofs[i].clone();
            extra.push([0; 32]);
            assert!(verify_merkle_inclusion(config, &messages[i], i, &extra, &root).is_err());
            if !proofs[i].is_empty() {
                assert!(verify_merkle_inclusion(
                    config,
                    &messages[i],
                    i,
                    &proofs[i][..proofs[i].len() - 1],
                    &root
                )
                .is_err());
            }
            if k > 1 {
                assert!(!verify_merkle_inclusion(
                    config,
                    &messages[i],
                    (i + 1) % k,
                    &proofs[i],
                    &root
                )
                .unwrap_or(false));
            }
        }
        assert!(verify_merkle_inclusion(config, &messages[0], k, &proofs[0], &root).is_err());
        match k {
            1 => assert!(proofs[0].is_empty()),
            3 => assert_eq!(proofs.iter().map(Vec::len).collect::<Vec<_>>(), [2, 2, 1]),
            5 => assert_eq!(
                proofs.iter().map(Vec::len).collect::<Vec<_>>(),
                [3, 3, 3, 3, 1]
            ),
            _ => {}
        }
    }
}

fn window_snapshot(window: &ReceiveAdmissionWindow) -> ([u8; 32], [u8; 32], u64, u64, u64, usize) {
    (
        window.committed_tip(),
        window.provisional_tip(),
        window.committed_count(),
        window.segment_index(),
        window.next_counter(),
        window.provisional_count(),
    )
}

#[test]
fn restore_and_commit_arithmetic_overflow_never_mutates_a_window() {
    let key = SigningKey::from_bytes(&[34; 32]);
    let receiver = SigningKey::from_bytes(&[35; 32]);
    let overflowing_restore =
        configured_context(SegmentConfig::new(3).unwrap(), &key, &receiver, u64::MAX, 0);
    assert!(matches!(
        ReceiveAdmissionWindow::new(overflowing_restore),
        Err(TraxError::ArithmeticOverflow)
    ));
    // Exercise each independently: segment index, next counter, committed count.
    for (k, segment, counter) in [(1, u64::MAX, 0), (1, 0, u64::MAX), (3, u64::MAX / 3, 0)] {
        let config = SegmentConfig::new(k).unwrap();
        let context = configured_context(config, &key, &receiver, segment, counter);
        let f = fixture(&key, &context);
        let seal = create_segment_seal(config, &key, &f.events).unwrap();
        let mut window = ReceiveAdmissionWindow::new(context).unwrap();
        stage_all(&mut window, &f);
        let before = window_snapshot(&window);
        assert!(matches!(
            window.verify_and_commit(&seal),
            Err(TraxError::ArithmeticOverflow)
        ));
        assert_eq!(window_snapshot(&window), before);
    }
}

#[test]
fn staging_counter_overflow_preserves_already_staged_events() {
    let key = SigningKey::from_bytes(&[36; 32]);
    let receiver = SigningKey::from_bytes(&[37; 32]);
    let config = SegmentConfig::new(3).unwrap();
    let context = configured_context(config, &key, &receiver, 0, u64::MAX);
    let safe_fixture = fixture(&key, &configured_context(config, &key, &receiver, 0, 0));
    let mut first = safe_fixture.events[0].clone();
    first.counter = u64::MAX;
    let mut window = ReceiveAdmissionWindow::new(context).unwrap();
    window
        .stage_with_payload(first.clone(), &safe_fixture.payloads[0])
        .unwrap();
    let mut next = safe_fixture.events[1].clone();
    next.previous_tip = event_tip(&first).unwrap();
    let before = window_snapshot(&window);
    assert!(matches!(
        window.stage_with_payload(next, &safe_fixture.payloads[1]),
        Err(TraxError::ArithmeticOverflow)
    ));
    assert_eq!(window_snapshot(&window), before);
}
