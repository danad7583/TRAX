use ed25519_dalek::SigningKey;
use trax::crypto::{hash32, merkle_root_and_proofs_k8, verify_merkle_inclusion_k8};
use trax::dag::{
    create_segment_seal_k8, event_bytes, event_tip, lineage_key_id, verify_segment_proof,
    ReceiveAdmissionWindow,
};
use trax::{PostGenesisEventV1, SegmentProof, TraxError};

fn events(
    key: &SigningKey,
    start: [u8; 32],
    segment: u64,
    first_counter: u64,
) -> Vec<PostGenesisEventV1> {
    let mut tip = start;
    (0..8)
        .map(|i| {
            let event = PostGenesisEventV1 {
                version: 1,
                session_id: hash32(b"session"),
                lineage_key_id: lineage_key_id(&key.verifying_key()),
                receiver_id: hash32(b"receiver"),
                segment_index: segment,
                counter: first_counter + i,
                previous_tip: tip,
                content_hash: hash32(&[i as u8]),
                payload_hash: hash32(&[i as u8, 9]),
            };
            tip = event_tip(&event).unwrap();
            event
        })
        .collect()
}

fn window(key: &SigningKey, tip: [u8; 32], segment: u64, counter: u64) -> ReceiveAdmissionWindow {
    ReceiveAdmissionWindow::new_k8(
        hash32(b"session"),
        hash32(b"receiver"),
        key.verifying_key(),
        tip,
        segment,
        counter,
    )
}

#[test]
fn seven_events_are_provisional_then_eight_commit_atomically() {
    let key = SigningKey::from_bytes(&[1; 32]);
    let genesis = hash32(b"genesis");
    let events = events(&key, genesis, 0, 10);
    let seal = create_segment_seal_k8(&key, &events).unwrap();
    let mut receiver = window(&key, genesis, 0, 10);
    for event in events.iter().take(7) {
        receiver.stage(event.clone()).unwrap();
    }
    assert_eq!(receiver.provisional_count(), 7);
    assert_eq!(receiver.committed_count(), 0);
    assert_eq!(receiver.committed_tip(), genesis);
    assert_ne!(receiver.provisional_tip(), genesis);
    assert!(matches!(
        receiver.verify_and_commit(&seal),
        Err(TraxError::IncompleteSegment)
    ));
    receiver.stage(events[7].clone()).unwrap();
    let admitted = receiver.verify_and_commit(&seal).unwrap();
    assert_eq!(admitted, events);
    assert_eq!(receiver.committed_count(), 8);
    assert_eq!(receiver.committed_tip(), event_tip(&events[7]).unwrap());
}

#[test]
fn reorder_tamper_bad_signature_and_wrong_key_fail() {
    let key = SigningKey::from_bytes(&[2; 32]);
    let wrong = SigningKey::from_bytes(&[3; 32]);
    let original = events(&key, hash32(b"g"), 0, 0);
    let seal = create_segment_seal_k8(&key, &original).unwrap();
    let mut reordered = original.clone();
    reordered.swap(2, 3);
    assert!(verify_segment_proof(
        &SegmentProof {
            events: reordered,
            seal: seal.clone()
        },
        &key.verifying_key()
    )
    .is_err());
    let mut tampered = original.clone();
    tampered[4].content_hash[0] ^= 1;
    assert!(verify_segment_proof(
        &SegmentProof {
            events: tampered,
            seal: seal.clone()
        },
        &key.verifying_key()
    )
    .is_err());
    let mut bad_sig = seal.clone();
    bad_sig.signature[0] ^= 1;
    assert!(matches!(
        verify_segment_proof(
            &SegmentProof {
                events: original.clone(),
                seal: bad_sig
            },
            &key.verifying_key()
        ),
        Err(TraxError::SegmentSignatureFailure)
    ));
    assert!(verify_segment_proof(
        &SegmentProof {
            events: original,
            seal
        },
        &wrong.verifying_key()
    )
    .is_err());
}

#[test]
fn wrong_context_continuity_and_counters_are_rejected() {
    let key = SigningKey::from_bytes(&[4; 32]);
    let genesis = hash32(b"g");
    let good = events(&key, genesis, 0, 5);
    let mut receiver = window(&key, genesis, 0, 5);
    let mut wrong_session = good[0].clone();
    wrong_session.session_id = hash32(b"wrong");
    assert!(matches!(
        receiver.stage(wrong_session),
        Err(TraxError::SessionMismatch)
    ));
    let mut wrong_tip = good[0].clone();
    wrong_tip.previous_tip = [9; 32];
    assert!(matches!(
        receiver.stage(wrong_tip),
        Err(TraxError::ProvisionalTipMismatch)
    ));
    receiver.stage(good[0].clone()).unwrap();
    let mut skipped = good[1].clone();
    skipped.counter += 1;
    assert!(matches!(
        receiver.stage(skipped),
        Err(TraxError::CounterDiscontinuity)
    ));
}

#[test]
fn failed_segment_preserves_prior_commit_and_clears_failed_window() {
    let key = SigningKey::from_bytes(&[5; 32]);
    let genesis = hash32(b"g");
    let first = events(&key, genesis, 0, 0);
    let first_seal = create_segment_seal_k8(&key, &first).unwrap();
    let mut receiver = window(&key, genesis, 0, 0);
    for event in &first {
        receiver.stage(event.clone()).unwrap();
    }
    receiver.verify_and_commit(&first_seal).unwrap();
    let committed_tip = receiver.committed_tip();
    let second = events(&key, committed_tip, 1, 8);
    let mut bad_seal = create_segment_seal_k8(&key, &second).unwrap();
    bad_seal.commitment.starting_committed_tip = hash32(b"wrong");
    for event in &second {
        receiver.stage(event.clone()).unwrap();
    }
    assert!(receiver.verify_and_commit(&bad_seal).is_err());
    assert_eq!(receiver.committed_count(), 8);
    assert_eq!(receiver.committed_tip(), committed_tip);
    assert_eq!(receiver.provisional_count(), 0);
    assert_eq!(receiver.provisional_tip(), committed_tip);
}

#[test]
fn all_inclusion_proofs_verify_and_corruption_fails() {
    let key = SigningKey::from_bytes(&[6; 32]);
    let events = events(&key, hash32(b"g"), 0, 0);
    let messages = events
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
