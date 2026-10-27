use ed25519_dalek::SigningKey;
use trax::crypto::{ed25519_sign, hash_domain};
use trax::encoding::{decode_strict, encode_deterministic};
use trax::genesis::{accept_genesis_offer, confirm_genesis, create_genesis_offer, VerifiedGenesis};
use trax::session::{session_start_id, HistoryKind, HistoryRecord, Relationship};
use trax::transmission::{Packet, SessionContext, SessionTerminal};
use trax::{HashAlgorithm, TransmissionProfile};

fn fixture() -> (SigningKey, SigningKey, Relationship, Relationship) {
    fixture_with_profile(TransmissionProfile::default())
}

fn fixture_with_profile(
    profile: TransmissionProfile,
) -> (SigningKey, SigningKey, Relationship, Relationship) {
    let a = SigningKey::from_bytes(&[1; 32]);
    let b = SigningKey::from_bytes(&[2; 32]);
    let offer = create_genesis_offer(&a, [3; 32], profile).unwrap();
    let accept =
        accept_genesis_offer(&offer, &b, |key| *key == a.verifying_key().to_bytes()).unwrap();
    let confirm = confirm_genesis(&offer, &accept, &a, |key| {
        *key == b.verifying_key().to_bytes()
    })
    .unwrap();
    let transcript = [offer, accept, confirm];
    let trusted = [a.verifying_key().to_bytes(), b.verifying_key().to_bytes()];
    let left = Relationship::new(
        VerifiedGenesis::verify(transcript.clone(), |key| trusted.contains(key)).unwrap(),
    )
    .unwrap();
    let right = Relationship::new(
        VerifiedGenesis::verify(transcript, |key| trusted.contains(key)).unwrap(),
    )
    .unwrap();
    (a, b, left, right)
}
fn admit(relationship: &mut Relationship, packets: &[Packet]) {
    let before = relationship.checkpoint();
    relationship.start_receive().unwrap();
    for (index, packet) in packets.iter().enumerate() {
        let verified = relationship.stage_packet(packet.clone()).unwrap();
        if index + 1 == packets.len() {
            let verified = verified.unwrap();
            assert_eq!(verified.packets(), packets);
        } else {
            assert!(verified.is_none());
            assert_eq!(relationship.checkpoint(), before);
        }
    }
}
fn roundtrip(
    left: &mut Relationship,
    right: &mut Relationship,
    initiator: &SigningKey,
    responder: &SigningKey,
) {
    for (key, message_type) in [(initiator, "request"), (responder, "response")] {
        let packets = left
            .build_transmission(key, message_type, &[vec![1, 2], vec![3]])
            .unwrap();
        admit(left, &packets);
        admit(right, &packets);
        assert_eq!(left.checkpoint(), right.checkpoint());
    }
}
fn close(left: &mut Relationship, right: &mut Relationship, key: &SigningKey) -> SessionTerminal {
    let terminal = left.create_close(key).unwrap();
    left.verify_and_close(&terminal).unwrap();
    right.verify_and_close(&terminal).unwrap();
    assert_eq!(left.checkpoint(), right.checkpoint());
    terminal
}

#[test]
fn genesis_is_the_traversable_root_and_drafts_cannot_advance_authority() {
    let (a, _, mut relationship, mirror) = fixture();
    let original = relationship.checkpoint();
    assert_eq!(original, mirror.checkpoint());
    assert_eq!(original.record_count, 0);
    assert_eq!(relationship.history().len(), 1);
    let root = relationship.record(&original.tip).unwrap();
    assert_eq!(root.id, relationship.genesis().anchor());
    assert_eq!(root.position, 0);
    assert_eq!(root.parent, None);
    assert!(
        matches!(&root.kind, HistoryKind::Genesis { transcript } if transcript == relationship.genesis().nodes())
    );
    assert!(relationship.ancestors(&root.id).unwrap().is_empty());
    relationship
        .begin_session(a.verifying_key().to_bytes(), [4; 32])
        .unwrap();
    assert_eq!(relationship.checkpoint(), original);
    assert_eq!(relationship.history().len(), 1);
    assert!(relationship.active_session().is_some());
    assert!(relationship
        .begin_session(a.verifying_key().to_bytes(), [5; 32])
        .is_err());
    assert!(relationship.abort_draft_session());
    assert!(!relationship.abort_draft_session());
    assert_eq!(relationship.checkpoint(), original);
}

#[test]
fn first_request_atomically_authenticates_the_start_and_all_packet_records() {
    let (a, _, mut sender, mut receiver) = fixture();
    sender
        .begin_session(a.verifying_key().to_bytes(), [4; 32])
        .unwrap();
    let context = sender.active_session().unwrap().context().clone();
    let packets = sender
        .build_transmission(&a, "task", &[vec![1], vec![2], vec![3]])
        .unwrap();
    assert_eq!(packets[0].session_start.as_ref(), Some(&context));
    assert!(packets[1..].iter().all(|p| p.session_start.is_none()));
    assert_eq!(packets[0].event.counter, 2);
    assert_eq!(
        packets[0].event.previous_tip,
        session_start_id(&context).unwrap()
    );
    let before = receiver.checkpoint();
    receiver.start_receive().unwrap();
    for packet in &packets[..2] {
        assert!(receiver.stage_packet(packet.clone()).unwrap().is_none());
        assert_eq!(receiver.checkpoint(), before);
        assert!(receiver.active_session().is_none());
        assert_eq!(receiver.history().len(), 1);
    }
    assert!(receiver.stage_packet(packets[2].clone()).unwrap().is_some());
    admit(&mut sender, &packets);
    assert_eq!(sender.checkpoint(), receiver.checkpoint());
    assert_eq!(receiver.history().len(), 5);
    assert!(
        matches!(&receiver.history()[1].kind, HistoryKind::SessionStart { context: c } if *c == context)
    );
    for (record, packet) in receiver.history()[2..].iter().zip(&packets) {
        assert_eq!(record.position, packet.event.counter);
        assert!(
            matches!(&record.kind, HistoryKind::Packet { event, authentication }
            if *event == packet.event && *authentication == packet.authentication)
        );
    }
    assert!(!sender.abort_draft_session());
    assert!(sender
        .begin_session(a.verifying_key().to_bytes(), [5; 32])
        .is_err());
}

#[test]
fn closed_sessions_form_one_continuous_mirrored_history_with_either_initiator() {
    let (a, b, mut left, mut right) = fixture();
    let mut previous = left.checkpoint();
    let mut session_ids = Vec::new();
    for index in 1..=4 {
        let (initiator, responder) = if index % 2 == 1 { (&a, &b) } else { (&b, &a) };
        left.begin_session(initiator.verifying_key().to_bytes(), [9; 32])
            .unwrap();
        let context = left.active_session().unwrap().context().clone();
        assert_eq!(context.previous_tip, previous.tip);
        assert_eq!(context.previous_history_hash, previous.history_hash);
        assert_eq!(context.previous_record_count, previous.record_count);
        assert_eq!(context.session_index, index);
        let id = left.active_session().unwrap().session_id();
        assert!(!session_ids.contains(&id));
        session_ids.push(id);
        roundtrip(&mut left, &mut right, initiator, responder);
        let before_close = left.checkpoint();
        let terminal = close(&mut left, &mut right, initiator);
        let checkpoint = left.checkpoint();
        assert_eq!(
            terminal.commitment.relationship_history_hash,
            before_close.history_hash
        );
        assert_eq!(
            terminal.commitment.session_history_hash,
            before_close.active_session.unwrap().history_hash
        );
        assert_eq!(terminal.commitment.first_counter, previous.record_count + 2);
        assert_eq!(terminal.commitment.last_counter, before_close.record_count);
        assert_eq!(terminal.commitment.packet_count, 4);
        assert_eq!(checkpoint.record_count, previous.record_count + 6);
        assert_eq!(checkpoint.completed_sessions, index);
        assert_eq!(checkpoint.last_session_id, Some(id));
        assert!(checkpoint.active_session.is_none());
        assert!(left.active_session().is_none());
        assert!(left.session().unwrap().closed());
        let record = left.record(&checkpoint.tip).unwrap();
        assert_eq!(record.parent, Some(before_close.tip));
        assert!(
            matches!(&record.kind, HistoryKind::SessionTerminal { terminal: stored } if stored == &terminal)
        );
        previous = checkpoint;
    }
    assert_eq!(left.history(), right.history());
    assert_eq!(left.history().len() as u64, previous.record_count + 1);
    let ancestors = left.ancestors(&previous.tip).unwrap();
    assert_eq!(ancestors.len() as u64, previous.record_count);
    for pair in left.history().windows(2) {
        assert_eq!(pair[1].parent, Some(pair[0].id));
        assert_eq!(left.children(&pair[0].id), vec![&pair[1]]);
    }
    assert!(left.children(&previous.tip).is_empty());
    assert!(left.record(&[99; 32]).is_none());
    assert!(left.ancestors(&[99; 32]).is_err());
}

#[test]
fn context_must_bind_the_exact_latest_authoritative_predecessor() {
    let (a, b, mut left, mut right) = fixture();
    left.begin_session(a.verifying_key().to_bytes(), [4; 32])
        .unwrap();
    let old_context = left.active_session().unwrap().context().clone();
    roundtrip(&mut left, &mut right, &a, &b);
    close(&mut left, &mut right, &a);
    assert!(left.begin_session_from_context(&old_context).is_err());
    left.begin_session(b.verifying_key().to_bytes(), [5; 32])
        .unwrap();
    let context = left.active_session().unwrap().context().clone();
    assert!(left.abort_draft_session());
    let mutations: Vec<fn(&mut SessionContext)> = vec![
        |c| c.version = 2,
        |c| c.relationship_id[0] ^= 1,
        |c| c.previous_tip[0] ^= 1,
        |c| c.previous_history_hash[0] ^= 1,
        |c| c.previous_record_count += 1,
        |c| c.session_index += 1,
        |c| c.profile.limits.max_packets -= 1,
        |c| c.responder = c.initiator,
        |c| c.initiator = [99; 32],
    ];
    let before = left.checkpoint();
    for mutate in mutations {
        let mut bad = context.clone();
        mutate(&mut bad);
        assert!(left.begin_session_from_context(&bad).is_err());
        assert_eq!(left.checkpoint(), before);
        assert!(left.active_session().is_none());
    }
    left.begin_session_from_context(&context).unwrap();
    assert_eq!(left.active_session().unwrap().context(), &context);
}

#[test]
fn missing_repeated_or_substituted_start_context_cannot_commit() {
    let (a, _, mut sender, mut receiver) = fixture();
    sender
        .begin_session(a.verifying_key().to_bytes(), [4; 32])
        .unwrap();
    let original = sender
        .build_transmission(&a, "task", &[vec![1], vec![2]])
        .unwrap();
    let mut missing = original.clone();
    missing[0].session_start = None;
    let mut repeated = original.clone();
    repeated[1].session_start = original[0].session_start.clone();
    let mut replaced = original.clone();
    replaced[0].session_start.as_mut().unwrap().nonce[0] ^= 1;
    let mut stale = original.clone();
    stale[0].session_start.as_mut().unwrap().previous_tip[0] ^= 1;
    for packets in [missing, repeated, replaced, stale] {
        let before = receiver.checkpoint();
        receiver.start_receive().unwrap();
        let mut failed = false;
        for packet in packets {
            if receiver.stage_packet(packet).is_err() {
                failed = true;
                break;
            }
        }
        assert!(failed);
        assert_eq!(receiver.checkpoint(), before);
        assert_eq!(receiver.history().len(), 1);
        assert!(receiver.active_session().is_none());
        assert!(!receiver.has_pending());
    }
    admit(&mut receiver, &original);
}

#[test]
fn incomplete_remote_start_can_be_abandoned_but_admitted_session_cannot_reset() {
    let (a, _, mut sender, mut receiver) = fixture();
    sender
        .begin_session(a.verifying_key().to_bytes(), [4; 32])
        .unwrap();
    let packets = sender
        .build_transmission(&a, "task", &[vec![1], vec![2]])
        .unwrap();
    receiver.start_receive().unwrap();
    assert!(receiver.stage_packet(packets[0].clone()).unwrap().is_none());
    assert!(receiver.abort_receive());
    assert!(receiver.active_session().is_none());
    receiver
        .begin_session(a.verifying_key().to_bytes(), [5; 32])
        .unwrap();
    assert!(receiver.abort_draft_session());
    admit(&mut receiver, &packets);
    assert!(!receiver.abort_draft_session());
    assert!(receiver
        .begin_session(a.verifying_key().to_bytes(), [6; 32])
        .is_err());
}

#[test]
fn every_original_record_contributes_to_the_relationship_history_hash() {
    let (a, b, mut left, mut right) = fixture();
    left.begin_session(a.verifying_key().to_bytes(), [4; 32])
        .unwrap();
    roundtrip(&mut left, &mut right, &a, &b);
    close(&mut left, &mut right, &a);
    let root = &left.history()[0];
    let mut hash = hash_domain(
        HashAlgorithm::Sha512256,
        b"TRAX:HISTORY:ROOT:V3\0",
        &[&encode_deterministic(root).unwrap()],
    )
    .unwrap();
    for record in &left.history()[1..] {
        let bytes = encode_deterministic(record).unwrap();
        assert_eq!(
            decode_strict::<HistoryRecord>(&bytes, 65536).unwrap(),
            *record
        );
        hash = hash_domain(
            HashAlgorithm::Sha512256,
            b"TRAX:HISTORY:RECORD:V3\0",
            &[&hash, &bytes],
        )
        .unwrap();
    }
    assert_eq!(hash, left.checkpoint().history_hash);
    let final_packet_record = left
        .history()
        .iter()
        .find(|r| {
            matches!(
                &r.kind,
                HistoryKind::Packet {
                    authentication: Some(_),
                    ..
                }
            )
        })
        .unwrap();
    let mut stripped = final_packet_record.clone();
    if let HistoryKind::Packet { authentication, .. } = &mut stripped.kind {
        *authentication = None;
    }
    assert_ne!(
        encode_deterministic(&stripped).unwrap(),
        encode_deterministic(final_packet_record).unwrap()
    );
}

#[test]
fn all_close_context_fields_and_unrelated_signatures_are_rejected_atomically() {
    let (a, b, mut left, mut right) = fixture();
    left.begin_session(a.verifying_key().to_bytes(), [4; 32])
        .unwrap();
    roundtrip(&mut left, &mut right, &a, &b);
    let terminal = left.create_close(&a).unwrap();
    let mutations: Vec<fn(&mut SessionTerminal)> = vec![
        |t| t.commitment.version = 2,
        |t| t.commitment.purpose.push('!'),
        |t| t.commitment.relationship_id[0] ^= 1,
        |t| t.commitment.session_id[0] ^= 1,
        |t| t.commitment.session_index += 1,
        |t| t.commitment.initiator[0] ^= 1,
        |t| t.commitment.responder[0] ^= 1,
        |t| t.commitment.final_data_tip[0] ^= 1,
        |t| t.commitment.session_history_hash[0] ^= 1,
        |t| t.commitment.relationship_history_hash[0] ^= 1,
        |t| t.commitment.first_counter += 1,
        |t| t.commitment.last_counter += 1,
        |t| t.commitment.packet_count += 1,
        |t| t.commitment.transmission_id += 1,
        |t| t.commitment.terminal_counter += 1,
        |t| t.signature[0] ^= 1,
    ];
    let before = left.checkpoint();
    for mutate in mutations {
        let mut bad = terminal.clone();
        mutate(&mut bad);
        assert!(left.verify_and_close(&bad).is_err());
        assert_eq!(left.checkpoint(), before);
    }
    let mut foreign = terminal.clone();
    let mut bytes = b"TRAX:SESSION:CLOSE:V3\0".to_vec();
    bytes.extend_from_slice(&encode_deterministic(&foreign.commitment).unwrap());
    foreign.signature = ed25519_sign(&b, &bytes);
    assert!(left.verify_and_close(&foreign).is_err());
    assert_eq!(left.checkpoint(), before);
    close(&mut left, &mut right, &a);
    assert!(left.verify_and_close(&terminal).is_err());
}

#[test]
fn closed_session_packets_cannot_start_a_new_session_or_reopen_the_previous_one() {
    let (a, b, mut left, mut right) = fixture();
    left.begin_session(a.verifying_key().to_bytes(), [4; 32])
        .unwrap();
    let old_request = left.build_transmission(&a, "request", &[vec![1]]).unwrap();
    admit(&mut left, &old_request);
    admit(&mut right, &old_request);
    let old_response = left.build_transmission(&b, "response", &[vec![2]]).unwrap();
    admit(&mut left, &old_response);
    admit(&mut right, &old_response);
    let old_terminal = close(&mut left, &mut right, &a);
    let before = right.checkpoint();
    for packets in [&old_request, &old_response] {
        right.start_receive().unwrap();
        assert!(right.stage_packet(packets[0].clone()).is_err());
        assert!(!right.has_pending());
        assert!(right.active_session().is_none());
        assert_eq!(right.checkpoint(), before);
    }
    assert!(right.verify_and_close(&old_terminal).is_err());
    left.begin_session(b.verifying_key().to_bytes(), [4; 32])
        .unwrap();
    roundtrip(&mut left, &mut right, &b, &a);
    close(&mut left, &mut right, &b);
    assert_eq!(right.checkpoint().completed_sessions, 2);
}

#[cfg(feature = "hash-blake3")]
#[test]
fn blake3_profile_preserves_continuity_and_traversal_across_sessions() {
    let profile = TransmissionProfile {
        hash_algorithm: HashAlgorithm::Blake3,
        ..TransmissionProfile::default()
    };
    let (a, b, mut left, mut right) = fixture_with_profile(profile);
    for (initiator, responder) in [(&a, &b), (&b, &a)] {
        left.begin_session(initiator.verifying_key().to_bytes(), [4; 32])
            .unwrap();
        roundtrip(&mut left, &mut right, initiator, responder);
        close(&mut left, &mut right, initiator);
    }
    assert_eq!(left.history(), right.history());
    assert_eq!(
        left.ancestors(&left.checkpoint().tip).unwrap().len(),
        left.history().len() - 1
    );
}
