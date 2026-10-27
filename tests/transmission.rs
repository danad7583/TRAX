use ed25519_dalek::SigningKey;
use trax::crypto::ed25519_sign;
use trax::encoding::{decode_strict, encode_deterministic};
use trax::genesis::{
    accept_genesis_offer, confirm_genesis, create_genesis_offer, GenesisNodeV2,
    TransmissionProfileV2, VerifiedGenesisV2,
};
use trax::transmission::{
    event_tip_v2, PacketV2, SessionV2, TransmissionCommitmentV2, TransmissionKindV2,
};
use trax::transmission_crypto::{hash_v2, MerkleAccumulatorV2};
use trax::{HashAlgorithm, TraxError};

fn transcript(profile: TransmissionProfileV2) -> (SigningKey, SigningKey, [GenesisNodeV2; 3]) {
    let a = SigningKey::from_bytes(&[1; 32]);
    let b = SigningKey::from_bytes(&[2; 32]);
    let offer = create_genesis_offer(&a, [3; 32], profile).unwrap();
    let accept =
        accept_genesis_offer(&offer, &b, |key| *key == a.verifying_key().to_bytes()).unwrap();
    let confirm = confirm_genesis(&offer, &accept, &a, |key| {
        *key == b.verifying_key().to_bytes()
    })
    .unwrap();
    (a, b, [offer, accept, confirm])
}

fn session(nodes: &[GenesisNodeV2; 3], initiator: &SigningKey, nonce: u8) -> SessionV2 {
    let trusted = [
        nodes[0].event.initiator_public_key,
        nodes[1].event.responder_public_key.unwrap(),
    ];
    let genesis = VerifiedGenesisV2::verify(nodes.clone(), |key| trusted.contains(key)).unwrap();
    SessionV2::new(genesis, initiator.verifying_key().to_bytes(), [nonce; 32]).unwrap()
}

fn admit(session: &mut SessionV2, packets: &[PacketV2]) -> Vec<u8> {
    let before = session.checkpoint();
    session.start_receive().unwrap();
    let mut released = Vec::new();
    for (index, packet) in packets.iter().enumerate() {
        let encoded = encode_deterministic(packet).unwrap();
        let verified = session.stage_encoded_packet(&encoded).unwrap();
        if index + 1 < packets.len() {
            assert!(verified.is_none());
            assert_eq!(session.checkpoint(), before);
            assert_eq!(session.nodes().len() as u64, before.event_count);
        } else {
            let verified = verified.unwrap();
            assert_eq!(verified.packets(), packets);
            assert_eq!(verified.payload_chunks().count(), packets.len());
            released = verified.payload();
        }
    }
    assert!(!session.has_pending());
    released
}

fn reject(session: &mut SessionV2, packets: &[PacketV2]) {
    let before = session.checkpoint();
    session.start_receive().unwrap();
    let mut failed = false;
    for packet in packets {
        match session.stage_packet(packet.clone()) {
            Ok(None) => assert_eq!(session.checkpoint(), before),
            Ok(Some(_)) => panic!("attacker input was released"),
            Err(_) => {
                failed = true;
                break;
            }
        }
    }
    assert!(failed, "expected explicit failure");
    assert_eq!(session.checkpoint(), before);
    assert!(!session.has_pending());
}

#[test]
fn all_required_sizes_reconstruct_payloads_and_independent_roots() {
    for n in [1, 2, 3, 7, 8, 9, 17, 35, 100, 138] {
        let (a, _, nodes) = transcript(TransmissionProfileV2::default());
        let mut sender = session(&nodes, &a, 4);
        let mut receiver = session(&nodes, &a, 4);
        let chunks: Vec<_> = (0..n).map(|i| vec![i as u8; 1400]).collect();
        let packets = sender.build_transmission(&a, "document", &chunks).unwrap();
        assert_eq!(
            packets
                .iter()
                .filter(|p| p.authentication.is_some())
                .count(),
            1
        );
        let mut merkle = MerkleAccumulatorV2::new(HashAlgorithm::Sha512256).unwrap();
        for packet in &packets {
            merkle
                .push(&encode_deterministic(&packet.event).unwrap())
                .unwrap();
        }
        assert_eq!(
            merkle.root().unwrap(),
            packets
                .last()
                .unwrap()
                .authentication
                .as_ref()
                .unwrap()
                .commitment
                .merkle_root
        );
        let expected: Vec<_> = chunks.concat();
        assert_eq!(admit(&mut receiver, &packets), expected);
        assert_eq!(admit(&mut sender, &packets), expected);
        assert_eq!(sender.checkpoint(), receiver.checkpoint());
        assert_eq!(sender.checkpoint().event_count, n as u64);
        assert_eq!(
            receiver.checkpoint().tip,
            event_tip_v2(HashAlgorithm::Sha512256, &packets[n - 1].event).unwrap()
        );
        for node in receiver.nodes() {
            assert_eq!(receiver.node(&node.tip()).unwrap().event(), node.event());
        }
    }
}

#[test]
fn bidirectional_multiple_rounds_and_original_initiator_only_terminal() {
    for reverse in [false, true] {
        let (a, b, nodes) = transcript(TransmissionProfileV2::default());
        let (initiator, responder) = if reverse { (&b, &a) } else { (&a, &b) };
        let mut left = session(&nodes, initiator, 4);
        let mut right = session(&nodes, initiator, 4);
        for (key, n) in [
            (initiator, 100),
            (responder, 17),
            (initiator, 3),
            (responder, 7),
        ] {
            let packets = left
                .build_transmission(key, "task", &vec![vec![9; 1400]; n])
                .unwrap();
            assert_eq!(admit(&mut left, &packets), admit(&mut right, &packets));
            assert_eq!(left.checkpoint(), right.checkpoint());
            assert!(!left.checkpoint().closed);
        }
        assert!(left.create_close(responder).is_err());
        let terminal = left.create_close(initiator).unwrap();
        let included = left.checkpoint();
        assert_eq!(terminal.commitment.history_hash, included.history_hash);
        assert_eq!(terminal.commitment.event_count, included.event_count);
        let encoded = encode_deterministic(&terminal).unwrap();
        left.verify_and_close(&terminal).unwrap();
        right.verify_encoded_close(&encoded).unwrap();
        assert_eq!(left.terminal(), right.terminal());
        assert_eq!(left.checkpoint(), right.checkpoint());
        assert_eq!(right.terminal().unwrap().signature, terminal.signature);
        assert_eq!(right.checkpoint().event_count, included.event_count + 1);
        assert!(right.checkpoint().closed);
        assert!(right.start_receive().is_err());
        assert!(right.verify_and_close(&terminal).is_err());
        assert!(left
            .build_transmission(initiator, "task", &[vec![]])
            .is_err());
    }
}

#[test]
fn payload_order_missing_duplicate_injected_and_final_authentication_fail_atomically() {
    let (a, _, nodes) = transcript(TransmissionProfileV2::default());
    let sender = session(&nodes, &a, 4);
    let original = sender
        .build_transmission(&a, "task", &vec![vec![10; 100]; 3])
        .unwrap();
    let mut cases = Vec::new();
    let mut p = original.clone();
    p[0].payload[0] ^= 1;
    cases.push(p);
    let mut p = original.clone();
    p[2].payload[0] ^= 1;
    cases.push(p);
    let mut p = original.clone();
    p.swap(0, 1);
    cases.push(p);
    let mut p = original.clone();
    p.remove(1);
    cases.push(p);
    let mut p = original.clone();
    p.insert(1, p[0].clone());
    cases.push(p);
    let mut p = original.clone();
    p[2].authentication = None;
    cases.push(p);
    let mut p = original.clone();
    p[0].authentication = p[2].authentication.clone();
    cases.push(p);
    let mut p = original.clone();
    p[2].authentication.as_mut().unwrap().signature[0] ^= 1;
    cases.push(p);
    let mut p = original.clone();
    p[0].event.counter = u64::MAX;
    cases.push(p);
    let mut p = original.clone();
    p[0].event.packet_index = u32::MAX;
    cases.push(p);
    for case in cases {
        reject(&mut session(&nodes, &a, 4), &case);
    }
    // Truncation is provisional, never trusted. Missing final packets can be
    // abandoned or expired without advancing authoritative history.
    let mut receiver = session(&nodes, &a, 4);
    let before = receiver.checkpoint();
    receiver.start_receive().unwrap();
    for packet in &original[..2] {
        assert!(receiver.stage_packet(packet.clone()).unwrap().is_none());
    }
    assert_eq!(receiver.checkpoint(), before);
    assert!(receiver.abort_receive());
    assert_eq!(receiver.checkpoint(), before);
}

#[test]
fn every_commitment_field_is_reconstructed_not_trusted() {
    let (a, _, nodes) = transcript(TransmissionProfileV2::default());
    let original = session(&nodes, &a, 4)
        .build_transmission(&a, "task", &[vec![1], vec![2]])
        .unwrap();
    let mutations: Vec<fn(&mut TransmissionCommitmentV2)> = vec![
        |c| c.version = 1,
        |c| c.purpose.push('!'),
        |c| c.relationship_id[0] ^= 1,
        |c| c.session_id[0] ^= 1,
        |c| c.transmission_id += 1,
        |c| c.initiator[0] ^= 1,
        |c| c.sender[0] ^= 1,
        |c| c.receiver[0] ^= 1,
        |c| c.key_epoch += 1,
        |c| c.kind = TransmissionKindV2::Response,
        |c| c.message_type.push('!'),
        |c| c.starting_tip[0] ^= 1,
        |c| c.first_counter += 1,
        |c| c.last_counter += 1,
        |c| c.packet_count += 1,
        |c| c.payload_bytes += 1,
        |c| c.merkle_root[0] ^= 1,
        |c| c.final_event_tip[0] ^= 1,
    ];
    for mutation in mutations {
        let mut packets = original.clone();
        mutation(
            &mut packets
                .last_mut()
                .unwrap()
                .authentication
                .as_mut()
                .unwrap()
                .commitment,
        );
        reject(&mut session(&nodes, &a, 4), &packets);
    }
    let event_mutations: Vec<fn(&mut trax::transmission::PacketEventV2)> = vec![
        |e| e.version = 1,
        |e| e.relationship_id[0] ^= 1,
        |e| e.session_id[0] ^= 1,
        |e| e.transmission_id += 1,
        |e| e.initiator[0] ^= 1,
        |e| e.sender[0] ^= 1,
        |e| e.receiver[0] ^= 1,
        |e| e.key_epoch += 1,
        |e| e.kind = TransmissionKindV2::Response,
        |e| e.previous_tip[0] ^= 1,
        |e| e.payload_len += 1,
    ];
    for mutation in event_mutations {
        let mut packets = original.clone();
        mutation(&mut packets[0].event);
        reject(&mut session(&nodes, &a, 4), &packets);
    }
}

fn rehash_attack(packets: &mut [PacketV2], key: Option<&SigningKey>) {
    packets[0].payload[0] ^= 1;
    let mut tip = packets[0].event.previous_tip;
    let mut merkle = MerkleAccumulatorV2::new(HashAlgorithm::Sha512256).unwrap();
    for packet in packets.iter_mut() {
        packet.event.previous_tip = tip;
        packet.event.payload_hash = hash_v2(
            HashAlgorithm::Sha512256,
            b"TRAX:PAYLOAD:V2\0",
            &[&packet.payload],
        )
        .unwrap();
        tip = event_tip_v2(HashAlgorithm::Sha512256, &packet.event).unwrap();
        merkle
            .push(&encode_deterministic(&packet.event).unwrap())
            .unwrap();
    }
    let seal = packets.last_mut().unwrap().authentication.as_mut().unwrap();
    seal.commitment.merkle_root = merkle.root().unwrap();
    seal.commitment.final_event_tip = tip;
    if let Some(key) = key {
        let mut bytes = b"TRAX:TRANSMISSION:V2\0".to_vec();
        bytes.extend_from_slice(&encode_deterministic(&seal.commitment).unwrap());
        seal.signature = ed25519_sign(key, &bytes);
    }
}

#[test]
fn network_attacker_can_rehash_every_link_but_cannot_authenticate_as_peer() {
    let (a, b, nodes) = transcript(TransmissionProfileV2::default());
    let c = SigningKey::from_bytes(&[99; 32]);
    let original = session(&nodes, &a, 4)
        .build_transmission(&a, "task", &vec![vec![1; 100]; 17])
        .unwrap();
    for key in [None, Some(&c), Some(&b)] {
        let mut forged = original.clone();
        rehash_attack(&mut forged, key);
        reject(&mut session(&nodes, &a, 4), &forged);
    }
    // A transparent unchanged relay remains valid; no network-path claims.
    assert_eq!(admit(&mut session(&nodes, &a, 4), &original), vec![1; 1700]);
}

#[test]
fn replays_cross_session_cross_direction_and_legacy_proofs_are_rejected() {
    let (a, b, nodes) = transcript(TransmissionProfileV2::default());
    let mut receiver = session(&nodes, &a, 4);
    let original = receiver.build_transmission(&a, "task", &[vec![1]]).unwrap();
    admit(&mut receiver, &original);
    reject(&mut receiver, &original);
    reject(&mut session(&nodes, &a, 5), &original);
    reject(&mut session(&nodes, &b, 4), &original);
    let mut raw_root = original.clone();
    let seal = raw_root[0].authentication.as_mut().unwrap();
    seal.signature = ed25519_sign(&a, &seal.commitment.merkle_root);
    reject(&mut session(&nodes, &a, 4), &raw_root);
    let mut old = session(&nodes, &a, 4);
    old.start_receive().unwrap();
    assert!(old
        .stage_encoded_packet(
            &encode_deterministic(&trax::PostGenesisEventV1 {
                version: 1,
                session_id: [0; 32],
                lineage_key_id: [0; 32],
                receiver_id: [0; 32],
                segment_index: 0,
                counter: 1,
                previous_tip: [0; 32],
                content_hash: [0; 32],
                payload_hash: [0; 32],
            })
            .unwrap()
        )
        .is_err());
    assert_eq!(old.checkpoint().event_count, 0);
    // Original history remains usable after rejecting a replay.
    let response = receiver
        .build_transmission(&b, "result", &[vec![2]])
        .unwrap();
    admit(&mut receiver, &response);
    reject(&mut receiver, &original);
}

#[test]
fn valid_legacy_window_and_graph_proofs_cannot_substitute_for_v2_packets() {
    use trax::crypto::hash32;
    use trax::dag::{
        create_segment_seal, event_tip, lineage_key_id, verify_segment_proof_intrinsic,
    };
    use trax::graph::{participant_id, PairDag, PairGenesis};
    use trax::{PostGenesisEventV1, ProtocolConfig, SegmentConfig, SegmentProof, SigningAlgorithm};
    let (a, b, nodes) = transcript(TransmissionProfileV2::default());
    let mut previous_tip = hash32(b"legacy genesis");
    let events: Vec<_> = (1..=8)
        .map(|counter| {
            let event = PostGenesisEventV1 {
                version: 1,
                session_id: hash32(b"legacy session"),
                lineage_key_id: lineage_key_id(&a.verifying_key()),
                receiver_id: hash32(b"receiver"),
                segment_index: 0,
                counter,
                previous_tip,
                content_hash: hash32(b"content"),
                payload_hash: hash32(b"payload"),
            };
            previous_tip = event_tip(&event).unwrap();
            event
        })
        .collect();
    let config = SegmentConfig::new(8).unwrap();
    let seal = create_segment_seal(config, &a, &events).unwrap();
    let mut proof = SegmentProof { events, seal };
    verify_segment_proof_intrinsic(config, &proof, &a.verifying_key()).unwrap();
    let mut receiver = session(&nodes, &a, 4);
    let before = receiver.checkpoint();
    receiver.start_receive().unwrap();
    assert!(receiver
        .stage_encoded_packet(&encode_deterministic(&proof).unwrap())
        .is_err());
    assert_eq!(receiver.checkpoint(), before);
    let mut packets = receiver.build_transmission(&a, "task", &[vec![1]]).unwrap();
    let new_signature = packets[0]
        .authentication
        .as_ref()
        .unwrap()
        .signature
        .clone();
    packets[0].authentication.as_mut().unwrap().signature = proof.seal.signature.clone();
    reject(&mut receiver, &packets);
    proof.seal.signature = new_signature;
    assert!(verify_segment_proof_intrinsic(config, &proof, &a.verifying_key()).is_err());
    assert!(decode_strict::<trax::SegmentSealV1>(
        &encode_deterministic(packets[0].authentication.as_ref().unwrap()).unwrap(),
        4096
    )
    .is_err());

    // The newer shared fixed-cadence graph also uses numeric version 2. Its
    // distinct schemas and signing domains still cannot cross into this V2.
    let config =
        ProtocolConfig::new(8, SigningAlgorithm::Ed25519, HashAlgorithm::Sha512256).unwrap();
    let genesis =
        PairGenesis::new(config, [88; 32], &a.verifying_key(), &b.verifying_key()).unwrap();
    let mut legacy = PairDag::from_verified_genesis(config, genesis).unwrap();
    let mut pending = legacy.begin_segment();
    for _ in 0..8 {
        pending
            .append(
                participant_id(&a.verifying_key().to_bytes()),
                legacy.main_branch(),
                vec![1],
            )
            .unwrap();
    }
    let graph_proof = pending
        .seal(participant_id(&a.verifying_key().to_bytes()), &a)
        .unwrap();
    legacy.verify_and_commit(&graph_proof).unwrap();
    receiver.start_receive().unwrap();
    assert!(receiver
        .stage_encoded_packet(&encode_deterministic(&graph_proof).unwrap())
        .is_err());
    assert_eq!(receiver.checkpoint(), before);
    assert!(!receiver.has_pending());
}

#[test]
fn closure_failures_never_modify_committed_history() {
    let (a, b, nodes) = transcript(TransmissionProfileV2::default());
    let mut ready = session(&nodes, &a, 4);
    assert!(ready.create_close(&a).is_err());
    for key in [&a, &b] {
        let p = ready.build_transmission(key, "task", &[vec![1]]).unwrap();
        admit(&mut ready, &p);
    }
    let terminal = ready.create_close(&a).unwrap();
    let before = ready.checkpoint();
    let mut bad = Vec::new();
    let mut t = terminal.clone();
    t.commitment.history_hash[0] ^= 1;
    bad.push(t);
    let mut t = terminal.clone();
    t.commitment.final_data_tip[0] ^= 1;
    bad.push(t);
    let mut t = terminal.clone();
    t.commitment.first_counter += 1;
    bad.push(t);
    let mut t = terminal.clone();
    t.commitment.last_counter += 1;
    bad.push(t);
    let mut t = terminal.clone();
    t.commitment.event_count += 1;
    bad.push(t);
    let mut t = terminal.clone();
    t.commitment.terminal_counter += 1;
    bad.push(t);
    let mut t = terminal.clone();
    t.commitment.session_id[0] ^= 1;
    bad.push(t);
    let mut t = terminal.clone();
    t.commitment.initiator = b.verifying_key().to_bytes();
    bad.push(t);
    let mut t = terminal.clone();
    t.signature[0] ^= 1;
    bad.push(t);
    let mut t = terminal.clone();
    let mut bytes = b"TRAX:SESSION:CLOSE:V2\0".to_vec();
    bytes.extend_from_slice(&encode_deterministic(&t.commitment).unwrap());
    t.signature = ed25519_sign(&b, &bytes);
    bad.push(t);
    for t in bad {
        assert!(ready.verify_and_close(&t).is_err());
        assert_eq!(ready.checkpoint(), before);
    }
    ready.start_receive().unwrap();
    assert!(ready.verify_and_close(&terminal).is_err());
    assert_eq!(ready.checkpoint(), before);
    ready.abort_receive();
    assert!(session(&nodes, &a, 5).verify_and_close(&terminal).is_err());
    ready.verify_and_close(&terminal).unwrap();
}

#[test]
fn bounded_resources_timeout_cleanup_and_strict_wire_decode() {
    let mut profile = TransmissionProfileV2::default();
    profile.limits.max_packets = 3;
    profile.limits.max_payload_bytes = 2000;
    profile.limits.timeout_ms = 2;
    let (a, _, nodes) = transcript(profile);
    let mut receiver = session(&nodes, &a, 4);
    let before = receiver.checkpoint();
    assert!(receiver
        .build_transmission(&a, "x", &vec![vec![0]; 4])
        .is_err());
    assert!(receiver
        .build_transmission(&a, "x", &[vec![0; 1401]])
        .is_err());
    assert!(receiver
        .build_transmission(&a, "x", &[vec![0; 1400], vec![0; 601]])
        .is_err());
    let packets = receiver
        .build_transmission(&a, "task", &[vec![1], vec![2]])
        .unwrap();
    receiver.start_receive().unwrap();
    assert!(receiver.start_receive().is_err());
    assert!(receiver.stage_packet(packets[0].clone()).unwrap().is_none());
    std::thread::sleep(std::time::Duration::from_millis(4));
    assert!(matches!(
        receiver.stage_packet(packets[1].clone()),
        Err(TraxError::TransmissionExpired)
    ));
    assert_eq!(receiver.checkpoint(), before);
    receiver.start_receive().unwrap();
    std::thread::sleep(std::time::Duration::from_millis(4));
    assert!(receiver.expire_receive());
    assert!(!receiver.has_pending());
    assert_eq!(receiver.checkpoint(), before);
    for bytes in [
        vec![0; 4097],
        vec![0x9b, 255, 255, 255, 255, 255, 255, 255, 255],
        vec![0x81; 100],
    ] {
        receiver.start_receive().unwrap();
        assert!(receiver.stage_encoded_packet(&bytes).is_err());
        assert!(!receiver.has_pending());
        assert_eq!(receiver.checkpoint(), before);
    }
    let valid = encode_deterministic(&packets[0]).unwrap();
    let mut tagged = vec![0xd9, 0x03, 0xe7];
    tagged.extend_from_slice(&valid);
    assert!(decode_strict::<PacketV2>(&tagged, 4096).is_err());
    let mut trailing = valid;
    trailing.push(0);
    assert!(decode_strict::<PacketV2>(&trailing, 4096).is_err());
}

#[test]
fn wire_budget_accounts_for_final_signature_and_fragmentation_reduces_data() {
    let mut profile = TransmissionProfileV2::default();
    profile.limits.max_wire_packet_bytes = 1800;
    let (a, _, nodes) = transcript(profile);
    let mut receiver = session(&nodes, &a, 4);
    assert!(receiver
        .build_transmission(&a, "document", &[vec![1; 1400]])
        .is_err());
    let payload = vec![7; 14000];
    let packets = receiver
        .fragment_transmission(&a, "document", &payload)
        .unwrap();
    assert!(packets.len() > 10);
    assert!(packets
        .iter()
        .all(|p| encode_deterministic(p).unwrap().len() <= 1800));
    assert_eq!(admit(&mut receiver, &packets), payload);
}

#[test]
fn arbitrary_bounded_mutations_never_release_unauthenticated_payload() {
    use rand::{Rng, SeedableRng};
    let (a, _, nodes) = transcript(TransmissionProfileV2::default());
    let sender = session(&nodes, &a, 4);
    let original = sender
        .build_transmission(&a, "task", &[vec![0; 32], vec![1; 32], vec![2; 32]])
        .unwrap();
    let mut rng = rand::rngs::StdRng::seed_from_u64(0x74726178);
    for _ in 0..128 {
        let mut encoded: Vec<_> = original
            .iter()
            .map(|p| encode_deterministic(p).unwrap())
            .collect();
        let p = rng.gen_range(0..encoded.len());
        let i = rng.gen_range(0..encoded[p].len());
        encoded[p][i] ^= 1 << rng.gen_range(0..8);
        let mut receiver = session(&nodes, &a, 4);
        let before = receiver.checkpoint();
        receiver.start_receive().unwrap();
        let mut failed = false;
        for bytes in encoded {
            match receiver.stage_encoded_packet(&bytes) {
                Err(_) => {
                    failed = true;
                    break;
                }
                Ok(None) => assert_eq!(receiver.checkpoint(), before),
                Ok(Some(_)) => panic!("mutated packet admitted"),
            }
        }
        assert!(failed);
        assert_eq!(receiver.checkpoint(), before);
    }
}
