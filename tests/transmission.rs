use ed25519_dalek::SigningKey;
use trax::crypto::ed25519_sign;
use trax::crypto::hash_domain;
use trax::encoding::{decode_strict, encode_deterministic};
use trax::genesis::{
    accept_genesis_offer, confirm_genesis, create_genesis_offer, GenesisNode, VerifiedGenesis,
};
use trax::merkle::MerkleAccumulator;
use trax::session::Relationship;
use trax::transmission::{event_tip, Packet, TransmissionCommitment, TransmissionKind};
use trax::{HashAlgorithm, TransmissionProfile, TraxError};

fn transcript(profile: TransmissionProfile) -> (SigningKey, SigningKey, [GenesisNode; 3]) {
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

fn session(nodes: &[GenesisNode; 3], initiator: &SigningKey, nonce: u8) -> Relationship {
    let trusted = [
        nodes[0].event.initiator_public_key,
        nodes[1].event.responder_public_key.unwrap(),
    ];
    let genesis = VerifiedGenesis::verify(nodes.clone(), |key| trusted.contains(key)).unwrap();
    let mut relationship = Relationship::new(genesis).unwrap();
    relationship
        .begin_session(initiator.verifying_key().to_bytes(), [nonce; 32])
        .unwrap();
    relationship
}

fn admit(session: &mut Relationship, packets: &[Packet]) -> Vec<u8> {
    let before = session.checkpoint();
    session.start_receive().unwrap();
    let mut released = Vec::new();
    for (index, packet) in packets.iter().enumerate() {
        let encoded = encode_deterministic(packet).unwrap();
        let verified = session.stage_encoded_packet(&encoded).unwrap();
        if index + 1 < packets.len() {
            assert!(verified.is_none());
            assert_eq!(session.checkpoint(), before);
            assert_eq!(session.history().len() as u64, before.record_count + 1);
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

fn reject(session: &mut Relationship, packets: &[Packet]) {
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

fn frozen_standalone_packet() -> Vec<u8> {
    // Read a frozen wire artifact as generic CBOR rather than retaining its
    // removed public protocol types just to manufacture a negative fixture.
    let transcript: ciborium::value::Value =
        decode_strict(include_bytes!("fixtures/standalone_session.cbor"), 65536).unwrap();
    let fields = transcript.as_map().unwrap();
    let request = fields
        .iter()
        .find(|(key, _)| key.as_text() == Some("request"))
        .unwrap()
        .1
        .as_array()
        .unwrap();
    let bytes = encode_deterministic(&request[0]).unwrap();
    assert!(bytes.len() <= TransmissionProfile::default().limits.max_wire_packet_bytes as usize);
    bytes
}

#[test]
fn all_required_sizes_reconstruct_payloads_and_independent_roots() {
    for n in [1, 2, 3, 7, 8, 9, 17, 35, 100, 138] {
        let (a, _, nodes) = transcript(TransmissionProfile::default());
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
        let mut merkle = MerkleAccumulator::new(HashAlgorithm::Sha512256).unwrap();
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
        assert_eq!(sender.checkpoint().record_count, n as u64 + 1);
        assert_eq!(
            receiver.checkpoint().tip,
            event_tip(HashAlgorithm::Sha512256, &packets[n - 1].event).unwrap()
        );
        for record in receiver.history() {
            assert_eq!(receiver.record(&record.id).unwrap(), record);
        }
    }
}

#[test]
fn bidirectional_multiple_rounds_and_original_initiator_only_terminal() {
    for reverse in [false, true] {
        let (a, b, nodes) = transcript(TransmissionProfile::default());
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
            assert!(!left.session().unwrap().closed());
        }
        assert!(left.create_close(responder).is_err());
        let terminal = left.create_close(initiator).unwrap();
        let included = left.checkpoint();
        assert_eq!(
            terminal.commitment.relationship_history_hash,
            included.history_hash
        );
        assert_eq!(
            terminal.commitment.packet_count,
            included.active_session.as_ref().unwrap().packet_count
        );
        let encoded = encode_deterministic(&terminal).unwrap();
        left.verify_and_close(&terminal).unwrap();
        right.verify_encoded_close(&encoded).unwrap();
        assert_eq!(
            left.session().unwrap().terminal(),
            right.session().unwrap().terminal()
        );
        assert_eq!(left.checkpoint(), right.checkpoint());
        assert_eq!(
            right.session().unwrap().terminal().unwrap().signature,
            terminal.signature
        );
        assert_eq!(right.checkpoint().record_count, included.record_count + 1);
        assert!(right.session().unwrap().closed());
        right.start_receive().unwrap();
        assert!(right.abort_receive());
        assert!(right.verify_and_close(&terminal).is_err());
        assert!(left
            .build_transmission(initiator, "task", &[vec![]])
            .is_err());
    }
}

#[test]
fn payload_order_missing_duplicate_injected_and_final_authentication_fail_atomically() {
    let (a, _, nodes) = transcript(TransmissionProfile::default());
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
    let (a, _, nodes) = transcript(TransmissionProfile::default());
    let original = session(&nodes, &a, 4)
        .build_transmission(&a, "task", &[vec![1], vec![2]])
        .unwrap();
    let mutations: Vec<fn(&mut TransmissionCommitment)> = vec![
        |c| c.version = 1,
        |c| c.purpose.push('!'),
        |c| c.relationship_id[0] ^= 1,
        |c| c.session_id[0] ^= 1,
        |c| c.transmission_id += 1,
        |c| c.initiator[0] ^= 1,
        |c| c.sender[0] ^= 1,
        |c| c.receiver[0] ^= 1,
        |c| c.key_epoch += 1,
        |c| c.kind = TransmissionKind::Response,
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
    let event_mutations: Vec<fn(&mut trax::transmission::PacketEvent)> = vec![
        |e| e.version = 1,
        |e| e.relationship_id[0] ^= 1,
        |e| e.session_id[0] ^= 1,
        |e| e.transmission_id += 1,
        |e| e.initiator[0] ^= 1,
        |e| e.sender[0] ^= 1,
        |e| e.receiver[0] ^= 1,
        |e| e.key_epoch += 1,
        |e| e.kind = TransmissionKind::Response,
        |e| e.previous_tip[0] ^= 1,
        |e| e.payload_len += 1,
    ];
    for mutation in event_mutations {
        let mut packets = original.clone();
        mutation(&mut packets[0].event);
        reject(&mut session(&nodes, &a, 4), &packets);
    }
}

fn rehash_attack(packets: &mut [Packet], key: Option<&SigningKey>) {
    packets[0].payload[0] ^= 1;
    let mut tip = packets[0].event.previous_tip;
    let mut merkle = MerkleAccumulator::new(HashAlgorithm::Sha512256).unwrap();
    for packet in packets.iter_mut() {
        packet.event.previous_tip = tip;
        packet.event.payload_hash = hash_domain(
            HashAlgorithm::Sha512256,
            b"TRAX:PAYLOAD:V3\0",
            &[&packet.payload],
        )
        .unwrap();
        tip = event_tip(HashAlgorithm::Sha512256, &packet.event).unwrap();
        merkle
            .push(&encode_deterministic(&packet.event).unwrap())
            .unwrap();
    }
    let seal = packets.last_mut().unwrap().authentication.as_mut().unwrap();
    seal.commitment.merkle_root = merkle.root().unwrap();
    seal.commitment.final_event_tip = tip;
    if let Some(key) = key {
        let mut bytes = b"TRAX:TRANSMISSION:V3\0".to_vec();
        bytes.extend_from_slice(&encode_deterministic(&seal.commitment).unwrap());
        seal.signature = ed25519_sign(key, &bytes);
    }
}

#[test]
fn network_attacker_can_rehash_every_link_but_cannot_authenticate_as_peer() {
    let (a, b, nodes) = transcript(TransmissionProfile::default());
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
fn replays_cross_session_cross_direction_and_foreign_proofs_are_rejected() {
    let (a, b, nodes) = transcript(TransmissionProfile::default());
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
        .stage_encoded_packet(&frozen_standalone_packet())
        .is_err());
    assert_eq!(old.checkpoint().record_count, 0);
    // Original history remains usable after rejecting a replay.
    let response = receiver
        .build_transmission(&b, "result", &[vec![2]])
        .unwrap();
    admit(&mut receiver, &response);
    reject(&mut receiver, &original);
}

#[test]
fn frozen_foreign_schema_and_signing_domains_cannot_substitute() {
    let (a, _, nodes) = transcript(TransmissionProfile::default());
    let mut receiver = session(&nodes, &a, 4);
    let before = receiver.checkpoint();
    receiver.start_receive().unwrap();
    assert!(receiver
        .stage_encoded_packet(&frozen_standalone_packet())
        .is_err());
    assert_eq!(receiver.checkpoint(), before);
    let original = receiver.build_transmission(&a, "task", &[vec![1]]).unwrap();
    for domain in [
        b"TRAX:TRANSMISSION:V2\0".as_slice(),
        b"TRAX:SEGMENT:SEAL:V1\0",
        b"TRAX:GRAPH:CHECKPOINT:V2\0",
    ] {
        let mut packets = original.clone();
        let seal = packets[0].authentication.as_mut().unwrap();
        let mut bytes = domain.to_vec();
        bytes.extend_from_slice(&encode_deterministic(&seal.commitment).unwrap());
        seal.signature = ed25519_sign(&a, &bytes);
        reject(&mut receiver, &packets);
    }
}

#[test]
fn closure_failures_never_modify_committed_history() {
    let (a, b, nodes) = transcript(TransmissionProfile::default());
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
    t.commitment.relationship_history_hash[0] ^= 1;
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
    t.commitment.packet_count += 1;
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
    let mut bytes = b"TRAX:SESSION:CLOSE:V3\0".to_vec();
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
    let mut profile = TransmissionProfile::default();
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
    assert!(decode_strict::<Packet>(&tagged, 4096).is_err());
    let mut trailing = valid;
    trailing.push(0);
    assert!(decode_strict::<Packet>(&trailing, 4096).is_err());
}

#[test]
fn wire_budget_accounts_for_final_signature_and_fragmentation_reduces_data() {
    let mut profile = TransmissionProfile::default();
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
fn fragmentation_separates_start_context_and_final_seal_with_exact_wire_budgets() {
    for budget in [1150, 1400, 1800, 4096] {
        let mut profile = TransmissionProfile::default();
        profile.limits.max_wire_packet_bytes = budget;
        profile.limits.max_packet_payload_bytes = budget.min(1400);
        let (a, _, nodes) = transcript(profile);
        for size in [0, 1, 2, 23, 24, 255, 256, 14000, 300000] {
            let mut receiver = session(&nodes, &a, 4);
            let payload = vec![7; size];
            let packets = receiver
                .fragment_transmission(&a, "document", &payload)
                .unwrap();
            assert!(packets
                .iter()
                .all(|p| encode_deterministic(p).unwrap().len() <= budget as usize));
            assert_eq!(
                packets
                    .iter()
                    .filter(|p| p.authentication.is_some())
                    .count(),
                1
            );
            assert!(packets[0].session_start.is_some());
            assert!(packets[1..].iter().all(|p| p.session_start.is_none()));
            if size > 0 {
                assert!(!packets.last().unwrap().payload.is_empty());
            }
            assert_eq!(admit(&mut receiver, &packets), payload);
        }
    }
    let mut profile = TransmissionProfile::default();
    profile.limits.max_wire_packet_bytes = 900;
    profile.limits.max_packet_payload_bytes = 900;
    let (a, _, nodes) = transcript(profile);
    let relationship = session(&nodes, &a, 4);
    assert!(relationship
        .fragment_transmission(&a, "document", &[1])
        .is_err());
    assert_eq!(relationship.checkpoint().record_count, 0);
}

#[test]
fn arbitrary_bounded_mutations_never_release_unauthenticated_payload() {
    use rand::{Rng, SeedableRng};
    let (a, _, nodes) = transcript(TransmissionProfile::default());
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
