// cargo bench --bench dag_benches
use criterion::{black_box, criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion};
use ed25519_dalek::SigningKey;
use trax::config::SegmentConfig;
use trax::crypto::hash32;
use trax::dag::{
    create_segment_seal, event_tip, lineage_key_id, ordered_merkle_root,
    verify_segment_proof_intrinsic,
};
use trax::graph::{participant_id, GraphSegmentProof, PairDag, PairGenesis, ParticipantId};
use trax::{HashAlgorithm, PostGenesisEventV1, ProtocolConfig, SegmentProof, SigningAlgorithm};

fn fixture() -> (SigningKey, Vec<PostGenesisEventV1>) {
    let key = SigningKey::from_bytes(&[7; 32]);
    let mut tip = hash32(b"genesis");
    let events = (0..8)
        .map(|i| {
            let event = PostGenesisEventV1 {
                version: 1,
                session_id: hash32(b"session"),
                lineage_key_id: lineage_key_id(&key.verifying_key()),
                receiver_id: hash32(b"receiver"),
                segment_index: 0,
                counter: i,
                previous_tip: tip,
                content_hash: hash32(&[i as u8]),
                payload_hash: hash32(&[i as u8, 1]),
            };
            tip = event_tip(&event).unwrap();
            event
        })
        .collect();
    (key, events)
}

fn benches(c: &mut Criterion) {
    let config = SegmentConfig::new(8).unwrap();
    let (key, events) = fixture();
    c.bench_function("ordered_k8_segment_merkle_root", |b| {
        b.iter(|| black_box(ordered_merkle_root(config, black_box(&events)).unwrap()))
    });
    c.bench_function("create_signed_k8_segment_seal", |b| {
        b.iter(|| {
            black_box(create_segment_seal(config, black_box(&key), black_box(&events)).unwrap())
        })
    });
    let proof = SegmentProof {
        seal: create_segment_seal(config, &key, &events).unwrap(),
        events,
    };
    c.bench_function("verify_signed_k8_segment", |b| {
        b.iter(|| {
            verify_segment_proof_intrinsic(
                config,
                black_box(&proof),
                black_box(&key.verifying_key()),
            )
            .unwrap();
            black_box(())
        })
    });
}

fn shared_proof(dag: &PairDag, key: &SigningKey, authors: [ParticipantId; 2]) -> GraphSegmentProof {
    let mut pending = dag.begin_segment();
    for index in 0..dag.config().k() {
        pending
            .append(
                authors[index % 2],
                dag.main_branch(),
                vec![index as u8; 128],
            )
            .unwrap();
    }
    pending
        .seal(participant_id(&key.verifying_key().to_bytes()), key)
        .unwrap()
}

fn shared_fixture(history_events: usize) -> (PairDag, SigningKey, [ParticipantId; 2]) {
    let key = SigningKey::from_bytes(&[41; 32]);
    let peer = SigningKey::from_bytes(&[42; 32]);
    let authors = [
        participant_id(&key.verifying_key().to_bytes()),
        participant_id(&peer.verifying_key().to_bytes()),
    ];
    let config =
        ProtocolConfig::new(8, SigningAlgorithm::Ed25519, HashAlgorithm::Sha512256).unwrap();
    let genesis = PairGenesis::new(
        config,
        [43; 32],
        &key.verifying_key(),
        &peer.verifying_key(),
    )
    .unwrap();
    let mut dag = PairDag::from_verified_genesis(config, genesis).unwrap();
    assert_eq!(history_events % config.k(), 0);
    for _ in 0..history_events / config.k() {
        let proof = shared_proof(&dag, &key, authors);
        dag.verify_and_commit(&proof).unwrap();
    }
    (dag, key, authors)
}

fn shared_graph_benches(c: &mut Criterion) {
    let mut group = c.benchmark_group("shared_pair_dag_k8_sha512_256");
    for history_events in [0, 1024] {
        let (dag, key, authors) = shared_fixture(history_events);
        group.bench_with_input(
            BenchmarkId::new("prepare", history_events),
            &dag,
            |b, dag| b.iter(|| black_box(black_box(dag).begin_segment())),
        );
        group.bench_with_input(
            BenchmarkId::new("stage_and_seal", history_events),
            &dag,
            |b, dag| b.iter(|| black_box(shared_proof(black_box(dag), black_box(&key), authors))),
        );
        let proof = shared_proof(&dag, &key, authors);
        group.bench_with_input(
            BenchmarkId::new("verify_and_commit", history_events),
            &dag,
            |b, dag| {
                // Clone the mutable fixture before timing; return it so teardown is
                // also outside timing. The measured operation admits one segment.
                b.iter_batched(
                    || dag.clone(),
                    |mut candidate| {
                        black_box(candidate.verify_and_commit(black_box(&proof)).unwrap());
                        candidate
                    },
                    BatchSize::PerIteration,
                )
            },
        );
    }
    group.finish();
}

criterion_group! { name = group; config = Criterion::default().without_plots(); targets = benches, shared_graph_benches }
criterion_main!(group);
