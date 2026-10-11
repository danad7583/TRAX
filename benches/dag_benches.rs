// cargo bench --bench dag_benches
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use ed25519_dalek::SigningKey;
use trax::crypto::hash32;
use trax::dag::{
    create_segment_seal_k8, event_tip, lineage_key_id, ordered_merkle_root, verify_segment_proof,
};
use trax::{PostGenesisEventV1, SegmentProof};

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
    let (key, events) = fixture();
    c.bench_function("ordered_k8_segment_merkle_root", |b| {
        b.iter(|| black_box(ordered_merkle_root(black_box(&events)).unwrap()))
    });
    c.bench_function("create_signed_k8_segment_seal", |b| {
        b.iter(|| black_box(create_segment_seal_k8(black_box(&key), black_box(&events)).unwrap()))
    });
    let proof = SegmentProof {
        seal: create_segment_seal_k8(&key, &events).unwrap(),
        events,
    };
    c.bench_function("verify_signed_k8_segment", |b| {
        b.iter(|| {
            black_box(
                verify_segment_proof(black_box(&proof), black_box(&key.verifying_key())).unwrap(),
            )
        })
    });
}

criterion_group! { name = group; config = Criterion::default().without_plots(); targets = benches }
criterion_main!(group);
