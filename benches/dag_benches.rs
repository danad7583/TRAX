
// cargo bench --bench dag_benches
use criterion::{criterion_group, criterion_main, Criterion, black_box};
use trax::dag::{cumulative_hash, verify_segment_proof};
use trax::types::{DagNode, SegmentProof};

fn make_dummy_segment(k: usize) -> SegmentProof {
    let mut nodes = Vec::with_capacity(k);
    for i in 0..k {
        nodes.push(DagNode {
            prev_tip_hash: [0u8;32],
            segment_anchor: [1u8;32],
            index: i as u64,
            ts: i as u64,
            op_type: 1,
            peer_id: [2u8;16],
            counter: i as u64,
            signature: vec![3u8; 64],
        });
    }
    let cumulative_hash = trax::dag::cumulative_hash(&nodes);
    SegmentProof { k: k as u32, nodes, cumulative_hash }
}

fn bench_k_window(c: &mut Criterion) {
    for &k in &[8usize, 16, 32, 64, 128, 256] {
        c.bench_function(&format!("verify_last_{}_nodes", k), |b| {
            let seg = make_dummy_segment(k);
            b.iter(|| {
                let ok = verify_segment_proof(black_box(&seg));
                black_box(ok)
            })
        });
    }
}

criterion_group!(benches, bench_k_window);
criterion_main!(benches);
