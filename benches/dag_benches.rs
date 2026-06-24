// cargo bench --bench dag_benches

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use trax::dag::verify_segment_proof;
use trax::types::{DagNode, SegmentProof};

#[cfg(feature = "crypto-ed25519")]
use ed25519_dalek::SigningKey;

#[cfg(feature = "crypto-ed25519")]
use trax::crypto::{ed25519_sign, ed25519_sign_batch_k8};

fn make_dummy_segment(k: usize) -> SegmentProof {
    let mut nodes = Vec::with_capacity(k);

    for i in 0..k {
        nodes.push(DagNode {
            prev_tip_hash: [0u8; 32],
            segment_anchor: [1u8; 32],
            index: i as u64,
            ts: i as u64,
            op_type: 1,
            peer_id: [2u8; 16],
            counter: i as u64,
            signature: vec![3u8; 64],
        });
    }

    let cumulative_hash = trax::dag::cumulative_hash(&nodes);

    SegmentProof {
        k: k as u32,
        nodes,
        cumulative_hash,
    }
}

fn make_messages(k: usize) -> Vec<Vec<u8>> {
    (0..k)
        .map(|i| {
            format!(
                "trax benchmark message index={} payload=agent-to-agent trust frame",
                i
            )
            .into_bytes()
        })
        .collect()
}

#[cfg(feature = "crypto-ed25519")]
fn fixed_signing_key() -> SigningKey {
    SigningKey::from_bytes(&[7u8; 32])
}

fn bench_k_window_verification(c: &mut Criterion) {
    for &k in &[8usize, 16, 32, 64, 128, 256] {
        c.bench_function(&format!("verify_last_{}_nodes", k), |b| {
            let seg = make_dummy_segment(k);

            b.iter(|| {
                let ok = verify_segment_proof(black_box(&seg));
                black_box(ok);
            })
        });
    }
}

#[cfg(feature = "crypto-ed25519")]
fn bench_ed25519_signing(c: &mut Criterion) {
    let sk = fixed_signing_key();

    for &k in &[8usize, 16, 32, 64, 128, 256] {
        c.bench_function(&format!("sign_{}_nodes_individual_ed25519", k), |b| {
            let messages = make_messages(k);

            b.iter(|| {
                for msg in &messages {
                    let sig = ed25519_sign(black_box(&sk), black_box(msg));
                    black_box(sig);
                }
            })
        });
    }
}

#[cfg(feature = "crypto-ed25519")]
fn bench_k8_merkle_batch_signing(c: &mut Criterion) {
    let sk = fixed_signing_key();

    c.bench_function("sign_batch_k8_merkle_root_ed25519", |b| {
        let messages = make_messages(8);

        b.iter(|| {
            let result = ed25519_sign_batch_k8(black_box(&sk), black_box(&messages));
            black_box(result);
        })
    });
}

#[cfg(feature = "crypto-ed25519")]
criterion_group! {
    name = benches;
    config = Criterion::default().without_plots();
    targets =
        bench_k_window_verification,
        bench_ed25519_signing,
        bench_k8_merkle_batch_signing
}

#[cfg(not(feature = "crypto-ed25519"))]
criterion_group! {
    name = benches;
    config = Criterion::default().without_plots();
    targets = bench_k_window_verification
}

criterion_main!(benches);