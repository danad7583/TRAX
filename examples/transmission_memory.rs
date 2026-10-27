//! Instrumented Rust-heap high-water measurements, separate from timing benches.
use ed25519_dalek::SigningKey;
use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};
use trax::genesis::{
    accept_genesis_offer, confirm_genesis, create_genesis_offer, TransmissionProfileV2,
    VerifiedGenesisV2,
};
use trax::transmission::SessionV2;

struct Counted;
static LIVE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);
fn add(bytes: usize) {
    let live = LIVE.fetch_add(bytes, Ordering::Relaxed) + bytes;
    PEAK.fetch_max(live, Ordering::Relaxed);
}
unsafe impl GlobalAlloc for Counted {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let p = System.alloc(layout);
        if !p.is_null() {
            add(layout.size());
        }
        p
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let p = System.alloc_zeroed(layout);
        if !p.is_null() {
            add(layout.size());
        }
        p
    }
    unsafe fn dealloc(&self, p: *mut u8, layout: Layout) {
        System.dealloc(p, layout);
        LIVE.fetch_sub(layout.size(), Ordering::Relaxed);
    }
    unsafe fn realloc(&self, p: *mut u8, old: Layout, new_size: usize) -> *mut u8 {
        let q = System.realloc(p, old, new_size);
        if !q.is_null() {
            if new_size >= old.size() {
                add(new_size - old.size());
            } else {
                LIVE.fetch_sub(old.size() - new_size, Ordering::Relaxed);
            }
        }
        q
    }
}
#[global_allocator]
static ALLOCATOR: Counted = Counted;
fn live(base: usize) -> usize {
    LIVE.load(Ordering::Relaxed).saturating_sub(base)
}

fn main() {
    println!("packets,payload_bytes,source_chunks_bytes,after_build_bytes,provisional_bytes,admitted_with_payload_bytes,history_only_bytes,peak_bytes");
    for count in [1, 8, 17, 100, 138, 1024] {
        let key = SigningKey::from_bytes(&[61; 32]);
        let peer = SigningKey::from_bytes(&[62; 32]);
        let a = key.verifying_key().to_bytes();
        let b = peer.verifying_key().to_bytes();
        let offer = create_genesis_offer(&key, [63; 32], TransmissionProfileV2::default()).unwrap();
        let acceptance = accept_genesis_offer(&offer, &peer, |k| k == &a).unwrap();
        let confirmation = confirm_genesis(&offer, &acceptance, &key, |k| k == &b).unwrap();
        let genesis =
            VerifiedGenesisV2::verify([offer, acceptance, confirmation], |k| k == &a || k == &b)
                .unwrap();
        let sender = SessionV2::new(genesis.clone(), a, [64; 32]).unwrap();
        let mut receiver = SessionV2::new(genesis, a, [64; 32]).unwrap();
        let baseline = LIVE.load(Ordering::Relaxed);
        PEAK.store(baseline, Ordering::Relaxed);
        let chunks = vec![vec![42; 1024]; count];
        let source = live(baseline);
        let packets = sender.build_transmission(&key, "request", &chunks).unwrap();
        let built = live(baseline);
        receiver.start_receive().unwrap();
        for packet in &packets[..count - 1] {
            assert!(receiver.stage_packet(packet.clone()).unwrap().is_none());
        }
        let pending = live(baseline);
        let verified = receiver
            .stage_packet(packets[count - 1].clone())
            .unwrap()
            .unwrap();
        let admitted = live(baseline);
        drop(verified);
        drop(packets);
        drop(chunks);
        let retained = live(baseline);
        let peak = PEAK.load(Ordering::Relaxed).saturating_sub(baseline);
        println!(
            "{count},{},{source},{built},{pending},{admitted},{retained},{peak}",
            count * 1024
        );
    }
}
