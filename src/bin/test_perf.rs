use aaicp_core::crypto::{ed25519_sign, ed25519_sign_batch_k8};
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use std::time::Instant;

fn main() {
    let mut rng = OsRng;
    let sk = SigningKey::generate(&mut rng);
    let messages: Vec<Vec<u8>> = (0..8)
        .map(|_| (0..1024).map(|_| rand::random::<u8>()).collect())
        .collect();
    
    // Non batch test
    let start = Instant::now();
    for m in &messages {
        let _sig = ed25519_sign(&sk, m);
    }
    println!("Non-batch elapsed: {:?}", start.elapsed());
    
    // Batch K-8 test
    let start = Instant::now();
    let (_root_sig, _proofs) = ed25519_sign_batch_k8(&sk, &messages);
    println!("Batch K=8 elapsed: {:?}", start.elapsed());
}
