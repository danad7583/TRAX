//! Helper to load conformance vectors from /vectors
use std::fs;
use std::path::PathBuf;

pub fn load_vector(name: &str) -> Vec<u8> {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("vectors");
    p.push(name);
    fs::read(p).expect("vector not found")
}
