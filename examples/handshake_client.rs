//! Minimal handshake client example
use trax::session::derive_session_id;

fn main() {
    // In a real demo you'd exchange nonces over the network.
    let nonce_a = b"nonce_A_32_bytes________________";
    let nonce_b = b"nonce_B_32_bytes________________";
    let context = b"trax:demo";
    let sid = derive_session_id(context, nonce_a, nonce_b, None);
    println!("session_id={:02x?}", sid);
}
