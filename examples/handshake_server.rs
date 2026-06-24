//! Minimal handshake server example
use aaicp_core::session::derive_session_id;

fn main() {
    // Mirror of the client for demonstration; real code would read/write sockets.
    let nonce_a = b"nonce_A_32_bytes________________";
    let nonce_b = b"nonce_B_32_bytes________________";
    let context = b"aaicp:demo";
    let sid = derive_session_id(context, nonce_a, nonce_b, None);
    println!("session_id={:02x?}", sid);
}
