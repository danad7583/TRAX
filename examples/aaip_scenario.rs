//! Simulate Agent A ↔ Agent B scenario per TRAX v1.1.0
use rand_core::OsRng;
use ed25519_dalek::{SigningKey, VerifyingKey, Signer, Verifier, Signature};
use trax::session::derive_session_id;
use trax::crypto::hash32;
use coset::{CborSerializable, CoseSign1, Header, ProtectedHeader, Algorithm, iana};

fn sign_cose(sk: &SigningKey, payload: &[u8]) -> Vec<u8> {
    let mut header = Header::default();
    header.alg = Some(Algorithm::Assigned(iana::Algorithm::EdDSA));

    let signature = sk.sign(payload).to_bytes().to_vec();
    let sign1 = CoseSign1 {
        protected: ProtectedHeader {
            original_data: None,
            header,
        },
        unprotected: Header::default(),
        payload: Some(payload.to_vec()),
        signature,
    };

    sign1.to_vec().expect("serialize cose")
}

fn verify_cose(vk: &VerifyingKey, bytes: &[u8]) -> bool {
    let Ok(sign1) = CoseSign1::from_slice(bytes) else {
        return false;
    };

    let Some(payload) = sign1.payload.as_ref() else {
        return false;
    };

    let Ok(signature) = Signature::from_slice(&sign1.signature) else {
        return false;
    };

    vk.verify(payload, &signature).is_ok()
}

fn main() {
    let nonce_a = b"nonce_A_32_bytes________________";
    let nonce_b = b"nonce_B_32_bytes________________";
    let context = b"trax:demo";
    let session_id = derive_session_id(context, nonce_a, nonce_b, None);
    println!("session_id={:02x?}", session_id);

    let sk_a = SigningKey::generate(&mut OsRng);
    let vk_a = sk_a.verifying_key();
    let sk_b = SigningKey::generate(&mut OsRng);
    let _vk_b = sk_b.verifying_key();

    let payload1 = b"{\"msg\":\"hello B\",\"counter\":1}";
    let env1 = sign_cose(&sk_a, payload1);
    println!("A->B COSE len={} bytes", env1.len());
    assert!(verify_cose(&vk_a, &env1));

    let tip_hash = hash32(&env1);
    println!("B tip_hash={:02x?}", tip_hash);

    let _sk_b2 = SigningKey::generate(&mut OsRng);
    println!("B rotated key; entering quarantine until fresh K-window validated");

    println!("Quarantine simulated; complete.");
}
