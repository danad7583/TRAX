//! TRAX Admission Envelope v1 for Packet 0 security binding.

use crate::crypto::{ed25519_sign, ed25519_verify, hash32};
use crate::encoding::{decode, encode_deterministic};
use crate::errors::TraxError;
use ed25519_dalek::{SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};

pub const ADMISSION_ENVELOPE_VERSION: u8 = 1;
pub const KEY_LEN: usize = 32;
pub const HASH_LEN: usize = 32;
pub const NONCE_LEN: usize = 16;
pub const SIGNATURE_LEN: usize = 64;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AdmissionEnvelopeV1 {
    pub version: u8,
    pub session_id: Vec<u8>,
    pub nonce: Vec<u8>,
    pub sender_public_key: Vec<u8>,
    pub receiver_public_key: Vec<u8>,
    pub payload_hash: Vec<u8>,
    pub message_type: String,
    pub dag_parent_refs: Vec<Vec<u8>>,
    pub proof_type: String,
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AdmissionEnvelopeV1Unsigned {
    pub version: u8,
    pub session_id: Vec<u8>,
    pub nonce: Vec<u8>,
    pub sender_public_key: Vec<u8>,
    pub receiver_public_key: Vec<u8>,
    pub payload_hash: Vec<u8>,
    pub message_type: String,
    pub dag_parent_refs: Vec<Vec<u8>>,
    pub proof_type: String,
}

#[allow(clippy::too_many_arguments)]
pub fn create_admission_envelope_v1(
    signing_key: &SigningKey,
    receiver_public_key: &[u8],
    session_id: &[u8],
    nonce: &[u8],
    payload: &[u8],
    message_type: &str,
    dag_parent_refs: &[Vec<u8>],
    proof_type: &str,
) -> Result<Vec<u8>, TraxError> {
    validate_envelope_inputs(
        receiver_public_key,
        session_id,
        nonce,
        message_type,
        dag_parent_refs,
        proof_type,
    )?;

    let unsigned = AdmissionEnvelopeV1Unsigned {
        version: ADMISSION_ENVELOPE_VERSION,
        session_id: session_id.to_vec(),
        nonce: nonce.to_vec(),
        sender_public_key: signing_key.verifying_key().as_bytes().to_vec(),
        receiver_public_key: receiver_public_key.to_vec(),
        payload_hash: hash32(payload).to_vec(),
        message_type: message_type.to_owned(),
        dag_parent_refs: dag_parent_refs.to_vec(),
        proof_type: proof_type.to_owned(),
    };

    let signing_bytes = encode_deterministic(&unsigned)?;
    let signature = ed25519_sign(signing_key, &signing_bytes);

    let envelope = AdmissionEnvelopeV1 {
        version: unsigned.version,
        session_id: unsigned.session_id,
        nonce: unsigned.nonce,
        sender_public_key: unsigned.sender_public_key,
        receiver_public_key: unsigned.receiver_public_key,
        payload_hash: unsigned.payload_hash,
        message_type: unsigned.message_type,
        dag_parent_refs: unsigned.dag_parent_refs,
        proof_type: unsigned.proof_type,
        signature,
    };

    encode_deterministic(&envelope)
}

pub fn decode_admission_envelope_v1(data: &[u8]) -> Result<AdmissionEnvelopeV1, TraxError> {
    decode(data)
}

pub fn verify_admission_envelope_v1(data: &[u8], payload: &[u8]) -> Result<bool, TraxError> {
    let envelope = decode_admission_envelope_v1(data)?;
    verify_decoded_admission_envelope_v1(&envelope, payload)
}

pub fn verify_admission_envelope_v1_for_receiver(
    data: &[u8],
    payload: &[u8],
    receiver_public_key: &[u8],
) -> Result<bool, TraxError> {
    validate_len("receiver_public_key", receiver_public_key, KEY_LEN)?;

    let envelope = decode_admission_envelope_v1(data)?;
    if envelope.receiver_public_key != receiver_public_key {
        return Ok(false);
    }

    verify_decoded_admission_envelope_v1(&envelope, payload)
}

fn verify_decoded_admission_envelope_v1(
    envelope: &AdmissionEnvelopeV1,
    payload: &[u8],
) -> Result<bool, TraxError> {
    validate_envelope(envelope)?;

    let expected_payload_hash = hash32(payload);
    if envelope.payload_hash.as_slice() != expected_payload_hash.as_slice() {
        return Ok(false);
    }

    let unsigned = AdmissionEnvelopeV1Unsigned {
        version: envelope.version,
        session_id: envelope.session_id.clone(),
        nonce: envelope.nonce.clone(),
        sender_public_key: envelope.sender_public_key.clone(),
        receiver_public_key: envelope.receiver_public_key.clone(),
        payload_hash: envelope.payload_hash.clone(),
        message_type: envelope.message_type.clone(),
        dag_parent_refs: envelope.dag_parent_refs.clone(),
        proof_type: envelope.proof_type.clone(),
    };

    let signing_bytes = encode_deterministic(&unsigned)?;
    let sender_public_key: [u8; KEY_LEN] = envelope
        .sender_public_key
        .as_slice()
        .try_into()
        .map_err(|_| TraxError::InvalidInput("sender_public_key must be 32 bytes"))?;
    let verifying_key =
        VerifyingKey::from_bytes(&sender_public_key).map_err(|_| TraxError::Crypto)?;

    Ok(ed25519_verify(
        &verifying_key,
        &signing_bytes,
        &envelope.signature,
    ))
}

fn validate_envelope(envelope: &AdmissionEnvelopeV1) -> Result<(), TraxError> {
    if envelope.version != ADMISSION_ENVELOPE_VERSION {
        return Err(TraxError::InvalidInput(
            "unsupported admission envelope version",
        ));
    }

    validate_envelope_inputs(
        &envelope.receiver_public_key,
        &envelope.session_id,
        &envelope.nonce,
        &envelope.message_type,
        &envelope.dag_parent_refs,
        &envelope.proof_type,
    )?;
    validate_len("sender_public_key", &envelope.sender_public_key, KEY_LEN)?;
    validate_len("payload_hash", &envelope.payload_hash, HASH_LEN)?;
    validate_len("signature", &envelope.signature, SIGNATURE_LEN)
}

fn validate_envelope_inputs(
    receiver_public_key: &[u8],
    session_id: &[u8],
    nonce: &[u8],
    message_type: &str,
    dag_parent_refs: &[Vec<u8>],
    proof_type: &str,
) -> Result<(), TraxError> {
    validate_len("receiver_public_key", receiver_public_key, KEY_LEN)?;
    validate_len("session_id", session_id, HASH_LEN)?;
    validate_len("nonce", nonce, NONCE_LEN)?;

    if message_type.is_empty() {
        return Err(TraxError::InvalidInput("message_type must not be empty"));
    }
    if proof_type.is_empty() {
        return Err(TraxError::InvalidInput("proof_type must not be empty"));
    }

    for parent_ref in dag_parent_refs {
        validate_len("dag_parent_ref", parent_ref, HASH_LEN)?;
    }

    Ok(())
}

fn validate_len(name: &'static str, value: &[u8], expected: usize) -> Result<(), TraxError> {
    if value.len() == expected {
        Ok(())
    } else {
        Err(TraxError::InvalidInput(match name {
            "receiver_public_key" => "receiver_public_key must be 32 bytes",
            "sender_public_key" => "sender_public_key must be 32 bytes",
            "session_id" => "session_id must be 32 bytes",
            "nonce" => "nonce must be 16 bytes",
            "payload_hash" => "payload_hash must be 32 bytes",
            "signature" => "signature must be 64 bytes",
            "dag_parent_ref" => "dag_parent_ref must be 32 bytes",
            _ => "invalid field length",
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encoding::encode_deterministic;
    use rand::rngs::OsRng;

    fn test_keys() -> (SigningKey, SigningKey, SigningKey) {
        let mut rng = OsRng;
        (
            SigningKey::generate(&mut rng),
            SigningKey::generate(&mut rng),
            SigningKey::generate(&mut rng),
        )
    }

    fn valid_envelope(sender: &SigningKey, receiver: &SigningKey) -> Vec<u8> {
        let session_id = hash32(b"session transcript");
        let nonce = [7u8; NONCE_LEN];
        let payload = b"packet zero payload";
        let parent_refs = vec![hash32(b"parent").to_vec()];

        create_admission_envelope_v1(
            sender,
            receiver.verifying_key().as_bytes(),
            &session_id,
            &nonce,
            payload,
            "packet0.admission",
            &parent_refs,
            "direct-ed25519",
        )
        .expect("admission envelope should encode")
    }

    #[test]
    fn valid_admission_envelope_verifies_successfully() {
        let (sender, receiver, _) = test_keys();
        let envelope = valid_envelope(&sender, &receiver);

        assert!(verify_admission_envelope_v1(&envelope, b"packet zero payload").unwrap());
    }

    #[test]
    fn tampered_payload_fails_verification() {
        let (sender, receiver, _) = test_keys();
        let envelope = valid_envelope(&sender, &receiver);

        assert!(!verify_admission_envelope_v1(&envelope, b"tampered").unwrap());
    }

    #[test]
    fn wrong_receiver_public_key_fails_receiver_bound_verification() {
        let (sender, receiver, wrong_receiver) = test_keys();
        let envelope = valid_envelope(&sender, &receiver);

        assert!(verify_admission_envelope_v1_for_receiver(
            &envelope,
            b"packet zero payload",
            receiver.verifying_key().as_bytes()
        )
        .unwrap());
        assert!(!verify_admission_envelope_v1_for_receiver(
            &envelope,
            b"packet zero payload",
            wrong_receiver.verifying_key().as_bytes()
        )
        .unwrap());
    }

    #[test]
    fn malformed_sender_key_length_fails_cleanly() {
        let (sender, receiver, _) = test_keys();
        let envelope = valid_envelope(&sender, &receiver);
        let mut decoded = decode_admission_envelope_v1(&envelope).unwrap();
        decoded.sender_public_key = vec![0u8; KEY_LEN - 1];
        let malformed = encode_deterministic(&decoded).unwrap();

        assert!(matches!(
            verify_admission_envelope_v1(&malformed, b"packet zero payload"),
            Err(TraxError::InvalidInput(
                "sender_public_key must be 32 bytes"
            ))
        ));
    }

    #[test]
    fn malformed_receiver_key_length_fails_cleanly() {
        let (sender, _, _) = test_keys();
        let session_id = hash32(b"session transcript");
        let nonce = [7u8; NONCE_LEN];

        assert!(matches!(
            create_admission_envelope_v1(
                &sender,
                &[0u8; KEY_LEN - 1],
                &session_id,
                &nonce,
                b"packet zero payload",
                "packet0.admission",
                &[],
                "direct-ed25519",
            ),
            Err(TraxError::InvalidInput(
                "receiver_public_key must be 32 bytes"
            ))
        ));
    }

    #[test]
    fn malformed_session_id_length_fails_cleanly() {
        let (sender, receiver, _) = test_keys();
        let nonce = [7u8; NONCE_LEN];

        assert!(matches!(
            create_admission_envelope_v1(
                &sender,
                receiver.verifying_key().as_bytes(),
                &[0u8; HASH_LEN - 1],
                &nonce,
                b"packet zero payload",
                "packet0.admission",
                &[],
                "direct-ed25519",
            ),
            Err(TraxError::InvalidInput("session_id must be 32 bytes"))
        ));
    }

    #[test]
    fn malformed_nonce_length_fails_cleanly() {
        let (sender, receiver, _) = test_keys();
        let session_id = hash32(b"session transcript");

        assert!(matches!(
            create_admission_envelope_v1(
                &sender,
                receiver.verifying_key().as_bytes(),
                &session_id,
                &[0u8; NONCE_LEN - 1],
                b"packet zero payload",
                "packet0.admission",
                &[],
                "direct-ed25519",
            ),
            Err(TraxError::InvalidInput("nonce must be 16 bytes"))
        ));
    }

    #[test]
    fn malformed_signature_length_fails_cleanly() {
        let (sender, receiver, _) = test_keys();
        let envelope = valid_envelope(&sender, &receiver);
        let mut decoded = decode_admission_envelope_v1(&envelope).unwrap();
        decoded.signature = vec![0u8; SIGNATURE_LEN - 1];
        let malformed = encode_deterministic(&decoded).unwrap();

        assert!(matches!(
            verify_admission_envelope_v1(&malformed, b"packet zero payload"),
            Err(TraxError::InvalidInput("signature must be 64 bytes"))
        ));
    }

    #[test]
    fn empty_message_type_fails_cleanly() {
        let (sender, receiver, _) = test_keys();
        let session_id = hash32(b"session transcript");
        let nonce = [7u8; NONCE_LEN];

        assert!(matches!(
            create_admission_envelope_v1(
                &sender,
                receiver.verifying_key().as_bytes(),
                &session_id,
                &nonce,
                b"packet zero payload",
                "",
                &[],
                "direct-ed25519",
            ),
            Err(TraxError::InvalidInput("message_type must not be empty"))
        ));
    }

    #[test]
    fn empty_proof_type_fails_cleanly() {
        let (sender, receiver, _) = test_keys();
        let session_id = hash32(b"session transcript");
        let nonce = [7u8; NONCE_LEN];

        assert!(matches!(
            create_admission_envelope_v1(
                &sender,
                receiver.verifying_key().as_bytes(),
                &session_id,
                &nonce,
                b"packet zero payload",
                "packet0.admission",
                &[],
                "",
            ),
            Err(TraxError::InvalidInput("proof_type must not be empty"))
        ));
    }

    #[test]
    fn invalid_dag_parent_reference_length_fails_cleanly() {
        let (sender, receiver, _) = test_keys();
        let session_id = hash32(b"session transcript");
        let nonce = [7u8; NONCE_LEN];
        let parent_refs = vec![vec![0u8; HASH_LEN - 1]];

        assert!(matches!(
            create_admission_envelope_v1(
                &sender,
                receiver.verifying_key().as_bytes(),
                &session_id,
                &nonce,
                b"packet zero payload",
                "packet0.admission",
                &parent_refs,
                "direct-ed25519",
            ),
            Err(TraxError::InvalidInput("dag_parent_ref must be 32 bytes"))
        ));
    }
}
