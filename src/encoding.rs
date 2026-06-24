//! Canonical encoding: CBOR with deterministic encoding, COSE_Sign1 container.
use crate::types::ProtectedHeaders;
use coset::{self, CoseSign1, iana, Algorithm, Header, ProtectedHeader};
use ciborium::ser;
use ciborium::de;
use std::io::Write;
use crate::errors::TraxError;

pub fn encode_deterministic<T: serde::Serialize>(value: &T) -> Result<Vec<u8>, TraxError> {
    let mut buf = vec![];
    ser::into_writer(value, &mut buf).map_err(|_| TraxError::Cbor)?;
    Ok(buf)
}

pub fn decode<'a, T: serde::de::DeserializeOwned>(data: &'a [u8]) -> Result<T, TraxError> {
    let v: T = de::from_reader(data).map_err(|_| TraxError::Cbor)?;
    Ok(v)
}

pub fn cose_sign1(_headers: &ProtectedHeaders, payload: &[u8], _key: &[u8]) -> Result<Vec<u8>, TraxError> {
    // Placeholder: integrate ed25519-dalek signing and build CoseSign1 with protected headers.
    use coset::CborSerializable;
    let mut h = Header::default();
    h.alg = Some(Algorithm::Assigned(iana::Algorithm::EdDSA));
    let sign1 = CoseSign1 {
        protected: ProtectedHeader {
            original_data: None,
            header: h,
        },
        unprotected: Header::default(),
        payload: Some(payload.to_vec()),
        signature: vec![],
    };
    let mut out: Vec<u8> = Vec::new();
    let bytes = sign1.to_vec().map_err(|_| TraxError::Cbor)?;
    out.write_all(&bytes).map_err(|_| TraxError::Cbor)?;
    Ok(out)
}
