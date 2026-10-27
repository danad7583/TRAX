//! Strict, length-first deterministic CBOR.
//!
//! Maps are sorted recursively by the length and then the lexical order of each
//! encoded key. Duplicate encoded keys are rejected. The decoder accepts exactly
//! one item and requires its bytes to match this deterministic representation.
//!
//! This replaces the prototype's declaration/insertion-order map encoding. Even
//! existing V1 structs therefore have different bytes, hashes, and signing
//! transcripts; old prototype proofs must not be carried into this profile.
use crate::errors::TraxError;
use crate::types::ProtectedHeaders;
use ciborium::de;
use ciborium::ser;
use ciborium::value::Value;

pub fn encode_deterministic<T: serde::Serialize>(value: &T) -> Result<Vec<u8>, TraxError> {
    let mut value = Value::serialized(value).map_err(|_| TraxError::Cbor)?;
    normalize(&mut value)?;
    encode_value(&value)
}

pub fn decode<T: serde::de::DeserializeOwned>(data: &[u8]) -> Result<T, TraxError> {
    let mut remaining = data;
    let mut value: Value = de::from_reader(&mut remaining).map_err(|_| TraxError::Cbor)?;
    if !remaining.is_empty() {
        return Err(TraxError::Cbor);
    }
    normalize(&mut value)?;
    if encode_value(&value)? != data {
        return Err(TraxError::Cbor);
    }
    value.deserialized().map_err(|_| TraxError::Cbor)
}

/// Strict protocol decoding with a byte cap and an exact typed round trip.
/// Unlike generic CBOR values, V2 schemas do not admit discarded semantic tags.
pub fn decode_strict<T: serde::de::DeserializeOwned + serde::Serialize>(
    data: &[u8],
    max_bytes: usize,
) -> Result<T, TraxError> {
    if data.len() > max_bytes {
        return Err(TraxError::InvalidInput("encoded record exceeds byte limit"));
    }
    let mut remaining = data;
    let value: Value = ciborium::de::from_reader_with_recursion_limit(&mut remaining, 64)
        .map_err(|_| TraxError::Cbor)?;
    if !remaining.is_empty() {
        return Err(TraxError::Cbor);
    }
    let decoded: T = value.deserialized().map_err(|_| TraxError::Cbor)?;
    if encode_deterministic(&decoded)? != data {
        return Err(TraxError::Cbor);
    }
    Ok(decoded)
}

fn encode_value(value: &Value) -> Result<Vec<u8>, TraxError> {
    let mut bytes = Vec::new();
    ser::into_writer(value, &mut bytes).map_err(|_| TraxError::Cbor)?;
    Ok(bytes)
}

fn normalize(value: &mut Value) -> Result<(), TraxError> {
    match value {
        Value::Map(entries) => {
            let mut ordered = Vec::with_capacity(entries.len());
            for (mut key, mut value) in std::mem::take(entries) {
                normalize(&mut key)?;
                normalize(&mut value)?;
                ordered.push((encode_value(&key)?, key, value));
            }
            ordered.sort_unstable_by(|left, right| {
                left.0
                    .len()
                    .cmp(&right.0.len())
                    .then_with(|| left.0.cmp(&right.0))
            });
            if ordered.windows(2).any(|pair| pair[0].0 == pair[1].0) {
                return Err(TraxError::Cbor);
            }
            *entries = ordered
                .into_iter()
                .map(|(_, key, value)| (key, value))
                .collect();
        }
        Value::Array(values) => {
            for value in values {
                normalize(value)?;
            }
        }
        Value::Tag(_, value) => normalize(value)?,
        // Ciborium selects the shortest exact floating-point representation.
        // Collapse NaN payloads/signs to one representation as well.
        Value::Float(number) if number.is_nan() => *number = f64::NAN,
        _ => {}
    }
    Ok(())
}

/// COSE signing is not implemented by this helper. Admission envelopes and
/// segment seals use their explicit Ed25519 signing APIs instead.
pub fn cose_sign1(
    _headers: &ProtectedHeaders,
    _payload: &[u8],
    _key: &[u8],
) -> Result<Vec<u8>, TraxError> {
    Err(TraxError::InvalidInput(
        "COSE_Sign1 signing is not implemented",
    ))
}
