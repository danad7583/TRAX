//! Strict, length-first deterministic CBOR.
//!
//! Maps are sorted recursively by the length and then the lexical order of each
//! encoded key. Duplicate encoded keys are rejected. The decoder accepts exactly
//! one item and requires its bytes to match this deterministic representation.
//!
use crate::errors::TraxError;
use ciborium::ser;
use ciborium::value::Value;

pub fn encode_deterministic<T: serde::Serialize>(value: &T) -> Result<Vec<u8>, TraxError> {
    let mut value = Value::serialized(value).map_err(|_| TraxError::Cbor)?;
    normalize(&mut value)?;
    encode_value(&value)
}

/// Strict protocol decoding with a byte cap and an exact typed round trip.
/// Protocol schemas reject semantic tags discarded by typed deserialization.
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
