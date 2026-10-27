use ciborium::value::Value;
use serde::ser::SerializeMap;
use serde::{Serialize, Serializer};
use std::collections::BTreeMap;
use trax::encoding::{decode_strict, encode_deterministic};

// A map whose serializer deliberately preserves the supplied insertion order.
struct OrderedMap(Vec<(&'static str, u64)>);

impl Serialize for OrderedMap {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(Some(self.0.len()))?;
        for (key, value) in &self.0 {
            map.serialize_entry(key, value)?;
        }
        map.end()
    }
}

#[test]
fn map_insertion_order_does_not_change_bytes() {
    let left = OrderedMap(vec![("aa", 2), ("z", 1)]);
    let right = OrderedMap(vec![("z", 1), ("aa", 2)]);
    let expected = [0xa2, 0x61, b'z', 0x01, 0x62, b'a', b'a', 0x02];
    assert_eq!(encode_deterministic(&left).unwrap(), expected);
    assert_eq!(encode_deterministic(&right).unwrap(), expected);
    assert_eq!(
        bounded_decode::<BTreeMap<String, u64>>(&expected).unwrap(),
        BTreeMap::from([("aa".to_owned(), 2), ("z".to_owned(), 1)])
    );
}

#[test]
fn nested_maps_are_normalized_in_arrays_and_tagged_values() {
    let left = Value::Array(vec![Value::Tag(
        100,
        Box::new(Value::Map(vec![
            (Value::Text("b".to_owned()), 2.into()),
            (Value::Text("a".to_owned()), 1.into()),
        ])),
    )]);
    let right = Value::Array(vec![Value::Tag(
        100,
        Box::new(Value::Map(vec![
            (Value::Text("a".to_owned()), 1.into()),
            (Value::Text("b".to_owned()), 2.into()),
        ])),
    )]);
    let bytes = encode_deterministic(&left).unwrap();
    assert_eq!(bytes, encode_deterministic(&right).unwrap());
    assert_eq!(bounded_decode::<Value>(&bytes).unwrap(), right);
}

#[test]
fn struct_fields_follow_the_same_map_profile() {
    #[derive(Serialize)]
    struct OutOfOrder {
        z: u64,
        a: u64,
    }
    assert_eq!(
        encode_deterministic(&OutOfOrder { z: 2, a: 1 }).unwrap(),
        [0xa2, 0x61, b'a', 1, 0x61, b'z', 2]
    );
}

#[test]
fn duplicate_keys_are_rejected_before_type_deserialization() {
    assert!(encode_deterministic(&OrderedMap(vec![("a", 1), ("a", 2)])).is_err());
    // A BTreeMap deserializer could otherwise silently replace the first value.
    let duplicate = [0xa2, 0x61, b'a', 1, 0x61, b'a', 2];
    assert!(bounded_decode::<BTreeMap<String, u64>>(&duplicate).is_err());
    let nested = [0x81, 0xa2, 0x61, b'a', 1, 0x61, b'a', 2];
    assert!(bounded_decode::<Value>(&nested).is_err());
}

#[test]
fn duplicate_complex_keys_are_detected_after_normalization() {
    let key = |reverse| {
        let mut entries = vec![
            (Value::Text("a".to_owned()), 1.into()),
            (Value::Text("b".to_owned()), 2.into()),
        ];
        if reverse {
            entries.reverse();
        }
        Value::Map(entries)
    };
    let value = Value::Map(vec![(key(false), 1.into()), (key(true), 2.into())]);
    assert!(encode_deterministic(&value).is_err());
}

#[test]
fn decoder_rejects_trailing_items_or_garbage() {
    for bytes in [[0x01, 0x02], [0x01, 0xff]] {
        assert!(bounded_decode::<u64>(&bytes).is_err());
    }
}

#[test]
fn decoder_rejects_malformed_cbor() {
    for bytes in [&[][..], &[0xa1][..], &[0x61, 0xff][..], &[0xff][..]] {
        assert!(
            bounded_decode::<Value>(bytes).is_err(),
            "accepted {bytes:x?}"
        );
    }
}

#[test]
fn decoder_rejects_non_deterministic_representations() {
    for bytes in [
        // Map keys in the wrong order.
        &[0xa2, 0x61, b'b', 2, 0x61, b'a', 1][..],
        // Integer 23 encoded with an unnecessary extra byte.
        &[0x18, 0x17][..],
        // Indefinite-length array instead of the definite-length representation.
        &[0x9f, 0x01, 0xff][..],
        // 1.0 encoded as a 64-bit float instead of an exact half-precision value.
        &[0xfb, 0x3f, 0xf0, 0, 0, 0, 0, 0, 0][..],
    ] {
        assert!(
            bounded_decode::<Value>(bytes).is_err(),
            "accepted {bytes:x?}"
        );
    }
}

#[test]
fn floating_point_nan_has_one_encoding_and_negative_zero_is_preserved() {
    let nan = [0xf9, 0x7e, 0x00];
    assert_eq!(encode_deterministic(&f64::NAN).unwrap(), nan);
    assert_eq!(
        encode_deterministic(&f64::from_bits(0xfff8_0000_0000_0042)).unwrap(),
        nan
    );
    assert!(bounded_decode::<f64>(&nan).unwrap().is_nan());
    assert!(bounded_decode::<f64>(&[0xf9, 0x7e, 0x01]).is_err());
    let negative_zero = encode_deterministic(&-0.0_f64).unwrap();
    assert_eq!(negative_zero, [0xf9, 0x80, 0]);
    assert_eq!(
        bounded_decode::<f64>(&negative_zero).unwrap().to_bits(),
        (-0.0_f64).to_bits()
    );
}

fn bounded_decode<T: serde::de::DeserializeOwned + Serialize>(
    data: &[u8],
) -> Result<T, trax::TraxError> {
    decode_strict(data, 4096)
}

#[test]
fn decoder_enforces_the_callers_byte_cap_and_parser_depth() {
    assert_eq!(decode_strict::<u64>(&[1], 1).unwrap(), 1);
    assert!(decode_strict::<u64>(&[1], 0).is_err());
    let mut deeply_nested = vec![0x81; 65];
    deeply_nested.push(0);
    assert!(decode_strict::<Value>(&deeply_nested, deeply_nested.len()).is_err());
    let mut shallow = vec![0x81; 8];
    shallow.push(0);
    assert!(decode_strict::<Value>(&shallow, shallow.len()).is_ok());
}

#[test]
fn typed_round_trip_rejects_tags_unknown_fields_and_changed_wire_types() {
    assert!(decode_strict::<u64>(&[0xc0, 0x01], 32).is_err());
    #[derive(Debug, serde::Deserialize, Serialize)]
    struct OnlyKnown {
        a: u64,
    }
    // Typed deserialization would otherwise discard the unknown key.
    let unknown = [0xa2, 0x61, b'a', 1, 0x61, b'b', 2];
    assert!(decode_strict::<OnlyKnown>(&unknown, 32).is_err());
    // Serde can deserialize a byte string as Vec<u8>, but re-encoding is an
    // integer array unless the field explicitly declares its byte-string type.
    assert!(decode_strict::<Vec<u8>>(&[0x41, 1], 32).is_err());
}
