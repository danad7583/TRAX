//! Memory-only Python relationships backed by the canonical Rust trust state.
#![allow(clippy::too_many_arguments, clippy::useless_conversion)]

use ciborium::value::Value;
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict, PyList};
use serde::Serialize;

use crate::config::{HashAlgorithm, TransmissionLimits, TransmissionProfile};
use crate::encoding::{decode_strict, encode_deterministic};
use crate::genesis::{
    accept_genesis_offer as accept_offer, confirm_genesis as confirm_offer,
    create_genesis_offer as create_offer, GenesisNode, VerifiedGenesis,
};
use crate::session::Relationship as CoreRelationship;
use crate::TraxError;

const MAX_GENESIS_BYTES: usize = 16 * 1024;

#[pyclass(module = "trax")]
struct PrivateKey {
    signing_key: ed25519_dalek::SigningKey,
}

#[pymethods]
impl PrivateKey {
    fn public_key<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new_bound(py, self.signing_key.verifying_key().as_bytes())
    }

    fn __repr__(&self) -> &'static str {
        "<trax.PrivateKey>"
    }
}

fn error(err: TraxError) -> PyErr {
    PyValueError::new_err(err.to_string())
}

fn fixed32(name: &str, bytes: &[u8]) -> PyResult<[u8; 32]> {
    bytes
        .try_into()
        .map_err(|_| PyValueError::new_err(format!("{name} must be 32 bytes")))
}

fn genesis(bytes: &[u8]) -> PyResult<GenesisNode> {
    decode_strict(bytes, MAX_GENESIS_BYTES).map_err(error)
}

fn value_to_python(py: Python<'_>, value: Value) -> PyResult<PyObject> {
    match value {
        Value::Null => Ok(py.None()),
        Value::Bool(value) => Ok(value.into_py(py)),
        Value::Integer(value) => Ok(i128::from(value).into_py(py)),
        Value::Text(value) => Ok(value.into_py(py)),
        Value::Bytes(value) => Ok(PyBytes::new_bound(py, &value).into_any().unbind()),
        Value::Array(values) => {
            let list = PyList::empty_bound(py);
            for value in values {
                list.append(value_to_python(py, value)?)?;
            }
            Ok(list.into_any().unbind())
        }
        Value::Map(fields) => {
            let dict = PyDict::new_bound(py);
            for (key, value) in fields {
                let Value::Text(key) = key else {
                    return Err(PyValueError::new_err(
                        "inspection record has a non-text key",
                    ));
                };
                dict.set_item(key, value_to_python(py, value)?)?;
            }
            Ok(dict.into_any().unbind())
        }
        _ => Err(PyValueError::new_err("unsupported inspection value")),
    }
}

fn inspect(py: Python<'_>, value: &impl Serialize) -> PyResult<PyObject> {
    let value = Value::serialized(value)
        .map_err(|_| PyValueError::new_err("inspection encoding failed"))?;
    value_to_python(py, value)
}

fn records<'py, T: Serialize>(
    py: Python<'py>,
    values: impl IntoIterator<Item = T>,
) -> PyResult<Bound<'py, PyList>> {
    let result = PyList::empty_bound(py);
    for value in values {
        let bytes = encode_deterministic(&value).map_err(error)?;
        result.append(PyBytes::new_bound(py, &bytes))?;
    }
    Ok(result)
}

#[pyfunction]
fn generate_keypair(py: Python<'_>) -> PyResult<Bound<'_, PyDict>> {
    let signing_key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
    let public_key = signing_key.verifying_key();
    let result = PyDict::new_bound(py);
    result.set_item("private_key", Py::new(py, PrivateKey { signing_key })?)?;
    result.set_item("public_key", PyBytes::new_bound(py, public_key.as_bytes()))?;
    Ok(result)
}

#[pyfunction]
fn generate_nonce<'py>(py: Python<'py>) -> Bound<'py, PyBytes> {
    use rand::RngCore;
    let mut nonce = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    PyBytes::new_bound(py, &nonce)
}

/// Generic Ed25519 signing, not an authenticated transmission/admission API.
#[pyfunction]
fn sign_message<'py>(
    py: Python<'py>,
    private_key: PyRef<'_, PrivateKey>,
    message: &[u8],
) -> Bound<'py, PyBytes> {
    PyBytes::new_bound(
        py,
        &crate::crypto::ed25519_sign(&private_key.signing_key, message),
    )
}

#[pyfunction]
fn verify_message(public_key: &[u8], message: &[u8], signature: &[u8]) -> PyResult<bool> {
    let public_key = fixed32("public_key", public_key)?;
    if signature.len() != 64 {
        return Err(PyValueError::new_err("signature must be 64 bytes"));
    }
    let key = ed25519_dalek::VerifyingKey::from_bytes(&public_key)
        .map_err(|_| PyValueError::new_err("invalid public_key"))?;
    Ok(crate::crypto::ed25519_verify(&key, message, signature))
}

#[pyfunction]
#[pyo3(signature = (private_key, nonce, *, hash_algorithm, max_packets=None, max_payload_bytes=None, max_packet_payload_bytes=None, max_wire_packet_bytes=None, timeout_ms=None))]
fn create_genesis_offer<'py>(
    py: Python<'py>,
    private_key: PyRef<'_, PrivateKey>,
    nonce: &[u8],
    hash_algorithm: &str,
    max_packets: Option<u32>,
    max_payload_bytes: Option<u64>,
    max_packet_payload_bytes: Option<u32>,
    max_wire_packet_bytes: Option<u32>,
    timeout_ms: Option<u64>,
) -> PyResult<Bound<'py, PyBytes>> {
    let hash_algorithm = match hash_algorithm {
        "sha512-256" => HashAlgorithm::Sha512256,
        "blake3" => HashAlgorithm::Blake3,
        _ => return Err(PyValueError::new_err("unsupported hash_algorithm")),
    };
    let defaults = TransmissionLimits::default();
    let profile = TransmissionProfile {
        hash_algorithm,
        limits: TransmissionLimits {
            max_packets: max_packets.unwrap_or(defaults.max_packets),
            max_payload_bytes: max_payload_bytes.unwrap_or(defaults.max_payload_bytes),
            max_packet_payload_bytes: max_packet_payload_bytes
                .unwrap_or(defaults.max_packet_payload_bytes),
            max_wire_packet_bytes: max_wire_packet_bytes.unwrap_or(defaults.max_wire_packet_bytes),
            timeout_ms: timeout_ms.unwrap_or(defaults.timeout_ms),
        },
        ..TransmissionProfile::default()
    };
    let offer =
        create_offer(&private_key.signing_key, fixed32("nonce", nonce)?, profile).map_err(error)?;
    let bytes = encode_deterministic(&offer).map_err(error)?;
    Ok(PyBytes::new_bound(py, &bytes))
}

#[pyfunction]
fn accept_genesis_offer<'py>(
    py: Python<'py>,
    offer: &[u8],
    private_key: PyRef<'_, PrivateKey>,
    trusted_peer: &[u8],
) -> PyResult<Bound<'py, PyBytes>> {
    let trusted_peer = fixed32("trusted_peer", trusted_peer)?;
    let accepted = accept_offer(&genesis(offer)?, &private_key.signing_key, |candidate| {
        candidate == &trusted_peer
    })
    .map_err(error)?;
    let bytes = encode_deterministic(&accepted).map_err(error)?;
    Ok(PyBytes::new_bound(py, &bytes))
}

#[pyfunction]
fn confirm_genesis<'py>(
    py: Python<'py>,
    offer: &[u8],
    acceptance: &[u8],
    private_key: PyRef<'_, PrivateKey>,
    trusted_peer: &[u8],
) -> PyResult<Bound<'py, PyBytes>> {
    let trusted_peer = fixed32("trusted_peer", trusted_peer)?;
    let confirmation = confirm_offer(
        &genesis(offer)?,
        &genesis(acceptance)?,
        &private_key.signing_key,
        |candidate| candidate == &trusted_peer,
    )
    .map_err(error)?;
    let bytes = encode_deterministic(&confirmation).map_err(error)?;
    Ok(PyBytes::new_bound(py, &bytes))
}

/// Memory-only authoritative relationship; no unchecked restore or session constructor.
#[pyclass(module = "trax")]
struct Relationship {
    inner: CoreRelationship,
}

#[pymethods]
impl Relationship {
    #[new]
    fn new(
        offer: &[u8],
        acceptance: &[u8],
        confirmation: &[u8],
        trusted_keys: Vec<Vec<u8>>,
    ) -> PyResult<Self> {
        if trusted_keys.len() != 2 {
            return Err(PyValueError::new_err(
                "exactly two trusted_keys are required",
            ));
        }
        let trusted = [
            fixed32("trusted_keys[0]", &trusted_keys[0])?,
            fixed32("trusted_keys[1]", &trusted_keys[1])?,
        ];
        if trusted[0] == trusted[1] {
            return Err(PyValueError::new_err("trusted_keys must be distinct"));
        }
        let verified = VerifiedGenesis::verify(
            [
                genesis(offer)?,
                genesis(acceptance)?,
                genesis(confirmation)?,
            ],
            |candidate| trusted.contains(candidate),
        )
        .map_err(error)?;
        Ok(Self {
            inner: CoreRelationship::new(verified).map_err(error)?,
        })
    }

    fn begin_session(&mut self, initiator: &[u8], nonce: &[u8]) -> PyResult<()> {
        self.inner
            .begin_session(fixed32("initiator", initiator)?, fixed32("nonce", nonce)?)
            .map_err(error)
    }

    fn checkpoint(&self, py: Python<'_>) -> PyResult<PyObject> {
        inspect(py, &self.inner.checkpoint())
    }

    fn session(&self, py: Python<'_>) -> PyResult<Option<PyObject>> {
        let Some(session) = self.inner.session() else {
            return Ok(None);
        };
        let result = PyDict::new_bound(py);
        result.set_item("context", inspect(py, session.context())?)?;
        result.set_item("checkpoint", inspect(py, &session.checkpoint())?)?;
        result.set_item("has_pending", session.has_pending())?;
        Ok(Some(result.into_any().unbind()))
    }

    fn history<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyList>> {
        records(py, self.inner.history())
    }

    fn record<'py>(&self, py: Python<'py>, id: &[u8]) -> PyResult<Option<Bound<'py, PyBytes>>> {
        self.inner
            .record(&fixed32("id", id)?)
            .map(|record| {
                encode_deterministic(record)
                    .map(|bytes| PyBytes::new_bound(py, &bytes))
                    .map_err(error)
            })
            .transpose()
    }

    fn ancestors<'py>(&self, py: Python<'py>, id: &[u8]) -> PyResult<Bound<'py, PyList>> {
        records(
            py,
            self.inner.ancestors(&fixed32("id", id)?).map_err(error)?,
        )
    }

    fn children<'py>(&self, py: Python<'py>, id: &[u8]) -> PyResult<Bound<'py, PyList>> {
        records(py, self.inner.children(&fixed32("id", id)?))
    }

    fn build_transmission<'py>(
        &self,
        py: Python<'py>,
        private_key: PyRef<'_, PrivateKey>,
        message_type: &str,
        chunks: Vec<Vec<u8>>,
    ) -> PyResult<Bound<'py, PyList>> {
        records(
            py,
            self.inner
                .build_transmission(&private_key.signing_key, message_type, &chunks)
                .map_err(error)?,
        )
    }

    fn fragment_transmission<'py>(
        &self,
        py: Python<'py>,
        private_key: PyRef<'_, PrivateKey>,
        message_type: &str,
        payload: &[u8],
    ) -> PyResult<Bound<'py, PyList>> {
        records(
            py,
            self.inner
                .fragment_transmission(&private_key.signing_key, message_type, payload)
                .map_err(error)?,
        )
    }

    fn start_receive(&mut self) -> PyResult<()> {
        self.inner.start_receive().map_err(error)
    }

    fn stage_packet<'py>(
        &mut self,
        py: Python<'py>,
        packet: &[u8],
    ) -> PyResult<Option<Bound<'py, PyBytes>>> {
        self.inner
            .stage_encoded_packet(packet)
            .map(|verified| {
                verified.map(|transmission| PyBytes::new_bound(py, &transmission.payload()))
            })
            .map_err(error)
    }

    fn has_pending(&self) -> bool {
        self.inner.has_pending()
    }

    fn abort_receive(&mut self) -> bool {
        self.inner.abort_receive()
    }

    fn abort_draft_session(&mut self) -> bool {
        self.inner.abort_draft_session()
    }

    fn expire_receive(&mut self) -> bool {
        self.inner.expire_receive()
    }

    fn create_close<'py>(
        &self,
        py: Python<'py>,
        private_key: PyRef<'_, PrivateKey>,
    ) -> PyResult<Bound<'py, PyBytes>> {
        let terminal = self
            .inner
            .create_close(&private_key.signing_key)
            .map_err(error)?;
        let bytes = encode_deterministic(&terminal).map_err(error)?;
        Ok(PyBytes::new_bound(py, &bytes))
    }

    fn verify_and_close(&mut self, terminal: &[u8]) -> PyResult<()> {
        self.inner.verify_encoded_close(terminal).map_err(error)
    }
}

#[pymodule]
fn trax(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add_class::<PrivateKey>()?;
    module.add_class::<Relationship>()?;
    module.add_function(wrap_pyfunction!(generate_keypair, module)?)?;
    module.add_function(wrap_pyfunction!(generate_nonce, module)?)?;
    module.add_function(wrap_pyfunction!(sign_message, module)?)?;
    module.add_function(wrap_pyfunction!(verify_message, module)?)?;
    module.add_function(wrap_pyfunction!(create_genesis_offer, module)?)?;
    module.add_function(wrap_pyfunction!(accept_genesis_offer, module)?)?;
    module.add_function(wrap_pyfunction!(confirm_genesis, module)?)?;
    Ok(())
}
