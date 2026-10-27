//! Thin Python access to Rust-owned V2 trust, lifecycle and admission state.
#![allow(clippy::too_many_arguments, clippy::useless_conversion)]

use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict, PyList};

use crate::encoding::{decode_strict, encode_deterministic};
use crate::genesis::{
    accept_genesis_offer, confirm_genesis, create_genesis_offer, GenesisNodeV2,
    TransmissionLimitsV2, TransmissionProfileV2, VerifiedGenesisV2,
};
use crate::python::PrivateKey;
use crate::transmission::SessionV2;
use crate::{HashAlgorithm, TraxError};

const MAX_GENESIS_BYTES: usize = 16 * 1024;

fn error(err: TraxError) -> PyErr {
    PyValueError::new_err(err.to_string())
}

fn fixed32(name: &str, bytes: &[u8]) -> PyResult<[u8; 32]> {
    bytes
        .try_into()
        .map_err(|_| PyValueError::new_err(format!("{name} must be 32 bytes")))
}

fn genesis(bytes: &[u8]) -> PyResult<GenesisNodeV2> {
    decode_strict(bytes, MAX_GENESIS_BYTES).map_err(error)
}

#[pyfunction]
#[pyo3(signature = (private_key, nonce, *, hash_algorithm="sha512-256", max_packets=None, max_payload_bytes=None, max_packet_payload_bytes=None, max_wire_packet_bytes=None, timeout_ms=None))]
fn tx_genesis_offer<'py>(
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
    let defaults = TransmissionLimitsV2::default();
    let profile = TransmissionProfileV2 {
        hash_algorithm,
        limits: TransmissionLimitsV2 {
            max_packets: max_packets.unwrap_or(defaults.max_packets),
            max_payload_bytes: max_payload_bytes.unwrap_or(defaults.max_payload_bytes),
            max_packet_payload_bytes: max_packet_payload_bytes
                .unwrap_or(defaults.max_packet_payload_bytes),
            max_wire_packet_bytes: max_wire_packet_bytes.unwrap_or(defaults.max_wire_packet_bytes),
            timeout_ms: timeout_ms.unwrap_or(defaults.timeout_ms),
        },
        ..TransmissionProfileV2::default()
    };
    let offer = create_genesis_offer(&private_key.signing_key, fixed32("nonce", nonce)?, profile)
        .map_err(error)?;
    let bytes = encode_deterministic(&offer).map_err(error)?;
    Ok(PyBytes::new_bound(py, &bytes))
}

#[pyfunction]
fn tx_genesis_accept<'py>(
    py: Python<'py>,
    offer: &[u8],
    private_key: PyRef<'_, PrivateKey>,
    trusted_peer: &[u8],
) -> PyResult<Bound<'py, PyBytes>> {
    let trusted_peer = fixed32("trusted_peer", trusted_peer)?;
    let accepted = accept_genesis_offer(&genesis(offer)?, &private_key.signing_key, |candidate| {
        candidate == &trusted_peer
    })
    .map_err(error)?;
    let bytes = encode_deterministic(&accepted).map_err(error)?;
    Ok(PyBytes::new_bound(py, &bytes))
}

#[pyfunction]
fn tx_genesis_confirm<'py>(
    py: Python<'py>,
    offer: &[u8],
    acceptance: &[u8],
    private_key: PyRef<'_, PrivateKey>,
    trusted_peer: &[u8],
) -> PyResult<Bound<'py, PyBytes>> {
    let trusted_peer = fixed32("trusted_peer", trusted_peer)?;
    let confirmation = confirm_genesis(
        &genesis(offer)?,
        &genesis(acceptance)?,
        &private_key.signing_key,
        |candidate| candidate == &trusted_peer,
    )
    .map_err(error)?;
    let bytes = encode_deterministic(&confirmation).map_err(error)?;
    Ok(PyBytes::new_bound(py, &bytes))
}

/// Owns one authoritative Rust session; construction always re-verifies genesis
/// against the explicitly supplied trusted keys. No state-restore API exists.
#[pyclass(module = "trax")]
struct TransmissionSessionV2 {
    inner: SessionV2,
}

#[pymethods]
impl TransmissionSessionV2 {
    #[new]
    fn new(
        offer: &[u8],
        acceptance: &[u8],
        confirmation: &[u8],
        initiator: &[u8],
        nonce: &[u8],
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
        let verified = VerifiedGenesisV2::verify(
            [
                genesis(offer)?,
                genesis(acceptance)?,
                genesis(confirmation)?,
            ],
            |candidate| trusted.contains(candidate),
        )
        .map_err(error)?;
        Ok(Self {
            inner: SessionV2::new(
                verified,
                fixed32("initiator", initiator)?,
                fixed32("nonce", nonce)?,
            )
            .map_err(error)?,
        })
    }

    fn checkpoint<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
        let checkpoint = self.inner.checkpoint();
        let result = PyDict::new_bound(py);
        result.set_item("session_id", PyBytes::new_bound(py, &checkpoint.session_id))?;
        result.set_item("tip", PyBytes::new_bound(py, &checkpoint.tip))?;
        result.set_item(
            "history_hash",
            PyBytes::new_bound(py, &checkpoint.history_hash),
        )?;
        result.set_item("event_count", checkpoint.event_count)?;
        result.set_item("transmission_id", checkpoint.transmission_id)?;
        result.set_item("closed", checkpoint.closed)?;
        Ok(result)
    }

    fn build_transmission<'py>(
        &self,
        py: Python<'py>,
        private_key: PyRef<'_, PrivateKey>,
        message_type: &str,
        chunks: Vec<Vec<u8>>,
    ) -> PyResult<Bound<'py, PyList>> {
        let packets = self
            .inner
            .build_transmission(&private_key.signing_key, message_type, &chunks)
            .map_err(error)?;
        let result = PyList::empty_bound(py);
        for packet in packets {
            let bytes = encode_deterministic(&packet).map_err(error)?;
            result.append(PyBytes::new_bound(py, &bytes))?;
        }
        Ok(result)
    }

    fn fragment_transmission<'py>(
        &self,
        py: Python<'py>,
        private_key: PyRef<'_, PrivateKey>,
        message_type: &str,
        payload: &[u8],
    ) -> PyResult<Bound<'py, PyList>> {
        let packets = self
            .inner
            .fragment_transmission(&private_key.signing_key, message_type, payload)
            .map_err(error)?;
        let result = PyList::empty_bound(py);
        for packet in packets {
            let bytes = encode_deterministic(&packet).map_err(error)?;
            result.append(PyBytes::new_bound(py, &bytes))?;
        }
        Ok(result)
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

pub(crate) fn register(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add_class::<TransmissionSessionV2>()?;
    module.add_function(wrap_pyfunction!(tx_genesis_offer, module)?)?;
    module.add_function(wrap_pyfunction!(tx_genesis_accept, module)?)?;
    module.add_function(wrap_pyfunction!(tx_genesis_confirm, module)?)?;
    Ok(())
}
