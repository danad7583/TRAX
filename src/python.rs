#![allow(clippy::too_many_arguments, clippy::useless_conversion)]

use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict, PyList};

const ED25519_PUBLIC_KEY_LEN: usize = 32;
const ED25519_SIGNATURE_LEN: usize = 64;
const NONCE_LEN: usize = 16;
const HASH32_LEN: usize = 32;

#[pyclass(module = "trax")]
struct PrivateKey {
    signing_key: ed25519_dalek::SigningKey,
}

#[pyclass(module = "trax")]
struct LocalDag {
    inner: crate::admission_dag::LocalAdmissionDag,
}

#[pyclass(module = "trax")]
struct ReceiveAdmissionWindow {
    inner: crate::dag::ReceiveAdmissionWindow,
}

#[pymethods]
impl ReceiveAdmissionWindow {
    #[new]
    #[pyo3(signature = (session_id, receiver_id, lineage_public_key, committed_tip, segment_index=0, next_counter=0))]
    fn new(
        session_id: &[u8],
        receiver_id: &[u8],
        lineage_public_key: &[u8],
        committed_tip: &[u8],
        segment_index: u64,
        next_counter: u64,
    ) -> PyResult<Self> {
        use ed25519_dalek::VerifyingKey;
        validate_len("session_id", session_id, HASH32_LEN)?;
        validate_len("receiver_id", receiver_id, HASH32_LEN)?;
        validate_len(
            "lineage_public_key",
            lineage_public_key,
            ED25519_PUBLIC_KEY_LEN,
        )?;
        validate_len("committed_tip", committed_tip, HASH32_LEN)?;
        let key_bytes: [u8; 32] = lineage_public_key.try_into().unwrap();
        let key = VerifyingKey::from_bytes(&key_bytes)
            .map_err(|_| PyValueError::new_err("invalid lineage public key"))?;
        Ok(Self {
            inner: crate::dag::ReceiveAdmissionWindow::new_k8(
                session_id.try_into().unwrap(),
                receiver_id.try_into().unwrap(),
                key,
                committed_tip.try_into().unwrap(),
                segment_index,
                next_counter,
            ),
        })
    }

    fn stage<'py>(&mut self, py: Python<'py>, event: &[u8]) -> PyResult<Bound<'py, PyBytes>> {
        let event = crate::encoding::decode(event).map_err(trax_error)?;
        let tip = self.inner.stage(event).map_err(trax_error)?;
        Ok(PyBytes::new_bound(py, &tip))
    }

    fn verify_and_commit<'py>(
        &mut self,
        py: Python<'py>,
        seal: &[u8],
    ) -> PyResult<Bound<'py, PyList>> {
        let seal = crate::encoding::decode(seal).map_err(trax_error)?;
        let encoded = self
            .inner
            .verify_and_commit(&seal)
            .map_err(trax_error)?
            .iter()
            .map(crate::encoding::encode_deterministic)
            .collect::<Result<Vec<_>, _>>()
            .map_err(trax_error)?;
        let result = PyList::empty_bound(py);
        for event in encoded {
            result.append(PyBytes::new_bound(py, &event))?;
        }
        Ok(result)
    }

    fn provisional_count(&self) -> usize {
        self.inner.provisional_count()
    }
    fn committed_count(&self) -> usize {
        self.inner.committed_count()
    }
    fn committed_tip<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new_bound(py, &self.inner.committed_tip())
    }
    fn provisional_tip<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new_bound(py, &self.inner.provisional_tip())
    }
}

#[pymethods]
impl PrivateKey {
    fn public_key<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        let verifying_key = self.signing_key.verifying_key();
        PyBytes::new_bound(py, verifying_key.as_bytes())
    }

    fn __repr__(&self) -> &'static str {
        "<trax.PrivateKey>"
    }
}

#[pymethods]
impl LocalDag {
    #[new]
    fn new() -> Self {
        Self {
            inner: crate::admission_dag::LocalAdmissionDag::new(),
        }
    }

    fn admit_packet0<'py>(
        &mut self,
        py: Python<'py>,
        envelope: &[u8],
        payload: &[u8],
        receiver_public_key: &[u8],
    ) -> PyResult<Bound<'py, PyBytes>> {
        let node_id = self
            .inner
            .admit_packet0(envelope, payload, receiver_public_key)
            .map_err(trax_error)?;
        Ok(PyBytes::new_bound(py, &node_id))
    }

    fn len(&self) -> usize {
        self.inner.len()
    }

    fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    fn __len__(&self) -> usize {
        self.len()
    }

    fn __repr__(&self) -> String {
        format!("<trax.LocalDag len={}>", self.len())
    }
}

#[pyfunction]
fn hash32<'py>(py: Python<'py>, data: &[u8]) -> Bound<'py, PyBytes> {
    let digest = crate::crypto::hash32(data);
    PyBytes::new_bound(py, &digest)
}

#[pyfunction]
#[pyo3(signature = (session_id, lineage_public_key, receiver_id, segment_index, counter, previous_tip, content_hash, payload_hash))]
fn create_post_genesis_event_v1<'py>(
    py: Python<'py>,
    session_id: &[u8],
    lineage_public_key: &[u8],
    receiver_id: &[u8],
    segment_index: u64,
    counter: u64,
    previous_tip: &[u8],
    content_hash: &[u8],
    payload_hash: &[u8],
) -> PyResult<Bound<'py, PyBytes>> {
    use ed25519_dalek::VerifyingKey;
    for (name, value) in [
        ("session_id", session_id),
        ("receiver_id", receiver_id),
        ("previous_tip", previous_tip),
        ("content_hash", content_hash),
        ("payload_hash", payload_hash),
    ] {
        validate_len(name, value, HASH32_LEN)?;
    }
    validate_len(
        "lineage_public_key",
        lineage_public_key,
        ED25519_PUBLIC_KEY_LEN,
    )?;
    let key = VerifyingKey::from_bytes(&lineage_public_key.try_into().unwrap())
        .map_err(|_| PyValueError::new_err("invalid lineage public key"))?;
    let event = crate::PostGenesisEventV1 {
        version: 1,
        session_id: session_id.try_into().unwrap(),
        lineage_key_id: crate::dag::lineage_key_id(&key),
        receiver_id: receiver_id.try_into().unwrap(),
        segment_index,
        counter,
        previous_tip: previous_tip.try_into().unwrap(),
        content_hash: content_hash.try_into().unwrap(),
        payload_hash: payload_hash.try_into().unwrap(),
    };
    let bytes = crate::encoding::encode_deterministic(&event).map_err(trax_error)?;
    Ok(PyBytes::new_bound(py, &bytes))
}

#[pyfunction]
fn create_segment_seal_k8<'py>(
    py: Python<'py>,
    private_key: PyRef<'py, PrivateKey>,
    events: Vec<Vec<u8>>,
) -> PyResult<Bound<'py, PyBytes>> {
    let events = events
        .iter()
        .map(|e| crate::encoding::decode(e))
        .collect::<Result<Vec<_>, _>>()
        .map_err(trax_error)?;
    let seal = crate::dag::create_segment_seal_k8(&private_key.signing_key, &events)
        .map_err(trax_error)?;
    let bytes = crate::encoding::encode_deterministic(&seal).map_err(trax_error)?;
    Ok(PyBytes::new_bound(py, &bytes))
}

#[pyfunction]
fn verify_segment_seal_k8(
    lineage_public_key: &[u8],
    events: Vec<Vec<u8>>,
    seal: &[u8],
) -> PyResult<bool> {
    use ed25519_dalek::VerifyingKey;
    validate_len(
        "lineage_public_key",
        lineage_public_key,
        ED25519_PUBLIC_KEY_LEN,
    )?;
    let key = VerifyingKey::from_bytes(&lineage_public_key.try_into().unwrap())
        .map_err(|_| PyValueError::new_err("invalid lineage public key"))?;
    let events = events
        .iter()
        .map(|e| crate::encoding::decode(e))
        .collect::<Result<Vec<_>, _>>()
        .map_err(trax_error)?;
    let seal = crate::encoding::decode(seal).map_err(trax_error)?;
    Ok(crate::dag::verify_segment_proof(&crate::SegmentProof { events, seal }, &key).is_ok())
}

#[pyfunction]
fn generate_keypair(py: Python<'_>) -> PyResult<Bound<'_, PyDict>> {
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    let mut rng = OsRng;
    let signing_key = SigningKey::generate(&mut rng);
    let verifying_key = signing_key.verifying_key();

    let keys = PyDict::new_bound(py);
    keys.set_item("private_key", Py::new(py, PrivateKey { signing_key })?)?;
    keys.set_item(
        "public_key",
        PyBytes::new_bound(py, verifying_key.as_bytes()),
    )?;
    Ok(keys)
}

#[pyfunction]
fn generate_nonce<'py>(py: Python<'py>) -> Bound<'py, PyBytes> {
    use rand::rngs::OsRng;
    use rand::RngCore;

    let mut nonce = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce);
    PyBytes::new_bound(py, &nonce)
}

#[pyfunction]
fn derive_session_id<'py>(
    py: Python<'py>,
    transcript_hash: &[u8],
    client_nonce: &[u8],
    server_nonce: &[u8],
) -> PyResult<Bound<'py, PyBytes>> {
    validate_len("transcript_hash", transcript_hash, HASH32_LEN)?;
    validate_len("client_nonce", client_nonce, NONCE_LEN)?;
    validate_len("server_nonce", server_nonce, NONCE_LEN)?;

    let session_id =
        crate::session::derive_session_id(transcript_hash, client_nonce, server_nonce, None);
    Ok(PyBytes::new_bound(py, &session_id))
}

#[pyfunction]
fn sign_message<'py>(
    py: Python<'py>,
    private_key: PyRef<'py, PrivateKey>,
    message: &[u8],
) -> PyResult<Bound<'py, PyBytes>> {
    let signature = crate::crypto::ed25519_sign(&private_key.signing_key, message);

    Ok(PyBytes::new_bound(py, &signature))
}

#[pyfunction]
fn verify_message(public_key: &[u8], message: &[u8], signature: &[u8]) -> PyResult<bool> {
    use ed25519_dalek::VerifyingKey;

    validate_len("public_key", public_key, ED25519_PUBLIC_KEY_LEN)?;
    validate_len("signature", signature, ED25519_SIGNATURE_LEN)?;

    let public_key: [u8; ED25519_PUBLIC_KEY_LEN] = public_key
        .try_into()
        .map_err(|_| PyValueError::new_err("public_key must be 32 bytes"))?;
    let verifying_key = VerifyingKey::from_bytes(&public_key)
        .map_err(|_| PyValueError::new_err("public_key is not a valid Ed25519 public key"))?;

    Ok(crate::crypto::ed25519_verify(
        &verifying_key,
        message,
        signature,
    ))
}

#[pyfunction]
#[pyo3(signature = (
    private_key,
    receiver_public_key,
    session_id,
    nonce,
    payload,
    message_type,
    dag_parent_refs=None,
    proof_type="none"
))]
fn create_admission_envelope_v1<'py>(
    py: Python<'py>,
    private_key: PyRef<'py, PrivateKey>,
    receiver_public_key: &[u8],
    session_id: &[u8],
    nonce: &[u8],
    payload: &[u8],
    message_type: &str,
    dag_parent_refs: Option<Vec<Vec<u8>>>,
    proof_type: &str,
) -> PyResult<Bound<'py, PyBytes>> {
    let dag_parent_refs = dag_parent_refs.unwrap_or_default();
    let envelope = crate::admission::create_admission_envelope_v1(
        &private_key.signing_key,
        receiver_public_key,
        session_id,
        nonce,
        payload,
        message_type,
        &dag_parent_refs,
        proof_type,
    )
    .map_err(trax_error)?;

    Ok(PyBytes::new_bound(py, &envelope))
}

#[pyfunction]
fn verify_admission_envelope_v1(envelope: &[u8], payload: &[u8]) -> PyResult<bool> {
    crate::admission::verify_admission_envelope_v1(envelope, payload).map_err(trax_error)
}

#[pyfunction]
fn verify_admission_envelope_v1_for_receiver(
    envelope: &[u8],
    payload: &[u8],
    receiver_public_key: &[u8],
) -> PyResult<bool> {
    crate::admission::verify_admission_envelope_v1_for_receiver(
        envelope,
        payload,
        receiver_public_key,
    )
    .map_err(trax_error)
}

#[pyfunction]
fn decode_admission_envelope_v1<'py>(
    py: Python<'py>,
    envelope: &[u8],
) -> PyResult<Bound<'py, PyDict>> {
    let envelope = crate::admission::decode_admission_envelope_v1(envelope).map_err(trax_error)?;
    let decoded = PyDict::new_bound(py);
    decoded.set_item("version", envelope.version)?;
    decoded.set_item("session_id", PyBytes::new_bound(py, &envelope.session_id))?;
    decoded.set_item("nonce", PyBytes::new_bound(py, &envelope.nonce))?;
    decoded.set_item(
        "sender_public_key",
        PyBytes::new_bound(py, &envelope.sender_public_key),
    )?;
    decoded.set_item(
        "receiver_public_key",
        PyBytes::new_bound(py, &envelope.receiver_public_key),
    )?;
    decoded.set_item(
        "payload_hash",
        PyBytes::new_bound(py, &envelope.payload_hash),
    )?;
    decoded.set_item("message_type", envelope.message_type)?;
    let dag_parent_refs = PyList::empty_bound(py);
    for parent_ref in envelope.dag_parent_refs {
        dag_parent_refs.append(PyBytes::new_bound(py, &parent_ref))?;
    }
    decoded.set_item("dag_parent_refs", dag_parent_refs)?;
    decoded.set_item("proof_type", envelope.proof_type)?;
    decoded.set_item("signature", PyBytes::new_bound(py, &envelope.signature))?;
    Ok(decoded)
}

fn validate_len(name: &str, value: &[u8], expected: usize) -> PyResult<()> {
    if value.len() == expected {
        Ok(())
    } else {
        Err(PyValueError::new_err(format!(
            "{name} must be {expected} bytes, got {}",
            value.len()
        )))
    }
}

fn trax_error(err: crate::TraxError) -> PyErr {
    PyValueError::new_err(err.to_string())
}

#[pymodule]
fn trax(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add_class::<LocalDag>()?;
    module.add_class::<PrivateKey>()?;
    module.add_class::<ReceiveAdmissionWindow>()?;
    module.add("DEFAULT_SEGMENT_K", crate::dag::DEFAULT_SEGMENT_K)?;
    module.add_function(wrap_pyfunction!(create_post_genesis_event_v1, module)?)?;
    module.add_function(wrap_pyfunction!(create_segment_seal_k8, module)?)?;
    module.add_function(wrap_pyfunction!(verify_segment_seal_k8, module)?)?;
    module.add_function(wrap_pyfunction!(create_admission_envelope_v1, module)?)?;
    module.add_function(wrap_pyfunction!(decode_admission_envelope_v1, module)?)?;
    module.add_function(wrap_pyfunction!(derive_session_id, module)?)?;
    module.add_function(wrap_pyfunction!(generate_keypair, module)?)?;
    module.add_function(wrap_pyfunction!(generate_nonce, module)?)?;
    module.add_function(wrap_pyfunction!(hash32, module)?)?;
    module.add_function(wrap_pyfunction!(sign_message, module)?)?;
    module.add_function(wrap_pyfunction!(verify_admission_envelope_v1, module)?)?;
    module.add_function(wrap_pyfunction!(
        verify_admission_envelope_v1_for_receiver,
        module
    )?)?;
    module.add_function(wrap_pyfunction!(verify_message, module)?)?;
    Ok(())
}
