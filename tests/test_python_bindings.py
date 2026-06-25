import trax
import pytest


def test_hash32_returns_expected_blake3_digest():
    assert (
        trax.hash32(b"hello").hex()
        == "ea8f163db38682925e4491c5e58d4bb3506ef8c14eb78a86e908c5624a67200f"
    )


def test_keypair_sign_verify_and_session_usage():
    keys = trax.generate_keypair()
    private_key = keys["private_key"]
    public_key = keys["public_key"]

    assert isinstance(private_key, trax.PrivateKey)
    assert not isinstance(private_key, bytes)
    assert private_key.public_key() == public_key
    assert repr(private_key) == "<trax.PrivateKey>"
    assert isinstance(public_key, bytes)
    assert len(public_key) == 32

    message = b"hello from python"
    signature = trax.sign_message(private_key, message)

    assert isinstance(signature, bytes)
    assert len(signature) == 64
    assert trax.verify_message(public_key, message, signature) is True
    assert trax.verify_message(public_key, b"tampered", signature) is False

    nonce_a = trax.generate_nonce()
    nonce_b = trax.generate_nonce()
    transcript_hash = trax.hash32(b"demo transcript")
    session_id = trax.derive_session_id(transcript_hash, nonce_a, nonce_b)

    assert len(nonce_a) == 16
    assert len(nonce_b) == 16
    assert len(session_id) == 32


def test_private_key_is_opaque_and_not_raw_bytes():
    keys = trax.generate_keypair()
    private_key = keys["private_key"]

    assert isinstance(private_key, trax.PrivateKey)
    assert not isinstance(private_key, bytes)
    assert not hasattr(private_key, "__bytes__")

    with pytest.raises(TypeError):
        len(private_key)

    with pytest.raises(TypeError):
        trax.sign_message(keys["public_key"], b"message")


def test_malformed_lengths_raise_value_error():
    keys = trax.generate_keypair()
    signature = trax.sign_message(keys["private_key"], b"message")

    with pytest.raises(TypeError):
        trax.sign_message(b"short", b"message")

    with pytest.raises(ValueError, match="public_key must be 32 bytes"):
        trax.verify_message(b"short", b"message", signature)

    with pytest.raises(ValueError, match="signature must be 64 bytes"):
        trax.verify_message(keys["public_key"], b"message", b"short")

    with pytest.raises(ValueError, match="transcript_hash must be 32 bytes"):
        trax.derive_session_id(b"short", trax.generate_nonce(), trax.generate_nonce())

    with pytest.raises(ValueError, match="client_nonce must be 16 bytes"):
        trax.derive_session_id(trax.hash32(b"demo"), b"short", trax.generate_nonce())


def test_admission_envelope_v1_binds_packet_zero_security_fields():
    sender = trax.generate_keypair()
    receiver = trax.generate_keypair()
    payload = b"packet zero payload"
    session_id = trax.hash32(b"session transcript")
    nonce = trax.generate_nonce()
    dag_parent_refs = [trax.hash32(b"parent-a"), trax.hash32(b"parent-b")]

    envelope = trax.create_admission_envelope_v1(
        sender["private_key"],
        receiver["public_key"],
        session_id,
        nonce,
        payload,
        "packet0.admission",
        dag_parent_refs,
        "direct-ed25519",
    )
    same_envelope = trax.create_admission_envelope_v1(
        sender["private_key"],
        receiver["public_key"],
        session_id,
        nonce,
        payload,
        "packet0.admission",
        dag_parent_refs,
        "direct-ed25519",
    )

    assert isinstance(envelope, bytes)
    assert envelope == same_envelope

    decoded = trax.decode_admission_envelope_v1(envelope)
    assert decoded["version"] == 1
    assert decoded["session_id"] == session_id
    assert decoded["nonce"] == nonce
    assert decoded["sender_public_key"] == sender["public_key"]
    assert decoded["receiver_public_key"] == receiver["public_key"]
    assert decoded["payload_hash"] == trax.hash32(payload)
    assert decoded["message_type"] == "packet0.admission"
    assert decoded["dag_parent_refs"] == dag_parent_refs
    assert decoded["proof_type"] == "direct-ed25519"
    assert len(decoded["signature"]) == 64

    assert trax.verify_admission_envelope_v1(envelope, payload) is True
    assert (
        trax.verify_admission_envelope_v1_for_receiver(
            envelope, payload, receiver["public_key"]
        )
        is True
    )

    assert trax.verify_admission_envelope_v1(envelope, b"tampered") is False
    assert (
        trax.verify_admission_envelope_v1_for_receiver(
            envelope, payload, sender["public_key"]
        )
        is False
    )


def test_admission_envelope_v1_rejects_malformed_inputs():
    sender = trax.generate_keypair()
    receiver = trax.generate_keypair()
    payload = b"payload"
    session_id = trax.hash32(b"session")
    nonce = trax.generate_nonce()

    with pytest.raises(ValueError, match="receiver_public_key must be 32 bytes"):
        trax.create_admission_envelope_v1(
            sender["private_key"],
            b"short",
            session_id,
            nonce,
            payload,
            "packet0.admission",
        )

    with pytest.raises(ValueError, match="session_id must be 32 bytes"):
        trax.create_admission_envelope_v1(
            sender["private_key"],
            receiver["public_key"],
            b"short",
            nonce,
            payload,
            "packet0.admission",
        )

    with pytest.raises(ValueError, match="nonce must be 16 bytes"):
        trax.create_admission_envelope_v1(
            sender["private_key"],
            receiver["public_key"],
            session_id,
            b"short",
            payload,
            "packet0.admission",
        )

    with pytest.raises(ValueError, match="message_type must not be empty"):
        trax.create_admission_envelope_v1(
            sender["private_key"],
            receiver["public_key"],
            session_id,
            nonce,
            payload,
            "",
        )

    with pytest.raises(ValueError, match="dag_parent_ref must be 32 bytes"):
        trax.create_admission_envelope_v1(
            sender["private_key"],
            receiver["public_key"],
            session_id,
            nonce,
            payload,
            "packet0.admission",
            [b"short"],
        )


def test_local_dag_admits_verified_packet0_only():
    sender = trax.generate_keypair()
    receiver = trax.generate_keypair()
    wrong_receiver = trax.generate_keypair()
    payload = b"packet zero payload"
    envelope = trax.create_admission_envelope_v1(
        sender["private_key"],
        receiver["public_key"],
        trax.hash32(b"session transcript"),
        trax.generate_nonce(),
        payload,
        "packet0.admission",
    )
    dag = trax.LocalDag()

    assert dag.is_empty() is True
    assert len(dag) == 0

    node_id = dag.admit_packet0(envelope, payload, receiver["public_key"])

    assert isinstance(node_id, bytes)
    assert len(node_id) == 32
    assert dag.is_empty() is False
    assert dag.len() == 1
    assert len(dag) == 1

    tampered_dag = trax.LocalDag()
    with pytest.raises(ValueError):
        tampered_dag.admit_packet0(envelope, b"tampered", receiver["public_key"])
    assert tampered_dag.len() == 0

    wrong_receiver_dag = trax.LocalDag()
    with pytest.raises(ValueError):
        wrong_receiver_dag.admit_packet0(
            envelope, payload, wrong_receiver["public_key"]
        )
    assert wrong_receiver_dag.len() == 0
