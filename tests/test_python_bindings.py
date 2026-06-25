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
