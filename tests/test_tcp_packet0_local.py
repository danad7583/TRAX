import socket
import struct
import threading
import traceback

import pytest
import trax


MAX_PACKET0_LEN = 64 * 1024
MAX_PAYLOAD_LEN = 1024 * 1024
SOCKET_TIMEOUT_SECONDS = 5.0


def _write_exact(sock, data):
    sock.sendall(data)


def _read_exact(sock, length):
    chunks = []
    remaining = length
    while remaining:
        chunk = sock.recv(remaining)
        if not chunk:
            raise EOFError("truncated frame")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _write_packet0_frame(sock, packet0, payload):
    _write_exact(sock, struct.pack(">I", len(packet0)))
    _write_exact(sock, packet0)
    _write_exact(sock, struct.pack(">I", len(payload)))
    _write_exact(sock, payload)


def _run_packet0_server(listener, receiver_public_key, result):
    dag = trax.LocalDag()
    try:
        listener.settimeout(SOCKET_TIMEOUT_SECONDS)
        conn, _addr = listener.accept()
        with conn:
            conn.settimeout(SOCKET_TIMEOUT_SECONDS)

            packet0_len = struct.unpack(">I", _read_exact(conn, 4))[0]
            if packet0_len == 0:
                raise ValueError("zero-length Packet 0")
            if packet0_len > MAX_PACKET0_LEN:
                raise ValueError("oversized Packet 0")

            packet0 = _read_exact(conn, packet0_len)

            payload_len = struct.unpack(">I", _read_exact(conn, 4))[0]
            if payload_len > MAX_PAYLOAD_LEN:
                raise ValueError("oversized payload")

            payload = _read_exact(conn, payload_len)

            try:
                node_id = dag.admit_packet0(packet0, payload, receiver_public_key)
                result.update(
                    {
                        "admitted": True,
                        "dag_len": dag.len(),
                        "node_id": node_id,
                    }
                )
            except Exception as exc:
                result.update(
                    {
                        "admitted": False,
                        "dag_len": dag.len(),
                        "admission_error": repr(exc),
                    }
                )
    except Exception as exc:
        result.update(
            {
                "admitted": False,
                "dag_len": dag.len(),
                "server_error": repr(exc),
            }
        )
    except BaseException:
        result.update(
            {
                "admitted": False,
                "dag_len": dag.len(),
                "server_exception": traceback.format_exc(),
            }
        )
    finally:
        listener.close()


def _serve_once(receiver_public_key):
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    host, port = listener.getsockname()
    result = {}
    thread = threading.Thread(
        target=_run_packet0_server,
        args=(listener, receiver_public_key, result),
        daemon=True,
    )
    thread.start()
    return host, port, thread, result


def _send_to_server(host, port, packet0, payload):
    with socket.create_connection((host, port), timeout=SOCKET_TIMEOUT_SECONDS) as sock:
        sock.settimeout(SOCKET_TIMEOUT_SECONDS)
        _write_packet0_frame(sock, packet0, payload)


def _finish_server(thread, result):
    thread.join(SOCKET_TIMEOUT_SECONDS)
    assert not thread.is_alive(), "server thread did not finish"
    if "server_exception" in result:
        pytest.fail(result["server_exception"])
    assert result, "server did not report a result"
    return result


def _keypairs():
    return trax.generate_keypair(), trax.generate_keypair(), trax.generate_keypair()


def _packet0(sender, receiver_public_key, payload):
    return trax.create_admission_envelope_v1(
        sender["private_key"],
        receiver_public_key,
        trax.hash32(b"tcp packet0 local session"),
        trax.generate_nonce(),
        payload,
        "packet0.admission",
    )


def test_tcp_packet0_valid_admits_one_node():
    sender, receiver, _wrong_receiver = _keypairs()
    payload = b"local tcp packet0 payload"
    packet0 = _packet0(sender, receiver["public_key"], payload)
    host, port, thread, result = _serve_once(receiver["public_key"])

    _send_to_server(host, port, packet0, payload)
    result = _finish_server(thread, result)

    assert result["admitted"] is True
    assert result["dag_len"] == 1
    assert isinstance(result["node_id"], bytes)
    assert len(result["node_id"]) == 32


def test_tcp_packet0_tampered_payload_rejected():
    sender, receiver, _wrong_receiver = _keypairs()
    packet0 = _packet0(sender, receiver["public_key"], b"original payload")
    host, port, thread, result = _serve_once(receiver["public_key"])

    _send_to_server(host, port, packet0, b"tampered payload")
    result = _finish_server(thread, result)

    assert result["admitted"] is False
    assert result["dag_len"] == 0


def test_tcp_packet0_wrong_receiver_rejected():
    sender, receiver, wrong_receiver = _keypairs()
    payload = b"local tcp packet0 payload"
    packet0 = _packet0(sender, wrong_receiver["public_key"], payload)
    host, port, thread, result = _serve_once(receiver["public_key"])

    _send_to_server(host, port, packet0, payload)
    result = _finish_server(thread, result)

    assert result["admitted"] is False
    assert result["dag_len"] == 0


def test_tcp_packet0_malformed_packet0_rejected():
    _sender, receiver, _wrong_receiver = _keypairs()
    host, port, thread, result = _serve_once(receiver["public_key"])

    _send_to_server(host, port, b"not a canonical packet0 envelope", b"payload")
    result = _finish_server(thread, result)

    assert result["admitted"] is False
    assert result["dag_len"] == 0


def test_tcp_packet0_oversized_packet0_rejected():
    _sender, receiver, _wrong_receiver = _keypairs()
    host, port, thread, result = _serve_once(receiver["public_key"])

    with socket.create_connection((host, port), timeout=SOCKET_TIMEOUT_SECONDS) as sock:
        sock.settimeout(SOCKET_TIMEOUT_SECONDS)
        _write_exact(sock, struct.pack(">I", MAX_PACKET0_LEN + 1))

    result = _finish_server(thread, result)

    assert result["admitted"] is False
    assert result["dag_len"] == 0
    assert "oversized Packet 0" in result["server_error"]
