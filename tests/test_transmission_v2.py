"""Exercise the Python boundary and independently reconstruct V2 wire hashes."""

import copy
import hashlib
import time

import pytest
import trax


def _head(major, value):
    if value < 24:
        return bytes([(major << 5) | value])
    for marker, width in [(24, 1), (25, 2), (26, 4), (27, 8)]:
        if value < 1 << (width * 8):
            return bytes([(major << 5) | marker]) + value.to_bytes(width, "big")
    raise ValueError("integer out of range")


def _encode(value):
    if value is None:
        return b"\xf6"
    if isinstance(value, bool):
        return b"\xf5" if value else b"\xf4"
    if isinstance(value, int):
        return _head(0, value) if value >= 0 else _head(1, -1 - value)
    if isinstance(value, bytes):
        return _head(2, len(value)) + value
    if isinstance(value, str):
        encoded = value.encode()
        return _head(3, len(encoded)) + encoded
    if isinstance(value, list):
        return _head(4, len(value)) + b"".join(map(_encode, value))
    if isinstance(value, dict):
        fields = [(_encode(key), _encode(item)) for key, item in value.items()]
        fields.sort(key=lambda pair: (len(pair[0]), pair[0]))
        return _head(5, len(fields)) + b"".join(key + item for key, item in fields)
    raise TypeError(type(value))


def _decode(encoded):
    def parse(offset):
        initial = encoded[offset]
        offset += 1
        major, argument = initial >> 5, initial & 31
        if major == 7:
            return {20: False, 21: True, 22: None}[argument], offset
        if argument >= 24:
            width = {24: 1, 25: 2, 26: 4, 27: 8}[argument]
            argument = int.from_bytes(encoded[offset:offset + width], "big")
            offset += width
        if major == 0:
            return argument, offset
        if major == 1:
            return -1 - argument, offset
        if major in (2, 3):
            value = encoded[offset:offset + argument]
            return value if major == 2 else value.decode(), offset + argument
        if major == 4:
            values = []
            for _ in range(argument):
                item, offset = parse(offset)
                values.append(item)
            return values, offset
        if major == 5:
            fields = {}
            for _ in range(argument):
                key, offset = parse(offset)
                value, offset = parse(offset)
                fields[key] = value
            return fields, offset
        raise ValueError("unsupported test CBOR type")

    value, end = parse(0)
    assert end == len(encoded)
    assert _encode(value) == encoded
    return value


def _hash(domain, *parts):
    digest = hashlib.new("sha512_256")
    digest.update(domain)
    for part in parts:
        digest.update(part)
    return digest.digest()


def _root(events):
    leaves = []
    for index, event in enumerate(events):
        encoded = _encode(event)
        leaves.append(_hash(b"TRAX:MERKLE:LEAF:V2\0", index.to_bytes(8, "big"),
                            len(encoded).to_bytes(8, "big"), encoded))

    def tree(nodes):
        if len(nodes) == 1:
            return nodes[0]
        split = 1 << ((len(nodes) - 1).bit_length() - 1)
        return _hash(b"TRAX:MERKLE:NODE:V2\0", tree(nodes[:split]), tree(nodes[split:]))

    return _hash(b"TRAX:MERKLE:ROOT:V2\0", len(events).to_bytes(8, "big"), tree(leaves))


def _genesis(a, b, **limits):
    offer = trax.tx_genesis_offer(a["private_key"], b"G" * 32, **limits)
    acceptance = trax.tx_genesis_accept(offer, b["private_key"], a["public_key"])
    confirmation = trax.tx_genesis_confirm(
        offer, acceptance, a["private_key"], b["public_key"]
    )
    return offer, acceptance, confirmation


def _session(genesis, a, b, nonce=b"S" * 32, initiator=None):
    return trax.TransmissionSessionV2(
        *genesis, initiator or a["public_key"], nonce,
        [a["public_key"], b["public_key"]]
    )


def _pair(**limits):
    a, b = trax.generate_keypair(), trax.generate_keypair()
    genesis = _genesis(a, b, **limits)
    return a, b, genesis, [_session(genesis, a, b), _session(genesis, a, b)]


def _deliver(sessions, packets, payload):
    for session in sessions:
        before = session.checkpoint()
        session.start_receive()
        for index, packet in enumerate(packets):
            result = session.stage_packet(packet)
            if index + 1 == len(packets):
                assert result == payload
            else:
                assert result is None
                assert session.checkpoint() == before
        assert not session.has_pending()
    assert sessions[0].checkpoint() == sessions[1].checkpoint()


def _rejected(session, packets):
    before = session.checkpoint()
    session.start_receive()
    with pytest.raises(ValueError):
        for packet in packets:
            assert session.stage_packet(packet) is None
    assert session.checkpoint() == before
    assert not session.has_pending()


@pytest.mark.parametrize("count", [1, 2, 3, 7, 8, 9, 17, 35, 100, 138])
def test_variable_sizes_independent_merkle_signature_history_and_payload(count):
    a, _, _, sessions = _pair()
    chunks = [bytes([index % 251]) * 1400 for index in range(count)]
    before = sessions[0].checkpoint()
    packets = sessions[0].build_transmission(a["private_key"], "document.request", chunks)
    decoded = list(map(_decode, packets))
    assert len(packets) == count
    assert all(packet["authentication"] is None for packet in decoded[:-1])
    final = decoded[-1]["authentication"]
    commitment = final["commitment"]
    assert commitment["packet_count"] == count
    assert commitment["payload_bytes"] == count * 1400
    assert commitment["merkle_root"] == _root([packet["event"] for packet in decoded])
    assert trax.verify_message(
        a["public_key"], b"TRAX:TRANSMISSION:V2\0" + _encode(commitment), final["signature"]
    )
    tip, history = before["tip"], before["history_hash"]
    for packet in decoded:
        event = packet["event"]
        assert event["previous_tip"] == tip
        assert event["payload_hash"] == _hash(b"TRAX:PAYLOAD:V2\0", packet["payload"])
        event_bytes = _encode(event)
        tip = _hash(b"TRAX:EVENT:V2\0", event_bytes)
        history = _hash(b"TRAX:HISTORY:EVENT:V2\0", history, event_bytes)
    history = _hash(b"TRAX:HISTORY:AUTH:V2\0", history, _encode(final))
    assert commitment["final_event_tip"] == tip
    _deliver(sessions, packets, b"".join(chunks))
    assert sessions[0].checkpoint()["tip"] == tip
    assert sessions[0].checkpoint()["history_hash"] == history


def test_multiple_bidirectional_rounds_and_single_initiator_terminal_artifact():
    a, b, _, sessions = _pair()
    with pytest.raises(ValueError):
        sessions[0].create_close(a["private_key"])
    for key, count, kind in [(a, 100, "request"), (b, 17, "response"),
                             (a, 9, "request"), (b, 7, "response")]:
        chunks = [(kind + str(index)).encode() for index in range(count)]
        packets = sessions[0].build_transmission(key["private_key"], kind, chunks)
        _deliver(sessions, packets, b"".join(chunks))
        assert not sessions[0].checkpoint()["closed"]
    before = sessions[0].checkpoint()
    with pytest.raises(ValueError):
        sessions[1].create_close(b["private_key"])
    terminal = sessions[0].create_close(a["private_key"])
    decoded = _decode(terminal)
    assert decoded["commitment"]["history_hash"] == before["history_hash"]
    assert trax.verify_message(
        a["public_key"], b"TRAX:SESSION:CLOSE:V2\0" + _encode(decoded["commitment"]),
        decoded["signature"]
    )
    for session in sessions:
        session.verify_and_close(terminal)
        assert session.checkpoint()["closed"]
        assert session.checkpoint()["event_count"] == before["event_count"] + 1
        with pytest.raises(ValueError):
            session.verify_and_close(terminal)
        with pytest.raises(ValueError):
            session.start_receive()
    assert sessions[0].checkpoint() == sessions[1].checkpoint()


def test_either_authenticated_peer_can_initiate_a_session():
    a, b, genesis, _ = _pair()
    sessions = [_session(genesis, a, b, initiator=b["public_key"]) for _ in range(2)]
    for key, kind in [(b, "request"), (a, "response")]:
        packets = sessions[0].build_transmission(key["private_key"], kind, [kind.encode()])
        _deliver(sessions, packets, kind.encode())
    terminal = sessions[0].create_close(b["private_key"])
    for session in sessions:
        session.verify_and_close(terminal)
    assert sessions[0].checkpoint() == sessions[1].checkpoint()


def test_genesis_requires_explicit_trust_and_opaque_private_keys():
    a, b, genesis, _ = _pair()
    stranger = trax.generate_keypair()
    with pytest.raises(ValueError):
        trax.tx_genesis_accept(genesis[0], b["private_key"], stranger["public_key"])
    with pytest.raises(ValueError):
        trax.tx_genesis_confirm(*genesis[:2], a["private_key"], stranger["public_key"])
    with pytest.raises(ValueError):
        trax.TransmissionSessionV2(*genesis, a["public_key"], b"S" * 32,
                                   [a["public_key"], stranger["public_key"]])
    with pytest.raises(TypeError):
        trax.tx_genesis_offer(a["public_key"], b"G" * 32)
    damaged = bytearray(genesis[1])
    damaged[-1] ^= 1
    with pytest.raises(ValueError):
        trax.TransmissionSessionV2(genesis[0], bytes(damaged), genesis[2],
                                   a["public_key"], b"S" * 32,
                                   [a["public_key"], b["public_key"]])


@pytest.mark.parametrize("attack", ["payload", "final_payload", "reorder", "missing",
                                    "duplicate", "signature", "count", "root", "sender",
                                    "receiver", "session", "transmission", "legacy"])
def test_rejected_wire_changes_never_advance_or_release_provisional_data(attack):
    a, _, _, sessions = _pair()
    packets = sessions[0].build_transmission(a["private_key"], "request", [b"one", b"two", b"three"])
    decoded = list(map(_decode, packets))
    if attack in ("payload", "final_payload"):
        decoded[0 if attack == "payload" else -1]["payload"] += b"!"
    elif attack == "reorder":
        decoded[0], decoded[1] = decoded[1], decoded[0]
    elif attack == "missing":
        decoded.pop(1)
    elif attack == "duplicate":
        decoded.insert(1, copy.deepcopy(decoded[0]))
    elif attack == "legacy":
        _rejected(sessions[1], [b"\xa0"])
        return
    else:
        auth = decoded[-1]["authentication"]
        if attack == "signature":
            auth["signature"] = bytes([auth["signature"][0] ^ 1]) + auth["signature"][1:]
        elif attack == "count":
            auth["commitment"]["packet_count"] += 1
        elif attack == "root":
            auth["commitment"]["merkle_root"] = b"X" * 32
        else:
            field = {"session": "session_id", "transmission": "transmission_id"}.get(attack, attack)
            auth["commitment"][field] = 99 if field == "transmission_id" else b"X" * 32
    _rejected(sessions[1], list(map(_encode, decoded)))


def test_attacker_can_rehash_all_links_but_cannot_authenticate_substituted_request():
    a, _, _, sessions = _pair()
    attacker = trax.generate_keypair()
    packets = sessions[0].build_transmission(a["private_key"], "request", [b"original", b"second", b"last"])
    forged = list(map(_decode, packets))
    forged[0]["payload"] = b"tampered"
    tip = sessions[1].checkpoint()["tip"]
    for packet in forged:
        event = packet["event"]
        event["previous_tip"] = tip
        event["payload_hash"] = _hash(b"TRAX:PAYLOAD:V2\0", packet["payload"])
        event["payload_len"] = len(packet["payload"])
        tip = _hash(b"TRAX:EVENT:V2\0", _encode(event))
    auth = forged[-1]["authentication"]
    auth["commitment"]["merkle_root"] = _root([packet["event"] for packet in forged])
    auth["commitment"]["final_event_tip"] = tip
    auth["signature"] = trax.sign_message(
        attacker["private_key"], b"TRAX:TRANSMISSION:V2\0" + _encode(auth["commitment"])
    )
    assert trax.verify_message(attacker["public_key"],
                               b"TRAX:TRANSMISSION:V2\0" + _encode(auth["commitment"]), auth["signature"])
    _rejected(sessions[1], list(map(_encode, forged)))


def test_cross_session_replay_wrong_direction_and_wrong_legitimate_signer_reject():
    a, b, genesis, sessions = _pair()
    packets = sessions[0].build_transmission(a["private_key"], "request", [b"request"])
    other_session = _session(genesis, a, b, nonce=b"T" * 32)
    _rejected(other_session, packets)
    wrong_signer = _decode(packets[-1])
    auth = wrong_signer["authentication"]
    auth["signature"] = trax.sign_message(b["private_key"], b"TRAX:TRANSMISSION:V2\0" + _encode(auth["commitment"]))
    _rejected(sessions[1], [_encode(wrong_signer)])
    _deliver(sessions, packets, b"request")
    _rejected(sessions[1], packets)
    with pytest.raises(ValueError):
        sessions[0].build_transmission(a["private_key"], "response", [b"wrong direction"])


def test_interruption_timeout_duplicate_staging_and_resource_limits():
    a, _, _, sessions = _pair(max_packets=2, max_payload_bytes=32,
                               max_packet_payload_bytes=16, timeout_ms=50)
    session = sessions[1]
    packets = sessions[0].build_transmission(a["private_key"], "request", [b"one", b"two"])
    before = session.checkpoint()
    for chunks in [[b"a", b"b", b"c"], [b"a" * 17]]:
        with pytest.raises(ValueError):
            sessions[0].build_transmission(a["private_key"], "request", chunks)
    session.start_receive()
    with pytest.raises(ValueError):
        session.start_receive()
    assert session.stage_packet(packets[0]) is None
    time.sleep(0.08)
    assert session.expire_receive()
    assert not session.has_pending()
    assert session.checkpoint() == before
    session.start_receive()
    assert session.stage_packet(packets[0]) is None
    assert session.abort_receive()
    assert not session.abort_receive()
    assert session.checkpoint() == before
    _rejected(session, [b"X" * 4097])
    _rejected(session, [b"\x81" * 100 + b"\x00"])


def test_fragmentation_respects_full_final_packet_budget():
    a, _, _, sessions = _pair(max_wire_packet_bytes=1400)
    payload = b"transport-sized data" * 300
    packets = sessions[0].fragment_transmission(a["private_key"], "request", payload)
    assert len(packets) > 1
    assert all(len(packet) <= 1400 for packet in packets)
    assert _decode(packets[-1])["authentication"] is not None
    _deliver(sessions, packets, payload)


def test_invalid_closure_history_boundary_signature_and_pending_state():
    a, b, genesis, sessions = _pair()
    for key, kind in [(a, "request"), (b, "response")]:
        packets = sessions[0].build_transmission(key["private_key"], kind, [kind.encode()])
        _deliver(sessions, packets, kind.encode())
    terminal = sessions[0].create_close(a["private_key"])
    before = sessions[1].checkpoint()
    for field in ["history_hash", "final_data_tip", "last_counter"]:
        changed = _decode(terminal)
        changed["commitment"][field] = 99 if field == "last_counter" else b"X" * 32
        with pytest.raises(ValueError):
            sessions[1].verify_and_close(_encode(changed))
        assert sessions[1].checkpoint() == before
    changed = _decode(terminal)
    changed["signature"] = trax.sign_message(b["private_key"], b"TRAX:SESSION:CLOSE:V2\0" + _encode(changed["commitment"]))
    with pytest.raises(ValueError):
        sessions[1].verify_and_close(_encode(changed))
    other = _session(genesis, a, b, nonce=b"T" * 32)
    with pytest.raises(ValueError):
        other.verify_and_close(terminal)
    packets = sessions[0].build_transmission(a["private_key"], "request", [b"first", b"final"])
    sessions[1].start_receive()
    assert sessions[1].stage_packet(packets[0]) is None
    with pytest.raises(ValueError):
        sessions[1].verify_and_close(terminal)
    assert sessions[1].checkpoint() == before
    assert sessions[1].abort_receive()
    sessions[1].verify_and_close(terminal)
    with pytest.raises(TypeError):
        copy.copy(sessions[1])
