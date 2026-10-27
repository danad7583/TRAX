"""Canonical Python admission and independently reconstructed protocol hashes."""

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
    offer = trax.create_genesis_offer(a["private_key"], b"G" * 32, hash_algorithm="sha512-256", **limits)
    acceptance = trax.accept_genesis_offer(offer, b["private_key"], a["public_key"])
    confirmation = trax.confirm_genesis(
        offer, acceptance, a["private_key"], b["public_key"]
    )
    return offer, acceptance, confirmation


def _relationship(genesis, a, b):
    return trax.Relationship(*genesis, [a["public_key"], b["public_key"]])


def _session(genesis, a, b, nonce=b"S" * 32, initiator=None):
    relationship = _relationship(genesis, a, b)
    relationship.begin_session(initiator or a["public_key"], nonce)
    return relationship


def _pair(**limits):
    a, b = trax.generate_keypair(), trax.generate_keypair()
    genesis = _genesis(a, b, **limits)
    return a, b, genesis, [_session(genesis, a, b), _relationship(genesis, a, b)]


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


@pytest.mark.parametrize("count", [1, 2, 3, 7, 8, 9, 17, 35, 100, 138, 1024])
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
        a["public_key"], b"TRAX:TRANSMISSION:V3\0" + _encode(commitment), final["signature"]
    )
    context = decoded[0]["session_start"]
    assert context["previous_tip"] == before["tip"]
    assert context["previous_history_hash"] == before["history_hash"]
    assert context["previous_record_count"] == before["record_count"]
    tip = _hash(b"TRAX:SESSION:START:V3\0", _encode(context))
    history = _hash(b"TRAX:HISTORY:INIT:V3\0", _encode(context))
    for packet in decoded:
        event = packet["event"]
        assert event["previous_tip"] == tip
        assert event["payload_hash"] == _hash(b"TRAX:PAYLOAD:V3\0", packet["payload"])
        event_bytes = _encode(event)
        tip = _hash(b"TRAX:EVENT:V3\0", event_bytes)
        history = _hash(b"TRAX:HISTORY:EVENT:V3\0", history, event_bytes)
    history = _hash(b"TRAX:HISTORY:AUTH:V3\0", history, _encode(final))
    assert commitment["final_event_tip"] == tip
    _deliver(sessions, packets, b"".join(chunks))
    assert sessions[0].checkpoint()["tip"] == tip
    assert sessions[0].session()["checkpoint"]["history_hash"] == history
    relationship_hash = before["history_hash"]
    for record in sessions[0].history()[1:]:
        relationship_hash = _hash(b"TRAX:HISTORY:RECORD:V3\0", relationship_hash, record)
    assert sessions[0].checkpoint()["history_hash"] == relationship_hash


def test_multiple_bidirectional_rounds_and_single_initiator_terminal_artifact():
    a, b, _, sessions = _pair()
    with pytest.raises(ValueError):
        sessions[0].create_close(a["private_key"])
    for key, count, kind in [(a, 100, "request"), (b, 17, "response"),
                             (a, 9, "request"), (b, 7, "response")]:
        chunks = [(kind + str(index)).encode() for index in range(count)]
        packets = sessions[0].build_transmission(key["private_key"], kind, chunks)
        _deliver(sessions, packets, b"".join(chunks))
        assert not sessions[0].session()["checkpoint"]["closed"]
    before = sessions[0].checkpoint()
    with pytest.raises(ValueError):
        sessions[1].create_close(b["private_key"])
    terminal = sessions[0].create_close(a["private_key"])
    decoded = _decode(terminal)
    assert decoded["commitment"]["relationship_history_hash"] == before["history_hash"]
    assert trax.verify_message(
        a["public_key"], b"TRAX:SESSION:CLOSE:V3\0" + _encode(decoded["commitment"]),
        decoded["signature"]
    )
    for session in sessions:
        session.verify_and_close(terminal)
        assert session.session()["checkpoint"]["closed"]
        assert session.checkpoint()["record_count"] == before["record_count"] + 1
        with pytest.raises(ValueError):
            session.verify_and_close(terminal)
        with pytest.raises(ValueError):
            session.build_transmission(a["private_key"], "request", [b"closed"])
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
        trax.accept_genesis_offer(genesis[0], b["private_key"], stranger["public_key"])
    with pytest.raises(ValueError):
        trax.confirm_genesis(*genesis[:2], a["private_key"], stranger["public_key"])
    with pytest.raises(ValueError):
        trax.Relationship(*genesis, [a["public_key"], stranger["public_key"]])
    with pytest.raises(TypeError):
        trax.create_genesis_offer(a["public_key"], b"G" * 32, hash_algorithm="sha512-256")
    damaged = bytearray(genesis[1])
    damaged[-1] ^= 1
    with pytest.raises(ValueError):
        trax.Relationship(genesis[0], bytes(damaged), genesis[2],
                                   [a["public_key"], b["public_key"]])


@pytest.mark.parametrize("attack", ["payload", "final_payload", "reorder", "missing",
                                    "duplicate", "signature", "count", "root", "sender",
                                    "receiver", "session", "transmission", "incompatible"])
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
    elif attack == "incompatible":
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
    tip = _hash(b"TRAX:SESSION:START:V3\0", _encode(forged[0]["session_start"]))
    for packet in forged:
        event = packet["event"]
        event["previous_tip"] = tip
        event["payload_hash"] = _hash(b"TRAX:PAYLOAD:V3\0", packet["payload"])
        event["payload_len"] = len(packet["payload"])
        tip = _hash(b"TRAX:EVENT:V3\0", _encode(event))
    auth = forged[-1]["authentication"]
    auth["commitment"]["merkle_root"] = _root([packet["event"] for packet in forged])
    auth["commitment"]["final_event_tip"] = tip
    auth["signature"] = trax.sign_message(
        attacker["private_key"], b"TRAX:TRANSMISSION:V3\0" + _encode(auth["commitment"])
    )
    assert trax.verify_message(attacker["public_key"],
                               b"TRAX:TRANSMISSION:V3\0" + _encode(auth["commitment"]), auth["signature"])
    _rejected(sessions[1], list(map(_encode, forged)))


def test_cross_session_replay_wrong_direction_and_wrong_legitimate_signer_reject():
    a, b, genesis, sessions = _pair()
    packets = sessions[0].build_transmission(a["private_key"], "request", [b"request"])
    other_session = _session(genesis, a, b, nonce=b"T" * 32)
    _rejected(other_session, packets)
    wrong_signer = _decode(packets[-1])
    auth = wrong_signer["authentication"]
    auth["signature"] = trax.sign_message(b["private_key"], b"TRAX:TRANSMISSION:V3\0" + _encode(auth["commitment"]))
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
    for field in ["relationship_history_hash", "session_history_hash", "final_data_tip", "last_counter"]:
        changed = _decode(terminal)
        changed["commitment"][field] = 99 if field == "last_counter" else b"X" * 32
        with pytest.raises(ValueError):
            sessions[1].verify_and_close(_encode(changed))
        assert sessions[1].checkpoint() == before
    changed = _decode(terminal)
    changed["signature"] = trax.sign_message(b["private_key"], b"TRAX:SESSION:CLOSE:V3\0" + _encode(changed["commitment"]))
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


def test_opaque_keys_nonce_lengths_and_generic_signature_checks():
    keys = trax.generate_keypair()
    private = keys["private_key"]
    assert isinstance(private, trax.PrivateKey)
    assert private.public_key() == keys["public_key"]
    assert repr(private) == "<trax.PrivateKey>"
    assert not isinstance(private, bytes)
    assert not hasattr(private, "__bytes__")
    assert len(trax.generate_nonce()) == 32
    signature = trax.sign_message(private, b"message")
    assert trax.verify_message(keys["public_key"], b"message", signature)
    assert not trax.verify_message(keys["public_key"], b"changed", signature)
    with pytest.raises(TypeError):
        trax.sign_message(keys["public_key"], b"message")
    with pytest.raises(ValueError):
        trax.verify_message(b"short", b"message", signature)
    with pytest.raises(ValueError):
        trax.verify_message(keys["public_key"], b"message", b"short")
    with pytest.raises(TypeError):
        trax.create_genesis_offer(private, b"G" * 32)
    with pytest.raises(ValueError):
        trax.create_genesis_offer(private, b"short", hash_algorithm="sha512-256")


def test_retired_protocols_and_unchecked_authority_constructors_are_not_exported():
    removed = [
        "Session", "TransmissionSessionV2", "LocalDag", "TrustedSessionContext",
        "ReceiveAdmissionWindow", "hash32", "derive_session_id", "receiver_id",
        "create_post_genesis_event_v1", "create_segment_seal", "verify_segment_seal_intrinsic",
        "verify_segment_seal_for_context", "create_admission_envelope_v1",
        "verify_admission_envelope_v1", "verify_admission_envelope_v1_for_receiver",
        "decode_admission_envelope_v1", "tx_genesis_offer", "tx_genesis_accept", "tx_genesis_confirm",
    ]
    assert all(not hasattr(trax, name) for name in removed)
    a, b, _, relationships = _pair()
    checkpoint = relationships[0].checkpoint()
    checkpoint["tip"] = b"X" * 32
    assert relationships[0].checkpoint()["tip"] != checkpoint["tip"]
    assert not hasattr(relationships[0], "from_verified_state")
    assert not hasattr(relationships[0], "__setstate__")
    assert len(a["public_key"]) == len(b["public_key"]) == 32


def test_unadmitted_local_intent_can_abort_but_accepted_history_cannot_reset():
    a, b, _, relationships = _pair()
    relationship = relationships[0]
    before = relationship.checkpoint()
    assert relationship.abort_draft_session()
    assert relationship.session() is None
    assert relationship.checkpoint() == before
    assert not relationship.abort_draft_session()
    relationship.begin_session(b["public_key"], b"N" * 32)
    packets = relationship.build_transmission(b["private_key"], "request", [b"new intent"])
    _deliver(relationships, packets, b"new intent")
    accepted = relationship.checkpoint()
    assert not relationship.abort_draft_session()
    with pytest.raises(ValueError):
        relationship.begin_session(a["public_key"], b"X" * 32)
    assert relationship.checkpoint() == accepted


def test_two_sessions_continue_the_relationship_and_full_history_includes_original_terminals():
    a, b, _, relationships = _pair()
    first_request = relationships[0].build_transmission(a["private_key"], "request", [b"one", b"two"])
    _deliver(relationships, first_request, b"onetwo")
    before = relationships[0].checkpoint()
    with pytest.raises(ValueError):
        relationships[0].begin_session(b["public_key"], b"N" * 32)
    assert relationships[0].checkpoint() == before
    response = relationships[1].build_transmission(b["private_key"], "response", [b"reply"])
    _deliver(relationships, response, b"reply")
    first_terminal = relationships[0].create_close(a["private_key"])
    for relationship in relationships:
        relationship.verify_and_close(first_terminal)
    first_boundary = relationships[0].checkpoint()
    assert first_boundary["completed_sessions"] == 1
    _rejected(relationships[0], first_request)

    relationships[1].begin_session(b["public_key"], b"N" * 32)
    next_request = relationships[1].build_transmission(b["private_key"], "request", [b"reverse request"])
    context = _decode(next_request[0])["session_start"]
    assert context["session_index"] == 2
    assert context["previous_tip"] == first_boundary["tip"]
    assert context["previous_history_hash"] == first_boundary["history_hash"]
    assert context["previous_record_count"] == first_boundary["record_count"]
    assert relationships[0].session()["checkpoint"]["closed"]
    _deliver(relationships, next_request, b"reverse request")
    next_response = relationships[0].build_transmission(a["private_key"], "response", [b"reverse reply"])
    _deliver(relationships, next_response, b"reverse reply")
    second_terminal = relationships[1].create_close(b["private_key"])
    for relationship in relationships:
        relationship.verify_and_close(second_terminal)
    assert relationships[0].checkpoint()["completed_sessions"] == 2
    assert relationships[0].history() == relationships[1].history()
    records = list(map(_decode, relationships[0].history()))
    assert records[0]["kind"]["type"] == "genesis"
    terminals = [record for record in records if record["kind"]["type"] == "session_terminal"]
    assert [_encode(record["kind"]["terminal"]) for record in terminals] == [first_terminal, second_terminal]
    assert records[-1]["id"] == relationships[0].checkpoint()["tip"]
    for index, record in enumerate(records):
        expected_parent = records[index - 1]["id"] if index else None
        assert record["parent"] == expected_parent
        assert record["position"] == index
        assert _decode(relationships[0].record(record["id"])) == record
        expected_children = [records[index + 1]] if index + 1 < len(records) else []
        assert list(map(_decode, relationships[0].children(record["id"]))) == expected_children
    ancestors = list(map(_decode, relationships[0].ancestors(records[-1]["id"])))
    assert ancestors == list(reversed(records[:-1]))
    assert relationships[0].record(b"X" * 32) is None
    history_hash = _hash(b"TRAX:HISTORY:ROOT:V3\0", _encode(records[0]))
    for record in records[1:]:
        kind = record["kind"]
        if kind["type"] == "session_start":
            expected_id = _hash(b"TRAX:SESSION:START:V3\0", _encode(kind["context"]))
        elif kind["type"] == "packet":
            expected_id = _hash(b"TRAX:EVENT:V3\0", _encode(kind["event"]))
        else:
            assert kind["type"] == "session_terminal"
            expected_id = _hash(b"TRAX:SESSION:TERMINAL:V3\0", _encode(kind["terminal"]))
        assert record["id"] == expected_id
        history_hash = _hash(b"TRAX:HISTORY:RECORD:V3\0", history_hash, _encode(record))
    assert relationships[0].checkpoint()["history_hash"] == history_hash
