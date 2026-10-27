// Independent wire/hash/signature conformance: Node's crypto, no TRAX imports.
// Run: node tests/verify_transcript.cjs
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const assert = require('node:assert/strict');
const source = fs.readFileSync(path.join(__dirname, '../vectors/relationship.cbor'));

function head(major, value) {
  const n = BigInt(value);
  if (n < 24n) return Buffer.from([(major << 5) | Number(n)]);
  for (const [marker, width] of [[24, 1], [25, 2], [26, 4], [27, 8]]) {
    if (n < (1n << BigInt(width * 8))) {
      const bytes = Buffer.alloc(width + 1); bytes[0] = (major << 5) | marker;
      for (let i = 0; i < width; i++) bytes[width - i] = Number((n >> BigInt(i * 8)) & 255n);
      return bytes;
    }
  }
  throw new Error('integer overflow');
}
function encode(value) {
  if (value === null) return Buffer.from([0xf6]);
  if (typeof value === 'boolean') return Buffer.from([value ? 0xf5 : 0xf4]);
  if (typeof value === 'number') return head(0, value);
  if (Buffer.isBuffer(value)) return Buffer.concat([head(2, value.length), value]);
  if (typeof value === 'string') { const bytes = Buffer.from(value); return Buffer.concat([head(3, bytes.length), bytes]); }
  if (Array.isArray(value)) return Buffer.concat([head(4, value.length), ...value.map(encode)]);
  const entries = Object.entries(value).map(([key, item]) => [encode(key), encode(item)]);
  entries.sort((a, b) => a[0].length - b[0].length || Buffer.compare(a[0], b[0]));
  return Buffer.concat([head(5, entries.length), ...entries.flat()]);
}
let offset = 0;
function decode() {
  const initial = source[offset++], major = initial >> 5;
  let count = initial & 31;
  if (major === 7) { assert.ok([20, 21, 22].includes(count)); return count === 22 ? null : count === 21; }
  if (count >= 24) {
    const width = new Map([[24, 1], [25, 2], [26, 4], [27, 8]]).get(count);
    assert.ok(width); let n = 0n;
    for (let i = 0; i < width; i++) n = (n << 8n) | BigInt(source[offset++]);
    assert.ok(n <= BigInt(Number.MAX_SAFE_INTEGER)); count = Number(n);
  }
  if (major === 0) return count;
  if (major === 2 || major === 3) { const bytes = source.subarray(offset, offset + count); offset += count; return major === 2 ? bytes : bytes.toString('utf8'); }
  if (major === 4) return Array.from({length: count}, decode);
  if (major === 5) {
    const result = {};
    for (let i = 0; i < count; i++) { const key = decode(); assert.ok(!Object.hasOwn(result, key)); result[key] = decode(); }
    return result;
  }
  throw new Error('unexpected CBOR');
}
const vector = decode();
assert.equal(offset, source.length);
assert.deepEqual(encode(vector), source);
function H(domain, ...parts) { const h = crypto.createHash('sha512-256'); h.update(domain); for (const part of parts) h.update(part); return h.digest(); }
function u64(n) { const bytes = Buffer.alloc(8); bytes.writeBigUInt64BE(BigInt(n)); return bytes; }
function verify(domain, record, signature, key) {
  const der = Buffer.concat([Buffer.from('302a300506032b6570032100', 'hex'), key]);
  assert.equal(crypto.verify(null, Buffer.concat([Buffer.from(domain), encode(record)]),
    crypto.createPublicKey({key: der, format: 'der', type: 'spki'}), signature), true);
}
function root(events) {
  const leaves = events.map((event, index) => { const bytes = encode(event); return H('TRAX:MERKLE:LEAF:V2\0', u64(index), u64(bytes.length), bytes); });
  function tree(nodes) {
    if (nodes.length === 1) return nodes[0];
    const split = 2 ** Math.floor(Math.log2(nodes.length - 1));
    return H('TRAX:MERKLE:NODE:V2\0', tree(nodes.slice(0, split)), tree(nodes.slice(split)));
  }
  return H('TRAX:MERKLE:ROOT:V2\0', u64(events.length), tree(leaves));
}
assert.equal(H('', source).toString('hex'), 'f9e1504e0aaa105315455f403500b3995a03e468620cc95df6726e25c7e9e957');

const [offer, accept, confirm] = vector.genesis;
const a = offer.event.initiator_public_key, b = accept.event.responder_public_key;
let previous = Buffer.alloc(32);
for (const [index, node] of vector.genesis.entries()) {
  assert.equal(node.event.version, 2);
  assert.equal(node.event.step, ['offer', 'accept', 'confirm'][index]);
  assert.deepEqual(node.event.previous_tip, previous);
  assert.deepEqual(node.event.profile, offer.event.profile);
  assert.deepEqual(node.event.nonce, offer.event.nonce);
  assert.deepEqual(node.event.initiator_public_key, a);
  assert.deepEqual(node.event.responder_public_key, index ? b : null);
  verify('TRAX:GENESIS:V2\0', node.event, node.signature, index === 1 ? b : a);
  previous = H('TRAX:GENESIS:NODE:V2\0', encode(node));
}
const relationship = H('TRAX:GENESIS:ANCHOR:V2\0', encode(vector.genesis));
let tip = relationship, position = 0;
const expectedRecords = [{id: relationship, parent: null, position: 0,
  kind: {type: 'genesis', transcript: vector.genesis}}];
let history = H('TRAX:HISTORY:ROOT:V3\0', encode(expectedRecords[0]));
function append(id, kind) {
  const record = {id, parent: tip, position: ++position, kind};
  tip = id; expectedRecords.push(record);
  history = H('TRAX:HISTORY:RECORD:V3\0', history, encode(record));
}
let sessionIndex = 0, lastSession = null;
for (const entry of vector.sessions) {
  const ctx = entry.context; sessionIndex++;
  const initiator = sessionIndex === 1 ? a : b;
  const responder = sessionIndex === 1 ? b : a;
  assert.deepEqual(ctx, {version: 3, relationship_id: relationship, profile: offer.event.profile,
    initiator, responder, nonce: Buffer.alloc(32, sessionIndex + 3), session_index: sessionIndex,
    previous_tip: tip, previous_history_hash: history, previous_record_count: position});
  const session = H('TRAX:SESSION:ID:V3\0', encode(ctx)); lastSession = session;
  const startId = H('TRAX:SESSION:START:V3\0', encode(ctx));
  append(startId, {type: 'session_start', context: ctx});
  const firstCounter = position + 1;
  let sessionHistory = H('TRAX:HISTORY:INIT:V3\0', encode(ctx));
  let transmission = 0, packetCount = 0;
  for (const packets of entry.transmissions) {
    const starting = tip, first = position + 1;
    const sender = transmission % 2 === 0 ? initiator : responder;
    const receiver = transmission % 2 === 0 ? responder : initiator;
    const kind = transmission % 2 === 0 ? 'request' : 'response';
    transmission++; let bytes = 0;
    for (const [index, packet] of packets.entries()) {
      const e = packet.event; bytes += packet.payload.length; packetCount++;
      assert.deepEqual(packet.session_start, transmission === 1 && index === 0 ? ctx : null);
      assert.deepEqual(e, {version: 3, relationship_id: relationship, session_id: session,
        transmission_id: transmission, initiator, sender, receiver, key_epoch: 0, kind,
        message_type: packets[0].event.message_type, packet_index: index, counter: position + 1,
        previous_tip: tip, payload_hash: H('TRAX:PAYLOAD:V3\0', packet.payload),
        payload_len: packet.payload.length, is_final: index + 1 === packets.length});
      if (index + 1 < packets.length) assert.equal(packet.authentication, null);
      const id = H('TRAX:EVENT:V3\0', encode(e));
      sessionHistory = H('TRAX:HISTORY:EVENT:V3\0', sessionHistory, encode(e));
      append(id, {type: 'packet', event: e, authentication: packet.authentication});
    }
    const seal = packets.at(-1).authentication;
    assert.deepEqual(seal.commitment, {version: 3, purpose: 'logical-transmission',
      relationship_id: relationship, session_id: session, transmission_id: transmission,
      initiator, sender, receiver, key_epoch: 0, kind, message_type: packets[0].event.message_type,
      starting_tip: starting, first_counter: first, last_counter: position,
      packet_count: packets.length, payload_bytes: bytes,
      merkle_root: root(packets.map(p => p.event)), final_event_tip: tip});
    verify('TRAX:TRANSMISSION:V3\0', seal.commitment, seal.signature, sender);
    sessionHistory = H('TRAX:HISTORY:AUTH:V3\0', sessionHistory, encode(seal));
  }
  assert.equal(transmission % 2, 0);
  assert.deepEqual(entry.terminal.commitment, {version: 3, purpose: 'session-close',
    relationship_id: relationship, session_id: session, session_index: sessionIndex, initiator, responder,
    final_data_tip: tip, session_history_hash: sessionHistory, relationship_history_hash: history,
    first_counter: firstCounter, last_counter: position, packet_count: packetCount,
    transmission_id: transmission, terminal_counter: position + 1});
  verify('TRAX:SESSION:CLOSE:V3\0', entry.terminal.commitment, entry.terminal.signature, initiator);
  const terminalId = H('TRAX:SESSION:TERMINAL:V3\0', encode(entry.terminal));
  append(terminalId, {type: 'session_terminal', terminal: entry.terminal});
  sessionHistory = H('TRAX:HISTORY:TERMINAL:V3\0', sessionHistory, encode(entry.terminal));
  assert.deepEqual(entry.checkpoint, {session_id: session, session_index: sessionIndex,
    tip, history_hash: sessionHistory, packet_count: packetCount, transmission_id: transmission, closed: true});
}
assert.equal(sessionIndex, 2);
assert.deepEqual(vector.history, expectedRecords);
assert.deepEqual(vector.checkpoint, {relationship_id: relationship, tip, history_hash: history,
  record_count: position, completed_sessions: sessionIndex, last_session_id: lastSession, active_session: null});
console.log('Independent canonical transcript passed: unchanged signed genesis, all packet/Merkle signatures, two linked sessions, every traversable history record, and original closures.');
