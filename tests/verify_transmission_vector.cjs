// Independent wire/hash/signature conformance: Node's crypto, no TRAX imports.
// Run: node tests/verify_transmission_vector.cjs
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const assert = require('node:assert/strict');
const source = fs.readFileSync(path.join(__dirname, '../vectors/transmission_v2.cbor'));

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
assert.equal(H('', source).toString('hex'), '1c524040831fa1f2c43fa1f68e6520fdef0982b1e83fa3dec177e309774dfaff');
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
assert.deepEqual(vector.context.relationship_id, relationship);
assert.deepEqual(vector.context.profile, offer.event.profile);
assert.deepEqual(vector.context.initiator, a); assert.deepEqual(vector.context.responder, b);
const session = H('TRAX:SESSION:ID:V2\0', encode(vector.context));
let tip = H('TRAX:SESSION:ANCHOR:V2\0', session, relationship);
let history = H('TRAX:HISTORY:INIT:V2\0', encode(vector.context));
let counter = 0, transmission = 0;
for (const [packets, sender, receiver, kind] of [[vector.request, a, b, 'request'], [vector.response, b, a, 'response']]) {
  const starting = tip, first = counter + 1; let bytes = 0; transmission++;
  for (const [index, packet] of packets.entries()) {
    const e = packet.event; counter++; bytes += packet.payload.length;
    assert.deepEqual(e, {version: 2, relationship_id: relationship, session_id: session,
      transmission_id: transmission, initiator: a, sender, receiver, key_epoch: 0, kind,
      message_type: packets[0].event.message_type, packet_index: index, counter, previous_tip: tip,
      payload_hash: H('TRAX:PAYLOAD:V2\0', packet.payload), payload_len: packet.payload.length,
      is_final: index + 1 === packets.length});
    if (index + 1 < packets.length) assert.equal(packet.authentication, null);
    tip = H('TRAX:EVENT:V2\0', encode(e));
    history = H('TRAX:HISTORY:EVENT:V2\0', history, encode(e));
  }
  const seal = packets.at(-1).authentication;
  assert.deepEqual(seal.commitment, {version: 2, purpose: 'logical-transmission',
    relationship_id: relationship, session_id: session, transmission_id: transmission,
    initiator: a, sender, receiver, key_epoch: 0, kind, message_type: packets[0].event.message_type,
    starting_tip: starting, first_counter: first, last_counter: counter, packet_count: packets.length,
    payload_bytes: bytes, merkle_root: root(packets.map(p => p.event)), final_event_tip: tip});
  verify('TRAX:TRANSMISSION:V2\0', seal.commitment, seal.signature, sender);
  history = H('TRAX:HISTORY:AUTH:V2\0', history, encode(seal));
}
assert.equal(Buffer.concat(vector.request.map(p => p.payload)).toString(), 'hello world!');
assert.deepEqual(vector.terminal.commitment, {version: 2, purpose: 'session-close',
  relationship_id: relationship, session_id: session, initiator: a, responder: b,
  final_data_tip: tip, history_hash: history, first_counter: 1, last_counter: counter,
  event_count: counter, transmission_id: transmission, terminal_counter: counter + 1});
verify('TRAX:SESSION:CLOSE:V2\0', vector.terminal.commitment, vector.terminal.signature, a);
tip = H('TRAX:SESSION:TERMINAL:V2\0', encode(vector.terminal));
history = H('TRAX:HISTORY:TERMINAL:V2\0', history, encode(vector.terminal));
assert.deepEqual(vector.checkpoint, {session_id: session, tip, history_hash: history,
  event_count: counter + 1, transmission_id: transmission, closed: true});
console.log('Independent V2 vector passed: genesis, all packet links, roots, original Ed25519 signatures, full history and closure.');
