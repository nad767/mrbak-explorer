import test from 'node:test';
import assert from 'node:assert/strict';
import { decompressQlz, parseQlzHeader } from '../src/quicklz.js';

/**
 * Helper to build a valid QuickLZ 1.31 frame for testing:
 * - uncompressed fallback frames (flag bit 0 = 0)
 * - compressed frames with literals, LZ matches (all 5 encodings), and RLE
 */
function makeUncompressedQlzFrame(payload, forceLong = false) {
  const isLong = forceLong || payload.length >= 216;
  const hdrLen = isLong ? 9 : 3;
  const total = hdrLen + payload.length;
  const out = Buffer.alloc(total);
  if (isLong) {
    out[0] = 0x02; // long header, uncompressed
    out.writeUInt32LE(total, 1);
    out.writeUInt32LE(payload.length, 5);
  } else {
    out[0] = 0x00; // short header, uncompressed
    out[1] = total;
    out[2] = payload.length;
  }
  Buffer.from(payload).copy(out, hdrLen);
  return out;
}

/**
 * Encode a QuickLZ 1.31 compressed stream from explicit ops:
 * ops = [{ type: 'lit', data: Buffer }, { type: 'match', offset, length }, { type: 'rle', byte, length }]
 */
function encodeQlzOps(ops) {
  const rawChunks = [];
  for (const op of ops) {
    if (op.type === 'lit') rawChunks.push(op.data);
    else if (op.type === 'rle') rawChunks.push(Buffer.alloc(op.length, op.byte));
    else if (op.type === 'match') {
      const prev = Buffer.concat(rawChunks);
      const start = prev.length - op.offset;
      const tmp = Buffer.alloc(op.length);
      for (let i = 0; i < op.length; i++) {
        tmp[i] = i < op.offset ? prev[start + i] : tmp[i - op.offset];
      }
      rawChunks.push(tmp);
    }
  }
  const plain = Buffer.concat(rawChunks);
  const body = [];
  let cwordPtrIdx = 0;
  let cwordVal = 0x80000000;

  const pushU32 = (v) => {
    body.push(v & 0xff, (v >>> 8) & 0xff, (v >>> 16) & 0xff, (v >>> 24) & 0xff);
  };
  const writeU32At = (idx, v) => {
    body[idx] = v & 0xff;
    body[idx + 1] = (v >>> 8) & 0xff;
    body[idx + 2] = (v >>> 16) & 0xff;
    body[idx + 3] = (v >>> 24) & 0xff;
  };
  const reserveCword = () => {
    cwordPtrIdx = body.length;
    body.push(0, 0, 0, 0);
    cwordVal = 0x80000000;
  };
  const emitBit = (bit) => {
    if ((cwordVal & 1) === 1) {
      writeU32At(cwordPtrIdx, ((cwordVal >>> 1) | 0x80000000) >>> 0);
      reserveCword();
    }
    cwordVal = ((cwordVal >>> 1) | (bit ? 0x80000000 : 0)) >>> 0;
  };

  reserveCword();

  let produced = 0;
  const guaranteed = plain.length >= 4 ? plain.length - 4 : 0;

  for (const op of ops) {
    if (op.type === 'lit') {
      for (const b of op.data) {
        emitBit(0);
        body.push(b);
        produced++;
      }
    } else if (op.type === 'match') {
      assert.ok(produced + op.length <= guaranteed, 'match must end before last 4 bytes');
      emitBit(1);
      if (op.length === 3 && op.offset <= 63) {
        body.push((op.offset << 2) & 0xff);
      } else if (op.length === 3 && op.offset <= 16383) {
        const f = (op.offset << 2) | 1;
        body.push(f & 0xff, (f >>> 8) & 0xff);
      } else if (op.length <= 18 && op.offset <= 1023) {
        const f = ((op.length - 3) << 2) | (op.offset << 6) | 2;
        body.push(f & 0xff, (f >>> 8) & 0xff);
      } else if (op.length <= 34 && op.offset <= 65535) {
        const f = ((op.length - 3) << 3) | (op.offset << 8) | 3;
        body.push(f & 0xff, (f >>> 8) & 0xff, (f >>> 16) & 0xff);
      } else {
        const f = ((op.length - 3) << 4) | (op.offset << 15) | 7;
        pushU32(f >>> 0);
      }
      produced += op.length;
    } else if (op.type === 'rle') {
      assert.ok(produced + op.length <= guaranteed, 'rle must end before last 4 bytes');
      emitBit(1);
      if (op.length <= 4095) {
        const f = 15 | (op.length << 4) | (op.byte << 16);
        body.push(f & 0xff, (f >>> 8) & 0xff, (f >>> 16) & 0xff);
      } else {
        const f = 15 | (op.byte << 16);
        body.push(f & 0xff, (f >>> 8) & 0xff, (f >>> 16) & 0xff);
        pushU32(op.length);
      }
      produced += op.length;
    }
  }

  while ((cwordVal & 1) !== 1) cwordVal >>>= 1;
  writeU32At(cwordPtrIdx, ((cwordVal >>> 1) | 0x80000000) >>> 0);

  const isLong = plain.length >= 216;
  const hdrLen = isLong ? 9 : 3;
  const total = hdrLen + body.length;
  const out = Buffer.alloc(total);
  if (isLong) {
    out[0] = 0x03;
    out.writeUInt32LE(total, 1);
    out.writeUInt32LE(plain.length, 5);
  } else {
    out[0] = 0x01;
    out[1] = total;
    out[2] = plain.length;
  }
  Buffer.from(body).copy(out, hdrLen);
  return { frame: out, expected: plain };
}

test('QuickLZ uncompressed short & long frames', () => {
  const shortData = Buffer.from('Hello QuickLZ short block!');
  const shortFrame = makeUncompressedQlzFrame(shortData);
  assert.deepEqual(Buffer.from(decompressQlz(shortFrame)), shortData);

  const longData = Buffer.alloc(4096, 0x42);
  longData.write('END_MARKER', 4080);
  const longFrame = makeUncompressedQlzFrame(longData);
  const hdr = parseQlzHeader(longFrame);
  assert.equal(hdr.isLong, true);
  assert.equal(hdr.isCompressed, false);
  assert.deepEqual(Buffer.from(decompressQlz(longFrame)), longData);
});

test('QuickLZ compressed stream with literals, LZ matches, and RLE', () => {
  const { frame, expected } = encodeQlzOps([
    { type: 'lit', data: Buffer.from('ABCDEFGH12345678') },
    { type: 'match', offset: 16, length: 3 },      // short match type 0 (offset <= 63, len 3)
    { type: 'match', offset: 19, length: 10 },     // match type 2 (len <= 18, off <= 1023)
    { type: 'rle', byte: 0x5a, length: 300 },      // RLE 300 bytes of 'Z'
    { type: 'match', offset: 310, length: 25 },    // match type 3 (len <= 34)
    { type: 'lit', data: Buffer.from('TAIL') },    // final 4 literal bytes
  ]);

  const out = decompressQlz(frame);
  assert.deepEqual(Buffer.from(out), expected);
});

test('QuickLZ tiny compressed block (<= 4 bytes)', () => {
  const frame = Buffer.from([0x01, 10, 3, 0x00, 0x00, 0x00, 0x00, 0x41, 0x42, 0x43]);
  assert.deepEqual(Buffer.from(decompressQlz(frame)), Buffer.from('ABC'));
});

test('QuickLZ match type 1 (long offset len=3), type 4 (len>34), and long RLE (>4095)', () => {
  const { frame, expected } = encodeQlzOps([
    { type: 'lit', data: Buffer.from('SEED_PATTERN_XYZ_0123456789_ABCDEFGHIJ') },
    { type: 'rle', byte: 0x33, length: 4200 },       // long RLE (> 4095)
    { type: 'match', offset: 4230, length: 3 },      // type 1 (len=3, offset > 63)
    { type: 'match', offset: 4230, length: 40 },     // type 4 (len > 34)
    { type: 'lit', data: Buffer.from('DONE') },
  ]);

  const out = decompressQlz(frame);
  assert.deepEqual(Buffer.from(out), expected);
});
