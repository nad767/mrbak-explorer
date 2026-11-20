import test from 'node:test';
import assert from 'node:assert/strict';
import { Writable } from 'node:stream';
import { Fat32Volume } from '../src/fat32.js';
import { cmdCat, cmdFind, cmdLs, cmdTree } from '../src/explorer.js';
import { buildSyntheticFat32Volume } from './helpers.js';

test('Fat32Volume parses 4096-byte sector virtual drive, LFNs, nested dirs, and multi-cluster files', async () => {
  const bigText = Buffer.from('A'.repeat(20000) + 'MARKER_END');
  const synth = buildSyntheticFat32Volume([
    { path: '/readme.txt', content: 'Hello from virtual drive!' },
    { path: '/Documents/Quarterly Report (Final).txt', content: bigText },
    { path: '/Documents/empty.bin', content: Buffer.alloc(0) },
  ]);

  const fat = new Fat32Volume({
    size: synth.disk.length,
    async readAt(offset, length) {
      return synth.disk.subarray(offset, offset + length);
    },
  });

  const bpb = await fat.init();
  assert.equal(bpb.bytesPerSector, 4096);
  assert.equal(bpb.clusterSize, 8192);

  const root = await fat.readDirectory(bpb.rootCluster);
  assert.equal(root.length, 2);
  assert.equal(root[0].name, 'Documents');
  assert.equal(root[0].isDirectory, true);
  assert.equal(root[1].name, 'readme.txt');

  const resolved = await fat.resolvePath('/documents/quarterly report (final).txt');
  assert.equal(resolved.entry.size, bigText.length);

  const readBack = await fat.readFileSlice(resolved.entry, 0, Infinity);
  assert.deepEqual(readBack, bigText);

  const slice = await fat.readFileSlice(resolved.entry, 19995, 15);
  assert.equal(slice.toString('utf8'), 'AAAAAMARKER_END');
});

test('Fat32Volume enforces bounded LRU dirCache/fatCache and detects cluster loops', async () => {
  const synth = buildSyntheticFat32Volume([{ path: '/a.txt', content: 'ok' }]);
  const fat = new Fat32Volume({
    size: synth.disk.length,
    async readAt(offset, length) {
      return synth.disk.subarray(offset, offset + length);
    },
  });
  await fat.init();

  fat.maxDirCacheEntries = 2;
  fat.dirCache.set(10, []);
  fat.dirCache.set(11, []);
  await fat.readDirectory(fat.bpb.rootCluster);
  assert.equal(fat.dirCache.size, 2);
  assert.equal(fat.dirCache.has(10), false);
  assert.equal(fat.dirCache.has(fat.bpb.rootCluster), true);

  // Corrupt FAT entry 2 -> 2 to trigger cluster loop detection
  const fat1Off = fat.bpb.fatStartByte;
  synth.disk.writeUInt32LE(2, fat1Off + 2 * 4);
  fat.fatCache.clear();
  await assert.rejects(() => fat.getClusterChain(2), /cluster loop detected/);
});

test('Fat32Volume rejects incomplete sparse LFN entries and streams zero-cluster files in chunks', async () => {
  const synth = buildSyntheticFat32Volume([
    { path: '/very-long-filename-for-sparse-lfn-check.txt', content: 'ok' },
  ]);
  const fat = new Fat32Volume({
    size: synth.disk.length,
    async readAt(offset, length) {
      return synth.disk.subarray(offset, offset + length);
    },
  });
  await fat.init();

  // Mark the middle LFN entry (seq 2 of 4 -> second 32-byte slot in root cluster) as deleted (0xE5)
  const rootOff = fat.clusterToByteOffset(fat.bpb.rootCluster);
  synth.disk[rootOff + 32] = 0xe5;

  const entries = await fat.readDirectory(fat.bpb.rootCluster);
  assert.equal(entries.length, 1);
  // Should fall back to short 8.3 name instead of concatenating sparse LFN slots
  assert.equal(entries[0].name, entries[0].shortName);

  // Stream a synthetic zero-cluster file larger than 64 KiB
  const chunks = [];
  await fat.streamFile(
    { name: 'sparse.bin', isDirectory: false, startCluster: 0, size: 100000 },
    (chunk) => chunks.push(Buffer.from(chunk))
  );
  const combined = Buffer.concat(chunks);
  assert.equal(combined.length, 100000);
  assert.ok(chunks.length >= 2);
  assert.ok(combined.every((b) => b === 0));
});

test('Recursive walkers guard against directory cycles and cmdCat respects stream backpressure', async () => {
  const payload = Buffer.alloc(150000, 0x58);
  const synth = buildSyntheticFat32Volume([
    { path: '/loopdir/file.txt', content: 'inside loopdir' },
    { path: '/big.bin', content: payload },
  ]);
  const fat = new Fat32Volume({
    size: synth.disk.length,
    async readAt(offset, length) {
      return synth.disk.subarray(offset, offset + length);
    },
  });
  await fat.init();

  // Point /loopdir's startCluster back to rootCluster (2) in its parent directory entry
  const rootOff = fat.clusterToByteOffset(fat.bpb.rootCluster);
  for (let off = rootOff; off + 32 <= rootOff + fat.bpb.clusterSize; off += 32) {
    if (synth.disk[off] === 0x00) break;
    if ((synth.disk[off + 11] & 0x10) !== 0) {
      synth.disk.writeUInt16LE(0, off + 20);
      synth.disk.writeUInt16LE(2, off + 26);
      break;
    }
  }
  fat.dirCache.clear();

  const session = { fat32: fat };
  const lsOut = await cmdLs(session, '/', { recursive: true });
  assert.match(lsOut, /\/loopdir\//);
  const treeOut = await cmdTree(session, '/');
  assert.match(treeOut, /loopdir\//);
  const findOut = await cmdFind(session, '*.bin');
  assert.match(findOut, /\/big\.bin/);

  // Slow writable with small highWaterMark forces write() === false and tests drain handling
  const received = [];
  const slowStream = new Writable({
    highWaterMark: 1024,
    write(chunk, _enc, cb) {
      received.push(Buffer.from(chunk));
      setTimeout(cb, 2);
    },
  });
  await cmdCat(session, '/big.bin', { writeStream: slowStream });
  assert.equal(Buffer.concat(received).length, payload.length);
});
