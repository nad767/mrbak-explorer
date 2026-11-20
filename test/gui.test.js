import test from 'node:test';
import assert from 'node:assert/strict';
import fsp from 'node:fs/promises';
import path from 'node:path';
import zlib from 'node:zlib';
import crypto from 'node:crypto';
import { startGuiServer } from '../src/gui-server.js';
import { buildSyntheticFat32Volume } from './helpers.js';

const TEST_DIR = path.resolve('.test-tmp-gui');

function buildSimpleMrbakx(fatVolume) {
  const chunks = [];
  let cursor = 0;
  const push = (b) => {
    chunks.push(b);
    cursor += b.length;
  };
  const metaHdr = (name8, len, md5, flags) => {
    const h = Buffer.alloc(32);
    Buffer.from(name8, 'ascii').copy(h, 0, 0, 8);
    h.writeUInt32LE(len, 8);
    md5.copy(h, 12, 0, 16);
    h[28] = flags;
    return h;
  };
  const idxEl = (pos, md5, len) => {
    const e = Buffer.alloc(30);
    e.writeBigUInt64LE(BigInt(pos), 0);
    md5.copy(e, 8, 0, 16);
    e.writeUInt32LE(len, 24);
    e.writeUInt16LE(0, 28);
    return e;
  };

  const rawHead = fatVolume.disk.subarray(0, fatVolume.headLen);
  const compHead = zlib.zstdCompressSync(rawHead);
  const headPos = cursor;
  push(compHead);

  const blockSize = 65536;
  const dataRegion = fatVolume.disk.subarray(fatVolume.headLen);
  const blockCount = Math.ceil(dataRegion.length / blockSize);
  const dataEls = [];
  for (let i = 0; i < blockCount; i++) {
    const raw = dataRegion.subarray(i * blockSize, (i + 1) * blockSize);
    const padded = raw.length < blockSize ? Buffer.concat([raw, Buffer.alloc(blockSize - raw.length)]) : raw;
    const comp = zlib.zstdCompressSync(padded);
    const pos = cursor;
    push(comp);
    dataEls.push(idxEl(pos, crypto.createHash('md5').update(padded).digest(), comp.length));
  }

  const indexFilePos = cursor;
  const track0 = Buffer.alloc(512);
  push(metaHdr('$TRACK0 ', track0.length, crypto.createHash('md5').update(track0).digest(), 0x01));
  push(track0);

  const rc = Buffer.alloc(4);
  rc.writeUInt32LE(1, 0);
  const bc = Buffer.alloc(4);
  bc.writeUInt32LE(dataEls.length, 0);
  const idxBody = Buffer.concat([
    rc,
    idxEl(headPos, crypto.createHash('md5').update(rawHead).digest(), compHead.length),
    bc,
    ...dataEls,
  ]);
  const compIdx = zlib.zstdCompressSync(idxBody);
  push(metaHdr('$INDEX  ', compIdx.length, crypto.createHash('md5').update(compIdx).digest(), 0x03));
  push(compIdx);

  const metaOff = cursor;
  const json = {
    _compression: { compression_level: 'medium', compression_method: 'zstd' },
    _encryption: { enable: false, key_iterations: 0 },
    _header: {
      backup_format: 'file_and_folder',
      backup_time: 1732100000,
      backup_type: 'full',
      delta_index: false,
      file_number: 0,
      imageid: '1122334455667788',
      index_file_position: indexFilePos,
      split_file: false,
    },
    disks: [
      {
        _header: { disk_format: 'mbr', disk_number: 0 },
        partitions: [
          {
            _header: { block_count: blockCount, block_size: blockSize, partition_number: 0 },
            _geometry: { start: 0, length: fatVolume.totalLen, boot_sector_offset: 0 },
            _file_system: {
              start: 0,
              lcn0_offset: fatVolume.headLen,
              reserved_sectors_byte_length: fatVolume.headLen,
            },
          },
        ],
      },
    ],
  };
  const compJson = zlib.zstdCompressSync(Buffer.from(JSON.stringify(json), 'utf8'));
  push(metaHdr('$JSON   ', compJson.length, crypto.createHash('md5').update(compJson).digest(), 0x03));
  push(compJson);

  const footer = Buffer.alloc(20);
  footer.writeBigUInt64LE(BigInt(metaOff), 0);
  Buffer.from('MACRIUM_FILE', 'ascii').copy(footer, 8);
  push(footer);
  return Buffer.concat(chunks);
}

test('GUI HTTP server serves HTML and API endpoints for browsing, previewing, downloading, and verifying', async (t) => {
  await fsp.mkdir(TEST_DIR, { recursive: true });
  t.after(async () => {
    await fsp.rm(TEST_DIR, { recursive: true, force: true });
  });

  const fat = buildSyntheticFat32Volume([
    { path: '/Docs/readme.txt', content: 'Hello GUI Explorer!' },
    { path: '/Docs/résumé-日本語.txt', content: 'Unicode filename!' },
    { path: '/bin/data.bin', content: Buffer.from([0x00, 0x01, 0x02, 0x03, 0xff]) },
  ]);
  const arcPath = path.join(TEST_DIR, 'gui.mrbakx');
  await fsp.writeFile(arcPath, buildSimpleMrbakx(fat));

  const gui = await startGuiServer();
  t.after(async () => {
    await gui.close();
  });

  const htmlRes = await fetch(`${gui.url}/`);
  assert.equal(htmlRes.status, 200);
  const html = await htmlRes.text();
  assert.match(html, /mrbak-explorer/);

  const openRes = await fetch(`${gui.url}/api/open`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ filePath: arcPath }),
  });
  assert.equal(openRes.status, 200);
  const openJson = await openRes.json();
  assert.equal(openJson.open, true);
  assert.equal(openJson.info.imageId, '1122334455667788');

  const lsRes = await fetch(`${gui.url}/api/ls?path=/Docs`);
  const lsJson = await lsRes.json();
  assert.equal(lsJson.entries.length, 2);
  assert.equal(lsJson.entries[0].name, 'readme.txt');
  assert.equal(lsJson.entries[1].name, 'résumé-日本語.txt');

  const prevRes = await fetch(`${gui.url}/api/preview?path=/Docs/readme.txt`);
  const prevJson = await prevRes.json();
  assert.equal(prevJson.kind, 'text');
  assert.equal(prevJson.text, 'Hello GUI Explorer!');

  const binPrevRes = await fetch(`${gui.url}/api/preview?path=/bin/data.bin`);
  const binPrevJson = await binPrevRes.json();
  assert.equal(binPrevJson.kind, 'binary');
  assert.match(binPrevJson.hex, /00 01 02 03 ff/);

  const dlRes = await fetch(`${gui.url}/api/download?path=/Docs/readme.txt`);
  assert.equal(dlRes.headers.get('x-content-type-options'), 'nosniff');
  assert.equal(await dlRes.text(), 'Hello GUI Explorer!');

  const unicodeDlRes = await fetch(`${gui.url}/api/download?path=${encodeURIComponent('/Docs/résumé-日本語.txt')}`);
  assert.equal(unicodeDlRes.status, 200);
  assert.match(unicodeDlRes.headers.get('content-disposition'), /filename\*=UTF-8''/);
  assert.equal(await unicodeDlRes.text(), 'Unicode filename!');

  const findRes = await fetch(`${gui.url}/api/find?q=*.txt`);
  const findJson = await findRes.json();
  assert.equal(findJson.matches.length, 2);
  assert.ok(findJson.matches.some((m) => m.path === '/Docs/readme.txt'));
  assert.ok(findJson.matches.some((m) => m.path === '/Docs/résumé-日本語.txt'));

  const verifyRes = await fetch(`${gui.url}/api/verify`, { method: 'POST' });
  const verifyJson = await verifyRes.json();
  assert.equal(verifyJson.mismatches, 0);

  const outDir = path.join(TEST_DIR, 'extracted');
  const extRes = await fetch(`${gui.url}/api/extract`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ innerPath: '/Docs', outDir, overwrite: true }),
  });
  const extJson = await extRes.json();
  assert.equal(extJson.filesExtracted, 2);
  assert.equal(
    await fsp.readFile(path.join(outDir, 'Docs', 'readme.txt'), 'utf8'),
    'Hello GUI Explorer!'
  );
  assert.equal(
    await fsp.readFile(path.join(outDir, 'Docs', 'résumé-日本語.txt'), 'utf8'),
    'Unicode filename!'
  );

  // Security checks: Host, Origin, Sec-Fetch-Site, and Content-Type guards
  const stateRes = await fetch(`${gui.url}/api/state`);
  const stateJson = await stateRes.json();
  assert.equal(stateJson.platform, process.platform);

  const crossOriginRes = await fetch(`${gui.url}/api/extract`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Origin: 'https://evil.example',
    },
    body: JSON.stringify({ innerPath: '/', outDir }),
  });
  assert.equal(crossOriginRes.status, 403);

  const crossSiteRes = await fetch(`${gui.url}/api/verify`, {
    method: 'POST',
    headers: { 'Sec-Fetch-Site': 'cross-site' },
  });
  assert.equal(crossSiteRes.status, 403);

  const badCtRes = await fetch(`${gui.url}/api/open`, {
    method: 'POST',
    headers: { 'Content-Type': 'text/plain' },
    body: JSON.stringify({ filePath: arcPath }),
  });
  assert.equal(badCtRes.status, 415);
});
