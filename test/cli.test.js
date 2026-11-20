import test from 'node:test';
import assert from 'node:assert/strict';
import fsp from 'node:fs/promises';
import path from 'node:path';
import zlib from 'node:zlib';
import crypto from 'node:crypto';
import { execFile, spawn } from 'node:child_process';
import { promisify } from 'node:util';
import { buildSyntheticFat32Volume } from './helpers.js';

const execFileAsync = promisify(execFile);
const CLI_PATH = path.resolve('bin/mrbak.js');
const TEST_DIR = path.resolve('.test-tmp-cli');

function makeSimpleReflectX(fatVolume) {
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
    e.writeBigInt64LE(BigInt(pos), 0);
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
      imageid: 'AABBCCDDEEFF0011',
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

test('CLI subcommands and interactive shell end-to-end', async (t) => {
  await fsp.mkdir(TEST_DIR, { recursive: true });
  t.after(async () => {
    await fsp.rm(TEST_DIR, { recursive: true, force: true });
  });

  const fat = buildSyntheticFat32Volume([
    { path: '/hello.txt', content: 'CLI Hello World\n' },
    { path: '/sub/data.csv', content: 'id,name\n1,alpha\n' },
  ]);
  const arcPath = path.join(TEST_DIR, 'sample.mrbakx');
  await fsp.writeFile(arcPath, makeSimpleReflectX(fat));

  const infoRes = await execFileAsync(process.execPath, [CLI_PATH, '--info', arcPath, '--json']);
  const infoJson = JSON.parse(infoRes.stdout);
  assert.equal(infoJson.imageId, 'AABBCCDDEEFF0011');

  const lsRes = await execFileAsync(process.execPath, [CLI_PATH, '--ls', arcPath, '/sub', '-la']);
  assert.match(lsRes.stdout, /data\.csv/);

  const catRes = await execFileAsync(process.execPath, [CLI_PATH, '--cat', arcPath, '/sub/data.csv']);
  assert.equal(catRes.stdout, 'id,name\n1,alpha\n');

  const verifyRes = await execFileAsync(process.execPath, [CLI_PATH, '--verify', arcPath]);
  assert.match(verifyRes.stdout, /Mismatches: 0/);

  const verRes = await execFileAsync(process.execPath, [CLI_PATH, '--version']);
  assert.match(verRes.stdout, /^mrbak-explorer v\d+\.\d+\.\d+/);

  const treeRes = await execFileAsync(process.execPath, [CLI_PATH, '--tree', arcPath, '-d', '2']);
  assert.match(treeRes.stdout, /data\.csv/);

  const findRes = await execFileAsync(process.execPath, [CLI_PATH, '--find', arcPath, '*.csv', '-t', 'f']);
  assert.match(findRes.stdout, /\/sub\/data\.csv/);

  const statRes = await execFileAsync(process.execPath, [CLI_PATH, '--stat', arcPath, '/sub/data.csv', '--json']);
  const statJson = JSON.parse(statRes.stdout);
  assert.equal(statJson.type, 'file');

  const metaRes = await execFileAsync(process.execPath, [CLI_PATH, '--metadata', arcPath]);
  assert.match(metaRes.stdout, /AABBCCDDEEFF0011/);

  const tailRes = await execFileAsync(process.execPath, [CLI_PATH, '--cat', arcPath, '/sub/data.csv', '--tail', '6']);
  assert.equal(tailRes.stdout, 'alpha\n');

  const outDir = path.join(TEST_DIR, 'cli-extracted');
  await execFileAsync(process.execPath, [CLI_PATH, '--extract', arcPath, '/sub', '-o', outDir]);
  assert.equal(await fsp.readFile(path.join(outDir, 'sub', 'data.csv'), 'utf8'), 'id,name\n1,alpha\n');

  await assert.rejects(
    () => execFileAsync(process.execPath, [CLI_PATH, '--cat', arcPath, '/sub/data.csv', '--offset', '1', '--tail', '2']),
    /Cannot combine --tail/
  );

  await assert.rejects(
    () => execFileAsync(process.execPath, [CLI_PATH, '--gui', '--port', '1.5']),
    /Invalid integer value/
  );

  await assert.rejects(
    () => execFileAsync(process.execPath, [CLI_PATH, '--gui', '--info', arcPath]),
    /Conflicting mode flags/
  );

  // Interactive shell test via stdin
  const shellRes = await new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [CLI_PATH, arcPath], { stdio: ['pipe', 'pipe', 'pipe'] });
    let out = '';
    let err = '';
    child.stdout.on('data', (d) => (out += d.toString('utf8')));
    child.stderr.on('data', (d) => (err += d.toString('utf8')));
    child.on('error', reject);
    child.on('close', (code) => {
      if (code !== 0) reject(new Error(`Shell exited with ${code}: ${err}`));
      else resolve({ out, err });
    });
    child.stdin.write('cd /sub\npwd\nls -l\ncat data.csv\nfind -t f\nexit\n');
    child.stdin.end();
  });

  assert.match(shellRes.out, /\/sub/);
  assert.match(shellRes.out, /data\.csv/);
  assert.match(shellRes.out, /1,alpha/);
  assert.match(shellRes.err, /Usage: find <pattern>/);
});
