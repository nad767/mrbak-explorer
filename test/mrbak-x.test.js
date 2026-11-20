import test from 'node:test';
import assert from 'node:assert/strict';
import fsp from 'node:fs/promises';
import path from 'node:path';
import zlib from 'node:zlib';
import crypto from 'node:crypto';
import { openMrbak } from '../src/container.js';
import { cmdExtract, cmdInfo, cmdLs } from '../src/explorer.js';
import { computeReflectXIv } from '../src/crypto-x.js';
import { buildSyntheticFat32Volume } from './helpers.js';

const TEST_DIR = path.resolve('.test-tmp-x');

function makeMetaBlockHeader(name8, bodyLen, md5, flags) {
  const hdr = Buffer.alloc(32);
  Buffer.from(name8, 'ascii').copy(hdr, 0, 0, 8);
  hdr.writeUInt32LE(bodyLen, 8);
  md5.copy(hdr, 12, 0, 16);
  hdr[28] = flags;
  return hdr;
}

function makeIndexElement(pos, md5, len, fileNo) {
  const el = Buffer.alloc(30);
  el.writeBigInt64LE(BigInt(pos), 0);
  md5.copy(el, 8, 0, 16);
  el.writeUInt32LE(len, 24);
  el.writeUInt16LE(fileNo, 28);
  return el;
}

function buildReflectXMrbak({
  fatVolume,
  password = null,
  aesType = 'aes-256',
  encryptMeta = false,
  blockSize = 65536,
}) {
  const chunks = [];
  let cursor = 0;
  const push = (b) => {
    chunks.push(b);
    cursor += b.length;
  };

  const imageIdHex = '5A0A01ABF8CCC19E';
  const imageIdBytes = Buffer.from(imageIdHex, 'hex');
  const iterations = 10000; // fast for unit tests

  let encCtx = null;
  let encJson = { enable: false, key_iterations: 0 };
  if (password) {
    const keyLen = aesType === 'aes-128' ? 16 : aesType === 'aes-192' ? 24 : 32;
    const salt = crypto.createHash('sha256').update(imageIdBytes).digest();
    const key = crypto.pbkdf2Sync(Buffer.from(password, 'utf8'), salt, iterations, keyLen, 'sha256');
    const hmac = crypto.createHmac('sha256', key).digest('hex');
    const keyHash = crypto.createHash('sha256').update(key).digest();
    encCtx = { key, keyHash, cipher: `${aesType}-cbc`, imageIdBytes };
    encJson = {
      aes_type: aesType,
      enable: true,
      hmac,
      key_derivation: 'pbkdf2',
      key_iterations: iterations,
    };
  }

  const encodePayload = (raw, blockIndex) => {
    let payload = zlib.zstdCompressSync(raw);
    if (encCtx) {
      const iv = computeReflectXIv(encCtx, 0, 0, blockIndex);
      const cipher = crypto.createCipheriv(encCtx.cipher, encCtx.key, iv);
      payload = Buffer.concat([cipher.update(payload), cipher.final()]);
    }
    return payload;
  };

  // Reserved sectors (FAT head)
  const rawHead = fatVolume.disk.subarray(0, fatVolume.headLen);
  const headPayload = encodePayload(rawHead, 0);
  const headPos = cursor;
  push(headPayload);
  const reservedElems = [
    makeIndexElement(
      headPos,
      crypto.createHash('md5').update(rawHead).digest(),
      headPayload.length,
      0
    ),
  ];

  // Data blocks
  const dataRegion = fatVolume.disk.subarray(fatVolume.headLen);
  const blockCount = Math.ceil(dataRegion.length / blockSize);
  const dataElems = [];
  for (let i = 0; i < blockCount; i++) {
    const slice = dataRegion.subarray(i * blockSize, (i + 1) * blockSize);
    const raw = slice.length < blockSize
      ? Buffer.concat([slice, Buffer.alloc(blockSize - slice.length)])
      : slice;
    if (raw.every((b) => b === 0) && i > 0) {
      dataElems.push(makeIndexElement(0, Buffer.alloc(16), 0, 0));
    } else {
      const payload = encodePayload(raw, i);
      const pos = cursor;
      push(payload);
      dataElems.push(
        makeIndexElement(pos, crypto.createHash('md5').update(raw).digest(), payload.length, 0)
      );
    }
  }

  // index_file_position: $TRACK0 + $INDEX
  const indexFilePosition = cursor;
  const track0Body = Buffer.alloc(512);
  push(
    makeMetaBlockHeader(
      '$TRACK0 ',
      track0Body.length,
      crypto.createHash('md5').update(track0Body).digest(),
      0x01 // last_block
    )
  );
  push(track0Body);

  const indexParts = [];
  const rcnt = Buffer.alloc(4);
  rcnt.writeUInt32LE(reservedElems.length, 0);
  indexParts.push(rcnt, ...reservedElems);
  const bcnt = Buffer.alloc(4);
  bcnt.writeUInt32LE(dataElems.length, 0);
  indexParts.push(bcnt, ...dataElems);
  const indexBody = Buffer.concat(indexParts);
  let compIndexBody = zlib.zstdCompressSync(indexBody);
  let idxFlags = 0x03; // last_block | compressed
  if (encryptMeta && encCtx) {
    const iv = computeReflectXIv(encCtx, 0, 0, 0);
    const cipher = crypto.createCipheriv(encCtx.cipher, encCtx.key, iv);
    compIndexBody = Buffer.concat([cipher.update(compIndexBody), cipher.final()]);
    idxFlags |= 0x04;
  }
  push(
    makeMetaBlockHeader(
      '$INDEX  ',
      compIndexBody.length,
      crypto.createHash('md5').update(compIndexBody).digest(),
      idxFlags
    )
  );
  push(compIndexBody);

  // Root metadata: $JSON
  const metaOff = cursor;
  const jsonObj = {
    _auxiliary_data: {
      destination: 'D:\\Backups\\demo-00-00.mrbak',
      macrium_reflect: { major: 10, minor: 0, build: 7919 },
    },
    _compression: { compression_level: 'medium', compression_method: 'zstd' },
    _encryption: encJson,
    _header: {
      backup_format: 'file_and_folder',
      backup_guid: '22e8a84b-6f50-4fde-945f-95593c44a9b9',
      backup_time: 1732100000,
      backup_type: 'full',
      delta_index: false,
      file_number: 0,
      imageid: imageIdHex,
      netbios_name: 'TEST-HOST',
      index_file_position: indexFilePosition,
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

  const jsonComp = zlib.zstdCompressSync(Buffer.from(JSON.stringify(jsonObj), 'utf8'));
  push(
    makeMetaBlockHeader(
      '$JSON   ',
      jsonComp.length,
      crypto.createHash('md5').update(jsonComp).digest(),
      0x03 // last_block | compressed
    )
  );
  push(jsonComp);

  // 20-byte footer
  const footer = Buffer.alloc(20);
  footer.writeBigUInt64LE(BigInt(metaOff), 0);
  Buffer.from('MACRIUM_FILE', 'ascii').copy(footer, 8);
  push(footer);

  return Buffer.concat(chunks);
}

test('Reflect X .mrbak/.mrbakx unencrypted and AES-256 encrypted exploration & verification', async (t) => {
  await fsp.mkdir(TEST_DIR, { recursive: true });
  t.after(async () => {
    await fsp.rm(TEST_DIR, { recursive: true, force: true });
  });

  const fatVol = buildSyntheticFat32Volume([
    { path: '/Photos/vacation-2026.txt', content: 'Sunset photo placeholder' },
    { path: '/secret.txt', content: 'Top secret Reflect X payload!' },
  ]);

  const plainFile = path.join(TEST_DIR, 'plain.mrbak');
  const encFile = path.join(TEST_DIR, 'encrypted.mrbakx');

  await fsp.writeFile(plainFile, buildReflectXMrbak({ fatVolume: fatVol }));
  await fsp.writeFile(
    encFile,
    buildReflectXMrbak({ fatVolume: fatVol, password: 'correct-horse-battery-staple' })
  );

  // Plain Reflect X
  const s1 = await openMrbak(plainFile);
  try {
    const info = await cmdInfo(s1);
    assert.match(info, /Macrium Reflect X/);
    assert.match(info, /zstd \(medium\)/);
    const ls = await cmdLs(s1, '/Photos');
    assert.match(ls, /vacation-2026\.txt/);
    const v = await s1.container.verify();
    assert.equal(v.mismatches, 0);
  } finally {
    await s1.close();
  }

  // Encrypted Reflect X - wrong password fails
  await assert.rejects(
    () => openMrbak(encFile, { password: 'wrong-password' }),
    /Incorrect password/
  );

  // Encrypted Reflect X - right password succeeds
  const s2 = await openMrbak(encFile, { password: 'correct-horse-battery-staple' });
  try {
    const outDir = path.join(TEST_DIR, 'out-enc');
    const res = await cmdExtract(s2, '/secret.txt', outDir, { overwrite: true });
    assert.equal(res.filesExtracted, 1);
    assert.equal(
      await fsp.readFile(path.join(outDir, 'secret.txt'), 'utf8'),
      'Top secret Reflect X payload!'
    );
    const v = await s2.container.verify();
    assert.equal(v.mismatches, 0);
  } finally {
    await s2.close();
  }

  // AES-128 with encrypted $INDEX metadata block
  const enc128File = path.join(TEST_DIR, 'encrypted-128.mrbakx');
  await fsp.writeFile(
    enc128File,
    buildReflectXMrbak({
      fatVolume: fatVol,
      password: 'aes-128-secret',
      aesType: 'aes-128',
      encryptMeta: true,
    })
  );
  const s3 = await openMrbak(enc128File, { password: 'aes-128-secret' });
  try {
    const ls = await cmdLs(s3, '/');
    assert.match(ls, /secret\.txt/);
    const v = await s3.container.verify();
    assert.equal(v.mismatches, 0);
  } finally {
    await s3.close();
  }
});

test('Reflect X delta_index incremental chain with updated FAT head and base backfill', async (t) => {
  await fsp.mkdir(TEST_DIR, { recursive: true });
  t.after(async () => {
    await fsp.rm(TEST_DIR, { recursive: true, force: true });
  });

  const blockSize = 65536;
  // Build base volume: /shared.txt in block 0, /base-only.txt spanning blocks 0, 1, 2
  const baseBody = 'Base content ' + 'B'.repeat(110000);
  const fatBase = buildSyntheticFat32Volume([
    { path: '/shared.txt', content: 'Initial shared version' },
    { path: '/base-only.txt', content: baseBody },
  ]);
  const fullPath = path.join(TEST_DIR, 'chain-00-00.mrbakx');
  await fsp.writeFile(fullPath, buildReflectXMrbak({ fatVolume: fatBase, blockSize }));

  // Build updated volume for incremental (fileNumber 1):
  // /shared.txt updated in block 0, /base-only.txt unchanged in blocks 0..2, /delta-new.txt in block 2
  const fatInc = buildSyntheticFat32Volume([
    { path: '/shared.txt', content: 'Updated shared version in delta!' },
    { path: '/base-only.txt', content: baseBody },
    { path: '/delta-new.txt', content: 'Brand new delta file' },
  ]);

  // Construct delta file (#1) containing updated reserved sectors + block 0 and block 2
  // while omitting unchanged block 1 so it must be backfilled from base file #0
  const chunks = [];
  let cursor = 0;
  const push = (b) => {
    chunks.push(b);
    cursor += b.length;
  };
  const makeDeltaElement = (pos, md5, len, fileNo, blockIndex) => {
    const el = Buffer.alloc(34);
    el.writeBigInt64LE(BigInt(pos), 0);
    md5.copy(el, 8, 0, 16);
    el.writeUInt32LE(len, 24);
    el.writeUInt16LE(fileNo, 28);
    el.writeUInt32LE(blockIndex, 30);
    return el;
  };

  const rawHeadInc = fatInc.disk.subarray(0, fatInc.headLen);
  const compHeadInc = zlib.zstdCompressSync(rawHeadInc);
  const headPos = cursor;
  push(compHeadInc);

  const dataRegionInc = fatInc.disk.subarray(fatInc.headLen);
  const totalBlocks = Math.ceil(dataRegionInc.length / blockSize);
  const deltaDataEls = [];
  for (const bi of [0, 2]) {
    const slice = dataRegionInc.subarray(bi * blockSize, (bi + 1) * blockSize);
    const padded =
      slice.length < blockSize ? Buffer.concat([slice, Buffer.alloc(blockSize - slice.length)]) : slice;
    const comp = zlib.zstdCompressSync(padded);
    const pos = cursor;
    push(comp);
    deltaDataEls.push(
      makeDeltaElement(pos, crypto.createHash('md5').update(padded).digest(), comp.length, 1, bi)
    );
  }

  const indexFilePosition = cursor;
  const track0Body = Buffer.alloc(512);
  push(
    makeMetaBlockHeader(
      '$TRACK0 ',
      track0Body.length,
      crypto.createHash('md5').update(track0Body).digest(),
      0x01
    )
  );
  push(track0Body);

  const rcnt = Buffer.alloc(4);
  rcnt.writeUInt32LE(1, 0);
  const bcnt = Buffer.alloc(4);
  bcnt.writeUInt32LE(deltaDataEls.length, 0);
  const deltaBody = Buffer.concat([
    rcnt,
    makeIndexElement(headPos, crypto.createHash('md5').update(rawHeadInc).digest(), compHeadInc.length, 1),
    bcnt,
    ...deltaDataEls,
  ]);
  const compIdx = zlib.zstdCompressSync(deltaBody);
  push(
    makeMetaBlockHeader(
      '$INDEX  ',
      compIdx.length,
      crypto.createHash('md5').update(compIdx).digest(),
      0x03
    )
  );
  push(compIdx);

  const metaOff = cursor;
  const deltaJson = {
    _compression: { compression_level: 'medium', compression_method: 'zstd' },
    _encryption: { enable: false, key_iterations: 0 },
    _header: {
      backup_format: 'file_and_folder',
      backup_time: 1732103600,
      backup_type: 'incremental',
      delta_index: true,
      file_number: 1,
      imageid: '5A0A01ABF8CCC19E',
      index_file_position: indexFilePosition,
      split_file: false,
    },
    disks: [
      {
        _header: { disk_format: 'mbr', disk_number: 0 },
        partitions: [
          {
            _header: {
              block_count: totalBlocks,
              block_size: blockSize,
              partition_number: 0,
              file_history: [
                { file_number: 0, file_name: 'C:\\Backups\\chain-00-00.mrbakx' },
                { file_number: 1, file_name: 'C:\\Backups\\chain-01-01.mrbakx' },
              ],
            },
            _geometry: { start: 0, length: fatInc.totalLen, boot_sector_offset: 0 },
            _file_system: {
              start: 0,
              lcn0_offset: fatInc.headLen,
              reserved_sectors_byte_length: fatInc.headLen,
            },
          },
        ],
      },
    ],
  };
  const compJson = zlib.zstdCompressSync(Buffer.from(JSON.stringify(deltaJson), 'utf8'));
  push(
    makeMetaBlockHeader(
      '$JSON   ',
      compJson.length,
      crypto.createHash('md5').update(compJson).digest(),
      0x03
    )
  );
  push(compJson);

  const footer = Buffer.alloc(20);
  footer.writeBigUInt64LE(BigInt(metaOff), 0);
  Buffer.from('MACRIUM_FILE', 'ascii').copy(footer, 8);
  push(footer);

  const incPath = path.join(TEST_DIR, 'chain-01-01.mrbakx');
  await fsp.writeFile(incPath, Buffer.concat(chunks));

  const sDelta = await openMrbak(incPath);
  try {
    const ls = await cmdLs(sDelta, '/');
    assert.match(ls, /delta-new\.txt/);
    assert.match(ls, /base-only\.txt/);

    const shared = await sDelta.fat32.resolvePath('/shared.txt');
    assert.equal(
      (await sDelta.fat32.readFileSlice(shared.entry, 0, Infinity)).toString('utf8'),
      'Updated shared version in delta!'
    );

    // Must read middle bytes in block 1 backfilled from base file #0 despite delta having reservedElements
    const baseOnly = await sDelta.fat32.resolvePath('/base-only.txt');
    const baseText = (await sDelta.fat32.readFileSlice(baseOnly.entry, 0, Infinity)).toString('utf8');
    assert.equal(baseText, baseBody);

    const v = await sDelta.container.verify();
    assert.equal(v.mismatches, 0);
  } finally {
    await sDelta.close();
  }

  // Mismatched imageid on an ancestor chain file must be rejected
  const mismatchDir = path.join(TEST_DIR, 'mismatch');
  await fsp.mkdir(mismatchDir, { recursive: true });
  await fsp.copyFile(incPath, path.join(mismatchDir, 'chain-01-01.mrbakx'));
  const mJson = Buffer.from(
    JSON.stringify({
      _header: { backup_format: 'file_and_folder', file_number: 0, imageid: 'FFFFFFFFFFFFFFFF' },
      disks: [{ _header: { disk_number: 0 }, partitions: [] }],
    }),
    'utf8'
  );
  const mHdr = makeMetaBlockHeader('$JSON   ', mJson.length, crypto.createHash('md5').update(mJson).digest(), 0x01);
  const mFooter = Buffer.alloc(20);
  mFooter.writeBigUInt64LE(1n, 0);
  Buffer.from('MACRIUM_FILE', 'ascii').copy(mFooter, 8);
  await fsp.writeFile(
    path.join(mismatchDir, 'chain-00-00.mrbakx'),
    Buffer.concat([Buffer.from([0]), mHdr, mJson, mFooter])
  );
  await assert.rejects(() => openMrbak(path.join(mismatchDir, 'chain-01-01.mrbakx')), /mismatched image ID/);
});
