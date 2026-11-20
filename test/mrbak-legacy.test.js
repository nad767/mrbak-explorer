import test from 'node:test';
import assert from 'node:assert/strict';
import fsp from 'node:fs/promises';
import path from 'node:path';
import crypto from 'node:crypto';
import { openMrbak } from '../src/container.js';
import { cmdExtract, cmdFind, cmdInfo, cmdLs, cmdTree } from '../src/explorer.js';
import { buildSyntheticFat32Volume } from './helpers.js';

const TEST_DIR = path.resolve('.test-tmp-legacy');
const TRAILER_MAGIC = Buffer.from('__79241006_2651_11D4_', 'ascii');

function makeQlzUncompressedBlock(buf) {
  const out = Buffer.alloc(9 + buf.length);
  out[0] = 0x02; // long header, uncompressed flag
  out.writeUInt32LE(out.length, 1);
  out.writeUInt32LE(buf.length, 5);
  buf.copy(out, 9);
  return out;
}

function buildLegacyMrbakFile({
  origPath,
  imageId = Buffer.from('0123456789abcdef', 'hex'),
  fileNo = 0,
  blockSize = 65536,
  fatVolume,
  deltaBlocks = null, // Map<blockIdx, Buffer>
  deltaFatVolume = null,
  ancestorPath = null,
  encryptedTag = null,
}) {
  const chunks = [];
  let cursor = 0;
  const push = (buf) => {
    chunks.push(buf);
    cursor += buf.length;
  };

  const records = [];
  if (!deltaBlocks) {
    const dataRegion = fatVolume.disk.subarray(fatVolume.headLen);
    const blockCount = Math.ceil(dataRegion.length / blockSize);
    for (let i = 0; i < blockCount; i++) {
      const slice = dataRegion.subarray(i * blockSize, (i + 1) * blockSize);
      const raw = slice.length < blockSize
        ? Buffer.concat([slice, Buffer.alloc(blockSize - slice.length)])
        : slice;
      const isZero = raw.every((b) => b === 0);
      if (isZero && i > 0 && i < blockCount - 1) {
        records.push({ fo: 0n, md5: Buffer.alloc(16) });
      } else {
        const fo = BigInt(cursor);
        const compressedFrame = makeQlzUncompressedBlock(raw);
        const md5 = crypto.createHash('md5').update(raw).digest();
        push(compressedFrame);
        records.push({ fo, md5 });
      }
    }
    // Raw FAT head immediately after last data block, ending at metaOff
    push(fatVolume.disk.subarray(0, fatVolume.headLen));
  } else {
    for (const [bn, raw] of deltaBlocks.entries()) {
      const fo = BigInt(cursor);
      const compressedFrame = makeQlzUncompressedBlock(raw);
      const md5 = crypto.createHash('md5').update(raw).digest();
      push(compressedFrame);
      records.push({ bn, fo, md5 });
    }
    if (deltaFatVolume) {
      push(deltaFatVolume.disk.subarray(0, deltaFatVolume.headLen));
    }
  }

  const metaOff = BigInt(cursor);
  const pathBuf = Buffer.from(origPath, 'utf8');
  const encXml = encryptedTag ? `<encryption>${encryptedTag}</encryption>` : '';
  const xml = `<?xml version="1.0" encoding="UTF-8"?><backup_definition><backup_type>1</backup_type><compression>1</compression>${encXml}<comment>Synthetic legacy test</comment></backup_definition>`;
  const xmlBuf = Buffer.from(xml, 'utf8');

  // Header
  const hdr = Buffer.alloc(13 + pathBuf.length);
  imageId.copy(hdr, 0, 0, 8);
  hdr.writeUInt16LE(deltaBlocks ? 1 : 0, 8);
  hdr.writeUInt16LE(fileNo, 10);
  hdr[12] = pathBuf.length;
  pathBuf.copy(hdr, 13);
  push(hdr);

  // XML length (u16) + XML + u32 timestamp
  const xmlLenBuf = Buffer.alloc(2);
  xmlLenBuf.writeUInt16LE(xmlBuf.length, 0);
  push(xmlLenBuf);
  push(xmlBuf);

  const tsBuf = Buffer.alloc(4);
  tsBuf.writeUInt32LE(1732100000, 0);
  push(tsBuf);

  if (deltaBlocks) {
    // Chain head: blockSize(4) + numChainFiles(4) + 0(2) + ancestor [u8 len][path][03 00 00 00][u16 fileNo]
    const chHead = Buffer.alloc(10);
    chHead.writeUInt32LE(blockSize, 0);
    chHead.writeUInt32LE(2, 4);
    push(chHead);
    const ancBuf = Buffer.from(ancestorPath, 'ascii');
    const ancEntry = Buffer.alloc(1 + ancBuf.length + 6);
    ancEntry[0] = ancBuf.length;
    ancBuf.copy(ancEntry, 1);
    ancEntry.writeUInt32LE(3, 1 + ancBuf.length);
    ancEntry.writeUInt16LE(0, 1 + ancBuf.length + 4);
    push(ancEntry);
  }

  // Partition marker: [u8 pathLen][path][36 bytes tail]
  const marker = Buffer.alloc(1 + pathBuf.length + 36);
  marker[0] = pathBuf.length;
  pathBuf.copy(marker, 1);
  push(marker);

  if (!deltaBlocks) {
    for (let i = 0; i < records.length; i++) {
      const rec = Buffer.alloc(30);
      rec.writeUInt16LE(0, 0);
      rec.writeUInt32LE(i === 0 ? records.length : i, 2);
      rec.writeBigUInt64LE(records[i].fo, 6);
      records[i].md5.copy(rec, 14);
      push(rec);
    }
  } else {
    for (let i = 0; i < records.length; i++) {
      const rec = Buffer.alloc(34);
      rec.writeUInt16LE(fileNo, 0);
      rec.writeUInt32LE(i === 0 ? records.length : records[i].bn - 1, 2);
      rec.writeBigUInt64LE(records[i].fo, 6);
      records[i].md5.copy(rec, 14);
      push(rec);
    }
  }

  // TailPtr (14 bytes) + Trailer (40 bytes)
  const tailPtr = Buffer.alloc(14);
  tailPtr.writeBigUInt64LE(metaOff, 6);
  push(tailPtr);

  const trailer = Buffer.alloc(40);
  TRAILER_MAGIC.copy(trailer, 0);
  trailer[TRAILER_MAGIC.length] = 0;
  trailer.writeUInt16LE(7, TRAILER_MAGIC.length + 1);
  push(trailer);

  return Buffer.concat(chunks);
}

test('Legacy .mrbak full + incremental chain browsing, verification, and extraction', async (t) => {
  await fsp.mkdir(TEST_DIR, { recursive: true });
  t.after(async () => {
    await fsp.rm(TEST_DIR, { recursive: true, force: true });
  });

  const fatVol = buildSyntheticFat32Volume([
    { path: '/notes.txt', content: 'Initial backup note\nLine 2\n' },
    { path: '/Projects/app.json', content: '{"ok":true,"version":1}' },
  ]);

  const fullPath = path.join(TEST_DIR, 'backup-00-00.mrbak');
  const incPath = path.join(TEST_DIR, 'backup-01-01.mrbak');

  await fsp.writeFile(
    fullPath,
    buildLegacyMrbakFile({ origPath: 'C:\\Backups\\backup-00-00.mrbak', fatVolume: fatVol })
  );

  // Open full .mrbak and test commands
  const session = await openMrbak(fullPath);
  try {
    const infoText = await cmdInfo(session);
    assert.match(infoText, /Reflect v7\/v8 Legacy/);
    assert.match(infoText, /QuickLZ 1\.31/);

    const lsRoot = await cmdLs(session, '/');
    assert.match(lsRoot, /Projects\//);
    assert.match(lsRoot, /notes\.txt/);

    const treeOut = await cmdTree(session, '/');
    assert.match(treeOut, /app\.json/);

    const findOut = await cmdFind(session, '*.json');
    assert.match(findOut, /\/Projects\/app\.json/);

    const verifyRes = await session.container.verify();
    assert.equal(verifyRes.mismatches, 0);
    assert.ok(verifyRes.checked > 0);

    const extractDir = path.join(TEST_DIR, 'out-full');
    const ex = await cmdExtract(session, '/', extractDir, { overwrite: true });
    assert.equal(ex.filesExtracted, 2);
    const extractedJson = await fsp.readFile(path.join(extractDir, 'Projects', 'app.json'), 'utf8');
    assert.equal(extractedJson, '{"ok":true,"version":1}');
  } finally {
    await session.close();
  }

  // Build an incremental .mrbak updating block 0 with modified data
  const blockSize = 65536;
  const origBlock0 = Buffer.alloc(blockSize);
  fatVol.disk.subarray(fatVol.headLen, fatVol.headLen + blockSize).copy(origBlock0);
  const patchedText = Buffer.from('Updated incremental!\n');
  // Replace 'Initial backup note\n' inside block 0
  const idx = origBlock0.indexOf('Initial backup note\n');
  assert.ok(idx >= 0);
  patchedText.copy(origBlock0, idx);

  const deltaMap = new Map([[0, origBlock0]]);
  await fsp.writeFile(
    incPath,
    buildLegacyMrbakFile({
      origPath: 'C:\\Backups\\backup-01-01.mrbak',
      fileNo: 1,
      blockSize,
      deltaBlocks: deltaMap,
      ancestorPath: 'C:\\Backups\\backup-00-00.mrbak',
    })
  );

  const incSession = await openMrbak(incPath);
  try {
    const incInfo = incSession.container.getInfo();
    assert.equal(incInfo.chainFiles.length, 2);
    const { entry } = await incSession.fat32.resolvePath('/notes.txt');
    const content = (await incSession.fat32.readFileSlice(entry, 0, Infinity)).toString('utf8');
    assert.match(content, /Updated incremental!/);
  } finally {
    await incSession.close();
  }

  // Delta with zero-MD5 placeholder at record 0 should NOT clobber base block 0
  const zeroPlaceholderPath = path.join(TEST_DIR, 'backup-02-02.mrbak');
  const buf0 = buildLegacyMrbakFile({
    origPath: 'C:\\Backups\\backup-02-02.mrbak',
    fileNo: 2,
    blockSize,
    deltaBlocks: new Map([[0, Buffer.alloc(blockSize)]]),
    ancestorPath: 'C:\\Backups\\backup-00-00.mrbak',
  });
  // Zero out record 0's fileOffset & MD5 in the delta index so it represents an unchanged block 0
  const metaOff2 = Number(buf0.readBigUInt64LE(buf0.length - 40 - 8));
  const pathBytes2 = Buffer.from('C:\\Backups\\backup-02-02.mrbak', 'utf8');
  const firstMarker = buf0.indexOf(pathBytes2, metaOff2 + 13 + pathBytes2.length);
  const rec0Off = firstMarker + pathBytes2.length + 36;
  buf0.writeBigUInt64LE(0n, rec0Off + 6);
  buf0.fill(0, rec0Off + 14, rec0Off + 30);
  await fsp.writeFile(zeroPlaceholderPath, buf0);

  const sPlaceholder = await openMrbak(zeroPlaceholderPath);
  try {
    const { entry } = await sPlaceholder.fat32.resolvePath('/notes.txt');
    const content = (await sPlaceholder.fat32.readFileSlice(entry, 0, Infinity)).toString('utf8');
    assert.match(content, /Initial backup note/);
  } finally {
    await sPlaceholder.close();
  }

  // Corrupt QuickLZ header in verify() should report mismatch/error cleanly rather than allocating huge buffer
  const corruptPath = path.join(TEST_DIR, 'corrupt.mrbak');
  const corruptBuf = await fsp.readFile(fullPath);
  corruptBuf.writeUInt32LE(0x7fffffff, 1); // corrupt compressedSize on block 0
  await fsp.writeFile(corruptPath, corruptBuf);
  const sCorrupt = await openMrbak(corruptPath);
  try {
    const res = await sCorrupt.container.verify();
    assert.ok(res.mismatches > 0);
    assert.match(res.errors[0], /Invalid QuickLZ compressed block size/);
  } finally {
    await sCorrupt.close();
  }

  // Legacy incremental with updated FAT head and newly added file
  const fatUpdated = buildSyntheticFat32Volume([
    { path: '/notes.txt', content: 'Initial backup note\nLine 2\n' },
    { path: '/Projects/app.json', content: '{"ok":true,"version":1}' },
    { path: '/added-in-inc.txt', content: 'Added via incremental FAT head!' },
  ]);
  const updatedBlock0 = Buffer.alloc(blockSize);
  fatUpdated.disk.subarray(fatUpdated.headLen, fatUpdated.headLen + blockSize).copy(updatedBlock0);
  const incWithFatPath = path.join(TEST_DIR, 'backup-03-03.mrbak');
  await fsp.writeFile(
    incWithFatPath,
    buildLegacyMrbakFile({
      origPath: 'C:\\Backups\\backup-03-03.mrbak',
      fileNo: 3,
      blockSize,
      deltaBlocks: new Map([[0, updatedBlock0]]),
      deltaFatVolume: fatUpdated,
      ancestorPath: 'C:\\Backups\\backup-00-00.mrbak',
    })
  );
  const sIncFat = await openMrbak(incWithFatPath);
  try {
    const { entry } = await sIncFat.fat32.resolvePath('/added-in-inc.txt');
    const txt = (await sIncFat.fat32.readFileSlice(entry, 0, Infinity)).toString('utf8');
    assert.equal(txt, 'Added via incremental FAT head!');
  } finally {
    await sIncFat.close();
  }

  // Encrypted legacy .mrbak is detected and rejected with an explicit unsupported error
  const encLegacyPath = path.join(TEST_DIR, 'encrypted-legacy.mrbak');
  await fsp.writeFile(
    encLegacyPath,
    buildLegacyMrbakFile({
      origPath: 'C:\\Backups\\encrypted-legacy.mrbak',
      fatVolume: fatVol,
      encryptedTag: '1',
    })
  );
  await assert.rejects(() => openMrbak(encLegacyPath), /proprietary undocumented encryption scheme/);
});
