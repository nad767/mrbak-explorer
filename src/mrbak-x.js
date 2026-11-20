import fs from 'node:fs/promises';
import path from 'node:path';
import zlib from 'node:zlib';
import crypto from 'node:crypto';
import { initReflectXCrypto, decryptReflectXBlock } from './crypto-x.js';

const MAGIC_X = Buffer.from('MACRIUM_FILE', 'ascii');
const K_FOOTER_SIZE = 20; // u64 metaOff + 12-byte magic
const K_BLOCK_HDR_SIZE = 32;
const K_INDEX_ELEM_SIZE = 30;
const K_DELTA_ELEM_SIZE = 34;

const FLAG_LAST = 1;
const FLAG_COMPRESSED = 2;
const FLAG_ENCRYPTED = 4;

function decompressZstd(buf) {
  if (typeof zlib.zstdDecompressSync !== 'function') {
    throw new Error(
      `Zstandard decompression requires Node.js >= 22.15.0 (current: ${process.version})`
    );
  }
  return zlib.zstdDecompressSync(buf);
}

async function readExact(fh, offset, length) {
  const buf = Buffer.allocUnsafe(length);
  let total = 0;
  while (total < length) {
    const { bytesRead } = await fh.read(buf, total, length - total, offset + total);
    if (bytesRead === 0) return buf.subarray(0, total);
    total += bytesRead;
  }
  return buf;
}

async function readMetaList(fh, startPos, fileSize, wantedNames, cryptoCtx = null) {
  let pos = startPos;
  const result = new Map();

  for (;;) {
    if (pos + K_BLOCK_HDR_SIZE > fileSize) {
      throw new Error(`Truncated metadata block header at offset ${pos}`);
    }
    const hdr = await readExact(fh, pos, K_BLOCK_HDR_SIZE);
    const name = hdr.subarray(0, 8).toString('ascii');
    const len = hdr.readUInt32LE(8);
    const expectedMd5 = hdr.subarray(12, 28);
    const flags = hdr[28];
    const bodyAt = pos + K_BLOCK_HDR_SIZE;

    if (bodyAt + len > fileSize) {
      throw new Error(`Metadata block "${name}" extends past EOF`);
    }

    if (wantedNames.has(name) && len > 0) {
      let body = await readExact(fh, bodyAt, len);
      const actualMd5 = crypto.createHash('md5').update(body).digest();
      if (!actualMd5.equals(expectedMd5)) {
        throw new Error(`Metadata block "${name}" MD5 mismatch`);
      }

      if (flags & FLAG_ENCRYPTED) {
        if (!cryptoCtx) {
          throw new Error(`Metadata block "${name}" is encrypted; provide --password`);
        }
        body = decryptReflectXBlock(cryptoCtx, body, 0, 0, 0);
      }

      if (flags & FLAG_COMPRESSED) {
        body = decompressZstd(body);
      }

      result.set(name, body);
    }

    pos = bodyAt + len;
    if (flags & FLAG_LAST) {
      return { blocks: result, nextPos: pos };
    }
  }
}

function parseIndexBlock(indexBuf, fileNumber, isDelta, fileSize) {
  if (indexBuf.length < 8) {
    throw new Error('$INDEX metadata block is too short');
  }
  let off = 0;
  const rcount = indexBuf.readUInt32LE(off);
  off += 4;
  if (off + rcount * K_INDEX_ELEM_SIZE + 4 > indexBuf.length) {
    throw new Error('Corrupt reserved-sectors count in $INDEX');
  }

  const reservedElements = [];
  for (let i = 0; i < rcount; i++, off += K_INDEX_ELEM_SIZE) {
    const filePosition = Number(indexBuf.readBigInt64LE(off));
    const md5 = Buffer.from(indexBuf.subarray(off + 8, off + 24));
    const blockLength = indexBuf.readUInt32LE(off + 24);
    const fileNum = indexBuf.readUInt16LE(off + 28);
    reservedElements.push({ filePosition, md5, blockLength, fileNumber: fileNum });
  }

  const bcount = indexBuf.readUInt32LE(off);
  off += 4;
  const elemSize = isDelta ? K_DELTA_ELEM_SIZE : K_INDEX_ELEM_SIZE;
  if (off + bcount * elemSize > indexBuf.length) {
    throw new Error('Corrupt data-blocks count in $INDEX');
  }

  const dataElements = [];
  for (let i = 0; i < bcount; i++, off += elemSize) {
    const filePosition = Number(indexBuf.readBigInt64LE(off));
    const md5 = Buffer.from(indexBuf.subarray(off + 8, off + 24));
    const blockLength = indexBuf.readUInt32LE(off + 24);
    const fileNum = indexBuf.readUInt16LE(off + 28);
    const blockIndex = isDelta ? indexBuf.readUInt32LE(off + 30) : i;
    if (blockLength > 0 && filePosition < 0) {
      throw new Error(`Block ${blockIndex} has invalid negative file position`);
    }
    if (blockLength > 0 && fileNum === fileNumber && filePosition + blockLength > fileSize) {
      throw new Error(`Block ${blockIndex} extends past EOF`);
    }
    dataElements.push({ filePosition, md5, blockLength, fileNumber: fileNum, blockIndex });
  }

  return { reservedElements, dataElements };
}

export async function isReflectXMrbak(filePath) {
  const fh = await fs.open(filePath, 'r');
  try {
    const stat = await fh.stat();
    if (stat.size < K_FOOTER_SIZE + K_BLOCK_HDR_SIZE) return false;
    const footer = await readExact(fh, stat.size - K_FOOTER_SIZE, K_FOOTER_SIZE);
    return footer.subarray(8, 20).equals(MAGIC_X);
  } finally {
    await fh.close();
  }
}

export class ReflectXMrbakContainer {
  constructor() {
    this.format = 'reflect-x';
    this.srcs = new Map(); // fileNumber -> { fh, filePath, fileSize, json }
    this.primaryFileNumber = 0;
    this.json = null;
    this.compressed = false;
    this.encrypted = false;
    this.cryptoCtx = null;
    this.fileBackup = false;
    this.parts = [];
    this.warnings = [];
    this.cache = new Map();
    this.maxCacheEntries = 256;
  }

  async _openSingleFile(filePath, password, isPrimary) {
    const fh = await fs.open(filePath, 'r');
    try {
      const stat = await fh.stat();
      const fileSize = stat.size;
      if (fileSize < K_FOOTER_SIZE + K_BLOCK_HDR_SIZE) {
        throw new Error(`File too small to be Reflect X backup: ${filePath}`);
      }
      const footer = await readExact(fh, fileSize - K_FOOTER_SIZE, K_FOOTER_SIZE);
      if (!footer.subarray(8, 20).equals(MAGIC_X)) {
        throw new Error(`Not a Macrium Reflect X file: ${filePath}`);
      }
      const metaOff = Number(footer.readBigUInt64LE(0));
      if (metaOff <= 0 || metaOff + K_BLOCK_HDR_SIZE > fileSize) {
        throw new Error('Invalid Reflect X metadata offset');
      }

      const rootMeta = await readMetaList(fh, metaOff, fileSize, new Set(['$JSON   ']));
      const jsonBuf = rootMeta.blocks.get('$JSON   ');
      if (!jsonBuf) {
        throw new Error('$JSON metadata block missing');
      }
      const json = JSON.parse(jsonBuf.toString('utf8'));
      const hdr = json._header;
      if (!hdr) throw new Error('Invalid $JSON metadata: missing _header');

      if (isPrimary) {
        this.json = json;
        this.primaryFileNumber = hdr.file_number ?? 0;
        const enc = json._encryption;
        this.encrypted = Boolean(enc?.enable);
        if (this.encrypted) {
          this.cryptoCtx = initReflectXCrypto(json, password);
        }
        const comp = json._compression;
        const level = (comp?.compression_level || '').toLowerCase();
        const method = (comp?.compression_method || '').toLowerCase();
        this.compressed = level !== 'none' && (level !== '' || method === 'zstd');
        if (this.compressed && method && method !== 'zstd') {
          throw new Error(`Unsupported Reflect X compression method: ${comp.compression_method}`);
        }
        this.fileBackup = hdr.backup_format === 'file_and_folder';
        if (hdr.split_file) {
          throw new Error('Split Reflect X backup files are not supported');
        }
      }

      return { fh, filePath, fileSize, json, fileNumber: hdr.file_number ?? 0 };
    } catch (err) {
      await fh.close().catch(() => {});
      throw err;
    }
  }

  async open(filePath, { password = null } = {}) {
    try {
      const primary = await this._openSingleFile(filePath, password, true);
      this.srcs.set(primary.fileNumber, primary);

      const disks = this.json.disks || [];
      if (disks.length === 0) {
        throw new Error('No disks present in $JSON metadata');
      }
      if (disks.length > 1) {
        this.warnings.push('Multi-disk backup: inspecting first disk');
      }

      const disk = disks[0];
      const diskNumber = disk._header?.disk_number ?? 0;
      const partsJson = disk.partitions || [];
      if (partsJson.length === 0) {
        throw new Error('No partitions present in $JSON metadata');
      }

      // Open any referenced ancestor/history files in the same folder
      const dir = path.dirname(filePath);
      const neededFiles = new Map(); // fileNumber -> fileName
      for (const pj of partsJson) {
        for (const fhEntry of pj._header?.file_history || []) {
          if (!this.srcs.has(fhEntry.file_number)) {
            neededFiles.set(fhEntry.file_number, fhEntry.file_name);
          }
        }
      }
      for (const [fnum, origName] of neededFiles.entries()) {
        const baseName = path.win32.basename(origName);
        const candPath = path.join(dir, baseName);
        let anc;
        try {
          anc = await this._openSingleFile(candPath, password, false);
        } catch (err) {
          this.warnings.push(`Could not open referenced chain file "${baseName}" (#${fnum}): ${err.message}`);
          continue;
        }
        if (
          this.json._header.imageid &&
          anc.json._header?.imageid &&
          anc.json._header.imageid !== this.json._header.imageid
        ) {
          await anc.fh.close().catch(() => {});
          throw new Error(`Chain file "${baseName}" has a mismatched image ID`);
        }
        this.srcs.set(fnum, anc);
      }

      // Read primary file's partition indices starting at index_file_position
      const indexPos = this.json._header.index_file_position;
      if (!indexPos || indexPos <= 0 || indexPos >= primary.fileSize) {
        throw new Error('Invalid index_file_position in $JSON');
      }

      let pos = indexPos;
      const trackMeta = await readMetaList(primary.fh, pos, primary.fileSize, new Set(['$TRACK0 ']), this.cryptoCtx);
      pos = trackMeta.nextPos;

      const isDelta = Boolean(this.json._header.delta_index);

      for (let pi = 0; pi < partsJson.length; pi++) {
        const pj = partsJson[pi];
        const ph = pj._header;
        const pg = pj._geometry;
        const pf = pj._file_system || {};
        const partNumber = ph.partition_number ?? pi;

        const partMeta = await readMetaList(primary.fh, pos, primary.fileSize, new Set(['$INDEX  ']), this.cryptoCtx);
        pos = partMeta.nextPos;
        const indexBuf = partMeta.blocks.get('$INDEX  ');
        if (!indexBuf) {
          throw new Error(`Missing $INDEX metadata block for partition ${pi}`);
        }

        const parsedIdx = parseIndexBlock(indexBuf, primary.fileNumber, isDelta, primary.fileSize);
        const part = await this._buildPartition(pj, pi, diskNumber, partNumber, parsedIdx, primary.fileNumber);

        // If delta/incremental, also merge base full & intermediate history if available
        if (isDelta && ph.file_history && ph.file_history.length > 1) {
          await this._overlayHistoryIndices(part, pj, pi, diskNumber, partNumber);
        }

        this.parts.push(part);
      }
    } catch (err) {
      await this.close();
      throw err;
    }
  }

  async _decodeStoredPayload(src, filePosition, blockLength, diskNumber, partNumber, blockIndex) {
    let buf = await readExact(src.fh, filePosition, blockLength);
    if (this.encrypted) {
      buf = decryptReflectXBlock(this.cryptoCtx, buf, diskNumber, partNumber, blockIndex);
    }
    if (this.compressed) {
      buf = decompressZstd(buf);
    }
    return buf;
  }

  async _buildPartition(pj, pi, diskNumber, partNumber, parsedIdx, primaryFileNumber) {
    const ph = pj._header;
    const pg = pj._geometry;
    const pf = pj._file_system || {};

    const diskOffset = Number(pg.start || 0);
    let size = Number(pg.length || 0);
    if (size === 0 && pg.end > diskOffset) {
      size = Number(pg.end) - diskOffset + 1;
    }
    const blockSize = Number(ph.block_size || 65536);

    const fsStart = pf.start !== undefined ? Number(pf.start) : diskOffset;
    const lcn0 = pf.lcn0_offset !== undefined ? Number(pf.lcn0_offset) : fsStart;
    let dataStart = 0;
    if (lcn0 >= fsStart) dataStart = lcn0 - fsStart;
    else if (lcn0 >= diskOffset) dataStart = lcn0 - diskOffset;

    const reservedLen = Number(pf.reserved_sectors_byte_length || 0);
    let head = Buffer.alloc(0);
    if (parsedIdx.reservedElements.length > 0) {
      const headChunks = [];
      let totalLen = 0;
      for (let i = 0; i < parsedIdx.reservedElements.length; i++) {
        const el = parsedIdx.reservedElements[i];
        if (el.blockLength === 0) continue;
        const src = this.srcs.get(el.fileNumber);
        if (!src) {
          throw new Error(`Missing chain file #${el.fileNumber} for reserved sectors`);
        }
        const decoded = await this._decodeStoredPayload(
          src,
          el.filePosition,
          el.blockLength,
          diskNumber,
          partNumber,
          i
        );
        headChunks.push(decoded);
        totalLen += decoded.length;
      }
      head = Buffer.concat(headChunks);
      if (reservedLen > 0 && head.length > reservedLen) {
        head = head.subarray(0, reservedLen);
      }
    }

    const totalBlocks = Number(ph.block_count || parsedIdx.dataElements.length);
    const blocks = new Array(totalBlocks).fill(null);
    for (const el of parsedIdx.dataElements) {
      if (el.blockLength === 0) continue;
      if (el.blockIndex >= blocks.length) {
        while (blocks.length <= el.blockIndex) blocks.push(null);
      }
      blocks[el.blockIndex] = {
        fileNumber: el.fileNumber,
        filePosition: el.filePosition,
        blockLength: el.blockLength,
        md5: el.md5,
        blockIndex: el.blockIndex,
      };
    }

    return {
      index: pi,
      diskNumber,
      partitionNumber: partNumber,
      diskOffset: this.fileBackup ? 0 : diskOffset,
      headOffset: Number(pg.boot_sector_offset || 0),
      size,
      blockSize,
      dataStart,
      head,
      blocks,
      fileSystemMeta: pf,
      primaryFileNumber,
    };
  }

  async _overlayHistoryIndices(part, pj, pi, diskNumber, partNumber) {
    // Backfill any missing head (reserved sectors) or unreferenced data blocks from ancestor files
    // in newest-to-oldest order so intermediate incrementals take precedence over the base full backup.
    const ancestorNums = Array.from(this.srcs.keys())
      .filter((fnum) => fnum !== this.primaryFileNumber)
      .sort((a, b) => b - a);

    for (const fnum of ancestorNums) {
      const needHead = part.head.length === 0;
      const needBlocks = part.blocks.some((b) => b === null);
      if (!needHead && !needBlocks) break;

      const ancSrc = this.srcs.get(fnum);
      const ancIndexPos = ancSrc.json._header?.index_file_position;
      if (!ancIndexPos || ancIndexPos <= 0 || ancIndexPos >= ancSrc.fileSize) continue;

      let pos = ancIndexPos;
      const t = await readMetaList(ancSrc.fh, pos, ancSrc.fileSize, new Set(['$TRACK0 ']), this.cryptoCtx);
      pos = t.nextPos;
      for (let k = 0; k <= pi; k++) {
        const pm = await readMetaList(ancSrc.fh, pos, ancSrc.fileSize, new Set(['$INDEX  ']), this.cryptoCtx);
        pos = pm.nextPos;
        if (k === pi) {
          const idxBuf = pm.blocks.get('$INDEX  ');
          if (idxBuf) {
            const ancIdx = parseIndexBlock(
              idxBuf,
              fnum,
              Boolean(ancSrc.json._header.delta_index),
              ancSrc.fileSize
            );
            const rebuilt = await this._buildPartition(
              ancSrc.json.disks?.[0]?.partitions?.[pi] || pj,
              pi,
              diskNumber,
              partNumber,
              ancIdx,
              fnum
            );
            if (part.head.length === 0 && rebuilt.head.length > 0) {
              part.head = rebuilt.head;
            }
            for (let bi = 0; bi < part.blocks.length; bi++) {
              if (!part.blocks[bi] && bi < rebuilt.blocks.length && rebuilt.blocks[bi]) {
                part.blocks[bi] = rebuilt.blocks[bi];
              }
            }
          }
        }
      }
    }
  }

  async _loadBlock(ref, part) {
    const cacheKey = `${ref.fileNumber}:${ref.filePosition}`;
    const cached = this.cache.get(cacheKey);
    if (cached) {
      this.cache.delete(cacheKey);
      this.cache.set(cacheKey, cached);
      return cached;
    }

    const src = this.srcs.get(ref.fileNumber);
    if (!src) {
      throw new Error(
        `Block #${ref.blockIndex} belongs to chain file #${ref.fileNumber}, which is not available in the directory`
      );
    }

    let decoded = await this._decodeStoredPayload(
      src,
      ref.filePosition,
      ref.blockLength,
      part.diskNumber,
      part.partitionNumber,
      ref.blockIndex
    );

    if (decoded.length < part.blockSize) {
      const padded = Buffer.alloc(part.blockSize);
      decoded.copy(padded, 0);
      decoded = padded;
    }

    if (this.cache.size >= this.maxCacheEntries) {
      const oldest = this.cache.keys().next().value;
      this.cache.delete(oldest);
    }
    this.cache.set(cacheKey, decoded);
    return decoded;
  }

  getVolumeStream(partIdx = 0) {
    const part = this.parts[partIdx];
    if (!part) throw new Error(`Partition ${partIdx} does not exist`);
    const self = this;

    return {
      size: part.size,
      async readAt(offset, length) {
        if (offset < 0 || offset >= part.size || length <= 0) return Buffer.alloc(0);
        const totalWant = Math.min(length, part.size - offset);
        const chunks = [];
        let pos = offset;
        let rem = totalWant;

        while (rem > 0) {
          const headEnd = part.headOffset + part.head.length;
          if (part.head.length > 0 && pos >= part.headOffset && pos < headEnd) {
            const hrel = pos - part.headOffset;
            const take = Math.min(rem, part.head.length - hrel);
            chunks.push(part.head.subarray(hrel, hrel + take));
            pos += take;
            rem -= take;
            continue;
          }

          if (pos < part.dataStart) {
            let lim = part.dataStart - pos;
            if (part.head.length > 0 && pos < part.headOffset && part.headOffset - pos < lim) {
              lim = part.headOffset - pos;
            }
            const take = Math.min(rem, lim);
            chunks.push(Buffer.alloc(take));
            pos += take;
            rem -= take;
            continue;
          }

          const drel = pos - part.dataStart;
          const blockIdx = Math.floor(drel / part.blockSize);
          const inBlock = drel % part.blockSize;
          const take = Math.min(rem, part.blockSize - inBlock);
          const ref = blockIdx < part.blocks.length ? part.blocks[blockIdx] : null;
          if (!ref) {
            chunks.push(Buffer.alloc(take));
          } else {
            const block = await self._loadBlock(ref, part);
            chunks.push(block.subarray(inBlock, inBlock + take));
          }
          pos += take;
          rem -= take;
        }

        return chunks.length === 1 ? chunks[0] : Buffer.concat(chunks);
      },
    };
  }

  async verify(onProgress) {
    let checked = 0;
    let total = 0;
    let mismatches = 0;
    const errors = [];

    for (const part of this.parts) {
      for (const b of part.blocks) {
        if (b) total++;
      }
    }

    for (const part of this.parts) {
      for (let i = 0; i < part.blocks.length; i++) {
        const b = part.blocks[i];
        if (!b) continue;
        try {
          const src = this.srcs.get(b.fileNumber);
          if (!src) {
            throw new Error(`Missing chain file #${b.fileNumber}`);
          }
          const raw = await this._decodeStoredPayload(
            src,
            b.filePosition,
            b.blockLength,
            part.diskNumber,
            part.partitionNumber,
            b.blockIndex
          );
          const md5 = crypto.createHash('md5').update(raw).digest();
          if (!md5.equals(b.md5)) {
            mismatches++;
            if (errors.length < 20) {
              errors.push(`Part ${part.index} block ${b.blockIndex}: MD5 mismatch`);
            }
          }
        } catch (err) {
          mismatches++;
          if (errors.length < 20) {
            errors.push(`Part ${part.index} block ${b.blockIndex}: ${err.message}`);
          }
        }
        checked++;
        if (onProgress && checked % 128 === 0) onProgress(checked, total);
      }
    }
    if (onProgress) onProgress(checked, total);
    return { checked, total, mismatches, errors };
  }

  getInfo() {
    const primary = this.srcs.get(this.primaryFileNumber);
    const hdr = this.json._header;
    const comp = this.json._compression || {};
    const enc = this.json._encryption || {};
    const aux = this.json._auxiliary_data || {};

    return {
      format: 'Macrium Reflect X',
      backupType: this.fileBackup
        ? `File and Folder (${hdr.backup_type || 'full'})`
        : `Disk Image (${hdr.backup_type || 'full'})`,
      filePath: primary.filePath,
      fileSize: primary.fileSize,
      imageId: hdr.imageid,
      backupGuid: hdr.backup_guid,
      netbiosName: hdr.netbios_name || null,
      originalPath: aux.destination || aux.backup_definition?.filename || null,
      backupTime: hdr.backup_time ? new Date(hdr.backup_time * 1000) : null,
      compression: this.compressed
        ? `${comp.compression_method || 'zstd'} (${comp.compression_level || 'medium'})`
        : 'None (Store)',
      encrypted: this.encrypted,
      encryptionType: this.encrypted ? enc.aes_type : null,
      comment: aux.backup_definition?.comment || null,
      reflectVersion: aux.macrium_reflect
        ? `${aux.macrium_reflect.major}.${aux.macrium_reflect.minor}.${aux.macrium_reflect.build}`
        : null,
      chainFiles: Array.from(this.srcs.values())
        .sort((a, b) => a.fileNumber - b.fileNumber)
        .map((s) => ({
          fileNumber: s.fileNumber,
          filePath: s.filePath,
          fileSize: s.fileSize,
        })),
      partitions: this.parts.map((p) => ({
        index: p.index,
        partitionNumber: p.partitionNumber,
        blockSize: p.blockSize,
        blockCount: p.blocks.length,
        storedBlocks: p.blocks.filter(Boolean).length,
        reservedSectorsBytes: p.head.length,
        virtualSize: p.size,
      })),
      warnings: this.warnings,
    };
  }

  async close() {
    for (const s of this.srcs.values()) {
      await s.fh.close().catch(() => {});
    }
    this.srcs.clear();
    this.cache.clear();
  }
}
