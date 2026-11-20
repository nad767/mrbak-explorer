import fs from 'node:fs/promises';
import path from 'node:path';
import crypto from 'node:crypto';
import { decompressQlz, parseQlzHeader } from './quicklz.js';

const TRAILER_MAGIC = Buffer.from('__79241006_2651_11D4_', 'ascii');
const K_TRAILER_SIZE = 40;
const K_TAIL_PTR_SIZE = 14;
const K_RECORD_SIZE = 30;
const K_RECORD_SIZE_DELTA = 34;
const K_PART_REC_TAIL = 36;
const K_MAX_QLZ_HEADER = 9;
const K_DEFAULT_BLOCK_SIZE = 65536;
const K_MAX_META_SIZE = 1024 * 1024 * 1024; // 1 GiB safety cap

function isPlausibleBlockSize(n) {
  return n >= 4096 && n <= 64 * 1024 * 1024 && (n & 511) === 0;
}

function isZeroMd5(buf, off) {
  for (let i = 0; i < 16; i++) {
    if (buf[off + i] !== 0) return false;
  }
  return true;
}

function parseFatBpbQuick(boot) {
  if (boot.length < 512) return null;
  if ((boot[0] !== 0xeb && boot[0] !== 0xe9) || boot[510] !== 0x55 || boot[511] !== 0xaa) {
    return null;
  }
  const dv = new DataView(boot.buffer, boot.byteOffset, boot.byteLength);
  const bps = dv.getUint16(11, true);
  const spc = boot[13];
  const resv = dv.getUint16(14, true);
  const nfats = boot[16];
  const rootEnt = dv.getUint16(17, true);
  let fatsz = dv.getUint16(22, true);
  if (fatsz === 0) fatsz = dv.getUint32(36, true);
  let total = dv.getUint16(19, true);
  if (total === 0) total = dv.getUint32(32, true);

  if (
    ![512, 1024, 2048, 4096].includes(bps) ||
    spc === 0 ||
    (spc & (spc - 1)) !== 0 ||
    resv === 0 ||
    (nfats !== 1 && nfats !== 2) ||
    fatsz === 0
  ) {
    return null;
  }

  const rootLen = Math.floor((rootEnt * 32 + bps - 1) / bps) * bps;
  const headLen = (resv + nfats * fatsz) * bps + rootLen;
  const totalLen = total * bps;
  return { headLen, totalLen, bps, spc };
}

function extractXmlTag(xml, tag) {
  const re = new RegExp(`<${tag}(?:\\s[^>]*)?>([^<]*)</${tag}>`, 'i');
  const m = xml.match(re);
  return m ? m[1].trim() : null;
}

function parseXmlPartitionNumbers(xml) {
  const nums = [];
  const re = /<partition(?:\s[^>]*)?>(\d+)<\/partition>/gi;
  let m;
  while ((m = re.exec(xml)) !== null) {
    const v = Number(m[1]);
    if (v >= 1 && v <= 1024) nums.push(v);
  }
  return nums;
}

function findXmlInFooter(footer, pathLen) {
  const magic = Buffer.from('<?xml', 'ascii');
  const searchStart = 13 + pathLen;
  const searchEnd = Math.min(footer.length, 16384);
  const slice = footer.subarray(0, searchEnd);
  const xmlStart = slice.indexOf(magic, searchStart);
  if (xmlStart === -1 || xmlStart < 7) return null;

  let xmlLen;
  if (footer.readUInt16LE(xmlStart - 6) === 0xffff && footer[xmlStart - 7] === 0xff) {
    xmlLen = footer.readUInt32LE(xmlStart - 4);
  } else {
    xmlLen = footer.readUInt16LE(xmlStart - 2);
  }
  if (xmlLen === 0 || xmlStart + xmlLen > footer.length) return null;
  return {
    xmlStart,
    xmlLen,
    xmlText: footer.subarray(xmlStart, xmlStart + xmlLen).toString('utf8'),
  };
}

function findMarkers(footer, pathBytes) {
  const end = footer.length - (K_TRAILER_SIZE + K_TAIL_PTR_SIZE);
  const pathLen = pathBytes.length;
  const markers = [];
  let pos = 0;
  while (pos < end) {
    const idx = footer.indexOf(pathBytes, pos);
    if (idx === -1 || idx >= end) break;
    if (idx !== 13 && idx >= 1 && footer[idx - 1] === pathLen) {
      markers.push(idx);
    }
    pos = idx + 1;
  }
  return markers;
}

function parseChainHead(footer, marker) {
  const paths = [];
  let explicitBs = 0;
  let numChainFiles = 0;
  let end = marker - 1;

  for (;;) {
    if (end < 7) break;
    const tail = end - 6;
    if (footer.readUInt32LE(tail) !== 3) break;

    let found = false;
    for (let plen = 255; plen >= 7; plen--) {
      if (tail < plen + 1) continue;
      const s = tail - plen - 1;
      if (footer[s] !== plen) continue;
      const slice = footer.subarray(s + 1, s + 1 + plen);
      let printable = true;
      for (let j = 0; j < plen; j++) {
        if (slice[j] < 0x20 || slice[j] >= 0x7f) {
          printable = false;
          break;
        }
      }
      if (!printable) continue;
      const str = slice.toString('ascii');
      const ext = str.slice(-6).toLowerCase();
      if (ext !== '.mrimg' && ext !== '.mrbak') continue;
      paths.unshift(str);
      end = s;
      found = true;
      break;
    }
    if (!found) break;
  }

  if (end >= 10) {
    const bs = footer.readUInt32LE(end - 10);
    const nf = footer.readUInt32LE(end - 6);
    if (isPlausibleBlockSize(bs)) explicitBs = bs;
    if (nf >= 1 && nf <= 256) numChainFiles = nf;
  }

  return { paths, explicitBs, numChainFiles };
}

async function readExact(fh, offset, length) {
  const buf = Buffer.allocUnsafe(length);
  let total = 0;
  while (total < length) {
    const { bytesRead } = await fh.read(buf, total, length - total, offset + total);
    if (bytesRead === 0) {
      return buf.subarray(0, total);
    }
    total += bytesRead;
  }
  return buf;
}

async function readChainFooter(filePath) {
  const fh = await fs.open(filePath, 'r');
  try {
    const stat = await fh.stat();
    const fileSize = stat.size;
    if (fileSize < K_TRAILER_SIZE + K_TAIL_PTR_SIZE + K_RECORD_SIZE) {
      throw new Error(`File too small to be a legacy Macrium backup: ${filePath}`);
    }
    const tail = await readExact(fh, fileSize - (K_TRAILER_SIZE + K_TAIL_PTR_SIZE), K_TRAILER_SIZE + K_TAIL_PTR_SIZE);
    const trailer = tail.subarray(K_TAIL_PTR_SIZE);
    if (!trailer.subarray(0, TRAILER_MAGIC.length).equals(TRAILER_MAGIC) || trailer[TRAILER_MAGIC.length] !== 0) {
      throw new Error(`Not a legacy Macrium Reflect v7/v8 file: ${filePath}`);
    }
    const metaOff = Number(tail.readBigUInt64LE(6));
    if (metaOff <= 0 || metaOff >= fileSize) {
      throw new Error('Invalid legacy metadata offset');
    }
    const footerSize = fileSize - metaOff;
    if (footerSize > K_MAX_META_SIZE) {
      throw new Error('Metadata footer exceeds 1 GiB safety limit');
    }
    const footer = await readExact(fh, metaOff, footerSize);
    return { fh, filePath, fileSize, metaOff, footer };
  } catch (err) {
    await fh.close().catch(() => {});
    throw err;
  }
}

function parseMbrPartitions(mbr) {
  const slots = [];
  for (let i = 0; i < 4; i++) {
    const off = 446 + i * 16;
    const type = mbr[off + 4];
    if (type === 0) continue;
    const lba = mbr.readUInt32LE(off + 8);
    const sectors = mbr.readUInt32LE(off + 12);
    if (sectors === 0) continue;
    slots.push({
      index: i + 1,
      type,
      extended: type === 0x05 || type === 0x0f || type === 0x85,
      startByte: lba * 512,
      sizeByte: sectors * 512,
    });
  }
  return slots;
}

function parseGptPartitions(footer, mbrOff) {
  const hdr = mbrOff + 512;
  if (hdr + 512 > footer.length) return null;
  if (footer.subarray(hdr, hdr + 8).toString('ascii') !== 'EFI PART') return null;

  const hdrSize = footer.readUInt32LE(hdr + 12);
  const numEnt = footer.readUInt32LE(hdr + 80);
  const entSize = footer.readUInt32LE(hdr + 84);
  if (hdrSize < 92 || hdrSize > 512 || numEnt === 0 || numEnt > 1024 || entSize < 128 || entSize > 4096) {
    return null;
  }
  const nEnt = Math.min(numEnt, 128);
  const bases = [hdr + 512, hdr + hdrSize];

  for (const base of bases) {
    if (base + nEnt * entSize > footer.length) continue;
    const slots = [];
    let bad = false;
    for (let i = 0; i < nEnt; i++) {
      const e = footer.subarray(base + i * entSize, base + (i + 1) * entSize);
      const zeroType = e.subarray(0, 16).every((b) => b === 0);
      if (zeroType) continue;
      const firstLba = Number(e.readBigUInt64LE(32));
      const lastLba = Number(e.readBigUInt64LE(40));
      if (lastLba < firstLba) {
        bad = true;
        break;
      }
      slots.push({
        index: slots.length + 1,
        type: 'GPT',
        extended: false,
        startByte: firstLba * 512,
        sizeByte: (lastLba - firstLba + 1) * 512,
      });
    }
    if (!bad && slots.length > 0) return slots;
  }
  return null;
}

export async function isLegacyMrbak(filePath) {
  const fh = await fs.open(filePath, 'r');
  try {
    const stat = await fh.stat();
    if (stat.size < K_TRAILER_SIZE + K_TAIL_PTR_SIZE + K_RECORD_SIZE) return false;
    const trailer = await readExact(fh, stat.size - K_TRAILER_SIZE, K_TRAILER_SIZE);
    return (
      trailer.subarray(0, TRAILER_MAGIC.length).equals(TRAILER_MAGIC) &&
      trailer[TRAILER_MAGIC.length] === 0
    );
  } finally {
    await fh.close();
  }
}

export class LegacyMrbakContainer {
  constructor() {
    this.format = 'legacy';
    this.srcs = []; // [{ fh, filePath, fileSize, metaOff, fileNo, footer }]
    this.parts = [];
    this.compressed = false;
    this.fileBackup = false;
    this.encrypted = false;
    this.blockSize = K_DEFAULT_BLOCK_SIZE;
    this.backupTime = 0;
    this.imageId = '';
    this.originalPath = '';
    this.xmlText = '';
    this.comment = '';
    this.warnings = [];
    this.cache = new Map();
    this.maxCacheEntries = 256;
  }

  async open(filePath) {
    const own = await readChainFooter(filePath);
    const { footer } = own;
    const pathLen = footer[12];
    if (pathLen === 0 || 13 + pathLen > footer.length) {
      await own.fh.close();
      throw new Error('Invalid legacy metadata header (path length)');
    }

    const ownPathBytes = footer.subarray(13, 13 + pathLen);
    const markers = findMarkers(footer, ownPathBytes);
    let chainPaths = [];
    if (markers.length > 0) {
      const ch = parseChainHead(footer, markers[0]);
      chainPaths = ch.paths;
      if (ch.numChainFiles !== 0 && ch.numChainFiles !== chainPaths.length + 1) {
        this.warnings.push('Chain file count does not match ancestor path list');
      }
    }

    if (chainPaths.length === 0) {
      this.srcs.push({ ...own, fileNo: footer.readUInt16LE(10) });
    } else {
      const dir = path.dirname(filePath);
      const ownId = footer.subarray(0, 8);
      for (let i = 0; i < chainPaths.length; i++) {
        const baseName = path.win32.basename(chainPaths[i]);
        const ancPath = path.join(dir, baseName);
        let anc;
        try {
          anc = await readChainFooter(ancPath);
        } catch (err) {
          await this.close();
          await own.fh.close();
          throw new Error(`Missing or unreadable chain ancestor "${baseName}": ${err.message}`);
        }
        if (!anc.footer.subarray(0, 8).equals(ownId)) {
          await anc.fh.close();
          await this.close();
          await own.fh.close();
          throw new Error(`Chain file "${baseName}" has a mismatched image ID`);
        }
        this.srcs.push({ ...anc, fileNo: anc.footer.readUInt16LE(10) });
      }
      this.srcs.push({ ...own, fileNo: footer.readUInt16LE(10) });
    }

    try {
      await this._parseBase(this.srcs[0]);
      for (let i = 1; i < this.srcs.length; i++) {
        await this._overlayDelta(this.srcs[i], i);
      }
      // Archive properties reflect the opened chain file
      const ownSrc = this.srcs[this.srcs.length - 1];
      const ownPlen = ownSrc.footer[12];
      if (ownPlen > 0 && 13 + ownPlen <= ownSrc.footer.length) {
        this.originalPath = ownSrc.footer.subarray(13, 13 + ownPlen).toString('utf8');
      }
      const ownXml = findXmlInFooter(ownSrc.footer, ownPlen);
      if (ownXml) {
        this.xmlText = ownXml.xmlText;
        const ownTsOff = ownXml.xmlStart + ownXml.xmlLen;
        if (ownTsOff + 4 <= ownSrc.footer.length) {
          this.backupTime = ownSrc.footer.readUInt32LE(ownTsOff);
        }
      }
    } catch (err) {
      await this.close();
      throw err;
    }
  }

  async _parseBase(baseSrc) {
    const { footer, metaOff, fh } = baseSrc;
    this.imageId = footer.subarray(0, 8).toString('hex').toUpperCase();
    const pathLen = footer[12];
    const pathBytes = footer.subarray(13, 13 + pathLen);
    this.originalPath = pathBytes.toString('utf8');

    const xmlInfo = findXmlInFooter(footer, pathLen);
    if (!xmlInfo) {
      throw new Error('Legacy backup XML definition not found in metadata');
    }
    this.xmlText = xmlInfo.xmlText;

    const compStr = extractXmlTag(this.xmlText, 'compression');
    const compressionTag = compStr !== null ? Number(compStr) : -1;
    const backupTypeStr = extractXmlTag(this.xmlText, 'backup_type');
    this.fileBackup = backupTypeStr === '1';
    this.comment = extractXmlTag(this.xmlText, 'comment') || '';

    const encTag = extractXmlTag(this.xmlText, 'encryption') || extractXmlTag(this.xmlText, 'aes');
    if (encTag && encTag !== '0' && encTag.toLowerCase() !== 'false' && encTag.toLowerCase() !== 'none') {
      this.encrypted = true;
      throw new Error(
        'Legacy Reflect v7/v8 encrypted .mrbak files use a proprietary undocumented encryption scheme and are not supported'
      );
    }

    const xmlNums = parseXmlPartitionNumbers(this.xmlText);
    const desc = xmlInfo.xmlStart + xmlInfo.xmlLen;
    if (desc + 4 <= footer.length) {
      this.backupTime = footer.readUInt32LE(desc);
    }

    const markers = findMarkers(footer, pathBytes);
    const end = footer.length - (K_TRAILER_SIZE + K_TAIL_PTR_SIZE);
    let firstStoredOffset = null;

    for (let k = 0; k < markers.length; k++) {
      const m = markers[k];
      const rec0 = m + pathLen + K_PART_REC_TAIL;
      if (rec0 + K_RECORD_SIZE > end) continue;
      const count = footer.readUInt32LE(rec0 + 2);
      const bound = k + 1 < markers.length ? markers[k + 1] - 1 : end;
      const need = rec0 + count * K_RECORD_SIZE;
      if (count === 0 || bound < need || bound - need > 4096) {
        this.warnings.push(`Implausible index section header at offset ${m}`);
        continue;
      }

      const blocks = new Array(count);
      for (let i = 0; i < count; i++) {
        const recOff = rec0 + i * K_RECORD_SIZE;
        if (isZeroMd5(footer, recOff + 14)) {
          blocks[i] = null;
        } else {
          const fo = Number(footer.readBigUInt64LE(recOff + 6));
          if (fo + K_MAX_QLZ_HEADER > metaOff) {
            blocks[i] = null;
          } else {
            const md5 = Buffer.from(footer.subarray(recOff + 14, recOff + 30));
            blocks[i] = { srcIdx: 0, fileOffset: fo, md5 };
            if (firstStoredOffset === null || fo < firstStoredOffset) {
              firstStoredOffset = fo;
            }
          }
        }
      }

      this.parts.push({
        index: this.parts.length,
        xmlNum: this.parts.length < xmlNums.length ? xmlNums[this.parts.length] : 0,
        blockSize: K_DEFAULT_BLOCK_SIZE,
        rawHeadSrcIdx: 0,
        rawHeadOff: 0,
        rawHeadLen: 0,
        diskOffset: 0,
        size: 0,
        blocks,
      });
    }

    if (this.parts.length === 0 || firstStoredOffset === null) {
      throw new Error('No partition/volume block index found in legacy .mrbak');
    }

    const qh = await readExact(fh, firstStoredOffset, K_MAX_QLZ_HEADER);
    if (compressionTag >= 0) {
      this.compressed = compressionTag !== 0;
    } else {
      const flag = qh[0];
      const csize = qh.readUInt32LE(1);
      const dsize = qh.readUInt32LE(5);
      if ((flag & ~3) !== 0 || !isPlausibleBlockSize(dsize)) {
        this.compressed = false;
      } else if (flag & 1) {
        this.compressed = csize >= 9 && csize <= dsize + 9;
      } else {
        this.compressed = csize === dsize + 9;
      }
    }

    this.blockSize = K_DEFAULT_BLOCK_SIZE;
    if (this.compressed) {
      if ((qh[0] & 2) !== 0 && isPlausibleBlockSize(qh.readUInt32LE(5))) {
        this.blockSize = qh.readUInt32LE(5);
      }
    } else {
      let best = 0;
      let prev = null;
      let seen = 0;
      for (const p of this.parts) {
        for (let i = 0; i < p.blocks.length && seen < 4096; i++) {
          const b = p.blocks[i];
          if (!b) continue;
          if (prev !== null && b.fileOffset > prev) {
            const d = b.fileOffset - prev;
            if (best === 0 || d < best) best = d;
            seen++;
          }
          prev = b.fileOffset;
        }
      }
      if (best > 0 && isPlausibleBlockSize(best)) this.blockSize = best;
    }

    // Refine per-section blockSize
    for (const part of this.parts) {
      part.blockSize = this.blockSize;
      if (this.compressed) {
        for (let i = 0; i + 1 < part.blocks.length; i++) {
          const b = part.blocks[i];
          if (!b) continue;
          const h = await readExact(fh, b.fileOffset, K_MAX_QLZ_HEADER);
          if ((h[0] & 2) !== 0 && isPlausibleBlockSize(h.readUInt32LE(5))) {
            part.blockSize = h.readUInt32LE(5);
          }
          break;
        }
      }
    }

    if (this.fileBackup) {
      const part = this.parts[0];
      let maxFo = null;
      for (const b of part.blocks) {
        if (b && (maxFo === null || b.fileOffset > maxFo)) maxFo = b.fileOffset;
      }
      if (maxFo === null) {
        throw new Error('File backup has no stored data blocks');
      }
      let headOff;
      if (this.compressed) {
        const h = await readExact(fh, maxFo, K_MAX_QLZ_HEADER);
        const qhdr = parseQlzHeader(h);
        if (qhdr.compressedSize < 3 || qhdr.compressedSize > part.blockSize + 9 + 4096) {
          throw new Error('Implausible QuickLZ header before virtual FAT32 system area (file may be encrypted or corrupt)');
        }
        headOff = maxFo + qhdr.compressedSize;
      } else {
        headOff = maxFo + part.blockSize;
      }

      if (headOff + 512 > metaOff) {
        throw new Error('Virtual FAT32 system area extends past metadata boundary');
      }
      const boot = await readExact(fh, headOff, 512);
      const bpb = parseFatBpbQuick(boot);
      if (!bpb || bpb.totalLen === 0 || headOff + bpb.headLen > metaOff) {
        throw new Error('Virtual FAT32 boot sector not found after data blocks (file may be encrypted or not a .mrbak)');
      }
      if (headOff + bpb.headLen !== metaOff) {
        this.warnings.push(
          `FAT system area end (${headOff + bpb.headLen}) differs from metadata offset (${metaOff})`
        );
      }
      part.rawHeadOff = headOff;
      part.rawHeadLen = bpb.headLen;
      part.size = bpb.totalLen;
    } else {
      // Disk image (.mrimg): find MBR/GPT partition layout and optional FAT raw heads
      let mbrOff = -1;
      const scanEnd = Math.min(footer.length - 512, desc + 1024);
      for (let off = desc; off <= scanEnd; off++) {
        if (footer[off + 510] === 0x55 && footer[off + 511] === 0xaa) {
          mbrOff = off;
          break;
        }
      }
      if (mbrOff !== -1) {
        const gptSlots = parseGptPartitions(footer, mbrOff);
        const slots = gptSlots || parseMbrPartitions(footer.subarray(mbrOff, mbrOff + 512));
        for (const part of this.parts) {
          const slot = slots.find((s) => s.index === part.xmlNum) || slots[part.index];
          part.size = slot ? slot.sizeByte : part.blocks.length * part.blockSize;
          part.diskOffset = slot ? slot.startByte : 0;
        }
      } else {
        for (const part of this.parts) {
          part.size = part.blocks.length * part.blockSize;
        }
      }

      let endOff = 0;
      for (const part of this.parts) {
        let first = null;
        let maxFo = null;
        for (const b of part.blocks) {
          if (!b) continue;
          if (first === null) first = b.fileOffset;
          if (maxFo === null || b.fileOffset > maxFo) maxFo = b.fileOffset;
        }
        if (first === null) continue;
        if (first > endOff) {
          const gap = first - endOff;
          const boot = await readExact(fh, endOff, 512);
          const bpb = parseFatBpbQuick(boot);
          if (bpb && bpb.headLen === gap) {
            part.rawHeadOff = endOff;
            part.rawHeadLen = bpb.headLen;
          }
        }
        if (this.compressed) {
          const h = await readExact(fh, maxFo, K_MAX_QLZ_HEADER);
          const qhdr = parseQlzHeader(h);
          endOff = maxFo + qhdr.compressedSize;
        } else {
          endOff = maxFo + part.blockSize;
        }
      }
    }
  }

  async _overlayDelta(src, srcIdx) {
    const { footer } = src;
    const pathLen = footer[12];
    if (pathLen === 0 || 13 + pathLen > footer.length) {
      throw new Error('Invalid delta metadata header');
    }
    const pathBytes = footer.subarray(13, 13 + pathLen);
    const xmlInfo = findXmlInFooter(footer, pathLen);
    if (!xmlInfo) throw new Error('Delta XML definition not found');

    const compStr = extractXmlTag(xmlInfo.xmlText, 'compression');
    if (compStr !== null && (Number(compStr) !== 0) !== this.compressed) {
      throw new Error('Delta chain compression setting mismatches base image');
    }

    const xmlNums = parseXmlPartitionNumbers(xmlInfo.xmlText);
    const markers = findMarkers(footer, pathBytes);
    const end = footer.length - (K_TRAILER_SIZE + K_TAIL_PTR_SIZE);
    let validIdx = 0;

    for (let k = 0; k < markers.length; k++) {
      const m = markers[k];
      const rec0 = m + pathLen + K_PART_REC_TAIL;
      if (rec0 + K_RECORD_SIZE_DELTA > end) continue;
      const count = footer.readUInt32LE(rec0 + 2);
      const bound = k + 1 < markers.length ? markers[k + 1] - 1 : end;
      const need = rec0 + count * K_RECORD_SIZE_DELTA;
      if (count === 0 || bound < need || bound - need > 4096) {
        throw new Error('Implausible delta index section header');
      }

      const num = validIdx < xmlNums.length ? xmlNums[validIdx] : 0;
      const part =
        (num !== 0 && this.parts.find((p) => p.xmlNum === num)) ||
        this.parts[validIdx] ||
        null;
      validIdx++;
      if (!part) continue;

      const pending = [];
      let maxFoForSrc = null;
      for (let i = 0; i < count; i++) {
        const recOff = rec0 + i * K_RECORD_SIZE_DELTA;
        if (isZeroMd5(footer, recOff + 14)) continue;
        const bn = i === 0 ? 0 : footer.readUInt32LE(recOff + 2) + 1;
        let useSrc = srcIdx;
        const fno = footer.readUInt16LE(recOff);
        if (fno !== src.fileNo) {
          const found = this.srcs.findIndex((s) => s.fileNo === fno);
          if (found === -1) continue;
          useSrc = found;
        }
        const fo = Number(footer.readBigUInt64LE(recOff + 6));
        if (fo + K_MAX_QLZ_HEADER > this.srcs[useSrc].metaOff) continue;
        if (useSrc === srcIdx && (maxFoForSrc === null || fo > maxFoForSrc)) {
          maxFoForSrc = fo;
        }
        const md5 = Buffer.from(footer.subarray(recOff + 14, recOff + 30));
        pending.push({ bn, ref: { srcIdx: useSrc, fileOffset: fo, md5 } });
      }

      // If an incremental/differential file backup stored an updated FAT32 head right before metaOff,
      // pick it up before capping block numbers so any volume size growth is respected.
      if (this.fileBackup && part === this.parts[0] && maxFoForSrc !== null) {
        let headOff = null;
        if (this.compressed) {
          const h = await readExact(src.fh, maxFoForSrc, K_MAX_QLZ_HEADER);
          if (h.length >= 3) {
            try {
              const qhdr = parseQlzHeader(h);
              if (qhdr.compressedSize >= qhdr.headerLen && qhdr.compressedSize <= part.blockSize + 9 + 4096) {
                headOff = maxFoForSrc + qhdr.compressedSize;
              }
            } catch {
              // Ignore malformed header check here
            }
          }
        } else {
          headOff = maxFoForSrc + part.blockSize;
        }
        if (headOff !== null && headOff + 512 <= src.metaOff) {
          const boot = await readExact(src.fh, headOff, 512);
          const bpb = parseFatBpbQuick(boot);
          if (bpb && bpb.totalLen > 0 && headOff + bpb.headLen === src.metaOff) {
            part.rawHeadSrcIdx = srcIdx;
            part.rawHeadOff = headOff;
            part.rawHeadLen = bpb.headLen;
            part.size = bpb.totalLen;
          }
        }
      }

      const cap = Math.floor(part.size / part.blockSize) + 16;
      for (const { bn, ref } of pending) {
        if (bn >= cap) continue;
        while (part.blocks.length <= bn) part.blocks.push(null);
        part.blocks[bn] = ref;
      }
    }
  }

  async _loadBlock(blockRef, blockSize) {
    const cacheKey = `${blockRef.srcIdx}:${blockRef.fileOffset}`;
    const cached = this.cache.get(cacheKey);
    if (cached) {
      this.cache.delete(cacheKey);
      this.cache.set(cacheKey, cached);
      return cached;
    }

    const src = this.srcs[blockRef.srcIdx];
    let out;
    if (!this.compressed) {
      out = await readExact(src.fh, blockRef.fileOffset, blockSize);
    } else {
      const hdrBytes = await readExact(src.fh, blockRef.fileOffset, K_MAX_QLZ_HEADER);
      const qhdr = parseQlzHeader(hdrBytes);
      const maxCsize = blockSize + 9 + 4096;
      if (qhdr.compressedSize < qhdr.headerLen || qhdr.compressedSize > maxCsize) {
        throw new Error(`Invalid QuickLZ compressed block size ${qhdr.compressedSize}`);
      }
      if (qhdr.decompressedSize === 0 || qhdr.decompressedSize > blockSize) {
        throw new Error(`Invalid QuickLZ decompressed block size ${qhdr.decompressedSize}`);
      }
      const compBuf = await readExact(src.fh, blockRef.fileOffset, qhdr.compressedSize);
      const decomp = decompressQlz(compBuf);
      if (decomp.length < blockSize) {
        out = Buffer.alloc(blockSize);
        out.set(decomp, 0);
      } else {
        out = Buffer.from(decomp.buffer, decomp.byteOffset, decomp.byteLength);
      }
    }

    if (this.cache.size >= this.maxCacheEntries) {
      const oldest = this.cache.keys().next().value;
      this.cache.delete(oldest);
    }
    this.cache.set(cacheKey, out);
    return out;
  }

  /**
   * Create a random-access stream view for partition `partIdx` (0 for .mrbak).
   */
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
          if (pos < part.rawHeadLen) {
            const take = Math.min(rem, part.rawHeadLen - pos);
            const headSrc = self.srcs[part.rawHeadSrcIdx || 0];
            const buf = await readExact(headSrc.fh, part.rawHeadOff + pos, take);
            chunks.push(buf);
            pos += buf.length;
            rem -= buf.length;
            if (buf.length < take) break;
            continue;
          }

          const drel = pos - part.rawHeadLen;
          const blockIdx = Math.floor(drel / part.blockSize);
          const inBlock = drel % part.blockSize;
          const take = Math.min(rem, part.blockSize - inBlock);
          const ref = blockIdx < part.blocks.length ? part.blocks[blockIdx] : null;
          if (!ref) {
            chunks.push(Buffer.alloc(take));
          } else {
            const block = await self._loadBlock(ref, part.blockSize);
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
          const src = this.srcs[b.srcIdx];
          let rawData;
          if (!this.compressed) {
            const avail = Math.max(0, src.metaOff - b.fileOffset);
            rawData = await readExact(src.fh, b.fileOffset, Math.min(part.blockSize, avail));
          } else {
            const hdrBytes = await readExact(src.fh, b.fileOffset, K_MAX_QLZ_HEADER);
            const qhdr = parseQlzHeader(hdrBytes);
            const maxCsize = part.blockSize + 9 + 4096;
            if (qhdr.compressedSize < qhdr.headerLen || qhdr.compressedSize > maxCsize) {
              throw new Error(`Invalid QuickLZ compressed block size ${qhdr.compressedSize}`);
            }
            if (qhdr.decompressedSize === 0 || qhdr.decompressedSize > part.blockSize) {
              throw new Error(`Invalid QuickLZ decompressed block size ${qhdr.decompressedSize}`);
            }
            const compBuf = await readExact(src.fh, b.fileOffset, qhdr.compressedSize);
            rawData = decompressQlz(compBuf);
          }
          const md5 = crypto.createHash('md5').update(rawData).digest();
          if (!md5.equals(b.md5)) {
            mismatches++;
            if (errors.length < 20) {
              errors.push(`Part ${part.index} block ${i}: MD5 mismatch`);
            }
          }
        } catch (err) {
          mismatches++;
          if (errors.length < 20) {
            errors.push(`Part ${part.index} block ${i}: ${err.message}`);
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
    const own = this.srcs[this.srcs.length - 1];
    return {
      format: 'Macrium Reflect v7/v8 Legacy',
      backupType: this.fileBackup ? 'File and Folder (.mrbak)' : 'Disk Image (.mrimg)',
      filePath: own.filePath,
      fileSize: own.fileSize,
      imageId: this.imageId,
      originalPath: this.originalPath,
      backupTime: this.backupTime ? new Date(this.backupTime * 1000) : null,
      compression: this.compressed ? 'QuickLZ 1.31 (Level 2)' : 'None (Store)',
      encrypted: this.encrypted,
      comment: this.comment || null,
      chainFiles: this.srcs.map((s) => ({
        fileNumber: s.fileNo,
        filePath: s.filePath,
        fileSize: s.fileSize,
      })),
      partitions: this.parts.map((p) => ({
        index: p.index,
        xmlPartitionNumber: p.xmlNum,
        blockSize: p.blockSize,
        blockCount: p.blocks.length,
        storedBlocks: p.blocks.filter(Boolean).length,
        rawHeadLength: p.rawHeadLen,
        virtualSize: p.size,
      })),
      warnings: this.warnings,
    };
  }

  async close() {
    for (const s of this.srcs) {
      await s.fh.close().catch(() => {});
    }
    this.srcs = [];
    this.cache.clear();
  }
}
