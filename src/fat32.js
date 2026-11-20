/**
 * Read-only FAT32 filesystem parser over a virtual volume reader `readAt(offset, length)`.
 *
 * Macrium Reflect .mrbak / .mrbakx File & Folder backups store all backed-up
 * files inside a "File Backup Virtual Drive" FAT32 volume (commonly with
 * 4096-byte sectors and large clusters).
 */

const ATTR_READ_ONLY = 0x01;
const ATTR_HIDDEN = 0x02;
const ATTR_SYSTEM = 0x04;
const ATTR_VOLUME_ID = 0x08;
const ATTR_DIRECTORY = 0x10;
const ATTR_ARCHIVE = 0x20;
const ATTR_LONG_NAME = ATTR_READ_ONLY | ATTR_HIDDEN | ATTR_SYSTEM | ATTR_VOLUME_ID;
const ATTR_LONG_NAME_MASK = ATTR_LONG_NAME | ATTR_DIRECTORY | ATTR_ARCHIVE;

const EOC_MIN = 0x0ffffff8;

/**
 * Decode DOS date + time (+ optional 10ms tenths) into a JS Date (UTC-naive local wall clock stored in Date UTC).
 */
function decodeDosDateTime(dateWord, timeWord, tenths = 0) {
  if (!dateWord) return null;
  const year = ((dateWord >> 9) & 0x7f) + 1980;
  const month = (dateWord >> 5) & 0x0f;
  const day = dateWord & 0x1f;
  const hour = (timeWord >> 11) & 0x1f;
  const minute = (timeWord >> 5) & 0x3f;
  const second = ((timeWord & 0x1f) * 2) + Math.floor(tenths / 100);
  const ms = (tenths % 100) * 10;
  if (month < 1 || month > 12 || day < 1 || day > 31) return null;
  return new Date(Date.UTC(year, month - 1, day, hour, minute, second, ms));
}

function decodeShortName(entry, off) {
  let base = '';
  for (let i = 0; i < 8; i++) {
    let ch = entry[off + i];
    if (i === 0 && ch === 0x05) ch = 0xe5;
    base += String.fromCharCode(ch);
  }
  base = base.replace(/ +$/, '');

  let ext = '';
  for (let i = 8; i < 11; i++) {
    ext += String.fromCharCode(entry[off + i]);
  }
  ext = ext.replace(/ +$/, '');

  const ntRes = entry[off + 12];
  if (ntRes & 0x08) base = base.toLowerCase();
  if (ntRes & 0x10) ext = ext.toLowerCase();

  return ext ? `${base}.${ext}` : base;
}

function extractLfnPart(entry, off) {
  const offsets = [
    1, 3, 5, 7, 9,
    14, 16, 18, 20, 22, 24,
    28, 30,
  ];
  let s = '';
  for (const pos of offsets) {
    const code = entry[off + pos] | (entry[off + pos + 1] << 8);
    if (code === 0x0000 || code === 0xffff) break;
    s += String.fromCharCode(code);
  }
  return s;
}

function lfnChecksum(shortBytes) {
  let sum = 0;
  for (let i = 0; i < 11; i++) {
    sum = (((sum & 1) << 7) + (sum >> 1) + shortBytes[i]) & 0xff;
  }
  return sum;
}

export function formatAttributes(attr) {
  return [
    attr & ATTR_DIRECTORY ? 'd' : '-',
    attr & ATTR_READ_ONLY ? 'r' : '-',
    attr & ATTR_HIDDEN ? 'h' : '-',
    attr & ATTR_SYSTEM ? 's' : '-',
    attr & ATTR_ARCHIVE ? 'a' : '-',
  ].join('');
}

export class Fat32Volume {
  /**
   * @param {{ readAt: (offset: number, length: number) => Promise<Uint8Array>, size: number }} volumeStream
   */
  constructor(volumeStream) {
    this.stream = volumeStream;
    this.bpb = null;
    this.fatCache = new Map(); // fatSectorIdx -> Uint8Array (LRU, max 64)
    this.maxFatCacheEntries = 64;
    this.dirCache = new Map(); // cluster -> entries[] (LRU, max 512)
    this.maxDirCacheEntries = 512;
  }

  async init() {
    const boot = await this.stream.readAt(0, 512);
    if (boot.length < 512 || boot[510] !== 0x55 || boot[511] !== 0xaa) {
      throw new Error('Invalid FAT boot sector signature (expected 0x55AA)');
    }
    const dv = new DataView(boot.buffer, boot.byteOffset, boot.byteLength);
    const bytesPerSector = dv.getUint16(11, true);
    const sectorsPerCluster = boot[13];
    const reservedSectors = dv.getUint16(14, true);
    const numFats = boot[16];
    const rootEntCnt = dv.getUint16(17, true);
    const fatSz16 = dv.getUint16(22, true);
    const totSec16 = dv.getUint16(19, true);
    const totSec32 = dv.getUint32(32, true);
    const fatSz32 = dv.getUint32(36, true);
    const rootCluster = dv.getUint32(44, true);
    const fsInfoSec = dv.getUint16(48, true);

    if (
      ![512, 1024, 2048, 4096].includes(bytesPerSector) ||
      sectorsPerCluster === 0 ||
      (sectorsPerCluster & (sectorsPerCluster - 1)) !== 0 ||
      reservedSectors === 0 ||
      numFats === 0
    ) {
      throw new Error('Unrecognized FAT BPB geometry');
    }

    if (fatSz16 !== 0 || rootEntCnt !== 0 || fatSz32 === 0) {
      throw new Error('Volume is FAT12/FAT16 rather than FAT32 (only FAT32 virtual drives are supported)');
    }

    const totalSectors = totSec16 !== 0 ? totSec16 : totSec32;
    const fatStartByte = reservedSectors * bytesPerSector;
    const fatBytes = fatSz32 * bytesPerSector;
    const dataStartSector = reservedSectors + numFats * fatSz32;
    const dataStartByte = dataStartSector * bytesPerSector;
    const clusterSize = bytesPerSector * sectorsPerCluster;
    const totalDataSectors = totalSectors > dataStartSector ? totalSectors - dataStartSector : 0;
    const totalClusters = Math.floor(totalDataSectors / sectorsPerCluster);

    const oemName = Buffer.from(boot.subarray(3, 11)).toString('ascii').replace(/\0+$/, '').trim();
    const volLabel = Buffer.from(boot.subarray(71, 82)).toString('ascii').replace(/ +$/, '');
    const fsType = Buffer.from(boot.subarray(82, 90)).toString('ascii').trim();

    let freeClusters = null;
    if (fsInfoSec > 0 && fsInfoSec < reservedSectors) {
      try {
        const fsInfo = await this.stream.readAt(fsInfoSec * bytesPerSector, 512);
        const fdv = new DataView(fsInfo.buffer, fsInfo.byteOffset, fsInfo.byteLength);
        if (fdv.getUint32(0, true) === 0x41615252) {
          const free = fdv.getUint32(488, true);
          if (free !== 0xffffffff) freeClusters = free;
        }
      } catch {
        // Ignore optional FSInfo failure
      }
    }

    this.bpb = {
      oemName,
      volLabel,
      fsType,
      bytesPerSector,
      sectorsPerCluster,
      clusterSize,
      reservedSectors,
      numFats,
      fatSz32,
      fatStartByte,
      fatBytes,
      dataStartSector,
      dataStartByte,
      rootCluster,
      totalSectors,
      totalClusters,
      freeClusters,
      volumeSizeBytes: totalSectors * bytesPerSector,
    };
    return this.bpb;
  }

  clusterToByteOffset(cluster) {
    return this.bpb.dataStartByte + (cluster - 2) * this.bpb.clusterSize;
  }

  /**
   * Read the next cluster number from FAT1 for a given cluster index.
   */
  async nextCluster(cluster) {
    const entryOff = cluster * 4;
    if (entryOff + 4 > this.bpb.fatBytes) {
      return 0x0fffffff;
    }
    const pageSize = 65536;
    const pageIdx = Math.floor(entryOff / pageSize);
    let page = this.fatCache.get(pageIdx);
    if (page) {
      this.fatCache.delete(pageIdx);
      this.fatCache.set(pageIdx, page);
    } else {
      const readLen = Math.min(pageSize, this.bpb.fatBytes - pageIdx * pageSize);
      page = await this.stream.readAt(this.bpb.fatStartByte + pageIdx * pageSize, readLen);
      if (this.fatCache.size >= this.maxFatCacheEntries) {
        const firstKey = this.fatCache.keys().next().value;
        this.fatCache.delete(firstKey);
      }
      this.fatCache.set(pageIdx, page);
    }
    const rel = entryOff - pageIdx * pageSize;
    const raw =
      (page[rel] |
        (page[rel + 1] << 8) |
        (page[rel + 2] << 16) |
        (page[rel + 3] << 24)) >>>
      0;
    return raw & 0x0fffffff;
  }

  /**
   * Follow the FAT cluster chain starting at `startCluster`.
   * @param {number} startCluster
   * @returns {Promise<number[]>}
   */
  async getClusterChain(startCluster) {
    if (startCluster < 2) return [];
    const chain = [];
    const seen = new Set();
    let cur = startCluster;
    const maxClusters = this.bpb.totalClusters + 16;
    while (cur >= 2 && cur < EOC_MIN && chain.length < maxClusters) {
      if (seen.has(cur)) {
        throw new Error(`FAT32 cluster loop detected at cluster ${cur}`);
      }
      seen.add(cur);
      chain.push(cur);
      cur = await this.nextCluster(cur);
    }
    return chain;
  }

  /**
   * Read a slice `[offset, offset + length)` from a file given its startCluster and size.
   * Uses `chain` if already resolved.
   */
  async readFileSlice(entry, offset = 0, length = Infinity, cachedChain = null) {
    if (entry.isDirectory) {
      throw new Error(`Cannot read bytes from directory: ${entry.name}`);
    }
    const start = Math.max(0, offset);
    if (start >= entry.size || length <= 0) {
      return Buffer.alloc(0);
    }
    const want = Math.min(length, entry.size - start);
    if (entry.startCluster < 2) {
      return Buffer.alloc(want);
    }

    const chain = cachedChain || (await this.getClusterChain(entry.startCluster));
    const cs = this.bpb.clusterSize;
    const firstIdx = Math.floor(start / cs);
    const lastIdx = Math.floor((start + want - 1) / cs);
    const chunks = [];
    let remaining = want;
    let inClusterOff = start % cs;

    for (let idx = firstIdx; idx <= lastIdx && remaining > 0; idx++) {
      if (idx >= chain.length) break;
      const cluster = chain[idx];
      const toRead = Math.min(remaining, cs - inClusterOff);
      const byteOff = this.clusterToByteOffset(cluster) + inClusterOff;
      const buf = await this.stream.readAt(byteOff, toRead);
      chunks.push(buf);
      remaining -= buf.length;
      inClusterOff = 0;
    }

    const result = Buffer.concat(chunks);
    return result.length > want ? result.subarray(0, want) : result;
  }

  /**
   * Stream a file's contents in chunks to a callback (for extraction / cat without full-file buffering).
   */
  async streamFile(entry, onChunk) {
    if (entry.isDirectory) {
      throw new Error(`Cannot stream directory: ${entry.name}`);
    }
    if (entry.size === 0) return;
    if (entry.startCluster < 2) {
      const zeroChunk = Buffer.alloc(Math.min(entry.size, 65536));
      let remaining = entry.size;
      while (remaining > 0) {
        const take = Math.min(remaining, zeroChunk.length);
        await onChunk(take === zeroChunk.length ? zeroChunk : zeroChunk.subarray(0, take));
        remaining -= take;
      }
      return;
    }

    const chain = await this.getClusterChain(entry.startCluster);
    const cs = this.bpb.clusterSize;
    let remaining = entry.size;
    for (const cluster of chain) {
      if (remaining <= 0) break;
      const toRead = Math.min(remaining, cs);
      const buf = await this.stream.readAt(this.clusterToByteOffset(cluster), toRead);
      await onChunk(buf);
      remaining -= buf.length;
    }
  }

  /**
   * Read and parse all directory entries in a directory starting at `dirCluster`.
   */
  async readDirectory(dirCluster) {
    const cached = this.dirCache.get(dirCluster);
    if (cached) {
      this.dirCache.delete(dirCluster);
      this.dirCache.set(dirCluster, cached);
      return cached;
    }

    const chain = await this.getClusterChain(dirCluster);
    const entries = [];
    let lfnParts = [];
    let lfnExpectedCsum = null;
    let lfnValid = false;
    let volumeLabel = null;
    let done = false;

    for (const cluster of chain) {
      if (done) break;
      const buf = await this.stream.readAt(this.clusterToByteOffset(cluster), this.bpb.clusterSize);
      const dv = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);

      for (let off = 0; off + 32 <= buf.length; off += 32) {
        const firstByte = buf[off];
        if (firstByte === 0x00) {
          done = true;
          break;
        }
        if (firstByte === 0xe5) {
          lfnParts = [];
          lfnValid = false;
          continue;
        }

        const attr = buf[off + 11];
        if ((attr & ATTR_LONG_NAME_MASK) === ATTR_LONG_NAME) {
          const ord = firstByte;
          const seq = ord & 0x1f;
          const isLast = (ord & 0x40) !== 0;
          const csum = buf[off + 13];
          const part = extractLfnPart(buf, off);
          if (isLast) {
            lfnParts = new Array(seq).fill(null);
            lfnExpectedCsum = csum;
            lfnValid = seq >= 1;
          }
          if (lfnValid && seq >= 1 && seq <= lfnParts.length && csum === lfnExpectedCsum) {
            lfnParts[seq - 1] = part;
          } else {
            lfnValid = false;
          }
          continue;
        }

        if (attr & ATTR_VOLUME_ID) {
          if (!volumeLabel) {
            volumeLabel = Buffer.from(buf.subarray(off, off + 11)).toString('ascii').replace(/ +$/, '');
          }
          lfnParts = [];
          lfnValid = false;
          continue;
        }

        const shortName = decodeShortName(buf, off);
        let name = shortName;
        if (lfnValid && lfnParts.every((p) => typeof p === 'string')) {
          const csum = lfnChecksum(buf.subarray(off, off + 11));
          if (csum === lfnExpectedCsum) {
            name = lfnParts.join('');
          }
        }
        lfnParts = [];
        lfnValid = false;

        if (name === '.' || name === '..') {
          continue;
        }

        const clusterHigh = dv.getUint16(off + 20, true);
        const clusterLow = dv.getUint16(off + 26, true);
        const startCluster = ((clusterHigh << 16) | clusterLow) >>> 0;
        const size = dv.getUint32(off + 28, true);

        const crtTimeTenth = buf[off + 13];
        const crtTime = dv.getUint16(off + 14, true);
        const crtDate = dv.getUint16(off + 16, true);
        const lstAccDate = dv.getUint16(off + 18, true);
        const wrtTime = dv.getUint16(off + 22, true);
        const wrtDate = dv.getUint16(off + 24, true);

        entries.push({
          name,
          shortName,
          attr,
          attrText: formatAttributes(attr),
          isDirectory: (attr & ATTR_DIRECTORY) !== 0,
          isHidden: (attr & (ATTR_HIDDEN | ATTR_SYSTEM)) !== 0,
          startCluster,
          size: (attr & ATTR_DIRECTORY) !== 0 ? 0 : size,
          createdAt: decodeDosDateTime(crtDate, crtTime, crtTimeTenth),
          modifiedAt: decodeDosDateTime(wrtDate, wrtTime, 0),
          accessedAt: decodeDosDateTime(lstAccDate, 0, 0),
        });
      }
    }

    if (dirCluster === this.bpb.rootCluster && volumeLabel && !this.bpb.rootVolumeLabel) {
      this.bpb.rootVolumeLabel = volumeLabel;
    }

    entries.sort((a, b) => {
      if (a.isDirectory !== b.isDirectory) return a.isDirectory ? -1 : 1;
      return a.name.localeCompare(b.name, undefined, { sensitivity: 'base' });
    });

    if (this.dirCache.size >= this.maxDirCacheEntries) {
      const oldest = this.dirCache.keys().next().value;
      this.dirCache.delete(oldest);
    }
    this.dirCache.set(dirCluster, entries);
    return entries;
  }

  /**
   * Resolve a path like `/Users/Alice/doc.txt` or `Users\Alice` from root (or relative to `cwdPath`).
   * @param {string} targetPath
   * @param {string} [cwdPath='/']
   * @returns {Promise<{ path: string, entry: object }>}
   */
  async resolvePath(targetPath, cwdPath = '/') {
    const normalized = normalizeFatPath(targetPath, cwdPath);
    if (normalized === '/') {
      return {
        path: '/',
        entry: {
          name: '/',
          shortName: '/',
          attr: ATTR_DIRECTORY,
          attrText: 'd----',
          isDirectory: true,
          isHidden: false,
          startCluster: this.bpb.rootCluster,
          size: 0,
          createdAt: null,
          modifiedAt: null,
          accessedAt: null,
        },
      };
    }

    const parts = normalized.slice(1).split('/');
    let curCluster = this.bpb.rootCluster;
    let curEntry = null;
    const resolvedParts = [];

    for (let i = 0; i < parts.length; i++) {
      const seg = parts[i];
      const entries = await this.readDirectory(curCluster);
      const segLower = seg.toLowerCase();
      const match = entries.find(
        (e) => e.name.toLowerCase() === segLower || e.shortName.toLowerCase() === segLower
      );
      if (!match) {
        throw new Error(`Path not found: ${normalized}`);
      }
      if (i < parts.length - 1 && !match.isDirectory) {
        throw new Error(`Not a directory: /${[...resolvedParts, match.name].join('/')}`);
      }
      resolvedParts.push(match.name);
      curEntry = match;
      curCluster = match.startCluster;
    }

    return {
      path: '/' + resolvedParts.join('/'),
      entry: curEntry,
    };
  }
}

/**
 * Normalize POSIX/Windows style paths inside the virtual drive.
 */
export function normalizeFatPath(inputPath = '/', cwdPath = '/') {
  let raw = (inputPath || '').replace(/\\/g, '/').trim();
  if (!raw) raw = cwdPath || '/';
  const base = raw.startsWith('/') ? [] : (cwdPath || '/').replace(/\\/g, '/').split('/').filter(Boolean);
  const parts = raw.split('/').filter(Boolean);
  const stack = [...base];
  for (const part of parts) {
    if (part === '.') continue;
    if (part === '..') {
      stack.pop();
    } else {
      stack.push(part);
    }
  }
  return '/' + stack.join('/');
}
