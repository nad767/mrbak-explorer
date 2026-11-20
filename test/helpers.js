import assert from 'node:assert/strict';

/**
 * Build a minimal, valid 4096-byte-sector FAT32 virtual drive image in memory,
 * mirroring Macrium Reflect's "File Backup Virtual Drive" layout.
 */
export function buildSyntheticFat32Volume(files) {
  const bps = 4096;
  const spc = 2; // 8 KiB clusters
  const clusterSize = bps * spc;
  const reservedSectors = 2;
  const numFats = 2;
  const fatSz32 = 2; // 8192 bytes = 2048 FAT entries
  const dataStartSector = reservedSectors + numFats * fatSz32; // sector 6
  const totalClusters = 256;
  const totalSectors = dataStartSector + totalClusters * spc;
  const disk = Buffer.alloc(totalSectors * bps);

  // Boot sector (sector 0)
  disk[0] = 0xeb;
  disk[1] = 0x58;
  disk[2] = 0x90;
  disk.write('MSDOS5.0', 3, 'ascii');
  disk.writeUInt16LE(bps, 11);
  disk[13] = spc;
  disk.writeUInt16LE(reservedSectors, 14);
  disk[16] = numFats;
  disk.writeUInt16LE(0, 17); // RootEntCnt = 0
  disk.writeUInt16LE(0, 19); // TotSec16 = 0
  disk[21] = 0xf8;
  disk.writeUInt16LE(0, 22); // FATSz16 = 0
  disk.writeUInt32LE(totalSectors, 32);
  disk.writeUInt32LE(fatSz32, 36);
  disk.writeUInt32LE(2, 44); // RootClus = 2
  disk.writeUInt16LE(1, 48); // FSInfo = 1
  disk.write('File Backup', 71, 'ascii');
  disk.write('FAT32   ', 82, 'ascii');
  disk[510] = 0x55;
  disk[511] = 0xaa;

  // FSInfo sector (sector 1)
  disk.writeUInt32LE(0x41615252, bps + 0);
  disk.writeUInt32LE(0x61417272, bps + 484);
  disk.writeUInt32LE(200, bps + 488);
  disk.writeUInt32LE(0xaa550000, bps + 508);

  const fat1Off = reservedSectors * bps;
  const fat2Off = (reservedSectors + fatSz32) * bps;
  const dataOff = dataStartSector * bps;

  const setFat = (cluster, val) => {
    disk.writeUInt32LE(val >>> 0, fat1Off + cluster * 4);
    disk.writeUInt32LE(val >>> 0, fat2Off + cluster * 4);
  };

  setFat(0, 0x0ffffff8);
  setFat(1, 0x0fffffff);
  setFat(2, 0x0fffffff); // root cluster

  let nextCluster = 3;
  const allocChain = (byteSize) => {
    const needed = Math.max(1, Math.ceil(byteSize / clusterSize));
    const chain = [];
    for (let i = 0; i < needed; i++) {
      chain.push(nextCluster++);
    }
    for (let i = 0; i < chain.length; i++) {
      setFat(chain[i], i + 1 < chain.length ? chain[i + 1] : 0x0fffffff);
    }
    return chain;
  };

  const clusterOffset = (c) => dataOff + (c - 2) * clusterSize;

  const lfnChecksum = (short11) => {
    let sum = 0;
    for (let i = 0; i < 11; i++) {
      sum = (((sum & 1) << 7) + (sum >> 1) + short11[i]) & 0xff;
    }
    return sum;
  };

  const makeShort11 = (name, idx) => {
    const dot = name.lastIndexOf('.');
    const rawBase = (dot > 0 ? name.slice(0, dot) : name)
      .toUpperCase()
      .replace(/[^A-Z0-9]/g, '_');
    const rawExt = (dot > 0 ? name.slice(dot + 1) : '')
      .toUpperCase()
      .replace(/[^A-Z0-9]/g, '');
    const base = (rawBase.slice(0, 6) + '~' + ((idx % 9) + 1)).padEnd(8, ' ').slice(0, 8);
    const ext = rawExt.padEnd(3, ' ').slice(0, 3);
    return Buffer.from(base + ext, 'ascii');
  };

  const dirEntriesMap = new Map();
  dirEntriesMap.set(2, []);

  const ensureDir = (parts) => {
    let curCluster = 2;
    for (const dirName of parts) {
      let existing = dirEntriesMap.get(curCluster).find((e) => e.name === dirName);
      if (!existing) {
        const newCluster = nextCluster++;
        setFat(newCluster, 0x0fffffff);
        dirEntriesMap.set(newCluster, []);
        existing = {
          name: dirName,
          isDir: true,
          cluster: newCluster,
          size: 0,
          attr: 0x10,
        };
        dirEntriesMap.get(curCluster).push(existing);
      }
      curCluster = existing.cluster;
    }
    return curCluster;
  };

  for (const f of files) {
    const segs = f.path.replace(/^\/+/, '').split('/').filter(Boolean);
    const fileName = segs.pop();
    const parentCluster = ensureDir(segs);
    const data = Buffer.isBuffer(f.content) ? f.content : Buffer.from(f.content, 'utf8');
    let startCluster = 0;
    if (data.length > 0) {
      const chain = allocChain(data.length);
      startCluster = chain[0];
      for (let i = 0; i < chain.length; i++) {
        const slice = data.subarray(i * clusterSize, (i + 1) * clusterSize);
        slice.copy(disk, clusterOffset(chain[i]));
      }
    }
    dirEntriesMap.get(parentCluster).push({
      name: fileName,
      isDir: false,
      cluster: startCluster,
      size: data.length,
      attr: f.attr ?? 0x20,
    });
  }

  let shortCounter = 0;
  for (const [dirCluster, items] of dirEntriesMap.entries()) {
    const dirBuf = Buffer.alloc(clusterSize);
    let off = 0;

    for (const item of items) {
      assert.ok(off + 32 <= clusterSize, 'Synthetic test dir overflow');
      const short11 = makeShort11(item.name, shortCounter++);
      const csum = lfnChecksum(short11);
      const lfnCount = Math.ceil(item.name.length / 13);

      for (let seq = lfnCount; seq >= 1; seq--) {
        const ord = seq | (seq === lfnCount ? 0x40 : 0);
        dirBuf[off] = ord;
        dirBuf[off + 11] = 0x0f;
        dirBuf[off + 12] = 0;
        dirBuf[off + 13] = csum;
        dirBuf.writeUInt16LE(0, off + 26);

        const chunk = item.name.slice((seq - 1) * 13, seq * 13);
        const charOffsets = [1, 3, 5, 7, 9, 14, 16, 18, 20, 22, 24, 28, 30];
        for (let ci = 0; ci < 13; ci++) {
          let code;
          if (ci < chunk.length) code = chunk.charCodeAt(ci);
          else if (ci === chunk.length) code = 0x0000;
          else code = 0xffff;
          dirBuf.writeUInt16LE(code, off + charOffsets[ci]);
        }
        off += 32;
      }

      short11.copy(dirBuf, off);
      dirBuf[off + 11] = item.attr;
      dirBuf.writeUInt16LE(25541, off + 14);
      dirBuf.writeUInt16LE(23924, off + 16);
      dirBuf.writeUInt16LE(23924, off + 18);
      dirBuf.writeUInt16LE((item.cluster >>> 16) & 0xffff, off + 20);
      dirBuf.writeUInt16LE(25541, off + 22);
      dirBuf.writeUInt16LE(23924, off + 24);
      dirBuf.writeUInt16LE(item.cluster & 0xffff, off + 26);
      dirBuf.writeUInt32LE(item.size, off + 28);
      off += 32;
    }

    dirBuf.copy(disk, clusterOffset(dirCluster));
  }

  return {
    disk,
    bps,
    spc,
    clusterSize,
    headLen: dataStartSector * bps,
    totalLen: disk.length,
  };
}
