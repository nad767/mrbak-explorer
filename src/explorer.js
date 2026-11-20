import fs from 'node:fs';
import fsp from 'node:fs/promises';
import path from 'node:path';
import { normalizeFatPath } from './fat32.js';

export function formatBytes(bytes) {
  if (bytes === 0) return '0 B';
  const units = ['B', 'KiB', 'MiB', 'GiB', 'TiB'];
  let idx = 0;
  let val = bytes;
  while (val >= 1024 && idx < units.length - 1) {
    val /= 1024;
    idx++;
  }
  return idx === 0 ? `${val} B` : `${val.toFixed(1)} ${units[idx]}`;
}

export function formatDate(d) {
  if (!d) return '                   ';
  return d.toISOString().replace('T', ' ').slice(0, 19);
}

function globToRegExp(pattern, caseInsensitive = true) {
  let re = '^';
  for (let i = 0; i < pattern.length; i++) {
    const ch = pattern[i];
    if (ch === '*') re += '.*';
    else if (ch === '?') re += '.';
    else if ('\\^$.|+()[]{}'.includes(ch)) re += '\\' + ch;
    else re += ch;
  }
  re += '$';
  return new RegExp(re, caseInsensitive ? 'i' : '');
}

function requireFat(session) {
  if (!session.fat32) {
    throw new Error(
      `No readable FAT32 virtual drive in this backup${session.fsError ? `: ${session.fsError}` : ''}`
    );
  }
  return session.fat32;
}

export async function cmdInfo(session, opts = {}) {
  const info = session.container.getInfo();
  if (session.fat32?.bpb) {
    const bpb = session.fat32.bpb;
    info.virtualDrive = {
      volumeLabel: bpb.rootVolumeLabel || bpb.volLabel || 'File Backup Virtual Drive',
      oemName: bpb.oemName,
      fileSystem: bpb.fsType || 'FAT32',
      bytesPerSector: bpb.bytesPerSector,
      sectorsPerCluster: bpb.sectorsPerCluster,
      clusterSize: bpb.clusterSize,
      totalClusters: bpb.totalClusters,
      freeClusters: bpb.freeClusters,
      volumeSizeBytes: bpb.volumeSizeBytes,
    };
  } else if (session.fsError) {
    info.virtualDriveError = session.fsError;
  }

  if (opts.json) {
    return JSON.stringify(info, null, 2);
  }

  const lines = [];
  lines.push(`Format        : ${info.format}`);
  lines.push(`Backup Type   : ${info.backupType}`);
  lines.push(`File          : ${info.filePath} (${formatBytes(info.fileSize)})`);
  lines.push(`Image ID      : ${info.imageId}`);
  if (info.backupGuid) lines.push(`Backup GUID   : ${info.backupGuid}`);
  if (info.netbiosName) lines.push(`Host          : ${info.netbiosName}`);
  if (info.reflectVersion) lines.push(`Reflect Ver   : ${info.reflectVersion}`);
  if (info.originalPath) lines.push(`Original Path : ${info.originalPath}`);
  if (info.backupTime) lines.push(`Backup Time   : ${info.backupTime.toISOString()}`);
  lines.push(`Compression   : ${info.compression}`);
  lines.push(
    `Encryption    : ${info.encrypted ? `Yes (${info.encryptionType || 'AES'})` : 'No'}`
  );
  if (info.comment) lines.push(`Comment       : ${info.comment}`);
  if (info.chainFiles.length > 1) {
    lines.push(`Chain Files   : ${info.chainFiles.length}`);
    for (const cf of info.chainFiles) {
      lines.push(`  [${cf.fileNumber}] ${path.basename(cf.filePath)} (${formatBytes(cf.fileSize)})`);
    }
  }
  for (const p of info.partitions) {
    lines.push(
      `Partition ${p.index}   : ${formatBytes(p.virtualSize)}, blockSize=${formatBytes(p.blockSize)}, blocks=${p.storedBlocks}/${p.blockCount}`
    );
  }
  if (info.virtualDrive) {
    const vd = info.virtualDrive;
    lines.push(
      `Virtual Drive : ${vd.fileSystem} ("${vd.volumeLabel}"), sector=${vd.bytesPerSector}B, cluster=${formatBytes(vd.clusterSize)}, size=${formatBytes(vd.volumeSizeBytes)}`
    );
  } else if (info.virtualDriveError) {
    lines.push(`Virtual Drive : Unavailable (${info.virtualDriveError})`);
  }
  for (const w of info.warnings) {
    lines.push(`Warning       : ${w}`);
  }
  return lines.join('\n');
}

export async function cmdLs(session, targetPath = '/', opts = {}) {
  const fat = requireFat(session);
  const resolved = await fat.resolvePath(targetPath, opts.cwd || '/');

  if (!resolved.entry.isDirectory) {
    if (opts.json) return JSON.stringify([resolved.entry], null, 2);
    return formatEntries([resolved.entry], opts);
  }

  if (!opts.recursive) {
    const entries = await fat.readDirectory(resolved.entry.startCluster);
    const filtered = opts.all ? entries : entries.filter((e) => !e.isHidden);
    if (opts.json) return JSON.stringify(filtered, null, 2);
    return formatEntries(filtered, opts);
  }

  const results = [];
  const visited = new Set([resolved.entry.startCluster]);
  const walk = async (cluster, prefix) => {
    const entries = await fat.readDirectory(cluster);
    const filtered = opts.all ? entries : entries.filter((e) => !e.isHidden);
    for (const e of filtered) {
      const fullPath = prefix === '/' ? `/${e.name}` : `${prefix}/${e.name}`;
      results.push({ ...e, path: fullPath });
      if (e.isDirectory && e.startCluster >= 2 && !visited.has(e.startCluster)) {
        visited.add(e.startCluster);
        await walk(e.startCluster, fullPath);
      }
    }
  };
  await walk(resolved.entry.startCluster, resolved.path);

  if (opts.json) return JSON.stringify(results, null, 2);
  return formatEntries(
    results.map((r) => ({ ...r, name: r.path })),
    opts
  );
}

function formatEntries(entries, opts) {
  if (entries.length === 0) return '(empty)';
  if (!opts.long) {
    return entries
      .map((e) => (e.isDirectory ? `${e.name}/` : e.name))
      .join('\n');
  }
  const sizeWidth = Math.max(
    6,
    ...entries.map((e) => (e.isDirectory ? 5 : String(e.size).length))
  );
  return entries
    .map((e) => {
      const sizeStr = (e.isDirectory ? '<DIR>' : String(e.size)).padStart(sizeWidth);
      const dateStr = formatDate(e.modifiedAt || e.createdAt);
      const suffix = e.isDirectory ? '/' : '';
      return `${e.attrText}  ${sizeStr}  ${dateStr}  ${e.name}${suffix}`;
    })
    .join('\n');
}

export async function cmdTree(session, targetPath = '/', opts = {}) {
  const fat = requireFat(session);
  const resolved = await fat.resolvePath(targetPath, opts.cwd || '/');
  const maxDepth = opts.maxDepth ?? Infinity;

  const lines = [resolved.path];
  let dirCount = 0;
  let fileCount = 0;
  let totalBytes = 0;
  const visited = new Set([resolved.entry.startCluster]);

  const walk = async (cluster, prefix, depth) => {
    if (depth >= maxDepth) return;
    const entries = await fat.readDirectory(cluster);
    const filtered = opts.all ? entries : entries.filter((e) => !e.isHidden);
    for (let i = 0; i < filtered.length; i++) {
      const e = filtered[i];
      const isLast = i === filtered.length - 1;
      const branch = isLast ? '└── ' : '├── ';
      const nextPrefix = prefix + (isLast ? '    ' : '│   ');
      if (e.isDirectory) {
        dirCount++;
        lines.push(`${prefix}${branch}${e.name}/`);
        if (e.startCluster >= 2 && !visited.has(e.startCluster)) {
          visited.add(e.startCluster);
          await walk(e.startCluster, nextPrefix, depth + 1);
        }
      } else {
        fileCount++;
        totalBytes += e.size;
        lines.push(`${prefix}${branch}${e.name} (${formatBytes(e.size)})`);
      }
    }
  };

  if (resolved.entry.isDirectory) {
    await walk(resolved.entry.startCluster, '', 0);
  }
  lines.push('');
  lines.push(`${dirCount} directories, ${fileCount} files (${formatBytes(totalBytes)})`);
  return lines.join('\n');
}

export async function cmdFind(session, pattern, opts = {}) {
  const fat = requireFat(session);
  const startPath = opts.path || opts.cwd || '/';
  const resolved = await fat.resolvePath(startPath, opts.cwd || '/');
  const hasWildcard = /[*?]/.test(pattern);
  const re = hasWildcard ? globToRegExp(pattern, true) : null;
  const needle = pattern.toLowerCase();
  const typeFilter = opts.type || null; // 'f' | 'd'
  if (typeFilter && typeFilter !== 'f' && typeFilter !== 'd') {
    throw new Error(`Invalid --type filter "${typeFilter}" (expected "f" or "d")`);
  }

  const matches = [];
  const visited = new Set([resolved.entry.startCluster]);
  const walk = async (cluster, prefix) => {
    const entries = await fat.readDirectory(cluster);
    for (const e of entries) {
      const fullPath = prefix === '/' ? `/${e.name}` : `${prefix}/${e.name}`;
      const typeOk =
        !typeFilter ||
        (typeFilter === 'd' && e.isDirectory) ||
        (typeFilter === 'f' && !e.isDirectory);
      const nameOk = re
        ? re.test(e.name) || re.test(fullPath)
        : e.name.toLowerCase().includes(needle) || fullPath.toLowerCase().includes(needle);
      if (typeOk && nameOk) {
        matches.push({ ...e, path: fullPath });
      }
      if (e.isDirectory && e.startCluster >= 2 && !visited.has(e.startCluster)) {
        visited.add(e.startCluster);
        await walk(e.startCluster, fullPath);
      }
    }
  };

  if (resolved.entry.isDirectory) {
    await walk(resolved.entry.startCluster, resolved.path);
  }

  if (opts.json) return JSON.stringify(matches, null, 2);
  if (matches.length === 0) return 'No matches found.';
  return matches
    .map((m) =>
      m.isDirectory
        ? `${m.attrText}  ${'<DIR>'.padStart(10)}  ${m.path}/`
        : `${m.attrText}  ${String(m.size).padStart(10)}  ${m.path}`
    )
    .join('\n');
}

export async function cmdStat(session, targetPath, opts = {}) {
  const fat = requireFat(session);
  const resolved = await fat.resolvePath(targetPath, opts.cwd || '/');
  const e = resolved.entry;
  const chain = e.startCluster >= 2 ? await fat.getClusterChain(e.startCluster) : [];
  const detail = {
    path: resolved.path,
    name: e.name,
    shortName: e.shortName,
    type: e.isDirectory ? 'directory' : 'file',
    attributes: e.attrText,
    size: e.size,
    startCluster: e.startCluster,
    clusterCount: chain.length,
    allocatedBytes: chain.length * fat.bpb.clusterSize,
    createdAt: e.createdAt,
    modifiedAt: e.modifiedAt,
    accessedAt: e.accessedAt,
  };
  if (opts.json) return JSON.stringify(detail, null, 2);
  return [
    `Path          : ${detail.path}`,
    `Short Name    : ${detail.shortName}`,
    `Type          : ${detail.type}`,
    `Attributes    : ${detail.attributes}`,
    `Size          : ${detail.size} bytes (${formatBytes(detail.size)})`,
    `Start Cluster : ${detail.startCluster} (${detail.clusterCount} clusters, ${formatBytes(detail.allocatedBytes)} allocated)`,
    `Created       : ${detail.createdAt ? detail.createdAt.toISOString() : 'N/A'}`,
    `Modified      : ${detail.modifiedAt ? detail.modifiedAt.toISOString() : 'N/A'}`,
    `Accessed      : ${detail.accessedAt ? detail.accessedAt.toISOString() : 'N/A'}`,
  ].join('\n');
}

async function writeStreamChunk(ws, chunk, getStreamErr = null) {
  if (!ws.write(chunk)) {
    await new Promise((res, rej) => {
      const cleanup = () => {
        ws.off('drain', onDrain);
        ws.off('error', onDrainErr);
        ws.off('close', onDrainClose);
      };
      const onDrain = () => { cleanup(); res(); };
      const onDrainErr = (err) => { cleanup(); rej(err); };
      const onDrainClose = () => {
        cleanup();
        const existingErr = getStreamErr ? getStreamErr() : null;
        rej(existingErr || new Error('Write stream closed unexpectedly'));
      };
      ws.once('drain', onDrain);
      ws.once('error', onDrainErr);
      ws.once('close', onDrainClose);
    });
  }
}

export async function cmdCat(session, targetPath, opts = {}) {
  const fat = requireFat(session);
  const resolved = await fat.resolvePath(targetPath, opts.cwd || '/');
  if (resolved.entry.isDirectory) {
    throw new Error(`Cannot read directory: ${resolved.path}`);
  }
  const offset = opts.offset ?? 0;
  const limit = opts.limit ?? Infinity;

  if (opts.tail !== undefined && (offset > 0 || Number.isFinite(limit))) {
    throw new Error('Cannot combine --tail with --offset or --limit');
  }

  if (offset > 0 || Number.isFinite(limit)) {
    const buf = await fat.readFileSlice(resolved.entry, offset, limit);
    if (opts.writeStream) {
      await writeStreamChunk(opts.writeStream, buf);
      return '';
    }
    return buf.toString('utf8');
  }

  if (opts.tail !== undefined) {
    const tailBytes = Math.max(0, opts.tail);
    const start = Math.max(0, resolved.entry.size - tailBytes);
    const buf = await fat.readFileSlice(resolved.entry, start, tailBytes);
    if (opts.writeStream) {
      await writeStreamChunk(opts.writeStream, buf);
      return '';
    }
    return buf.toString('utf8');
  }

  const chunks = [];
  await fat.streamFile(resolved.entry, async (chunk) => {
    if (opts.writeStream) {
      await writeStreamChunk(opts.writeStream, chunk);
    } else {
      chunks.push(chunk);
    }
  });
  return opts.writeStream ? '' : Buffer.concat(chunks).toString('utf8');
}

const WINDOWS_RESERVED_NAME_RE = /^(con|prn|aux|nul|com[1-9]|lpt[1-9])(\..*)?$/i;

function sanitizeExtractName(name) {
  let safe = String(name || '')
    .replace(/[\x00-\x1f\\/:*?"<>|]/g, '_')
    .replace(/[. ]+$/, '');
  if (!safe || safe === '.' || safe === '..') return null;
  if (process.platform === 'win32' && WINDOWS_RESERVED_NAME_RE.test(safe)) {
    safe = `_${safe}`;
  }
  return safe;
}

function resolveSafeChild(parentDir, childName) {
  const resolvedParent = path.resolve(parentDir);
  const target = path.resolve(resolvedParent, childName);
  const rel = path.relative(resolvedParent, target);
  if (!rel || rel.startsWith('..') || path.isAbsolute(rel)) {
    throw new Error(`Refusing path traversal outside destination: ${childName}`);
  }
  return target;
}

export async function cmdExtract(session, innerPath = '/', outDir = './extracted', opts = {}) {
  const fat = requireFat(session);
  const resolved = await fat.resolvePath(innerPath || '/', opts.cwd || '/');
  const destRoot = path.resolve(outDir);
  await fsp.mkdir(destRoot, { recursive: true });

  let filesExtracted = 0;
  let dirsCreated = 0;
  let bytesExtracted = 0;

  const extractFile = async (entry, destFile) => {
    await fsp.mkdir(path.dirname(destFile), { recursive: true });
    if (!opts.overwrite && fs.existsSync(destFile)) {
      throw new Error(`Destination file already exists (use --overwrite): ${destFile}`);
    }
    const ws = fs.createWriteStream(destFile);
    let streamErr = null;
    const onWsErr = (err) => {
      if (!streamErr) streamErr = err;
    };
    ws.on('error', onWsErr);
    try {
      await fat.streamFile(entry, async (chunk) => {
        if (streamErr) throw streamErr;
        await writeStreamChunk(ws, chunk, () => streamErr);
      });
      if (streamErr) throw streamErr;
      await new Promise((res, rej) => {
        if (ws.writableFinished) { res(); return; }
        const cleanup = () => {
          ws.off('finish', onFinish);
          ws.off('error', onEndErr);
        };
        const onFinish = () => { cleanup(); res(); };
        const onEndErr = (err) => { cleanup(); rej(err); };
        ws.once('finish', onFinish);
        ws.once('error', onEndErr);
        ws.end();
      });
    } catch (err) {
      ws.destroy();
      throw err;
    } finally {
      ws.off('error', onWsErr);
    }
    if (opts.preserveTimestamps && (entry.modifiedAt || entry.createdAt)) {
      const mtime = entry.modifiedAt || entry.createdAt;
      const atime = entry.accessedAt || mtime;
      await fsp.utimes(destFile, atime, mtime).catch(() => {});
    }
    filesExtracted++;
    bytesExtracted += entry.size;
  };

  if (!resolved.entry.isDirectory) {
    const safeFileName = sanitizeExtractName(resolved.entry.name);
    if (!safeFileName) {
      throw new Error(`Refusing to extract unsafe filename: ${resolved.entry.name}`);
    }
    const destFile = resolveSafeChild(destRoot, safeFileName);
    await extractFile(resolved.entry, destFile);
    return { filesExtracted, dirsCreated, bytesExtracted, destRoot };
  }

  let baseDest = destRoot;
  if (resolved.path !== '/') {
    const safeDirName = sanitizeExtractName(resolved.entry.name);
    if (!safeDirName) {
      throw new Error(`Refusing to extract unsafe directory name: ${resolved.entry.name}`);
    }
    baseDest = resolveSafeChild(destRoot, safeDirName);
  }

  const visited = new Set([resolved.entry.startCluster]);
  const walkExtract = async (cluster, curDest) => {
    await fsp.mkdir(curDest, { recursive: true });
    dirsCreated++;
    const entries = await fat.readDirectory(cluster);
    for (const e of entries) {
      const safeName = sanitizeExtractName(e.name);
      if (!safeName) continue;
      const target = resolveSafeChild(curDest, safeName);
      if (e.isDirectory) {
        if (e.startCluster >= 2) {
          if (!visited.has(e.startCluster)) {
            visited.add(e.startCluster);
            await walkExtract(e.startCluster, target);
          }
        } else {
          await fsp.mkdir(target, { recursive: true });
          dirsCreated++;
        }
      } else {
        await extractFile(e, target);
      }
    }
  };

  await walkExtract(resolved.entry.startCluster, baseDest);
  return { filesExtracted, dirsCreated, bytesExtracted, destRoot };
}

export function cmdMetadata(session) {
  const c = session.container;
  if (c.format === 'reflect-x') {
    return JSON.stringify(c.json, null, 2);
  }
  return c.xmlText || '(no XML metadata found)';
}

export function joinInnerPath(cwd, target) {
  return normalizeFatPath(target, cwd);
}
