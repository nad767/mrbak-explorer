import http from 'node:http';
import fsp from 'node:fs/promises';
import path from 'node:path';
import { execFile } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { openMrbak } from './container.js';
import { cmdExtract } from './explorer.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const INDEX_HTML_PATH = path.join(__dirname, 'web', 'index.html');

const IMAGE_EXTS = new Set(['.png', '.jpg', '.jpeg', '.gif', '.webp', '.bmp', '.svg', '.ico']);
const MIME_TYPES = {
  '.html': 'text/html; charset=utf-8',
  '.txt': 'text/plain; charset=utf-8',
  '.log': 'text/plain; charset=utf-8',
  '.md': 'text/markdown; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.xml': 'application/xml; charset=utf-8',
  '.csv': 'text/csv; charset=utf-8',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.gif': 'image/gif',
  '.webp': 'image/webp',
  '.bmp': 'image/bmp',
  '.svg': 'image/svg+xml',
  '.pdf': 'application/pdf',
};

function sendJson(res, statusCode, obj) {
  const body = JSON.stringify(obj);
  res.writeHead(statusCode, {
    'Content-Type': 'application/json; charset=utf-8',
    'Content-Length': Buffer.byteLength(body),
    'Cache-Control': 'no-store',
    'X-Content-Type-Options': 'nosniff',
  });
  res.end(body);
}

function formatContentDisposition(filename) {
  const asciiFallback = String(filename || 'download')
    .replace(/[^\x20-\x7e]/g, '_')
    .replace(/["\\]/g, '_');
  const encoded = encodeURIComponent(String(filename || 'download')).replace(
    /[!'()*]/g,
    (c) => '%' + c.charCodeAt(0).toString(16).toUpperCase()
  );
  return `attachment; filename="${asciiFallback}"; filename*=UTF-8''${encoded}`;
}

async function readJsonBody(req) {
  const chunks = [];
  let total = 0;
  for await (const chunk of req) {
    total += chunk.length;
    if (total > 1024 * 1024) {
      const err = new Error('Request body too large');
      err.statusCode = 413;
      throw err;
    }
    chunks.push(chunk);
  }
  if (chunks.length === 0) return {};
  const ct = (req.headers['content-type'] || '').toLowerCase();
  if (!ct.includes('application/json')) {
    const err = new Error('Content-Type must be application/json');
    err.statusCode = 415;
    throw err;
  }
  return JSON.parse(Buffer.concat(chunks).toString('utf8'));
}

function isAllowedHostHeader(hostHeader, boundPort) {
  if (!hostHeader) return true;
  const m = String(hostHeader).match(/^(\[[0-9a-fA-F:]+\]|[^:]+)(?::(\d+))?$/);
  if (!m) return false;
  const hostname = m[1].toLowerCase();
  const portPart = m[2];
  if (hostname !== '127.0.0.1' && hostname !== 'localhost' && hostname !== '[::1]') {
    return false;
  }
  if (portPart !== undefined && boundPort && Number(portPart) !== boundPort) {
    return false;
  }
  return true;
}

function isAllowedCrossSiteCheck(req, boundPort) {
  const sfs = (req.headers['sec-fetch-site'] || '').toLowerCase();
  if (sfs && sfs !== 'same-origin' && sfs !== 'none') {
    return false;
  }
  const origin = req.headers.origin;
  if (origin) {
    const allowed = new Set([
      `http://127.0.0.1:${boundPort}`,
      `http://localhost:${boundPort}`,
      `http://[::1]:${boundPort}`,
    ]);
    if (!allowed.has(origin.toLowerCase())) {
      return false;
    }
  }
  return true;
}

function formatHexDump(buf) {
  const lines = [];
  for (let off = 0; off < buf.length; off += 16) {
    const slice = buf.subarray(off, off + 16);
    const hex = Array.from(slice, (b) => b.toString(16).padStart(2, '0')).join(' ').padEnd(47, ' ');
    const ascii = Array.from(slice, (b) => (b >= 0x20 && b <= 0x7e ? String.fromCharCode(b) : '.')).join('');
    lines.push(`${off.toString(16).padStart(8, '0')}  ${hex}  |${ascii}|`);
  }
  return lines.join('\n');
}

function isLikelyText(buf) {
  if (buf.length === 0) return true;
  let weird = 0;
  for (let i = 0; i < buf.length; i++) {
    const b = buf[i];
    if (b === 0) return false;
    if (b < 0x09 || (b > 0x0d && b < 0x20)) weird++;
  }
  return weird / buf.length < 0.05;
}

function buildInfoPayload(session) {
  const info = session.container.getInfo();
  if (session.fat32?.bpb) {
    const bpb = session.fat32.bpb;
    info.virtualDrive = {
      volumeLabel: bpb.rootVolumeLabel || bpb.volLabel || 'File Backup Virtual Drive',
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
  return info;
}

function openNativeWindowsDialog(mode) {
  return new Promise((resolve, reject) => {
    if (process.platform !== 'win32') {
      reject(new Error('Native file picker is only available on Windows; type the path directly.'));
      return;
    }
    const script =
      mode === 'folder'
        ? `Add-Type -AssemblyName System.Windows.Forms; $d = New-Object System.Windows.Forms.FolderBrowserDialog; if ($d.ShowDialog() -eq 'OK') { $d.SelectedPath }`
        : `Add-Type -AssemblyName System.Windows.Forms; $d = New-Object System.Windows.Forms.OpenFileDialog; $d.Filter = 'Macrium Backups (*.mrbak;*.mrbakx;*.mrimg;*.mrimgx)|*.mrbak;*.mrbakx;*.mrimg;*.mrimgx|All files (*.*)|*.*'; if ($d.ShowDialog() -eq 'OK') { $d.FileName }`;
    execFile('powershell.exe', ['-NoProfile', '-STA', '-Command', script], { timeout: 120000 }, (err, stdout) => {
      if (err) {
        reject(new Error(`Dialog failed: ${err.message}`));
        return;
      }
      resolve(stdout.trim() || null);
    });
  });
}

function globToRegExp(pattern) {
  let re = '^';
  for (let i = 0; i < pattern.length; i++) {
    const ch = pattern[i];
    if (ch === '*') re += '.*';
    else if (ch === '?') re += '.';
    else if ('\\^$.|+()[]{}'.includes(ch)) re += '\\' + ch;
    else re += ch;
  }
  re += '$';
  return new RegExp(re, 'i');
}

export async function startGuiServer(options = {}) {
  const host = options.host || '127.0.0.1';
  const port = options.port ?? 0;
  const htmlBytes = await fsp.readFile(INDEX_HTML_PATH);

  let session = null;
  let initialFile = options.initialFile || null;
  let initialError = null;

  if (initialFile) {
    try {
      session = await openMrbak(initialFile, {
        password: options.password,
        partition: options.partition ?? 0,
      });
    } catch (err) {
      initialError = err.message;
    }
  }

  const requireFat = () => {
    if (!session) throw new Error('No backup file is currently open');
    if (!session.fat32) {
      throw new Error(`No readable FAT32 virtual drive${session.fsError ? `: ${session.fsError}` : ''}`);
    }
    return session.fat32;
  };

  const server = http.createServer(async (req, res) => {
    const boundPort = server.address()?.port || port;
    if (!isAllowedHostHeader(req.headers.host, boundPort)) {
      sendJson(res, 403, { error: 'Forbidden Host header' });
      return;
    }
    if (req.method !== 'GET' && req.method !== 'HEAD' && !isAllowedCrossSiteCheck(req, boundPort)) {
      sendJson(res, 403, { error: 'Forbidden cross-origin request' });
      return;
    }
    try {
      const u = new URL(req.url, `http://127.0.0.1:${boundPort || 80}`);
      const pathname = u.pathname;

      if (req.method === 'GET' && pathname === '/') {
        res.writeHead(200, {
          'Content-Type': 'text/html; charset=utf-8',
          'Content-Length': htmlBytes.length,
          'X-Content-Type-Options': 'nosniff',
        });
        res.end(htmlBytes);
        return;
      }

      if (req.method === 'GET' && pathname === '/api/state') {
        sendJson(res, 200, {
          open: Boolean(session),
          info: session ? buildInfoPayload(session) : null,
          initialFile,
          initialError,
          platform: process.platform,
        });
        return;
      }

      if (req.method === 'POST' && pathname === '/api/open') {
        const body = await readJsonBody(req);
        if (!body.filePath) {
          sendJson(res, 400, { error: 'Missing filePath' });
          return;
        }
        const nextSession = await openMrbak(body.filePath, {
          password: body.password || null,
          partition: body.partition ?? 0,
        });
        if (session) await session.close();
        session = nextSession;
        initialFile = body.filePath;
        initialError = null;
        sendJson(res, 200, { open: true, info: buildInfoPayload(session) });
        return;
      }

      if (req.method === 'POST' && pathname === '/api/close') {
        if (session) {
          await session.close();
          session = null;
        }
        sendJson(res, 200, { open: false });
        return;
      }

      if (req.method === 'GET' && pathname === '/api/ls') {
        const fat = requireFat();
        const target = u.searchParams.get('path') || '/';
        const showAll = u.searchParams.get('all') === '1';
        const resolved = await fat.resolvePath(target, '/');
        if (!resolved.entry.isDirectory) {
          sendJson(res, 200, { path: resolved.path, entries: [resolved.entry] });
          return;
        }
        const entries = await fat.readDirectory(resolved.entry.startCluster);
        sendJson(res, 200, {
          path: resolved.path,
          entries: showAll ? entries : entries.filter((e) => !e.isHidden),
        });
        return;
      }

      if (req.method === 'GET' && pathname === '/api/stat') {
        const fat = requireFat();
        const target = u.searchParams.get('path') || '/';
        const resolved = await fat.resolvePath(target, '/');
        const e = resolved.entry;
        const chain = e.startCluster >= 2 ? await fat.getClusterChain(e.startCluster) : [];
        sendJson(res, 200, {
          path: resolved.path,
          name: e.name,
          shortName: e.shortName,
          type: e.isDirectory ? 'directory' : 'file',
          attributes: e.attrText,
          size: e.size,
          startCluster: e.startCluster,
          clusterCount: chain.length,
          createdAt: e.createdAt,
          modifiedAt: e.modifiedAt,
          accessedAt: e.accessedAt,
        });
        return;
      }

      if (req.method === 'GET' && pathname === '/api/find') {
        const fat = requireFat();
        const q = (u.searchParams.get('q') || '').trim();
        if (!q) {
          sendJson(res, 200, { matches: [] });
          return;
        }
        const hasWild = /[*?]/.test(q);
        const re = hasWild ? globToRegExp(q) : null;
        const needle = q.toLowerCase();
        const matches = [];
        const visited = new Set([fat.bpb.rootCluster]);
        const walk = async (cluster, prefix) => {
          const entries = await fat.readDirectory(cluster);
          for (const e of entries) {
            const fullPath = prefix === '/' ? `/${e.name}` : `${prefix}/${e.name}`;
            const hit = re
              ? re.test(e.name) || re.test(fullPath)
              : e.name.toLowerCase().includes(needle) || fullPath.toLowerCase().includes(needle);
            if (hit) matches.push({ ...e, path: fullPath });
            if (
              e.isDirectory &&
              e.startCluster >= 2 &&
              matches.length < 2000 &&
              !visited.has(e.startCluster)
            ) {
              visited.add(e.startCluster);
              await walk(e.startCluster, fullPath);
            }
          }
        };
        await walk(fat.bpb.rootCluster, '/');
        sendJson(res, 200, { matches });
        return;
      }

      if (req.method === 'GET' && pathname === '/api/preview') {
        const fat = requireFat();
        const target = u.searchParams.get('path') || '/';
        const resolved = await fat.resolvePath(target, '/');
        if (resolved.entry.isDirectory) {
          sendJson(res, 400, { error: 'Cannot preview directory' });
          return;
        }
        const ext = path.extname(resolved.entry.name).toLowerCase();
        if (IMAGE_EXTS.has(ext) && resolved.entry.size <= 25 * 1024 * 1024) {
          sendJson(res, 200, { kind: 'image', size: resolved.entry.size });
          return;
        }
        const maxBytes = 128 * 1024;
        const buf = await fat.readFileSlice(resolved.entry, 0, maxBytes);
        if (isLikelyText(buf)) {
          sendJson(res, 200, {
            kind: 'text',
            truncated: resolved.entry.size > maxBytes,
            text: buf.toString('utf8'),
          });
        } else {
          const hexSlice = buf.subarray(0, 4096);
          sendJson(res, 200, {
            kind: 'binary',
            previewBytes: hexSlice.length,
            hex: formatHexDump(hexSlice),
          });
        }
        return;
      }

      if (req.method === 'GET' && pathname === '/api/download') {
        const fat = requireFat();
        const target = u.searchParams.get('path') || '/';
        const resolved = await fat.resolvePath(target, '/');
        if (resolved.entry.isDirectory) {
          sendJson(res, 400, { error: 'Cannot download a directory directly; use Extract' });
          return;
        }
        const ext = path.extname(resolved.entry.name).toLowerCase();
        const mime = MIME_TYPES[ext] || 'application/octet-stream';
        res.writeHead(200, {
          'Content-Type': mime,
          'Content-Length': resolved.entry.size,
          'Content-Disposition': formatContentDisposition(resolved.entry.name),
          'X-Content-Type-Options': 'nosniff',
        });
        let clientClosed = false;
        const onClientClose = () => { clientClosed = true; };
        res.once('close', onClientClose);
        try {
          await fat.streamFile(resolved.entry, async (chunk) => {
            if (clientClosed || res.destroyed || res.writableEnded) {
              throw new Error('Client disconnected');
            }
            if (!res.write(chunk)) {
              await new Promise((r, rej) => {
                const cleanup = () => {
                  res.off('drain', onDrain);
                  res.off('close', onClose);
                  res.off('error', onErr);
                };
                const onDrain = () => { cleanup(); r(); };
                const onClose = () => { cleanup(); rej(new Error('Client disconnected')); };
                const onErr = (err) => { cleanup(); rej(err); };
                res.once('drain', onDrain);
                res.once('close', onClose);
                res.once('error', onErr);
              });
            }
          });
          if (!res.writableEnded) res.end();
        } finally {
          res.off('close', onClientClose);
        }
        return;
      }

      if (req.method === 'POST' && pathname === '/api/extract') {
        if (!session) throw new Error('No backup file is currently open');
        const body = await readJsonBody(req);
        const resObj = await cmdExtract(
          session,
          body.innerPath || '/',
          body.outDir || './extracted',
          {
            overwrite: Boolean(body.overwrite),
            preserveTimestamps: Boolean(body.preserveTimestamps),
          }
        );
        sendJson(res, 200, resObj);
        return;
      }

      if (req.method === 'POST' && pathname === '/api/verify') {
        if (!session) throw new Error('No backup file is currently open');
        const result = await session.container.verify();
        sendJson(res, 200, result);
        return;
      }

      if (req.method === 'GET' && pathname === '/api/metadata') {
        if (!session) throw new Error('No backup file is currently open');
        const metadata =
          session.container.format === 'reflect-x'
            ? JSON.stringify(session.container.json, null, 2)
            : session.container.xmlText || '(no XML metadata found)';
        sendJson(res, 200, { metadata });
        return;
      }

      if (req.method === 'POST' && pathname === '/api/browse-local') {
        const body = await readJsonBody(req);
        const picked = await openNativeWindowsDialog(body.mode === 'folder' ? 'folder' : 'file');
        sendJson(res, 200, { path: picked });
        return;
      }

      sendJson(res, 404, { error: 'Not found' });
    } catch (err) {
      if (!res.headersSent) {
        sendJson(res, err.statusCode || 400, { error: err.message });
      } else {
        res.end();
      }
    }
  });

  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(port, host, () => resolve());
  });

  const addr = server.address();
  const url = `http://${host}:${addr.port}`;

  return {
    server,
    url,
    port: addr.port,
    async close() {
      if (session) {
        await session.close().catch(() => {});
        session = null;
      }
      await new Promise((resolve) => server.close(() => resolve()));
    },
  };
}
