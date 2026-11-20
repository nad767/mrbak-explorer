#!/usr/bin/env node
import fs from 'node:fs';
import { spawn } from 'node:child_process';
import { parseArgs } from 'node:util';
import { openMrbak } from '../src/container.js';
import {
  cmdCat,
  cmdExtract,
  cmdFind,
  cmdInfo,
  cmdLs,
  cmdMetadata,
  cmdStat,
  cmdTree,
  formatBytes,
} from '../src/explorer.js';
import { startGuiServer } from '../src/gui-server.js';
import { runShell } from '../src/shell.js';

const HELP = `mrbak-explorer - Explore Macrium Reflect .mrbak / .mrbakx backup files

Usage:
  mrbak --gui [file] [--port N] [--no-open]   Launch local web GUI explorer
  mrbak [--shell] <file> [options]            Open interactive explorer shell
  mrbak --info <file> [--json]                Show container & virtual drive metadata
  mrbak --ls <file> [path] [-l] [-a] [-r]     List files and directories
  mrbak --tree <file> [path] [-d depth] [-a]  Display directory tree
  mrbak --find <file> <pattern> [-t f|d]      Search paths/filenames (supports * and ?)
  mrbak --stat <file> <path> [--json]         Show file/directory metadata
  mrbak --cat <file> <path> [--offset N] [--limit N] [--tail N]
                                              Write file contents to stdout
  mrbak --extract <file> [path] [-o dir] [--overwrite] [--preserve-timestamps]
                                              Extract a file, folder, or full backup
  mrbak --verify <file>                       Verify block MD5 checksums
  mrbak --metadata <file>                     Dump embedded JSON or XML definition

Options:
  -f, --file <path>          Backup file path (optional alternative to positional <file>)
  -p, --password <pw>        Password for encrypted Reflect X backups
  --partition <idx>          Partition index for disk images (.mrimg/.mrimgx, default: 0)
  --port <N>                 Port for GUI server (default: auto)
  --no-open                  Do not automatically open browser when starting GUI
  --json                     Output structured JSON (--info, --ls, --find, --stat)
  -l, --long                 Long directory listing (--ls)
  -a, --all                  Include hidden/system entries (--ls, --tree)
  -r, --recursive            Recurse subdirectories (--ls)
  -d, --depth <N>            Maximum tree depth (--tree)
  -t, --type <f|d>           Filter search results to files or directories (--find)
  -o, --output <dir>         Destination directory for --extract (default: ./extracted)
  --overwrite                Overwrite existing files when extracting
  --preserve-timestamps      Restore file mtime/atime when extracting
  --offset <N>               Byte offset for --cat
  --limit <N>                Max bytes to read for --cat
  --tail <N>                 Read last N bytes for --cat
  -V, --version              Show version number
  -h, --help                 Show this help message
`;

const ACTION_FLAGS = [
  'gui',
  'shell',
  'info',
  'ls',
  'tree',
  'find',
  'stat',
  'cat',
  'extract',
  'verify',
  'metadata',
];

const LEGACY_SUBCOMMANDS = new Set([...ACTION_FLAGS, 'dir']);

function parseNumberOpt(val, name, fallback) {
  if (val === undefined) return fallback;
  const trimmed = String(val).trim();
  if (!trimmed) {
    throw new Error(`Invalid numeric value for --${name}: "${val}"`);
  }
  const n = Number(trimmed);
  if (!Number.isInteger(n) || n < 0) {
    throw new Error(`Invalid integer value for --${name}: "${val}"`);
  }
  return n;
}

function parseCliArgs(argv) {
  const { values, positionals } = parseArgs({
    args: argv,
    allowPositionals: true,
    allowNegative: true,
    strict: true,
    options: {
      gui: { type: 'boolean', short: 'g', default: false },
      shell: { type: 'boolean', short: 's', default: false },
      info: { type: 'boolean', short: 'i', default: false },
      ls: { type: 'boolean', default: false },
      tree: { type: 'boolean', default: false },
      find: { type: 'boolean', default: false },
      stat: { type: 'boolean', default: false },
      cat: { type: 'boolean', default: false },
      extract: { type: 'boolean', short: 'x', default: false },
      verify: { type: 'boolean', short: 'v', default: false },
      metadata: { type: 'boolean', short: 'm', default: false },

      file: { type: 'string', short: 'f' },
      password: { type: 'string', short: 'p' },
      partition: { type: 'string' },
      port: { type: 'string' },
      open: { type: 'boolean', default: true },
      json: { type: 'boolean', default: false },
      long: { type: 'boolean', short: 'l', default: false },
      all: { type: 'boolean', short: 'a', default: false },
      recursive: { type: 'boolean', short: 'r', default: false },
      depth: { type: 'string', short: 'd' },
      type: { type: 'string', short: 't' },
      output: { type: 'string', short: 'o', default: './extracted' },
      overwrite: { type: 'boolean', default: false },
      'preserve-timestamps': { type: 'boolean', default: false },
      offset: { type: 'string' },
      limit: { type: 'string' },
      tail: { type: 'string' },
      version: { type: 'boolean', short: 'V', default: false },
      help: { type: 'boolean', short: 'h', default: false },
    },
  });

  const selectedActions = ACTION_FLAGS.filter((k) => values[k]);
  if (selectedActions.length > 1) {
    throw new Error(
      `Conflicting mode flags: ${selectedActions.map((a) => `--${a}`).join(', ')}`
    );
  }

  let cmd = selectedActions[0] || null;
  let rest = [...positionals];

  // Fallback support if user invoked with a positional subcommand (e.g. `mrbak info file.mrbak`)
  if (!cmd && rest.length > 0 && LEGACY_SUBCOMMANDS.has(rest[0].toLowerCase()) && !fs.existsSync(rest[0])) {
    cmd = rest.shift().toLowerCase();
  }

  let filePath = values.file || null;
  if (!filePath && rest.length > 0) {
    filePath = rest.shift();
  }

  if (!cmd) {
    cmd = 'shell';
  }

  return {
    cmd,
    filePath,
    args: rest,
    flags: {
      version: values.version,
      help: values.help,
      long: values.long || cmd === 'dir',
      all: values.all,
      recursive: values.recursive,
      json: values.json,
      overwrite: values.overwrite,
      preserveTimestamps: values['preserve-timestamps'],
      noOpen: !values.open,
      password: values.password ?? null,
      outDir: values.output,
      maxDepth: parseNumberOpt(values.depth, 'depth', Infinity),
      type: values.type ?? null,
      partition: parseNumberOpt(values.partition, 'partition', 0),
      port: parseNumberOpt(values.port, 'port', 0),
      offset: parseNumberOpt(values.offset, 'offset', 0),
      limit: parseNumberOpt(values.limit, 'limit', Infinity),
      tail: values.tail !== undefined ? parseNumberOpt(values.tail, 'tail', 0) : undefined,
    },
  };
}

function openBrowser(url) {
  const onError = (err) => {
    console.error(`Warning: could not open browser automatically: ${err.message}`);
  };
  let child;
  if (process.platform === 'win32') {
    child = spawn('cmd.exe', ['/c', 'start', '', url], { detached: true, stdio: 'ignore' });
  } else if (process.platform === 'darwin') {
    child = spawn('open', [url], { detached: true, stdio: 'ignore' });
  } else {
    child = spawn('xdg-open', [url], { detached: true, stdio: 'ignore' });
  }
  child.on('error', onError);
  child.unref();
}

async function main() {
  const { cmd, filePath, args, flags } = parseCliArgs(process.argv.slice(2));
  if (flags.version) {
    const pkg = JSON.parse(fs.readFileSync(new URL('../package.json', import.meta.url), 'utf8'));
    console.log(`${pkg.name} v${pkg.version}`);
    process.exit(0);
  }
  if (flags.help || (cmd !== 'gui' && !filePath)) {
    console.log(HELP);
    process.exit(flags.help ? 0 : 1);
  }

  if (cmd === 'gui') {
    const gui = await startGuiServer({
      initialFile: filePath || null,
      password: flags.password,
      partition: flags.partition,
      port: flags.port,
    });
    console.log(`mrbak-explorer GUI running at ${gui.url}`);
    console.log('Press Ctrl+C to stop.');
    if (!flags.noOpen) {
      openBrowser(gui.url);
    }
    const shutdown = async () => {
      await gui.close();
      process.exit(0);
    };
    process.on('SIGINT', shutdown);
    process.on('SIGTERM', shutdown);
    return;
  }

  const session = await openMrbak(filePath, {
    password: flags.password,
    partition: flags.partition,
  });

  try {
    switch (cmd) {
      case 'shell':
        await runShell(session);
        break;
      case 'info':
        console.log(await cmdInfo(session, { json: flags.json }));
        break;
      case 'ls':
      case 'dir':
        console.log(
          await cmdLs(session, args[0] || '/', {
            long: flags.long,
            all: flags.all,
            recursive: flags.recursive,
            json: flags.json,
          })
        );
        break;
      case 'tree':
        console.log(
          await cmdTree(session, args[0] || '/', {
            maxDepth: flags.maxDepth,
            all: flags.all,
          })
        );
        break;
      case 'find':
        if (!args[0]) throw new Error('Usage: mrbak --find <file> <pattern>');
        console.log(
          await cmdFind(session, args[0], {
            type: flags.type,
            json: flags.json,
          })
        );
        break;
      case 'stat':
        if (!args[0]) throw new Error('Usage: mrbak --stat <file> <path>');
        console.log(await cmdStat(session, args[0], { json: flags.json }));
        break;
      case 'cat':
        if (!args[0]) throw new Error('Usage: mrbak --cat <file> <path>');
        await cmdCat(session, args[0], {
          offset: flags.offset,
          limit: flags.limit,
          tail: flags.tail,
          writeStream: process.stdout,
        });
        break;
      case 'extract': {
        const res = await cmdExtract(session, args[0] || '/', flags.outDir, {
          overwrite: flags.overwrite,
          preserveTimestamps: flags.preserveTimestamps,
        });
        console.log(
          `Extracted ${res.filesExtracted} file(s), ${res.dirsCreated} dir(s) (${formatBytes(res.bytesExtracted)}) -> ${res.destRoot}`
        );
        break;
      }
      case 'verify': {
        const res = await session.container.verify((done, total) => {
          if (process.stderr.isTTY) {
            process.stderr.write(`\rVerifying blocks: ${done}/${total}`);
          }
        });
        if (process.stderr.isTTY) process.stderr.write('\n');
        console.log(`Verified ${res.checked}/${res.total} blocks. Mismatches: ${res.mismatches}`);
        for (const err of res.errors) console.error(`  ! ${err}`);
        if (res.mismatches > 0) process.exitCode = 2;
        break;
      }
      case 'metadata':
        console.log(cmdMetadata(session));
        break;
    }
  } finally {
    await session.close();
  }
}

main().catch((err) => {
  console.error(`Error: ${err.message}`);
  process.exit(1);
});
