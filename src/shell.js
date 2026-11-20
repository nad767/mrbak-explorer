import readline from 'node:readline';
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
  joinInnerPath,
} from './explorer.js';

function getCompletionToken(line) {
  let argIndex = 0;
  let inToken = false;
  let quote = null;
  let tokenStart = line.length;

  for (let i = 0; i < line.length; i++) {
    const ch = line[i];
    if (quote) {
      if (ch === quote) {
        quote = null;
      } else if (ch === '\\' && quote === '"' && i + 1 < line.length) {
        i++;
      }
    } else if (ch === '"' || ch === "'") {
      if (!inToken) {
        inToken = true;
        tokenStart = i + 1;
      }
      quote = ch;
    } else if (/\s/.test(ch)) {
      if (inToken) {
        argIndex++;
        inToken = false;
      }
      tokenStart = i + 1;
    } else if (!inToken) {
      inToken = true;
      tokenStart = i;
    }
  }

  return {
    isCommand: argIndex === 0 && !quote,
    partial: line.slice(tokenStart),
  };
}

function splitShellArgs(line) {
  const args = [];
  let cur = '';
  let quote = null;
  for (let i = 0; i < line.length; i++) {
    const ch = line[i];
    if (quote) {
      if (ch === quote) {
        quote = null;
      } else if (ch === '\\' && quote === '"' && i + 1 < line.length) {
        cur += line[++i];
      } else {
        cur += ch;
      }
    } else if (ch === '"' || ch === "'") {
      quote = ch;
    } else if (/\s/.test(ch)) {
      if (cur.length > 0) {
        args.push(cur);
        cur = '';
      }
    } else {
      cur += ch;
    }
  }
  if (cur.length > 0) args.push(cur);
  return args;
}

function printShellHelp() {
  console.log(`Available commands:
  ls [path] [-l] [-a] [-r]    List directory contents (alias: dir)
  cd <path>                   Change current directory inside backup
  pwd                         Print current virtual directory
  tree [path] [-d <depth>]    Show directory tree
  find <pattern> [-t f|d]     Search files/folders (supports * and ? globs)
  stat <path>                 Show FAT32 entry metadata & cluster details
  cat <path>                  Print file contents to terminal
  head [-n lines] <path>      Show first N lines (default 20)
  extract [path] [destDir]    Extract file or folder (alias: get)
  info                        Show backup container & virtual drive info
  metadata                    Dump embedded JSON/XML backup definition
  verify                      Verify block MD5 checksums & decompression
  help                        Show this help
  exit | quit                 Exit explorer`);
}

export async function runShell(session) {
  let cwd = '/';
  console.log('Macrium Reflect .mrbak Interactive Explorer');
  console.log(await cmdInfo(session));
  console.log('\nType "help" for commands, "exit" to quit.');

  const completer = async (line) => {
    if (!session.fat32) return [[], line];
    const { isCommand, partial } = getCompletionToken(line);
    if (isCommand) {
      const cmds = [
        'ls', 'dir', 'cd', 'pwd', 'tree', 'find', 'stat', 'cat', 'head',
        'extract', 'get', 'info', 'metadata', 'verify', 'help', 'exit', 'quit',
      ];
      const hits = cmds.filter((c) => c.startsWith(partial));
      return [hits.length ? hits : cmds, partial];
    }
    const normalizedPartial = partial.replace(/\\/g, '/');
    const slashIdx = normalizedPartial.lastIndexOf('/');
    const dirPart = slashIdx >= 0 ? normalizedPartial.slice(0, slashIdx + 1) : '';
    const prefix = slashIdx >= 0 ? normalizedPartial.slice(slashIdx + 1) : normalizedPartial;
    try {
      const resolved = await session.fat32.resolvePath(dirPart || '.', cwd);
      if (!resolved.entry.isDirectory) return [[], partial];
      const entries = await session.fat32.readDirectory(resolved.entry.startCluster);
      const hits = entries
        .filter((e) => e.name.toLowerCase().startsWith(prefix.toLowerCase()))
        .map((e) => `${dirPart}${e.name}${e.isDirectory ? '/' : ''}`);
      return [hits, partial];
    } catch {
      return [[], partial];
    }
  };

  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout,
    prompt: `mrbak:${cwd}> `,
    completer: (line, cb) => {
      completer(line).then(
        (res) => cb(null, res),
        () => cb(null, [[], line])
      );
    },
  });

  let closed = false;
  rl.on('close', () => {
    closed = true;
  });

  rl.prompt();

  for await (const rawLine of rl) {
    const line = rawLine.trim();
    if (!line) {
      if (!closed) {
        rl.setPrompt(`mrbak:${cwd}> `);
        rl.prompt();
      }
      continue;
    }

    const parts = splitShellArgs(line);
    const cmd = parts[0].toLowerCase();
    const rest = parts.slice(1);

    try {
      if (cmd === 'exit' || cmd === 'quit' || cmd === 'q') {
        break;
      } else if (cmd === 'help' || cmd === '?') {
        printShellHelp();
      } else if (cmd === 'pwd') {
        console.log(cwd);
      } else if (cmd === 'cd') {
        if (!session.fat32) throw new Error('No FAT32 virtual drive available');
        const target = rest[0] || '/';
        const resolved = await session.fat32.resolvePath(target, cwd);
        if (!resolved.entry.isDirectory) {
          throw new Error(`Not a directory: ${resolved.path}`);
        }
        cwd = resolved.path;
      } else if (cmd === 'ls' || cmd === 'dir') {
        let target = '.';
        const opts = { cwd, long: cmd === 'dir', all: false, recursive: false };
        for (const a of rest) {
          if (a === '-l') opts.long = true;
          else if (a === '-a') opts.all = true;
          else if (a === '-r' || a === '-R') opts.recursive = true;
          else if (a.startsWith('-')) {
            if (a.includes('l')) opts.long = true;
            if (a.includes('a')) opts.all = true;
            if (a.includes('r') || a.includes('R')) opts.recursive = true;
          } else {
            target = a;
          }
        }
        console.log(await cmdLs(session, target, opts));
      } else if (cmd === 'tree') {
        let target = '.';
        let maxDepth = Infinity;
        let all = false;
        for (let i = 0; i < rest.length; i++) {
          if (rest[i] === '-d') {
            if (i + 1 >= rest.length) throw new Error('Usage: tree [path] [-d <depth>] [-a]');
            const n = Number(rest[++i]);
            if (!Number.isInteger(n) || n < 0) throw new Error(`Invalid depth: "${rest[i]}"`);
            maxDepth = n;
          } else if (rest[i] === '-a') {
            all = true;
          } else {
            target = rest[i];
          }
        }
        console.log(await cmdTree(session, target, { cwd, maxDepth, all }));
      } else if (cmd === 'find') {
        let pattern = null;
        let type = null;
        for (let i = 0; i < rest.length; i++) {
          if (rest[i] === '-t' || rest[i] === '--type') {
            if (i + 1 >= rest.length) throw new Error('Usage: find <pattern> [-t f|d]');
            type = rest[++i];
          } else if (!pattern) {
            pattern = rest[i];
          }
        }
        if (!pattern) throw new Error('Usage: find <pattern> [-t f|d]');
        console.log(await cmdFind(session, pattern, { cwd, type }));
      } else if (cmd === 'stat') {
        if (!rest[0]) throw new Error('Usage: stat <path>');
        console.log(await cmdStat(session, rest[0], { cwd }));
      } else if (cmd === 'cat') {
        if (!rest[0]) throw new Error('Usage: cat <path>');
        await cmdCat(session, rest[0], { cwd, writeStream: process.stdout });
        process.stdout.write('\n');
      } else if (cmd === 'head') {
        let linesCount = 20;
        let target = null;
        for (let i = 0; i < rest.length; i++) {
          if (rest[i] === '-n') {
            if (i + 1 >= rest.length) throw new Error('Usage: head [-n lines] <path>');
            const n = Number(rest[++i]);
            if (!Number.isInteger(n) || n < 0) throw new Error(`Invalid line count: "${rest[i]}"`);
            linesCount = n;
          } else {
            target = rest[i];
          }
        }
        if (!target) throw new Error('Usage: head [-n lines] <path>');
        const buf = await session.fat32.readFileSlice(
          (await session.fat32.resolvePath(target, cwd)).entry,
          0,
          65536
        );
        const text = buf.toString('utf8').split(/\r?\n/).slice(0, linesCount).join('\n');
        console.log(text);
      } else if (cmd === 'extract' || cmd === 'get') {
        const inner = rest[0] ? joinInnerPath(cwd, rest[0]) : cwd;
        const dest = rest[1] || './extracted';
        const res = await cmdExtract(session, inner, dest, {
          cwd,
          overwrite: true,
          preserveTimestamps: true,
        });
        console.log(
          `Extracted ${res.filesExtracted} file(s), ${res.dirsCreated} dir(s) (${formatBytes(res.bytesExtracted)}) -> ${res.destRoot}`
        );
      } else if (cmd === 'info') {
        console.log(await cmdInfo(session));
      } else if (cmd === 'metadata') {
        console.log(cmdMetadata(session));
      } else if (cmd === 'verify') {
        const res = await session.container.verify((done, total) => {
          process.stdout.write(`\rVerifying blocks: ${done}/${total}`);
        });
        process.stdout.write('\n');
        console.log(
          `Verified ${res.checked}/${res.total} blocks. Mismatches: ${res.mismatches}`
        );
        for (const err of res.errors) console.log(`  ! ${err}`);
      } else {
        console.log(`Unknown command: "${cmd}". Type "help" for available commands.`);
      }
    } catch (err) {
      console.error(`Error: ${err.message}`);
    }

    if (!closed) {
      rl.setPrompt(`mrbak:${cwd}> `);
      rl.prompt();
    }
  }

  rl.close();
}
