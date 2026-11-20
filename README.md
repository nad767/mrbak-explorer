# mrbak-explorer

Utility for exploring, searching, verifying, and extracting **Macrium Reflect** `.mrbak` and `.mrbakx` File & Folder backups (with basic support for `.mrimg` / `.mrimgx` disk images).

> **Disclaimer:** This utility was AI-coded to overcome a specific blockage and has only undergone minimal human code review & testing. While it's read-only toward backup archives, it is published and open-sourced as-is for anyone in a similar situation to use **at their own risk and responsibility**.

## Motivation

Trying to mount `.mrbak` files on modern Windows using Macrium Reflect 7 can fail with `"A driver cannot load on this device"` (`Driver: psmounterex.sys`), an issue reportedly also reproducing in Reflect 8. `mrbak-explorer` parses the container and virtual FAT32 volume directly in user space - no kernel driver or Macrium Reflect installation required.

## Requirements

Node.js `>= 22.15.0` (required for built-in `zlib.zstdDecompressSync`).

## Usage

Clone locally, then run via npm scripts (`npm run gui`, `npm run cli -- ...`) or directly with Node.js (`node bin/mrbak.js`). To run from anywhere, run `npm link` inside the cloned repo, then use `mrbak` globally.

### GUI Usage

Launch the local web GUI explorer:

```sh
npm run gui
# OR: node bin/mrbak.js --gui
```

Pre-load a specific backup file:

```sh
npm run gui -- path/to/backup.mrbak
```

Pre-load an encrypted Reflect X backup on a custom port without auto-opening a browser tab:

```sh
npm run gui -- path/to/backup.mrbakx -p "my-password" --port 3847 --no-open
```

### CLI Usage

Launch the interactive explorer shell:

```sh
npm run cli -- path/to/backup.mrbak
# OR: node bin/mrbak.js path/to/backup.mrbak
```

With an encrypted Reflect X backup password:

```sh
npm run cli -- --shell path/to/backup.mrbakx -p "my-password"
```

**Show metadata & virtual drive info (or as JSON):**

```sh
npm run cli -- --info path/to/backup.mrbak
npm run cli -- --info path/to/backup.mrbak --json
```

**Browse directories (`-l` long, `-r` recursive) or render a depth-limited tree:**

```sh
npm run cli -- --ls path/to/backup.mrbak / -l
npm run cli -- --ls path/to/backup.mrbak /Documents -r
npm run cli -- --tree path/to/backup.mrbak -d 3
```

**Search by glob or substring (`-t f|d` for files or directories):**

```sh
npm run cli -- --find path/to/backup.mrbak "*.docx"
npm run cli -- --find path/to/backup.mrbak invoice -t f
```

**Inspect entry details or print a file to stdout:**

```sh
npm run cli -- --stat path/to/backup.mrbak "/Documents/Report.pdf"
npm run cli -- --cat path/to/backup.mrbak "/notes.txt"
```

**Extract a file, folder, or full backup:**

```sh
npm run cli -- --extract path/to/backup.mrbak "/Documents" -o ./restored --preserve-timestamps
```

**Verify stored blocks or dump embedded XML/JSON metadata:**

```sh
npm run cli -- --verify path/to/backup.mrbak
npm run cli -- --metadata path/to/backup.mrbak
```

## Features

- **Cross-Platform & Zero-Dependency:** Runs on Windows, macOS, and Linux using pure ES modules and Node.js built-ins (`node:zlib`, `node:crypto`, `node:http`, `node:readline`) plus an inline JavaScript QuickLZ 1.31 decompressor - no `npm install` or native C++ toolchain needed.
- **Macrium Reflect v7 / v8 Legacy (`.mrbak` / `.mrimg`):**
  - Parses `__79241006_2651_11D4_` trailers, embedded XML definitions, and QuickLZ 1.31 (Level 2) or uncompressed (`Store`) blocks.
  - Detects legacy encrypted `.mrbak` files (proprietary undocumented scheme) and reports them as unsupported.
- **Macrium Reflect X (`.mrbak` / `.mrbakx` / `.mrimgx`):**
  - Parses `MACRIUM_FILE` footers and `$JSON` / `$INDEX` / `$TRACK0` metadata blocks.
  - Native-speed Zstandard (`zstd`) and uncompressed blocks.
  - Full AES-128 / AES-192 / AES-256 CBC decryption with PBKDF2-HMAC-SHA256 key derivation, HMAC verification, and ESSIV IVs (`--password`), including encrypted metadata blocks.
- **Incremental & Differential Backup Chains:** Resolves ancestor files in the same folder and overlays delta block indices (`_overlayDelta` for legacy chains including updated FAT heads; `file_history` + `delta_index` for Reflect X) to reconstruct point-in-time views without duplicating base data.
- **Instant Opening & Bounded Memory:** Uses `O(1)` tail-metadata jumps (`54 B` legacy / `20 B` Reflect X) and lazy on-demand block decoding, zero-filling unstored blocks in memory without disk I/O. Multi-tier LRU caches (`256` decoded blocks, `64` `64 KiB` FAT pages, `512` parsed directories) keep memory bounded regardless of archive size.
- **Read-Only Virtual FAT32 Driver:** Parses Macrium's `4096`-byte-sector "File Backup Virtual Drive" directly without admin rights, supporting VFAT Long File Names (with checksum and completeness validation), DOS timestamps, hidden/system attribute filtering (`-a`), and FAT cluster-loop detection.
- **Local Web GUI (`--gui`):** Self-contained `127.0.0.1` HTTP server and single-page dark UI featuring a lazy folder tree, sortable directory table, breadcrumbs, glob/substring search, inline previews (up to `128 KiB` text, `4 KiB` binary hex dump, and `<= 25 MiB` images), Unicode-safe streaming browser downloads, verification/metadata modals, automatic password prompting, a Windows native file/folder picker bridge, and `Host`/`Origin`/`Sec-Fetch-Site` guards.
- **CLI & Interactive Explorer Shell:** Scriptable subcommands (with `--json` output for `--info`, `--ls`, `--find`, `--stat`, plus byte-range `--cat` with `--offset`, `--limit`, `--tail`) and a default interactive REPL shell with virtual path tab-completion (`ls`, `dir`, `cd`, `pwd`, `tree`, `find`, `stat`, `cat`, `head`, `extract`, `get`, `info`, `metadata`, `verify`).
- **Safe Streaming Extraction & Integrity Verification:** Streams files cluster-by-cluster with backpressure, path-traversal and Windows reserved-device-name sanitization, `--overwrite`, and `--preserve-timestamps`. `--verify` bypasses caches to MD5-check and decompress every stored block.

## Architecture & Trade-offs

Container parsers (`src/mrbak-legacy.js`, `src/mrbak-x.js`) expose a lazy random-access stream (`readAt(offset, length)`) to the read-only FAT32 driver (`src/fat32.js`), powering the CLI/REPL and local web GUI.

- **JS QuickLZ vs. native Zstd:** Legacy QuickLZ 1.31 runs in JavaScript to avoid native addons, trading higher CPU usage on large legacy reads for zero build/install friction.
- **Same-folder chain resolution:** Ancestor files are resolved by basename inside the same directory as the opened `.mrbak` / `.mrbakx`. Reflect X `delta_index` chains are covered by a synthetic 2-file chain test, though live Macrium Reflect delta captures may still uncover format edge cases.
- **Read-only FAT32 scope:** Non-FAT32 partitions in `.mrimg` / `.mrimgx` disk images (such as NTFS or ext4) expose container-level `--info`, `--metadata`, and `--verify` only.
- **GUI constraints:** File previews are capped at `128 KiB` for text and `4 KiB` for binary hex (use Download or `--cat` for full files). The native "Browse…" picker uses PowerShell Windows Forms on Windows; on macOS and Linux, paths are entered directly.

### Module Overview

| Module | Responsibility |
| --- | --- |
| `bin/mrbak.js` | CLI argument parser, subcommand dispatcher, GUI launcher |
| `src/container.js` | Format auto-detection (Reflect X vs Legacy) and FAT32 initialization |
| `src/mrbak-legacy.js` | Reflect v7/v8 container, XML parser, delta chains, block verify |
| `src/quicklz.js` | QuickLZ 1.31 frame header parser and memory-safe decompressor |
| `src/mrbak-x.js` | Reflect X container, `$JSON`/`$INDEX` reader, Zstd + chain handling |
| `src/crypto-x.js` | Reflect X PBKDF2-HMAC-SHA256, HMAC validation, ESSIV IV, AES-CBC |
| `src/fat32.js` | FAT32 BPB, paged FAT walker, LFN directory parser, file streaming |
| `src/explorer.js` | High-level `info`, `ls`, `tree`, `find`, `stat`, `cat`, `extract` |
| `src/shell.js` | Interactive REPL shell with virtual path tab-completion |
| `src/gui-server.js` | Localhost HTTP API + Windows native file/folder dialog bridge |
| `src/web/index.html` | Single-page explorer UI |

## License

[MIT](LICENSE)
