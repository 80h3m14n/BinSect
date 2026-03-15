# BinSect Commands Reference

This document is a quick command guide for BinSect CLI and interactive mode.

## 1. Build and Run

```bash
make
./binsect /usr/bin/ls
```

If installed globally:

```bash
binsect /usr/bin/ls
```

## 2. CLI Commands

### Basic usage

```bash
./binsect [options] <binary_file>
```

### Options

- `-h`, `--help`: Show help.
- `-v`, `--verbose`: Enable verbose analysis output.
- `-i`, `--interactive`: Start interactive REPL.
- `-f`, `--format`: Select output format.
- `-t`, `--type`: Force file type.

### Output format values (`-f`)

- `byte`
- `assembly`
- `strings`
- `hex`
- `all`
- `<plugin-mode>` (for plugin-registered modes, for example `entropy`)

### File type values (`-t`)

- `raw`
- `text`
- `pe`
- `elf`
- `apk`
- `pdf`
- `zip`
- `tar`
- `macho`
- `dex`
- `class`
- `wasm`
- `powershell`
- `python`
- `javascript`
- `firmware`

### CLI Examples

```bash
./binsect /bin/ls
./binsect -v /usr/bin/ls
./binsect -f hex /usr/bin/passwd
./binsect -f strings README.md
./binsect -t elf -f assembly /usr/bin/ls
./binsect -i /usr/bin/ls
```

## 3. Interactive Mode Commands

Start interactive mode:

```bash
./binsect -i
```

Or auto-load a file at startup:

```bash
./binsect -i /usr/bin/ls
```

### Session control

- `help` or `?`: Show command help.
- `q`, `quit`, `exit`: Leave interactive mode.
- `clear`: Clear terminal screen.
- `verbose`: Toggle verbose mode on/off.

### File and info

- `load <file>`: Load/reload a file.
- `i` or `info`: Show file info, seek offset, detected format, verbose state.

### Seek/navigation

- `s`: Print current seek offset.
- `s <addr>`: Seek to absolute offset (decimal or hex, for example `s 0x100`).
- `s+ <delta>`: Seek forward.
- `s- <delta>`: Seek backward.
- `ni [n]`: Step cursor forward by `n` bytes (default `1`).
- `si [n]`: Step cursor forward by `n` bytes (default `1`).

### Printing/analysis

- `pd [n]`: Disassemble from current seek.
- `px [n]`: Hex dump from current seek.
- `p8 [n]`: Raw bytes from current seek.
- `ps [n]`: Extract strings from current seek window.
- `iz`: Extract strings from whole loaded file.
- `aa [n]`: Code-flow analysis for current seek window.
- `af`: Alias for windowed flow analysis.
- `afl`: Security analysis summary.

### Pattern search

- `/x <hex...>`: Find byte pattern and store hits.
  - Example: `/x 55 48 89 e5`
- `sn` or `/xn`: Jump to next stored hit.
- `sp` or `/xp`: Jump to previous stored hit.

## 4. Interactive Workflow Example

```text
load /usr/bin/ls
s 0x40
pd 64
/x 7f 45 4c 46
sn
px 64
q
```

## 5. Notes

- Use `./binsect` in the project directory unless BinSect is installed into your PATH.
- If no file is loaded in interactive mode, commands that require data will prompt you to run `load <file>`.
- Arrow-key history navigation depends on the terminal sending standard ANSI escape sequences.
