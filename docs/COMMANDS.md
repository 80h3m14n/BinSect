# BinSect Commands Reference

This document is a quick command guide for BinSect CLI and interactive mode.


## Basic commands

Commands can be either short-hand i,e -h or long-form i.e --help. Commands are case-insensitive.


| Command | Task |
|---------|------|
| ?       | Show help |
| clear   | Clear screen |
| exit    | Exit interactive mode |
| h       | Show help |
| i       | Show file info (format, size, seek offset, verbose state) |
| load    | Load/reload a file |
| p       | Print data (disassembly, hex, strings, etc.) |
| t       | Toggle output format (byte, assembly, strings, hex, all) |
| q       | Quit interactive mode |
| v       | Toggle verbose mode |



## CLI Commands

### Basic usage

```bash
binsect [options] <binary_file>
```


### CLI Examples

```bash
binsect /bin/ls
binsect -v /usr/bin/ls
binsect -f hex /usr/bin/passwd
binsect -f strings README.md
binsect -t elf -f assembly /usr/bin/ls
binsect -i /usr/bin/ls
```

## Interactive Mode Commands

Start interactive mode:

```bash
./binsect -i
```

Or auto-load a file at startup:

```bash
./binsect -i /usr/bin/ls
```

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



## Interactive Workflow Example

```text
load /usr/bin/ls
s 0x40
pd 64
/x 7f 45 4c 46
sn
px 64
q
```

## Notes

- Use `./binsect` in the project directory unless BinSect is installed into your PATH.
- If no file is loaded in interactive mode, commands that require data will prompt you to run `load <file>`.
- Arrow-key history navigation depends on the terminal sending standard ANSI escape sequences.
