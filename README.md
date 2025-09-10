# SentinelSec - Advanced Security Analysis Tool

A comprehensive security analysis tool that performs disassembly, vulnerability detection, packer analysis, and multi-format file inspection.

## ⚠️ Disclaimer

This tool was developed with [GitHub Copilot](https://github.com/copilot) assistance.

## Features

### 🔍 Core Analysis

- **x86-64 Disassembly**: Instruction decoding with security pattern detection
- **Multiple Output Formats**: Hex dump, byte arrays, assembly mnemonics, string extraction
- **Packer Detection**: Identifies UPX, ASPack, Themida, VMProtect, and other packers
- **Interactive Mode**: Command-line interface for dynamic analysis

### 📁 Advanced File Format Support

- **Executables**: PE, ELF, Mach-O (macOS) with header analysis
- **Mobile**: Android APK and DEX file inspection
- **Web**: WebAssembly (WASM) module analysis
- **Scripts**: PowerShell, Python, JavaScript detection and analysis
- **Archives**: ZIP, TAR with content enumeration
- **Documents**: PDF, Office formats (DOCX, PPTX)
- **Firmware**: IoT/router firmware with entropy analysis

### 🛡️ Security Analysis

- **Vulnerability Patterns**: Buffer overflows, ROP gadgets, shellcode signatures
- **Malware Detection**: Anti-analysis techniques, polymorphic code patterns
- **Risk Assessment**: Automated security scoring with color-coded severity
- **Control Flow Analysis**: Execution path mapping and complexity metrics

## Usage

```bash
# Basic analysis
./sentinelsec /bin/ls

# Specific output format
./sentinelsec -f hex /usr/bin/passwd     # Hex dump only
./sentinelsec -f strings document.pdf   # Extract strings
./sentinelsec -f assembly binary.exe    # Assembly output

# Force file type
./sentinelsec -t pe program.exe         # Force PE analysis
./sentinelsec -t wasm module.wasm       # WebAssembly analysis
./sentinelsec -t python script.py       # Python script analysis

# Interactive mode
./sentinelsec -i                        # Interactive shell

# Verbose analysis
./sentinelsec -v binary_file            # Detailed output
```

## Output Formats

- **byte**: Raw byte values
- **assembly**: Assembly mnemonics
- **strings**: Extract readable text (ASCII/Unicode)
- **hex**: Hexadecimal dump with ASCII
- **all**: All formats combined (default)

## Building

### Prerequisites

- GCC compiler with C99 support
- Linux/Unix environment
- Math library (libm)

### Installation

```bash
# Clone and build
git clone <repository_url>
cd sentinelsec
make              # Build SentinelSec

# Optional: Install to system PATH
sudo cp sentinelsec /usr/local/bin/
```

### Build Commands

```bash
make              # Build SentinelSec
make clean        # Clean build artifacts
make debug        # Debug build with GDB support
```

## Output Format

The tool provides multiple analysis layers:

1. **Basic Disassembly**: Offset, hex bytes, and instruction mnemonics
2. **Vulnerability Alerts**: Color-coded security warnings
3. **Code Flow Analysis**: Statistics on different operation types
4. **Security Report**: Comprehensive risk assessment
5. **Specialized Analysis**: Encryption, control flow, and threat detection

### Example Output

```
=== DISASSEMBLY WITH VULNERABILITY ANALYSIS ===
0x0000: 0x55 PUSH RBP
0x0001: 0x48 REX.W prefix
    [VULN] FUNC_PROLOGUE: Standard function prologue (Severity: LOW)
0x0002: 0x8b MOV
    [VULN] STACK_ACCESS: Direct stack access without bounds checking (Severity: MEDIUM)
...

=== SECURITY ANALYSIS REPORT ===
⚠️  SHELLCODE PATTERNS DETECTED
⚠️  ROP GADGETS DETECTED
Overall Risk Level: HIGH
```

## Architecture

### Core Modules

- `cli.c`: Command-line interface and main entry point
- `disassemble.c`: x86-64 disassembly engine with pattern matching
- `analysis.c`: Security analysis algorithms and threat detection
- `formats.c`: File format detection and parsing
- `packer.c`: Packer detection and analysis
- `advanced_formats.c`: Advanced format handlers (Mach-O, DEX, WASM, etc.)
- `output.c`: Multiple output format generators

### Detection Databases

- **Packer Signatures**: UPX, ASPack, Themida, VMProtect, etc.
- **Vulnerability Patterns**: ROP gadgets, shellcode, buffer overflows
- **File Formats**: 15+ supported formats with magic byte detection
- **Malware Indicators**: Anti-analysis, obfuscation patterns

## Limitations

## Supported Formats

| Category        | Formats                | Analysis Features                     |
| --------------- | ---------------------- | ------------------------------------- |
| **Executables** | PE, ELF, Mach-O        | Header parsing, section analysis      |
| **Mobile**      | APK, DEX               | Android package inspection            |
| **Web**         | WASM                   | WebAssembly module analysis           |
| **Scripts**     | PowerShell, Python, JS | Code pattern detection                |
| **Archives**    | ZIP, TAR               | Content enumeration                   |
| **Documents**   | PDF, DOCX, PPTX        | Embedded object detection             |
| **Firmware**    | IoT images             | Entropy analysis, signature detection |

## License

Educational and security research tool. Use responsibly and in compliance with applicable laws.
