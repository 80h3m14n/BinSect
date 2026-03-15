# Binsect - Advanced Security Analysis Tool

A comprehensive security analysis tool that performs disassembly, vulnerability detection, packer analysis, and multi-format file inspection.

Radare2-like commands

## Features

### 🔍 Core Analysis

- **x86-64 Disassembly**: Instruction decoding with security pattern detection
- **Multiple Output Formats**: Hex dump, byte arrays, assembly mnemonics, string extraction
- **Packer Detection**: Identifies UPX, ASPack, Themida, VMProtect, and other packers
- **Interactive Mode**: Command-line interface for dynamic analysis

### 📁 File Format Support

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

---

## Building

### Prerequisites

- GCC compiler with C99 support
- Linux/Unix environment
- Math library (libm)

### Installation

```bash
# Clone and build
git clone <repository_url>
cd binsect
make              # Build binsect

# Optional: Install to system PATH
sudo cp binsect /usr/local/bin/
# Or
sudo ln -s $(pwd)/binsect /usr/local/bin/binsect
# Or
sudo make install
```

### Build Commands

```bash
make              # Build binsect
make plugins      # Build sample plugin (plugins/sample_plugin.so)
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



## Usage

```bash
# Basic analysis
./binsect [options] <binary_file>

# Interactive mode
./binsect -i <binary_file>
```

## Output Formats

- **byte**: Raw byte values
- **assembly**: Assembly mnemonics
- **strings**: Extract readable text (ASCII/Unicode)
- **hex**: Hexadecimal dump with ASCII
- **all**: All formats combined (default)

---

## Architecture

### Core Modules

- `src/cli.c`: Command-line interface and main entry point
- `src/disassemble.c`: x86-64 disassembly engine with pattern matching
- `src/analysis.c`: Security analysis algorithms and threat detection
- `src/formats.c`: File format detection and parsing
- `src/packer.c`: Packer detection and analysis
- `src/advanced_formats.c`: Advanced format handlers (Mach-O, DEX, WASM, etc.)
- `src/output.c`: Multiple output format generators
- `src/module_registry.c`: Runtime module registry (output, format analyzers, packer detectors)
- `src/plugin.c`: Dynamic plugin loader for `.so` extensions in `plugins/`

### Public Headers (Split By Domain)

- `include/core_types.h`: Shared enums and structs
- `include/disasm_api.h`: Disassembly interfaces
- `include/analysis_api.h`: Security analysis interfaces
- `include/output_api.h`: Output and string extraction interfaces
- `include/formats_api.h`: File format detection/processing interfaces
- `include/packer_api.h`: Packer detection interfaces
- `include/advanced_formats_api.h`: Advanced format analyzers
- `include/disassembler.h`: Compatibility umbrella header

### Modular Extension Model

BinSect now includes a module registry that decouples the CLI pipeline from concrete implementations.

- Output handlers are dispatched through `dispatch_output_handler(...)`
- Format analyzers can be added at runtime via `register_format_handler(...)`
- Packer detectors are composable via `register_packer_detector(...)`

This allows adding new analysis capabilities without editing central switch statements in the core flow.

### Plugin Interface

Plugins are shared objects loaded from the `plugins/` directory at startup.

1. Implement `binsect_plugin_abi_version()` and return `BINSECT_PLUGIN_ABI_VERSION`.
2. Implement `binsect_plugin_init(const BinSectPluginApi *api)` in your plugin.
3. Validate `api->abi_version` in plugin init.
4. Call API callbacks to register handlers.
5. Build as `.so` and drop into `plugins/`.

The loader now enforces a strict ABI version match before initialization.

Sample plugin included:

- Source: `plugins/sample_plugin.c`
- Registers output mode: `entropy`
- Registers detector: `sample-xor-detector`

Usage example:

```bash
make plugins
./binsect -f entropy /bin/ls
```

Reference headers:

- `include/plugin.h`
- `include/module_registry.h`

Plugin developer resources:

- `plugins/plugin_template.c`
- `docs/PLUGIN_DEVELOPMENT.md`
- `docs/COMMANDS.md`

The built-in modules are still registered by default, so existing behavior remains intact.

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

## ⚠️ Disclaimer

This tool was developed with the help of[GitHub Copilot's](https://github.com/copilot) AI code generation capabilities.

> It is intended for educational purposes only and should not be used for any illegal or unethical activities. The developers are not responsible for any misuse of this tool. Always ensure you have proper authorization before analyzing or testing any software or systems.
