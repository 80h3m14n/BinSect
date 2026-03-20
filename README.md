# Binsect - Security Analysis Tool

A comprehensive security analysis tool that performs disassembly, vulnerability detection, packer analysis, and multi-format file inspection.



## Features

### 🔍 Core Analysis

- **x86-64 Disassembly**: Instruction decoding with security pattern detection
- **Multiple Output Formats**: Hex dump, byte arrays, assembly mnemonics, string extraction
- **Security analysis**: Packer Detection, malicious pattern recognition, control flow analysis
- **Interactive Mode**: Command-line interface for dynamic analysis

### 📁 File Format Support

| Category        | Formats                | Analysis Features                     |
| --------------- | ---------------------- | ------------------------------------- |
| **Executables** | PE, ELF, Mach-O        | Header parsing, section analysis      |
| **Mobile**      | APK, DEX               | Android package inspection            |
| **Web**         | WASM                   | WebAssembly module analysis           |
| **Scripts**     | PowerShell, Python, JS | Code pattern detection                |
| **Archives**    | ZIP, TAR               | Content enumeration                   |
| **Documents**   | PDF, DOCX, PPTX        | Embedded object detection             |
| **Firmware**    | IoT images             | Entropy analysis, signature detection |


### 🛡️ Security Analysis

- **Vulnerability Patterns**: Buffer overflows, ROP gadgets, shellcode signatures
- **Risk Assessment**: Automated security scoring with color-coded severity
- **Control Flow Analysis**: Execution path mapping and complexity metrics
- **Packer Signatures**: UPX, ASPack, Themida, VMProtect, etc.
- **File Formats**: 15+ supported formats with magic byte detection
- **Malware Indicators**: Anti-analysis, obfuscation patterns,  polymorphic code patterns



---

## Installation

### 1. From Source

Prerequisites
- GCC compiler with C99 support
- Linux/Unix environment
- Math library (libm)

```bash
git clone https://github.com/80h3m14n/Binsect.git
cd BinSect
make         # Build binsect

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


---


## License

Educational and security research tool. Use responsibly and in compliance with applicable laws.

## ⚠️ Disclaimer

This tool was developed with the help of[GitHub Copilot's](https://github.com/copilot) AI code generation capabilities.

> It is intended for educational purposes only and should not be used for any illegal or unethical activities. The developers are not responsible for any misuse of this tool. Always ensure you have proper authorization before analyzing or testing any software or systems.
