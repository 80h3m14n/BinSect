**Binsect**

The name "BinSect" originates from a combination of "Bin" (short for binary, referring to binary files) and "Sect" (suggesting section or dissection), reflecting its purpose as a tool for dissecting and analyzing binary executables.

## Usage

```bash
# Basic analysis
./binsect [options] <binary_file>

# Interactive mode
./binsect -i <binary_file>
```


## Output Format

The tool provides multiple analysis layers:

1. **Basic Disassembly**: Offset, hex bytes, and instruction mnemonics, strings
2. **Vulnerability Alerts**: Color-coded security warnings
3. **Code Flow Analysis**: Statistics on different operation types
4. **Security Report**: Comprehensive risk assessment
5. **Specialized Analysis**: Encryption, control flow, and threat detection
