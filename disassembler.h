#ifndef DISASSEMBLER_H
#define DISASSEMBLER_H

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>

// Output format types
typedef enum
{
    OUTPUT_BYTE,     // Byte representation
    OUTPUT_ASSEMBLY, // Assembly mnemonics
    OUTPUT_STRINGS,  // String extraction
    OUTPUT_HEX,      // Hexadecimal dump
    OUTPUT_ALL       // All formats
} OutputFormat;

// File format types
typedef enum
{
    FORMAT_RAW,        // Raw binary
    FORMAT_PE,         // Portable Executable
    FORMAT_ELF,        // Executable and Linkable Format
    FORMAT_APK,        // Android Package
    FORMAT_PDF,        // PDF Document
    FORMAT_DOCX,       // Word Document
    FORMAT_PPTX,       // PowerPoint
    FORMAT_ZIP,        // ZIP Archive
    FORMAT_TAR,        // TAR Archive
    FORMAT_MACHO,      // Mach-O (macOS)
    FORMAT_DEX,        // Android DEX
    FORMAT_CLASS,      // Java Class
    FORMAT_WASM,       // WebAssembly
    FORMAT_POWERSHELL, // PowerShell Script
    FORMAT_PYTHON,     // Python Script
    FORMAT_JAVASCRIPT, // JavaScript
    FORMAT_FIRMWARE,   // Firmware Image
    FORMAT_UNKNOWN     // Unknown format
} FileFormat;

// Packer types
typedef enum
{
    PACKER_NONE,
    PACKER_UPX,
    PACKER_ASPACK,
    PACKER_THEMIDA,
    PACKER_VMPROTECT,
    PACKER_PETITE,
    PACKER_PECOMPACT,
    PACKER_MPRESS,
    PACKER_ARMADILLO,
    PACKER_GENERIC,
    PACKER_UNKNOWN
} PackerType;

// Packer detection result
typedef struct
{
    PackerType type;
    const char *name;
    float confidence;
    char *details;
    bool is_packed;
} PackerResult;

// String analysis result
typedef struct
{
    char *text;
    size_t offset;
    size_t length;
    bool is_ascii;
    bool is_unicode;
} StringResult;

// Vulnerability severity levels
typedef enum
{
    VULN_LOW,
    VULN_MEDIUM,
    VULN_HIGH,
    VULN_CRITICAL
} VulnSeverity;

// Vulnerability pattern structure
typedef struct
{
    uint8_t *pattern;
    size_t length;
    char *name;
    char *description;
    char *severity; // Changed to string for consistency
    char *mitigation;
} VulnPattern;

// Instruction structure for basic disassembly
typedef struct
{
    uint8_t opcode;
    char *mnemonic;
    int operand_count;
    char *description;
} Instruction;

// Analysis results structure
typedef struct
{
    int total_instructions;
    int stack_operations;
    int jump_operations;
    int arithmetic_operations;
    int vulnerability_count;
    bool has_shellcode_patterns;
    bool has_rop_gadgets;
    bool has_function_prologue;
} AnalysisResult;

// Function prototypes
void disassemble_with_analysis(uint8_t *code, size_t length);
bool check_vulnerability_patterns(uint8_t *code, size_t length, size_t offset);
char *decode_instruction(uint8_t opcode);
void analyze_code_flow(uint8_t *code, size_t length);
void print_severity_color(const char *severity);
void reset_color(void);
AnalysisResult perform_security_analysis(uint8_t *code, size_t length);
void print_security_report(AnalysisResult *result);

// New output format functions
void output_bytes(uint8_t *code, size_t length);
void output_assembly(uint8_t *code, size_t length);
void output_hex_dump(uint8_t *code, size_t length);
void output_strings(uint8_t *code, size_t length);
void output_all_formats(uint8_t *code, size_t length);

// File format detection and support
FileFormat detect_file_format(uint8_t *data, size_t length);
const char *get_format_name(FileFormat format);
bool process_file_format(uint8_t *data, size_t length, FileFormat format);

// String extraction functions
StringResult *extract_strings(uint8_t *data, size_t length, size_t *count);
void free_string_results(StringResult *results, size_t count);
bool is_printable_ascii(const char *str, size_t len);
bool is_unicode_string(uint8_t *data, size_t len);

// Packer detection functions
PackerResult detect_packer(uint8_t *data, size_t length);
const char *get_packer_name(PackerType type);
void print_packer_info(PackerResult *result);

// Advanced file format analysis
bool analyze_macho_format(uint8_t *data, size_t length);
bool analyze_dex_format(uint8_t *data, size_t length);
bool analyze_class_format(uint8_t *data, size_t length);
bool analyze_wasm_format(uint8_t *data, size_t length);
bool analyze_script_format(uint8_t *data, size_t length, FileFormat format);
bool analyze_firmware_format(uint8_t *data, size_t length);

// Advanced pattern matching
bool is_potential_shellcode(uint8_t *code, size_t length);
bool contains_rop_gadgets(uint8_t *code, size_t length);
void detect_encryption_patterns(uint8_t *code, size_t length);
void analyze_control_flow(uint8_t *code, size_t length);

#endif // DISASSEMBLER_H
