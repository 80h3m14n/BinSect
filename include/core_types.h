#ifndef CORE_TYPES_H
#define CORE_TYPES_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef enum
{
    OUTPUT_BYTE,
    OUTPUT_ASSEMBLY,
    OUTPUT_STRINGS,
    OUTPUT_HEX,
    OUTPUT_ALL
} OutputFormat;

typedef enum
{
    FORMAT_RAW,
    FORMAT_PE,
    FORMAT_ELF,
    FORMAT_APK,
    FORMAT_PDF,
    FORMAT_DOCX,
    FORMAT_PPTX,
    FORMAT_ZIP,
    FORMAT_TAR,
    FORMAT_MACHO,
    FORMAT_DEX,
    FORMAT_CLASS,
    FORMAT_WASM,
    FORMAT_POWERSHELL,
    FORMAT_PYTHON,
    FORMAT_JAVASCRIPT,
    FORMAT_TEXT,
    FORMAT_FIRMWARE,
    FORMAT_UNKNOWN
} FileFormat;

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

typedef struct
{
    PackerType type;
    const char *name;
    float confidence;
    char *details;
    bool is_packed;
} PackerResult;

typedef struct
{
    char *text;
    size_t offset;
    size_t length;
    bool is_ascii;
    bool is_unicode;
} StringResult;

typedef enum
{
    VULN_LOW,
    VULN_MEDIUM,
    VULN_HIGH,
    VULN_CRITICAL
} VulnSeverity;

typedef struct
{
    uint8_t *pattern;
    size_t length;
    char *name;
    char *description;
    char *severity;
    char *mitigation;
} VulnPattern;

typedef struct
{
    uint8_t opcode;
    char *mnemonic;
    int operand_count;
    char *description;
} Instruction;

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

#endif
