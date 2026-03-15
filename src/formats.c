#include "advanced_formats_api.h"
#include "formats_api.h"
#include "module_registry.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

// File format signatures
static const struct
{
    uint8_t signature[8];
    size_t sig_len;
    FileFormat format;
    const char *name;
} format_signatures[] = {
    {{0x4D, 0x5A}, 2, FORMAT_PE, "PE (Portable Executable)"},
    {{0x7F, 0x45, 0x4C, 0x46}, 4, FORMAT_ELF, "ELF (Executable and Linkable Format)"},
    {{0x50, 0x4B, 0x03, 0x04}, 4, FORMAT_APK, "ZIP/APK Archive"},
    {{0x50, 0x4B, 0x03, 0x04}, 4, FORMAT_ZIP, "ZIP Archive"},
    {{0x25, 0x50, 0x44, 0x46}, 4, FORMAT_PDF, "PDF Document"},
    {{0x50, 0x4B, 0x03, 0x04}, 4, FORMAT_DOCX, "Office Document (DOCX/PPTX)"},
    {{0x75, 0x73, 0x74, 0x61, 0x72}, 5, FORMAT_TAR, "TAR Archive"},
    {{0x1F, 0x8B}, 2, FORMAT_TAR, "GZIP TAR Archive"},

    // New advanced formats
    {{0xFE, 0xED, 0xFA, 0xCE}, 4, FORMAT_MACHO, "Mach-O 32-bit"},
    {{0xFE, 0xED, 0xFA, 0xCF}, 4, FORMAT_MACHO, "Mach-O 64-bit"},
    {{0xCA, 0xFE, 0xBA, 0xBE}, 4, FORMAT_MACHO, "Universal Binary"},
    {{0x64, 0x65, 0x78, 0x0A}, 4, FORMAT_DEX, "Android DEX"},
    {{0xCA, 0xFE, 0xBA, 0xBE}, 4, FORMAT_CLASS, "Java Class"},
    {{0x00, 0x61, 0x73, 0x6D}, 4, FORMAT_WASM, "WebAssembly"},
};

static const size_t num_signatures = sizeof(format_signatures) / sizeof(format_signatures[0]);

static bool is_identifier_char(char c)
{
    return isalnum((unsigned char)c) || c == '_';
}

static bool contains_keyword(const char *text, const char *keyword)
{
    if (text == NULL || keyword == NULL || keyword[0] == '\0')
    {
        return false;
    }

    const size_t key_len = strlen(keyword);
    const char *cursor = text;
    while ((cursor = strstr(cursor, keyword)) != NULL)
    {
        const bool left_ok = (cursor == text) || !is_identifier_char(cursor[-1]);
        const char right = cursor[key_len];
        const bool right_ok = (right == '\0') || !is_identifier_char(right);
        if (left_ok && right_ok)
        {
            return true;
        }

        cursor += key_len;
    }

    return false;
}

static bool is_probably_text(uint8_t *data, size_t length)
{
    if (data == NULL || length == 0)
    {
        return false;
    }

    const size_t sample_len = length > 4096 ? 4096 : length;
    size_t printable_or_ws = 0;
    size_t alpha_count = 0;
    size_t nul_count = 0;

    for (size_t i = 0; i < sample_len; i++)
    {
        const unsigned char c = data[i];
        if (c == '\0')
        {
            nul_count++;
            continue;
        }

        if (isprint(c) || c == '\n' || c == '\r' || c == '\t')
        {
            printable_or_ws++;
            if (isalpha(c))
            {
                alpha_count++;
            }
        }
    }

    if (nul_count > 0)
    {
        return false;
    }

    const double printable_ratio = (double)printable_or_ws / (double)sample_len;
    const double alpha_ratio = (double)alpha_count / (double)sample_len;

    return printable_ratio >= 0.90 && alpha_ratio >= 0.20;
}

// Detect file format based on magic bytes
FileFormat detect_file_format(uint8_t *data, size_t length)
{
    if (length < 4)
        return FORMAT_RAW;

    for (size_t i = 0; i < num_signatures; i++)
    {
        if (length >= format_signatures[i].sig_len)
        {
            if (memcmp(data, format_signatures[i].signature, format_signatures[i].sig_len) == 0)
            {
                // Special handling for Office documents vs regular ZIP
                if (format_signatures[i].format == FORMAT_DOCX)
                {
                    // Look deeper into the file to distinguish
                    if (length > 100)
                    {
                        // Simple heuristic: look for Office-specific strings
                        char *data_str = (char *)data;
                        if (strstr(data_str, "word/") || strstr(data_str, "ppt/") ||
                            strstr(data_str, "xl/") || strstr(data_str, "docProps/"))
                        {
                            if (strstr(data_str, "word/"))
                                return FORMAT_DOCX;
                            if (strstr(data_str, "ppt/"))
                                return FORMAT_PPTX;
                        }
                    }
                    return FORMAT_ZIP; // Default to ZIP if not clearly Office
                }

                // Special handling for APK vs ZIP
                if (format_signatures[i].format == FORMAT_APK)
                {
                    if (length > 100)
                    {
                        char *data_str = (char *)data;
                        if (strstr(data_str, "AndroidManifest.xml") ||
                            strstr(data_str, "classes.dex") ||
                            strstr(data_str, "META-INF/"))
                        {
                            return FORMAT_APK;
                        }
                    }
                    return FORMAT_ZIP; // Default to ZIP if not clearly APK
                }

                // Special handling for Java Class vs Mach-O Universal Binary
                if (format_signatures[i].format == FORMAT_MACHO &&
                    memcmp(data, "\xCA\xFE\xBA\xBE", 4) == 0)
                {
                    // Check if it's Java class (has version info at offset 4-6)
                    if (length > 8)
                    {
                        uint16_t major = __builtin_bswap16(*(uint16_t *)(data + 6));
                        // Java class files have reasonable version numbers
                        if (major >= 45 && major <= 65)
                        {
                            return FORMAT_CLASS;
                        }
                    }
                    return FORMAT_MACHO; // Default to Mach-O if not clearly Java
                }

                return format_signatures[i].format;
            }
        }
    }

    // Script detection (text-based)
    if (length > 20)
    {
        char *text = (char *)data;

        // PowerShell detection
        if (strncmp(text, "#!", 2) == 0 && strstr(text, "powershell"))
        {
            return FORMAT_POWERSHELL;
        }
        int ps_score = 0;
        if (strstr(text, "param("))
            ps_score++;
        if (strstr(text, "Get-"))
            ps_score++;
        if (strstr(text, "Set-"))
            ps_score++;
        if (strstr(text, "$_"))
            ps_score++;
        if (strstr(text, "Write-Host"))
            ps_score++;
        if (strstr(text, "Invoke-Expression") || contains_keyword(text, "IEX"))
            ps_score++;
        if (ps_score >= 2)
        {
            return FORMAT_POWERSHELL;
        }

        // Python detection
        if (strncmp(text, "#!/usr/bin/python", 17) == 0 ||
            strncmp(text, "#!/usr/bin/env python", 21) == 0)
        {
            return FORMAT_PYTHON;
        }
        int py_score = 0;
        if (contains_keyword(text, "import"))
            py_score++;
        if (contains_keyword(text, "def"))
            py_score++;
        if (contains_keyword(text, "class"))
            py_score++;
        if (contains_keyword(text, "from"))
            py_score++;
        if (strstr(text, "if __name__ == '__main__'"))
            py_score += 2;
        if (py_score >= 2)
        {
            return FORMAT_PYTHON;
        }

        // JavaScript detection
        if (strncmp(text, "#!/usr/bin/node", 15) == 0)
        {
            return FORMAT_JAVASCRIPT;
        }
        int js_score = 0;
        if (contains_keyword(text, "function"))
            js_score++;
        if (contains_keyword(text, "var"))
            js_score++;
        if (contains_keyword(text, "let"))
            js_score++;
        if (contains_keyword(text, "const"))
            js_score++;
        if (strstr(text, "console.log"))
            js_score++;
        if (contains_keyword(text, "document") || contains_keyword(text, "window"))
            js_score++;

        bool js_structure = false;
        if (strstr(text, "function(") || strstr(text, "=>") || strstr(text, "console.log("))
        {
            js_structure = true;
        }
        else if (strstr(text, ";") && (strstr(text, "{") || strstr(text, "}")))
        {
            js_structure = true;
        }

        if (js_score >= 2 && js_structure)
        {
            return FORMAT_JAVASCRIPT;
        }

        if (is_probably_text(data, length))
        {
            return FORMAT_TEXT;
        }
    }

    return FORMAT_RAW;
}

// Get format name string
const char *get_format_name(FileFormat format)
{
    for (size_t i = 0; i < num_signatures; i++)
    {
        if (format_signatures[i].format == format)
        {
            return format_signatures[i].name;
        }
    }

    switch (format)
    {
    case FORMAT_RAW:
        return "Raw Binary";
    case FORMAT_MACHO:
        return "Mach-O Executable";
    case FORMAT_DEX:
        return "Android DEX";
    case FORMAT_CLASS:
        return "Java Class";
    case FORMAT_WASM:
        return "WebAssembly";
    case FORMAT_POWERSHELL:
        return "PowerShell Script";
    case FORMAT_PYTHON:
        return "Python Script";
    case FORMAT_JAVASCRIPT:
        return "JavaScript";
    case FORMAT_TEXT:
        return "Text";
    case FORMAT_FIRMWARE:
        return "Firmware Image";
    case FORMAT_UNKNOWN:
        return "Unknown Format";
    default:
        return "Unrecognized Format";
    }
}

// Parse PE header information
static void parse_pe_header(uint8_t *data, size_t length)
{
    if (length < 64)
        return;

    printf("  PE Header Analysis:\n");

    // DOS header
    uint16_t *dos_header = (uint16_t *)data;
    printf("    DOS Signature: 0x%04X\n", dos_header[0]);

    if (length > 60)
    {
        uint32_t pe_offset = *(uint32_t *)(data + 60);
        if (pe_offset < length - 4)
        {
            printf("    PE Offset: 0x%08X\n", pe_offset);

            if (pe_offset + 24 < length)
            {
                uint32_t *pe_sig = (uint32_t *)(data + pe_offset);
                printf("    PE Signature: 0x%08X\n", *pe_sig);

                if (*pe_sig == 0x00004550)
                { // "PE\0\0"
                    uint16_t *coff_header = (uint16_t *)(data + pe_offset + 4);
                    printf("    Machine Type: 0x%04X\n", coff_header[0]);
                    printf("    Number of Sections: %u\n", coff_header[1]);
                    printf("    Timestamp: %u\n", *(uint32_t *)(coff_header + 2));
                }
            }
        }
    }
}

// Parse ELF header information
static void parse_elf_header(uint8_t *data, size_t length)
{
    if (length < 52)
        return;

    printf("  ELF Header Analysis:\n");
    printf("    Magic: %02X %02X %02X %02X\n", data[0], data[1], data[2], data[3]);
    printf("    Class: %s\n", data[4] == 1 ? "32-bit" : data[4] == 2 ? "64-bit"
                                                                     : "Unknown");
    printf("    Data Encoding: %s\n", data[5] == 1 ? "Little Endian" : data[5] == 2 ? "Big Endian"
                                                                                    : "Unknown");
    printf("    Version: %u\n", data[6]);
    printf("    OS/ABI: %u\n", data[7]);

    if (length > 16)
    {
        uint16_t type = *(uint16_t *)(data + 16);
        printf("    Type: %s\n",
               type == 1 ? "Relocatable" : type == 2 ? "Executable"
                                       : type == 3   ? "Shared Object"
                                       : type == 4   ? "Core File"
                                                     : "Unknown");

        uint16_t machine = *(uint16_t *)(data + 18);
        printf("    Machine: 0x%04X\n", machine);
    }
}

// Parse ZIP/APK structure
static void parse_zip_structure(uint8_t *data, size_t length)
{
    printf("  ZIP/Archive Structure:\n");

    // Look for central directory
    size_t entries = 0;
    for (size_t i = 0; i < length - 4; i++)
    {
        if (data[i] == 0x50 && data[i + 1] == 0x4B)
        {
            uint16_t sig = *(uint16_t *)(data + i + 2);
            if (sig == 0x0304)
            { // Local file header
                entries++;
                if (entries <= 10)
                { // Show first 10 entries
                    if (i + 30 < length)
                    {
                        uint16_t name_len = *(uint16_t *)(data + i + 26);
                        if (i + 30 + name_len < length)
                        {
                            printf("    Entry %zu: ", entries);
                            for (int j = 0; j < name_len && j < 50; j++)
                            {
                                printf("%c", isprint(data[i + 30 + j]) ? data[i + 30 + j] : '?');
                            }
                            printf("\n");
                        }
                    }
                }
            }
        }
    }
    printf("    Total entries found: %zu\n", entries);
}

// Process different file formats
bool process_file_format(uint8_t *data, size_t length, FileFormat format)
{
    printf("\n=== FILE FORMAT ANALYSIS ===\n");
    printf("Detected Format: %s\n", get_format_name(format));

    bool continue_disassembly = false;
    if (run_registered_format_handler(format, data, length, &continue_disassembly))
    {
        return continue_disassembly;
    }

    switch (format)
    {
    case FORMAT_PE:
        parse_pe_header(data, length);
        printf("  Recommendation: Use PE-specific tools like PEiD, Detect It Easy\n");
        break;

    case FORMAT_ELF:
        parse_elf_header(data, length);
        printf("  Recommendation: Use readelf, objdump, or file command\n");
        break;

    case FORMAT_APK:
        parse_zip_structure(data, length);
        printf("  APK-specific analysis:\n");
        printf("    - Contains Android application code\n");
        printf("    - Use aapt, apktool, or jadx for detailed analysis\n");
        printf("    - Check for classes.dex, AndroidManifest.xml\n");
        break;

    case FORMAT_ZIP:
        parse_zip_structure(data, length);
        printf("  Recommendation: Extract and analyze individual files\n");
        break;

    case FORMAT_PDF:
        printf("  PDF Document Analysis:\n");
        printf("    - Binary may contain embedded JavaScript or executables\n");
        printf("    - Use pdf-parser, peepdf, or similar tools\n");
        printf("    - Check for suspicious objects and streams\n");
        break;

    case FORMAT_DOCX:
    case FORMAT_PPTX:
        printf("  Office Document Analysis:\n");
        printf("    - Modern Office documents are ZIP archives\n");
        printf("    - May contain macros or embedded objects\n");
        printf("    - Use oledump, oletools, or unzip for analysis\n");
        break;

    case FORMAT_TAR:
        printf("  TAR Archive Analysis:\n");
        printf("    - Unix/Linux archive format\n");
        printf("    - Extract with tar command\n");
        printf("    - May be compressed (gzip, bzip2, etc.)\n");
        break;

    case FORMAT_TEXT:
        printf("  Text File Analysis:\n");
        printf("    - Human-readable text content detected\n");
        printf("    - Use string and pattern search commands for content inspection\n");
        break;

    case FORMAT_RAW:
        printf("  Raw Binary Analysis:\n");
        printf("    - No specific format detected\n");
        printf("    - Proceeding with generic disassembly\n");
        return true; // Continue with normal disassembly

    case FORMAT_UNKNOWN:
    default:
        printf("  Unknown Format:\n");
        printf("    - Unable to determine file type\n");
        printf("    - Proceeding with raw binary analysis\n");
        return true;
    }

    return false; // Format was recognized and processed
}
