#include "advanced_formats_api.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <math.h>

// Forward declaration
static float calculate_entropy(uint8_t *data, size_t length);

// Mach-O analysis
bool analyze_macho_format(uint8_t *data, size_t length)
{
    if (length < 32)
        return false;

    printf("\n=== MACH-O ANALYSIS ===\n");

    // Check for Mach-O magic numbers
    uint32_t magic = *(uint32_t *)data;

    switch (magic)
    {
    case 0xFEEDFACE: // 32-bit Mach-O
        printf("Format: Mach-O 32-bit\n");
        break;
    case 0xFEEDFACF: // 64-bit Mach-O
        printf("Format: Mach-O 64-bit\n");
        break;
    case 0xCAFEBABE: // Universal binary
        printf("Format: Universal Binary (Fat Binary)\n");
        if (length > 8)
        {
            uint32_t arch_count = __builtin_bswap32(*(uint32_t *)(data + 4));
            printf("Architectures: %u\n", arch_count);

            for (uint32_t i = 0; i < arch_count && i < 10; i++)
            {
                size_t offset = 8 + i * 20;
                if (offset + 20 <= length)
                {
                    uint32_t cpu_type = __builtin_bswap32(*(uint32_t *)(data + offset));
                    uint32_t cpu_subtype = __builtin_bswap32(*(uint32_t *)(data + offset + 4));
                    printf("  Arch %u: CPU Type 0x%X, Subtype 0x%X\n", i, cpu_type, cpu_subtype);
                }
            }
        }
        return true;
    default:
        return false;
    }

    if (length > 16)
    {
        uint32_t cpu_type = *(uint32_t *)(data + 4);
        uint32_t file_type = *(uint32_t *)(data + 12);
        uint32_t num_cmds = *(uint32_t *)(data + 16);

        printf("CPU Type: 0x%X ", cpu_type);
        switch (cpu_type)
        {
        case 0x7:
            printf("(x86)\n");
            break;
        case 0x01000007:
            printf("(x86_64)\n");
            break;
        case 0xC:
            printf("(ARM)\n");
            break;
        case 0x0100000C:
            printf("(ARM64)\n");
            break;
        default:
            printf("(Unknown)\n");
            break;
        }

        printf("File Type: ");
        switch (file_type)
        {
        case 1:
            printf("Object file\n");
            break;
        case 2:
            printf("Executable\n");
            break;
        case 6:
            printf("Dynamic library\n");
            break;
        case 8:
            printf("Bundle\n");
            break;
        default:
            printf("Type %u\n", file_type);
            break;
        }

        printf("Load Commands: %u\n", num_cmds);
    }

    printf("Recommendations:\n");
    printf("- Use 'otool -l' for detailed load command analysis\n");
    printf("- Use 'nm' to list symbols\n");
    printf("- Use 'strings' to extract readable strings\n");

    return true;
}

// Android DEX analysis
bool analyze_dex_format(uint8_t *data, size_t length)
{
    if (length < 112)
        return false;

    // Check DEX magic
    if (memcmp(data, "dex\n", 4) != 0)
        return false;

    printf("\n=== ANDROID DEX ANALYSIS ===\n");

    // Parse DEX header
    char version[4];
    memcpy(version, data + 4, 3);
    version[3] = '\0';
    printf("DEX Version: %s\n", version);

    uint32_t checksum = *(uint32_t *)(data + 8);
    printf("Checksum: 0x%08X\n", checksum);

    uint32_t file_size = *(uint32_t *)(data + 32);
    printf("File Size: %u bytes\n", file_size);

    uint32_t header_size = *(uint32_t *)(data + 36);
    printf("Header Size: %u bytes\n", header_size);

    uint32_t string_ids_size = *(uint32_t *)(data + 56);
    uint32_t type_ids_size = *(uint32_t *)(data + 64);
    uint32_t proto_ids_size = *(uint32_t *)(data + 72);
    uint32_t field_ids_size = *(uint32_t *)(data + 80);
    uint32_t method_ids_size = *(uint32_t *)(data + 88);
    uint32_t class_defs_size = *(uint32_t *)(data + 96);

    printf("String IDs: %u\n", string_ids_size);
    printf("Type IDs: %u\n", type_ids_size);
    printf("Prototype IDs: %u\n", proto_ids_size);
    printf("Field IDs: %u\n", field_ids_size);
    printf("Method IDs: %u\n", method_ids_size);
    printf("Class Definitions: %u\n", class_defs_size);

    printf("\nDEX Analysis:\n");
    if (string_ids_size > 10000)
    {
        printf("- Large number of strings (possible obfuscation)\n");
    }
    if (method_ids_size > 5000)
    {
        printf("- Large number of methods (complex application)\n");
    }

    printf("\nRecommendations:\n");
    printf("- Use 'dexdump' for detailed analysis\n");
    printf("- Use 'jadx' to decompile to Java\n");
    printf("- Use 'apktool' for full APK analysis\n");

    return true;
}

// Java Class file analysis
bool analyze_class_format(uint8_t *data, size_t length)
{
    if (length < 10)
        return false;

    // Check Java class magic
    if (*(uint32_t *)data != 0xBEBAFECA)
        return false; // 0xCAFEBABE in big-endian

    printf("\n=== JAVA CLASS ANALYSIS ===\n");

    uint16_t minor_version = __builtin_bswap16(*(uint16_t *)(data + 4));
    uint16_t major_version = __builtin_bswap16(*(uint16_t *)(data + 6));

    printf("Class File Version: %u.%u\n", major_version, minor_version);

    // Map major version to Java version
    printf("Java Version: ");
    switch (major_version)
    {
    case 45:
        printf("1.1\n");
        break;
    case 46:
        printf("1.2\n");
        break;
    case 47:
        printf("1.3\n");
        break;
    case 48:
        printf("1.4\n");
        break;
    case 49:
        printf("5\n");
        break;
    case 50:
        printf("6\n");
        break;
    case 51:
        printf("7\n");
        break;
    case 52:
        printf("8\n");
        break;
    case 53:
        printf("9\n");
        break;
    case 54:
        printf("10\n");
        break;
    case 55:
        printf("11\n");
        break;
    default:
        printf("%u (Unknown)\n", major_version - 44);
        break;
    }

    if (length > 10)
    {
        uint16_t constant_pool_count = __builtin_bswap16(*(uint16_t *)(data + 8));
        printf("Constant Pool Count: %u\n", constant_pool_count);
    }

    printf("\nRecommendations:\n");
    printf("- Use 'javap -c' to disassemble bytecode\n");
    printf("- Use 'jd-gui' for decompilation\n");
    printf("- Check for obfuscation patterns\n");

    return true;
}

// WebAssembly analysis
bool analyze_wasm_format(uint8_t *data, size_t length)
{
    if (length < 8)
        return false;

    // Check WASM magic and version
    if (memcmp(data, "\x00asm", 4) != 0)
        return false;

    printf("\n=== WEBASSEMBLY ANALYSIS ===\n");

    uint32_t version = *(uint32_t *)(data + 4);
    printf("WASM Version: %u\n", version);

    if (version != 1)
    {
        printf("Warning: Non-standard WASM version\n");
    }

    // Parse sections
    size_t offset = 8;
    int section_count = 0;

    printf("\nSections:\n");
    while (offset < length && section_count < 20)
    {
        if (offset + 2 > length)
            break;

        uint8_t section_id = data[offset++];

        // Read LEB128 size (simplified)
        uint32_t size = 0;
        int shift = 0;
        uint8_t byte;
        do
        {
            if (offset >= length)
                break;
            byte = data[offset++];
            size |= (byte & 0x7F) << shift;
            shift += 7;
        } while (byte & 0x80);

        printf("  Section %d: ", section_id);
        switch (section_id)
        {
        case 0:
            printf("Custom");
            break;
        case 1:
            printf("Type");
            break;
        case 2:
            printf("Import");
            break;
        case 3:
            printf("Function");
            break;
        case 4:
            printf("Table");
            break;
        case 5:
            printf("Memory");
            break;
        case 6:
            printf("Global");
            break;
        case 7:
            printf("Export");
            break;
        case 8:
            printf("Start");
            break;
        case 9:
            printf("Element");
            break;
        case 10:
            printf("Code");
            break;
        case 11:
            printf("Data");
            break;
        default:
            printf("Unknown (%d)", section_id);
            break;
        }
        printf(" (size: %u bytes)\n", size);

        offset += size;
        section_count++;
    }

    printf("\nRecommendations:\n");
    printf("- Use 'wasm-objdump' for detailed analysis\n");
    printf("- Use 'wasm2wat' to convert to text format\n");
    printf("- Check for suspicious imports/exports\n");

    return true;
}

// Script analysis (PowerShell, Python, JavaScript)
bool analyze_script_format(uint8_t *data, size_t length, FileFormat format)
{
    if (length < 10)
        return false;

    const char *script_type = "";

    switch (format)
    {
    case FORMAT_POWERSHELL:
        script_type = "PowerShell";
        break;
    case FORMAT_PYTHON:
        script_type = "Python";
        break;
    case FORMAT_JAVASCRIPT:
        script_type = "JavaScript";
        break;
    default:
        return false;
    }

    printf("\n=== %s SCRIPT ANALYSIS ===\n", script_type);

    // Convert to string for analysis
    char *script = malloc(length + 1);
    memcpy(script, data, length);
    script[length] = '\0';

    // Basic statistics
    int line_count = 1;
    int comment_lines = 0;
    int function_count = 0;
    bool has_obfuscation = false;

    for (size_t i = 0; i < length; i++)
    {
        if (data[i] == '\n')
            line_count++;
    }

    // Look for suspicious patterns
    if (strstr(script, "eval(") || strstr(script, "exec("))
    {
        has_obfuscation = true;
    }

    // Count functions/methods
    switch (format)
    {
    case FORMAT_POWERSHELL:
        if (strstr(script, "function "))
            function_count++;
        if (strstr(script, "#"))
            comment_lines++;
        if (strstr(script, "Invoke-Expression") || strstr(script, "IEX"))
        {
            has_obfuscation = true;
        }
        break;
    case FORMAT_PYTHON:
        if (strstr(script, "def "))
            function_count++;
        if (strstr(script, "#"))
            comment_lines++;
        break;
    case FORMAT_JAVASCRIPT:
        if (strstr(script, "function "))
            function_count++;
        if (strstr(script, "//"))
            comment_lines++;
        break;
    default:
        break;
    }

    printf("Lines: %d\n", line_count);
    printf("Functions: %d\n", function_count);
    printf("Comment Lines: %d\n", comment_lines);

    if (has_obfuscation)
    {
        printf("\033[0;31m"); // Red
        printf("⚠️  OBFUSCATION DETECTED\n");
        printf("\033[0m");
    }

    // Check for common malicious patterns
    printf("\nSecurity Analysis:\n");
    if (strstr(script, "powershell") || strstr(script, "cmd.exe"))
    {
        printf("- Command execution detected\n");
    }
    if (strstr(script, "download") || strstr(script, "wget") || strstr(script, "curl"))
    {
        printf("- Network download capability\n");
    }
    if (strstr(script, "base64") || strstr(script, "decode"))
    {
        printf("- Base64 encoding/decoding\n");
    }

    printf("\nRecommendations:\n");
    printf("- Run in isolated environment\n");
    printf("- Check for encoded payloads\n");
    printf("- Monitor network activity\n");

    free(script);
    return true;
}

// Firmware analysis
bool analyze_firmware_format(uint8_t *data, size_t length)
{
    printf("\n=== FIRMWARE ANALYSIS ===\n");

    if (length < 512)
    {
        printf("File too small for typical firmware\n");
        return false;
    }

    // Check for common firmware signatures
    bool found_signature = false;

    // U-Boot signature
    for (size_t i = 0; i < length - 8; i++)
    {
        if (memcmp(&data[i], "U-Boot", 6) == 0)
        {
            printf("U-Boot bootloader detected at offset 0x%zx\n", i);
            found_signature = true;
            break;
        }
    }

    // Linux kernel signature
    for (size_t i = 0; i < length - 16; i++)
    {
        if (memcmp(&data[i], "Linux version", 13) == 0)
        {
            printf("Linux kernel detected at offset 0x%zx\n", i);
            found_signature = true;
            break;
        }
    }

    // SquashFS signature
    for (size_t i = 0; i < length - 4; i++)
    {
        if (memcmp(&data[i], "sqsh", 4) == 0 || memcmp(&data[i], "hsqs", 4) == 0)
        {
            printf("SquashFS filesystem detected at offset 0x%zx\n", i);
            found_signature = true;
            break;
        }
    }

    // JFFS2 signature
    for (size_t i = 0; i < length - 4; i++)
    {
        if (data[i] == 0x19 && data[i + 1] == 0x85)
        {
            printf("JFFS2 filesystem detected at offset 0x%zx\n", i);
            found_signature = true;
            break;
        }
    }

    // Calculate entropy for different sections
    if (length > 1024)
    {
        float entropy_start = calculate_entropy(data, 1024);
        float entropy_mid = calculate_entropy(data + length / 2, 1024);
        float entropy_end = calculate_entropy(data + length - 1024, 1024);

        printf("Entropy Analysis:\n");
        printf("  Start: %.2f\n", entropy_start);
        printf("  Middle: %.2f\n", entropy_mid);
        printf("  End: %.2f\n", entropy_end);

        if (entropy_start > 7.5f || entropy_mid > 7.5f || entropy_end > 7.5f)
        {
            printf("  High entropy detected - possibly compressed/encrypted\n");
        }
    }

    if (!found_signature)
    {
        printf("No common firmware signatures found\n");
        printf("This may be encrypted, compressed, or proprietary firmware\n");
    }

    printf("\nRecommendations:\n");
    printf("- Use 'binwalk' for detailed firmware analysis\n");
    printf("- Use 'firmware-mod-kit' for extraction\n");
    printf("- Check for encryption or compression\n");
    printf("- Look for embedded certificates or keys\n");

    return found_signature;
}

// Helper function for entropy calculation (also used in packer.c)
static float calculate_entropy(uint8_t *data, size_t length)
{
    if (length == 0)
        return 0.0f;

    int freq[256] = {0};
    for (size_t i = 0; i < length; i++)
    {
        freq[data[i]]++;
    }

    float entropy = 0.0f;
    for (int i = 0; i < 256; i++)
    {
        if (freq[i] > 0)
        {
            float p = (float)freq[i] / length;
            entropy -= p * log2f(p);
        }
    }

    return entropy;
}
