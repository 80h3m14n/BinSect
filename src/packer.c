#define _GNU_SOURCE
#include "module_registry.h"
#include "packer_api.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <math.h>

// Packer signature database
typedef struct
{
    PackerType type;
    const char *name;
    uint8_t signature[32];
    size_t sig_len;
    size_t offset;
    const char *description;
} PackerSignature;

static PackerSignature packer_signatures[] = {
    // UPX signatures
    {PACKER_UPX, "UPX", {0x55, 0x50, 0x58, 0x21}, 4, 0, "UPX Packer"},
    {PACKER_UPX, "UPX", {0x4D, 0x5A, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0x00, 0x00, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, 32, 0, "UPX PE Header"},

    // ASPack signatures
    {PACKER_ASPACK, "ASPack", {0x60, 0xE8, 0x03, 0x00, 0x00, 0x00, 0xE9, 0xEB}, 8, 0, "ASPack Entry Point"},
    {PACKER_ASPACK, "ASPack", {0x60, 0xE8, 0x00, 0x00, 0x00, 0x00, 0x5D, 0x81, 0xED}, 9, 0, "ASPack Variant"},

    // Themida signatures
    {PACKER_THEMIDA, "Themida", {0x8B, 0xC0, 0x01, 0xC8, 0x83, 0xC0, 0x01, 0x50}, 8, 0, "Themida Obfuscation"},
    {PACKER_THEMIDA, "Themida", {0xB8, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00}, 8, 0, "Themida Marker"},

    // VMProtect signatures
    {PACKER_VMPROTECT, "VMProtect", {0x68, 0x00, 0x00, 0x00, 0x00, 0xC3}, 6, 0, "VMProtect Entry"},
    {PACKER_VMPROTECT, "VMProtect", {0xE8, 0x00, 0x00, 0x00, 0x00, 0x58, 0x05}, 7, 0, "VMProtect Call"},

    // PEtite signatures
    {PACKER_PETITE, "PEtite", {0xB8, 0x00, 0x00, 0x00, 0x00, 0x66, 0x9C, 0x60}, 8, 0, "PEtite Entry"},
    {PACKER_PETITE, "PEtite", {0x66, 0x9C, 0x60, 0x50, 0x8B, 0xD8}, 6, 0, "PEtite Stub"},

    // PECompact signatures
    {PACKER_PECOMPACT, "PECompact", {0xEB, 0x06, 0x68, 0x00, 0x00, 0x00, 0x00, 0xC3}, 8, 0, "PECompact Entry"},
    {PACKER_PECOMPACT, "PECompact", {0x53, 0x51, 0x52, 0x56, 0x57, 0x55, 0x8B, 0xEC}, 8, 0, "PECompact Stub"},

    // MPRESS signatures
    {PACKER_MPRESS, "MPRESS", {0x60, 0xE8, 0x00, 0x00, 0x00, 0x00, 0x58, 0x05}, 8, 0, "MPRESS Entry"},
    {PACKER_MPRESS, "MPRESS", {0x4D, 0x50, 0x52, 0x45, 0x53, 0x53}, 6, 0, "MPRESS Signature"},

    // Armadillo signatures
    {PACKER_ARMADILLO, "Armadillo", {0x55, 0x8B, 0xEC, 0x6A, 0xFF, 0x68}, 6, 0, "Armadillo Entry"},
    {PACKER_ARMADILLO, "Armadillo", {0x60, 0xE8, 0x00, 0x00, 0x00, 0x00, 0x5D, 0x50}, 8, 0, "Armadillo Stub"}};

static const size_t num_packer_signatures = sizeof(packer_signatures) / sizeof(PackerSignature);

// Entropy calculation for packer detection
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

// Check for common packer patterns
static bool check_packer_patterns(uint8_t *data, size_t length)
{
    // High entropy sections (common in packed executables)
    if (length > 1024)
    {
        float entropy = calculate_entropy(data, 1024);
        if (entropy > 7.5f)
            return true;
    }

    // Unusual section names in PE files
    if (length > 64 && data[0] == 0x4D && data[1] == 0x5A)
    {
        // Look for packed section names
        for (size_t i = 0; i < length - 8; i++)
        {
            if (strncmp((char *)&data[i], "UPX0", 4) == 0 ||
                strncmp((char *)&data[i], "UPX1", 4) == 0 ||
                strncmp((char *)&data[i], ".aspack", 7) == 0 ||
                strncmp((char *)&data[i], ".themida", 8) == 0)
            {
                return true;
            }
        }
    }

    // Import table anomalies
    int import_count = 0;
    for (size_t i = 0; i < length - 16; i++)
    {
        if (data[i] == 0xFF && data[i + 1] == 0x25)
        { // JMP [import]
            import_count++;
        }
    }

    // Suspiciously few imports for a real executable
    if (length > 10000 && import_count < 5)
        return true;

    return false;
}

// Built-in signature and heuristic detector used by the registry.
PackerResult detect_packer_signature(uint8_t *data, size_t length)
{
    PackerResult result = {PACKER_NONE, "None", 0.0f, NULL, false};

    if (length < 64)
    {
        result.details = strdup("File too small for packer analysis");
        return result;
    }

    float max_confidence = 0.0f;
    PackerType detected_type = PACKER_NONE;
    const char *detected_name = "None";

    // Check signature database
    for (size_t i = 0; i < num_packer_signatures; i++)
    {
        PackerSignature *sig = &packer_signatures[i];

        // Check at various offsets
        for (size_t offset = 0; offset < length - sig->sig_len && offset < 1024; offset += 16)
        {
            if (memcmp(&data[offset], sig->signature, sig->sig_len) == 0)
            {
                float confidence = 0.9f; // High confidence for exact signature match

                if (confidence > max_confidence)
                {
                    max_confidence = confidence;
                    detected_type = sig->type;
                    detected_name = sig->name;
                    result.details = strdup(sig->description);
                }
                break;
            }
        }
    }

    // Heuristic analysis
    if (max_confidence < 0.5f)
    {
        if (check_packer_patterns(data, length))
        {
            max_confidence = 0.6f;
            detected_type = PACKER_GENERIC;
            detected_name = "Generic Packer";
            result.details = strdup("Heuristic detection - high entropy or suspicious patterns");
        }
    }

    result.type = detected_type;
    result.name = detected_name;
    result.confidence = max_confidence;
    result.is_packed = (max_confidence > 0.3f);

    return result;
}

// Main packer detection entrypoint that runs all registered detector modules.
PackerResult detect_packer(uint8_t *data, size_t length)
{
    register_builtin_modules();
    return run_registered_packer_detectors(data, length);
}

// Get packer name from type
const char *get_packer_name(PackerType type)
{
    switch (type)
    {
    case PACKER_UPX:
        return "UPX";
    case PACKER_ASPACK:
        return "ASPack";
    case PACKER_THEMIDA:
        return "Themida";
    case PACKER_VMPROTECT:
        return "VMProtect";
    case PACKER_PETITE:
        return "PEtite";
    case PACKER_PECOMPACT:
        return "PECompact";
    case PACKER_MPRESS:
        return "MPRESS";
    case PACKER_ARMADILLO:
        return "Armadillo";
    case PACKER_GENERIC:
        return "Generic Packer";
    case PACKER_NONE:
        return "None";
    default:
        return "Unknown";
    }
}

// Print packer detection results
void print_packer_info(PackerResult *result)
{
    printf("\n=== PACKER DETECTION ===\n");

    if (result->is_packed)
    {
        printf("\033[0;31m"); // Red for packed
        printf("⚠️  PACKED EXECUTABLE DETECTED\n");
        printf("\033[0m");
        printf("Packer: %s\n", result->name);
        printf("Confidence: %.1f%%\n", result->confidence * 100.0f);
        if (result->details)
        {
            printf("Details: %s\n", result->details);
        }

        printf("\nRecommendations:\n");
        switch (result->type)
        {
        case PACKER_UPX:
            printf("- Use 'upx -d' to unpack\n");
            printf("- UPX is reversible packer\n");
            break;
        case PACKER_ASPACK:
            printf("- Use ASPack unpacker tools\n");
            printf("- May require manual unpacking\n");
            break;
        case PACKER_THEMIDA:
            printf("- Advanced protection - use specialized tools\n");
            printf("- Consider dynamic analysis\n");
            break;
        case PACKER_VMPROTECT:
            printf("- Virtualization-based protection\n");
            printf("- Extremely difficult to unpack\n");
            break;
        default:
            printf("- Use generic unpacking tools\n");
            printf("- Consider dynamic analysis\n");
            break;
        }
    }
    else
    {
        printf("\033[0;32m"); // Green for not packed
        printf("✓ No packer detected\n");
        printf("\033[0m");
        printf("Confidence: %.1f%%\n", (1.0f - result->confidence) * 100.0f);
    }
}
