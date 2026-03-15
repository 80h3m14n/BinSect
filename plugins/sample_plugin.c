#include <math.h>
#include <stdio.h>

#include "../include/plugin.h"

#define SAMPLE_PLUGIN_ABI_VERSION 1u

static float sample_entropy(const uint8_t *data, size_t length)
{
    if (length == 0)
    {
        return 0.0f;
    }

    int counts[256] = {0};
    for (size_t i = 0; i < length; i++)
    {
        counts[data[i]]++;
    }

    float entropy = 0.0f;
    for (int i = 0; i < 256; i++)
    {
        if (counts[i] > 0)
        {
            const float p = (float)counts[i] / (float)length;
            entropy -= p * log2f(p);
        }
    }

    return entropy;
}

static void output_entropy(uint8_t *code, size_t length)
{
    printf("\n=== ENTROPY OUTPUT (PLUGIN) ===\n");
    printf("Length: %zu bytes\n", length);
    printf("Entropy: %.4f bits/byte\n", sample_entropy(code, length));
}

static PackerResult detect_xor_obfuscation(uint8_t *data, size_t length)
{
    PackerResult result = {PACKER_NONE, "None", 0.0f, NULL, false};

    if (length < 128)
    {
        return result;
    }

    size_t xor_count = 0;
    for (size_t i = 0; i + 1 < length; i++)
    {
        if (data[i] == 0x31 || data[i] == 0x35 || (data[i] == 0x81 && data[i + 1] == 0xF0))
        {
            xor_count++;
        }
    }

    const float ratio = (float)xor_count / (float)length;
    if (ratio > 0.02f)
    {
        result.type = PACKER_GENERIC;
        result.name = "XorObf";
        result.confidence = ratio > 0.06f ? 0.72f : 0.45f;
        result.details = (char *)"Sample plugin detector: high XOR instruction density";
        result.is_packed = true;
    }

    return result;
}

uint32_t binsect_plugin_abi_version(void)
{
    return SAMPLE_PLUGIN_ABI_VERSION;
}

bool binsect_plugin_init(const BinSectPluginApi *api)
{
    if (api == NULL || api->abi_version != SAMPLE_PLUGIN_ABI_VERSION)
    {
        return false;
    }

    if (!api->register_output_handler(OUTPUT_ALL, "entropy", output_entropy))
    {
        return false;
    }

    if (!api->register_packer_detector("sample-xor-detector", detect_xor_obfuscation))
    {
        return false;
    }

    return true;
}
