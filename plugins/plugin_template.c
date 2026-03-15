#include "../include/plugin.h"

#include <stdint.h>
#include <stdio.h>

// Keep plugin ABI in sync with host ABI.
#define TEMPLATE_PLUGIN_ABI_VERSION BINSECT_PLUGIN_ABI_VERSION

static void template_output(uint8_t *code, size_t length)
{
    (void)code;
    printf("\n=== TEMPLATE OUTPUT (PLUGIN) ===\n");
    printf("Length: %zu bytes\n", length);
}

static PackerResult template_detector(uint8_t *data, size_t length)
{
    (void)data;
    (void)length;

    PackerResult result = {
        .type = PACKER_NONE,
        .name = "None",
        .confidence = 0.0f,
        .details = NULL,
        .is_packed = false,
    };

    // TODO: set result fields if your detector finds a match.
    return result;
}

uint32_t binsect_plugin_abi_version(void)
{
    return TEMPLATE_PLUGIN_ABI_VERSION;
}

bool binsect_plugin_init(const BinSectPluginApi *api)
{
    if (api == NULL || api->abi_version != TEMPLATE_PLUGIN_ABI_VERSION)
    {
        return false;
    }

    if (!api->register_output_handler(OUTPUT_ALL, "template", template_output))
    {
        return false;
    }

    if (!api->register_packer_detector("template-detector", template_detector))
    {
        return false;
    }

    return true;
}
