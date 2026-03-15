#ifndef PLUGIN_H
#define PLUGIN_H

#include <stdbool.h>
#include <stdint.h>

#include "module_registry.h"

#define BINSECT_PLUGIN_ABI_VERSION 1u

typedef struct
{
    uint32_t abi_version;
    bool (*register_output_handler)(OutputFormat format, const char *name, OutputHandlerFn handler);
    bool (*register_format_handler)(FileFormat format, const char *name, FormatHandlerFn handler);
    bool (*register_packer_detector)(const char *name, PackerDetectorFn detector);
} BinSectPluginApi;

typedef bool (*BinSectPluginInitFn)(const BinSectPluginApi *api);
typedef uint32_t (*BinSectPluginAbiVersionFn)(void);

int load_plugins_from_directory(const char *directory);
void unload_plugins(void);

#endif
