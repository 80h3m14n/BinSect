#ifndef MODULE_REGISTRY_H
#define MODULE_REGISTRY_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "core_types.h"
#include "advanced_formats_api.h"
#include "output_api.h"
#include "packer_api.h"

typedef void (*OutputHandlerFn)(uint8_t *code, size_t length);
typedef bool (*FormatHandlerFn)(uint8_t *data, size_t length);
typedef PackerResult (*PackerDetectorFn)(uint8_t *data, size_t length);

bool register_output_handler(OutputFormat format, const char *name, OutputHandlerFn handler);
bool dispatch_output_handler(OutputFormat format, uint8_t *code, size_t length);
bool dispatch_output_handler_by_name(const char *name, uint8_t *code, size_t length);

bool register_format_handler(FileFormat format, const char *name, FormatHandlerFn handler);
bool run_registered_format_handler(FileFormat format, uint8_t *data, size_t length, bool *continue_disassembly);

bool register_packer_detector(const char *name, PackerDetectorFn detector);
PackerResult run_registered_packer_detectors(uint8_t *data, size_t length);

void register_builtin_modules(void);

#endif
