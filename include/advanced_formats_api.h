#ifndef ADVANCED_FORMATS_API_H
#define ADVANCED_FORMATS_API_H

#include "core_types.h"

bool analyze_macho_format(uint8_t *data, size_t length);
bool analyze_dex_format(uint8_t *data, size_t length);
bool analyze_class_format(uint8_t *data, size_t length);
bool analyze_wasm_format(uint8_t *data, size_t length);
bool analyze_script_format(uint8_t *data, size_t length, FileFormat format);
bool analyze_firmware_format(uint8_t *data, size_t length);

#endif
