#ifndef FORMATS_API_H
#define FORMATS_API_H

#include "core_types.h"

FileFormat detect_file_format(uint8_t *data, size_t length);
const char *get_format_name(FileFormat format);
bool process_file_format(uint8_t *data, size_t length, FileFormat format);

#endif
