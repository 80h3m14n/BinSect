#ifndef OUTPUT_API_H
#define OUTPUT_API_H

#include "core_types.h"

void output_bytes(uint8_t *code, size_t length);
void output_assembly(uint8_t *code, size_t length);
void output_hex_dump(uint8_t *code, size_t length);
void output_strings(uint8_t *code, size_t length);
void output_all_formats(uint8_t *code, size_t length);

StringResult *extract_strings(uint8_t *data, size_t length, size_t *count);
void free_string_results(StringResult *results, size_t count);
bool is_printable_ascii(const char *str, size_t len);
bool is_unicode_string(uint8_t *data, size_t len);

#endif
