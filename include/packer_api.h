#ifndef PACKER_API_H
#define PACKER_API_H

#include "core_types.h"

PackerResult detect_packer(uint8_t *data, size_t length);
PackerResult detect_packer_signature(uint8_t *data, size_t length);
const char *get_packer_name(PackerType type);
void print_packer_info(PackerResult *result);

#endif
