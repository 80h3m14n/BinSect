#ifndef DISASM_API_H
#define DISASM_API_H

#include "core_types.h"

void disassemble_with_analysis(uint8_t *code, size_t length);
bool check_vulnerability_patterns(uint8_t *code, size_t length, size_t offset);
char *decode_instruction(uint8_t opcode);
void analyze_code_flow(uint8_t *code, size_t length);

#endif
