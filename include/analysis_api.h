#ifndef ANALYSIS_API_H
#define ANALYSIS_API_H

#include "core_types.h"

void print_severity_color(const char *severity);
void reset_color(void);
AnalysisResult perform_security_analysis(uint8_t *code, size_t length);
void print_security_report(AnalysisResult *result);

bool is_potential_shellcode(uint8_t *code, size_t length);
bool contains_rop_gadgets(uint8_t *code, size_t length);
void detect_encryption_patterns(uint8_t *code, size_t length);
void analyze_control_flow(uint8_t *code, size_t length);

#endif
