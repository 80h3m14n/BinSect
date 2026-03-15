#include "analysis_api.h"

#include <stdio.h>
#include <string.h>

// Advanced shellcode detection patterns
static uint8_t shellcode_patterns[][8] = {
    {0x31, 0xc0, 0x50, 0x68}, // XOR EAX, EAX; PUSH EAX; PUSH immediate
    {0x6a, 0x00, 0x6a, 0x00}, // PUSH 0; PUSH 0 (common in shellcode)
    {0xeb, 0xfe},             // JMP $-2 (infinite loop)
    {0x90, 0x90, 0x90, 0x90}, // NOP sled
    {0x31, 0xdb, 0x31, 0xc9}, // XOR EBX, EBX; XOR ECX, ECX
    {0x99, 0x31, 0xc0, 0xb0}, // CDQ; XOR EAX, EAX; MOV AL, imm8
};

// ROP gadget patterns
static uint8_t rop_patterns[][4] = {
    {0x58, 0xc3}, // POP RAX; RET
    {0x59, 0xc3}, // POP RCX; RET
    {0x5a, 0xc3}, // POP RDX; RET
    {0x5b, 0xc3}, // POP RBX; RET
    {0x5c, 0xc3}, // POP RSP; RET (stack pivot)
    {0x5d, 0xc3}, // POP RBP; RET
    {0x5e, 0xc3}, // POP RSI; RET
    {0x5f, 0xc3}, // POP RDI; RET
    {0xff, 0xe0}, // JMP RAX
    {0xff, 0xe4}, // JMP RSP
};

// Encryption/obfuscation patterns
static uint8_t crypto_patterns[][4] = {
    {0xd1, 0xc0}, // ROL EAX, 1
    {0xd1, 0xc8}, // ROR EAX, 1
    {0x35},       // XOR EAX, imm32
    {0x81, 0xf0}, // XOR EAX, imm32
};

bool is_potential_shellcode(uint8_t *code, size_t length)
{
    int pattern_matches = 0;
    int suspicious_sequences = 0;

    // Check for common shellcode patterns
    for (size_t i = 0; i < length - 4; i++)
    {
        for (int p = 0; p < 6; p++)
        {
            if (memcmp(code + i, shellcode_patterns[p], 4) == 0)
            {
                pattern_matches++;
                break;
            }
        }

        // Check for suspicious byte sequences
        if (code[i] == 0x90 && code[i + 1] == 0x90)
        { // NOP sled
            suspicious_sequences++;
        }

        if (code[i] == 0x31 && (code[i + 1] & 0xf0) == 0xc0)
        { // XOR reg, reg
            suspicious_sequences++;
        }
    }

    // Heuristic: if we have multiple patterns, it's likely shellcode
    return (pattern_matches >= 2 || suspicious_sequences >= 3);
}

bool contains_rop_gadgets(uint8_t *code, size_t length)
{
    int gadget_count = 0;

    for (size_t i = 0; i < length - 2; i++)
    {
        for (int p = 0; p < 10; p++)
        {
            size_t pattern_len = (p < 8) ? 2 : 2; // Most ROP patterns are 2 bytes
            if (i + pattern_len <= length)
            {
                if (memcmp(code + i, rop_patterns[p], pattern_len) == 0)
                {
                    gadget_count++;
                    printf("    [ROP] Found gadget at offset 0x%04zx\n", i);
                }
            }
        }
    }

    return gadget_count > 0;
}

void detect_encryption_patterns(uint8_t *code, size_t length)
{
    printf("\n=== ENCRYPTION/OBFUSCATION ANALYSIS ===\n");

    int xor_count = 0;
    int rotate_count = 0;
    int entropy_high_bytes = 0;
    int crypto_pattern_matches = 0;

    for (size_t i = 0; i < length - 1; i++)
    {
        // Check against known crypto patterns
        for (size_t p = 0; p < sizeof(crypto_patterns) / sizeof(crypto_patterns[0]); p++)
        {
            bool matches = true;
            size_t pattern_len = (crypto_patterns[p][2] == 0 && crypto_patterns[p][3] == 0) ? (crypto_patterns[p][1] == 0 ? 1 : 2) : 4;

            if (i + pattern_len <= length)
            {
                for (size_t j = 0; j < pattern_len; j++)
                {
                    if (code[i + j] != crypto_patterns[p][j])
                    {
                        matches = false;
                        break;
                    }
                }
                if (matches)
                {
                    crypto_pattern_matches++;
                }
            }
        }

        // Count XOR operations
        if (code[i] == 0x31 || code[i] == 0x35 ||
            (code[i] == 0x81 && code[i + 1] == 0xf0))
        {
            xor_count++;
        }

        // Count rotation operations
        if ((code[i] == 0xd1 && (code[i + 1] == 0xc0 || code[i + 1] == 0xc8)) ||
            (code[i] == 0xc1 && (code[i + 1] & 0xf8) == 0xc0))
        {
            rotate_count++;
        }

        // Simple entropy check (high entropy bytes)
        if (code[i] > 0x7f && code[i] < 0x90)
        {
            entropy_high_bytes++;
        }
    }

    printf("[0x00000000]> pi  # Crypto/obfuscation analysis\n");
    printf("Crypto: xor=%d rot=%d entropy=%.1f%% patterns=%d\n",
           xor_count, rotate_count, (entropy_high_bytes * 100.0) / length, crypto_pattern_matches);

    if (xor_count > 3 || rotate_count > 2)
    {
        printf("\033[0;33m"); // Yellow
        printf("Obfuscation: DETECTED\n");
        printf("\033[0m");
    }
    else
    {
        printf("Obfuscation: CLEAR\n");
    }
}

void analyze_control_flow(uint8_t *code, size_t length)
{
    printf("[0x00000000]> af  # Control flow analysis\n");

    int conditional_jumps = 0;
    int unconditional_jumps = 0;
    int function_calls = 0;
    int returns = 0;

    for (size_t i = 0; i < length - 1; i++)
    {
        // Conditional jumps (0x70-0x7f)
        if (code[i] >= 0x70 && code[i] <= 0x7f)
        {
            conditional_jumps++;
        }

        // Unconditional jumps
        if (code[i] == 0xeb || code[i] == 0xe9 ||
            (code[i] == 0xff && (code[i + 1] & 0x38) == 0x20))
        {
            unconditional_jumps++;
        }

        // Function calls
        if (code[i] == 0xe8 ||
            (code[i] == 0xff && (code[i + 1] & 0x38) == 0x10))
        {
            function_calls++;
        }

        // Returns
        if (code[i] == 0xc3 || code[i] == 0xc2)
        {
            returns++;
        }
    }

    printf("Control: jcc=%d jmp=%d call=%d ret=%d\n",
           conditional_jumps, unconditional_jumps, function_calls, returns);

    // Simple anomaly detection
    if (unconditional_jumps > conditional_jumps + function_calls)
    {
        printf("\033[0;33m"); // Yellow
        printf("Flow: SUSPICIOUS (many unconditional jumps)\n");
        printf("\033[0m");
    }
    else
    {
        printf("Flow: NORMAL\n");
    }
}

AnalysisResult perform_security_analysis(uint8_t *code, size_t length)
{
    AnalysisResult result = {0};

    result.total_instructions = length; // Simplified
    result.has_shellcode_patterns = is_potential_shellcode(code, length);
    result.has_rop_gadgets = contains_rop_gadgets(code, length);

    // Count various operation types
    for (size_t i = 0; i < length; i++)
    {
        switch (code[i])
        {
        case 0x55:
        case 0x50:
        case 0x51:
        case 0x52:
        case 0x53:
        case 0x54:
        case 0x56:
        case 0x57: // PUSH operations
        case 0x58:
        case 0x59:
        case 0x5a:
        case 0x5b:
        case 0x5c:
        case 0x5d:
        case 0x5e:
        case 0x5f: // POP operations
            result.stack_operations++;
            break;
        case 0xff:
        case 0xeb:
        case 0xe9:
        case 0xe8: // Jumps and calls
            result.jump_operations++;
            break;
        case 0x83:
        case 0x31:
        case 0x01:
        case 0x29: // Arithmetic
            result.arithmetic_operations++;
            break;
        }

        // Check for function prologue
        if (i < length - 3 && code[i] == 0x55 &&
            code[i + 1] == 0x48 && code[i + 2] == 0x89 && code[i + 3] == 0xe5)
        {
            result.has_function_prologue = true;
        }
    }

    return result;
}

void print_security_report(AnalysisResult *result)
{
    printf("\n[0x00000000]> afl  # Analysis summary\n");

    // Compact summary
    printf("Instructions: %d | Stack: %d | Jumps: %d | Vulns: %d\n",
           result->total_instructions, result->stack_operations,
           result->jump_operations, result->vulnerability_count);

    // Security flags in compact format
    printf("Flags: ");
    if (result->has_shellcode_patterns)
    {
        printf("\033[0;31mSHELL\033[0m ");
    }
    if (result->has_rop_gadgets)
    {
        printf("\033[0;31mROP\033[0m ");
    }
    if (result->has_function_prologue)
    {
        printf("\033[0;32mPROLOG\033[0m ");
    }

    // Overall risk assessment
    int risk_score = 0;
    if (result->has_shellcode_patterns)
        risk_score += 3;
    if (result->has_rop_gadgets)
        risk_score += 2;
    if (result->vulnerability_count > 0)
        risk_score += result->vulnerability_count;

    printf("Risk: ");
    if (risk_score >= 5)
    {
        printf("\033[1;31mCRITICAL\033[0m");
    }
    else if (risk_score >= 3)
    {
        printf("\033[0;31mHIGH\033[0m");
    }
    else if (risk_score >= 1)
    {
        printf("\033[0;33mMED\033[0m");
    }
    else
    {
        printf("\033[0;32mLOW\033[0m");
    }
    printf("\n");
}