#include "analysis_api.h"
#include "disasm_api.h"

#include <stdio.h>
#include <string.h>

// Common x86-64 instruction patterns that may indicate vulnerabilities
static VulnPattern vuln_patterns[] = {
    // Buffer overflow patterns
    {(uint8_t[]){0x48, 0x8b, 0x45}, 3, "STACK_ACCESS", "Direct stack access without bounds checking", "MEDIUM", "Use bounds checking and safe functions"},
    {(uint8_t[]){0x48, 0x89, 0x45}, 3, "STACK_WRITE", "Stack write operation", "MEDIUM", "Implement stack canaries"},
    {(uint8_t[]){0x48, 0x8d, 0x45}, 3, "STACK_LEA", "Stack address calculation", "LOW", "Validate buffer boundaries"},

    // Jump/call patterns that might indicate ROP gadgets
    {(uint8_t[]){0xff, 0xe0}, 2, "JMP_RAX", "Jump to RAX - potential ROP gadget", "HIGH", "Enable CFI and DEP"},
    {(uint8_t[]){0xff, 0xe4}, 2, "JMP_RSP", "Jump to RSP - potential stack pivot", "CRITICAL", "Implement stack isolation"},
    {(uint8_t[]){0xc3}, 1, "RET", "Return instruction - ROP gadget component", "LOW", "Use return address protection"},

    // Format string vulnerabilities
    {(uint8_t[]){0x48, 0x8d, 0x3d}, 3, "LEA_RDI", "LEA RDI instruction - potential format string", "MEDIUM", "Use safe format functions"},

    // Unsafe memory operations
    {(uint8_t[]){0x48, 0x31, 0xc0}, 3, "XOR_RAX", "XOR RAX,RAX - register clearing", "LOW", "Normal operation"},
    {(uint8_t[]){0x48, 0xff, 0xc0}, 3, "INC_RAX", "Increment RAX - potential integer overflow", "MEDIUM", "Check for integer overflow"},

    // Shellcode patterns
    {(uint8_t[]){0x31, 0xc0}, 2, "XOR_EAX_EAX", "XOR EAX,EAX - common shellcode pattern", "HIGH", "Enable DEP and ASLR"},
    {(uint8_t[]){0x50}, 1, "PUSH_RAX", "PUSH RAX - stack manipulation", "LOW", "Monitor stack operations"},

    // Function prologue/epilogue that might be exploitable
    {(uint8_t[]){0x55, 0x48, 0x89, 0xe5}, 4, "FUNC_PROLOGUE", "Standard function prologue", "LOW", "Standard function structure"},
    {(uint8_t[]){0x48, 0x89, 0xec}, 3, "MOV_RSP_RBP", "Stack frame setup", "LOW", "Normal stack frame operation"},
};

static const size_t num_patterns = sizeof(vuln_patterns) / sizeof(VulnPattern);

// Simple x86-64 instruction decoder
static Instruction instructions[] = {
    {0x55, "PUSH RBP", 0, "Save base pointer"},
    {0x48, "REX.W prefix", 0, "64-bit operand prefix"},
    {0x89, "MOV", 2, "Move data between registers/memory"},
    {0x8b, "MOV", 2, "Move data from memory to register"},
    {0x8d, "LEA", 2, "Load effective address"},
    {0x83, "Arithmetic", 2, "Arithmetic operations with immediate"},
    {0xec, "SUB ESP", 1, "Subtract from stack pointer"},
    {0x05, "ADD EAX", 1, "Add immediate to EAX"},
    {0xb8, "MOV EAX", 1, "Move immediate to EAX"},
    {0x13, "ADC", 2, "Add with carry"},
    {0x00, "ADD", 2, "Add operation"},
    {0xff, "Various", 1, "Various operations based on ModR/M"},
    {0xe0, "LOOPNE/JMP", 1, "Loop or jump instruction"},
    {0xe4, "IN AL/JMP", 1, "Input or jump instruction"},
    {0xc3, "RET", 0, "Return from procedure"},
    {0x31, "XOR", 2, "Exclusive OR operation"},
    {0xc0, "ROL/ROR", 2, "Rotate left/right"},
    {0x50, "PUSH RAX", 0, "Push RAX onto stack"},
};

static const size_t num_instructions = sizeof(instructions) / sizeof(Instruction);

void print_severity_color(const char *severity)
{
    if (strcmp(severity, "CRITICAL") == 0)
    {
        printf("\033[1;31m"); // Bright red
    }
    else if (strcmp(severity, "HIGH") == 0)
    {
        printf("\033[0;31m"); // Red
    }
    else if (strcmp(severity, "MEDIUM") == 0)
    {
        printf("\033[0;33m"); // Yellow
    }
    else
    {
        printf("\033[0;32m"); // Green for LOW
    }
}

void reset_color()
{
    printf("\033[0m");
}

bool check_vulnerability_patterns(uint8_t *code, size_t length, size_t offset)
{
    bool found = false;

    for (size_t p = 0; p < num_patterns; p++)
    {
        VulnPattern *pattern = &vuln_patterns[p];

        if (offset + pattern->length <= length)
        {
            if (memcmp(code + offset, pattern->pattern, pattern->length) == 0)
            {
                // Print comment in radare2 style
                printf("  ; ");
                print_severity_color(pattern->severity);
                printf("[%s] %s", pattern->severity, pattern->name);
                reset_color();
                printf("\n");
                found = true;
            }
        }
    }

    return found;
}

char *decode_instruction(uint8_t opcode)
{
    for (size_t i = 0; i < num_instructions; i++)
    {
        if (instructions[i].opcode == opcode)
        {
            return instructions[i].mnemonic;
        }
    }
    return "UNKNOWN";
}

void analyze_code_flow(uint8_t *code, size_t length)
{
    printf("\n[0x00000000]> aa  # Code flow analysis\n");

    int stack_ops = 0;
    int jump_ops = 0;
    int arithmetic_ops = 0;
    bool has_ret = false;

    for (size_t i = 0; i < length; i++)
    {
        switch (code[i])
        {
        case 0x55: // PUSH RBP
        case 0x50: // PUSH RAX
            stack_ops++;
            break;
        case 0xff: // Various jumps/calls
            jump_ops++;
            break;
        case 0x83: // Arithmetic
        case 0x31: // XOR
            arithmetic_ops++;
            break;
        case 0xc3: // RET
            has_ret = true;
            break;
        }
    }

    // Compact flow summary
    printf("Flow: stack=%d jumps=%d arith=%d ret=%s\n",
           stack_ops, jump_ops, arithmetic_ops, has_ret ? "yes" : "no");

    // Risk assessment
    if (jump_ops > 3 && stack_ops > 2)
    {
        print_severity_color("HIGH");
        printf("Risk: HIGH (complex flow)\n");
        reset_color();
    }
    else if (stack_ops > 4)
    {
        print_severity_color("MEDIUM");
        printf("Risk: MEDIUM (many stack ops)\n");
        reset_color();
    }
    else
    {
        printf("\033[0;32m"); // Green
        printf("Risk: LOW\n");
        printf("\033[0m");
    }
}
void disassemble_with_analysis(uint8_t *code, size_t length)
{
    printf("[0x00000000]> pd %zu  # %zu bytes\n", length, length);

    for (size_t i = 0; i < length; i++)
    {
        // Print in radare2 style: address | hex | instruction | comment
        printf("0x%08zx   %02x             ", i, code[i]);

        // Try to decode instruction
        char *instruction = decode_instruction(code[i]);
        printf("%-12s", instruction);

        // Check for vulnerability patterns at this offset - show as comments
        if (check_vulnerability_patterns(code, length, i))
        {
            // Pattern already printed in check_vulnerability_patterns as comment
        }
        else
        {
            printf("\n");
        }
    }
}
