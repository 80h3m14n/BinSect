#include "disassembler.h"
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

// External functions
extern bool is_potential_shellcode(uint8_t *code, size_t length);
extern bool contains_rop_gadgets(uint8_t *code, size_t length);
extern void detect_encryption_patterns(uint8_t *code, size_t length);
extern void analyze_control_flow(uint8_t *code, size_t length);
extern AnalysisResult perform_security_analysis(uint8_t *code, size_t length);
extern void print_security_report(AnalysisResult *result);
extern void disassemble_with_analysis(uint8_t *code, size_t length);

void print_usage(const char *program_name)
{
    printf("Usage: %s [options] <binary_file>\n", program_name);
    printf("Options:\n");
    printf("  -h, --help       Show this help message\n");
    printf("  -v, --verbose    Enable verbose output\n");
    printf("  -i, --interactive Start interactive mode\n");
    printf("  -f, --format     Output format: byte|assembly|strings|hex|all\n");
    printf("  -t, --type       Force file type: raw|pe|elf|apk|pdf|zip|tar|macho|dex|class|wasm|powershell|python|javascript|firmware\n");
    printf("\nOutput Formats:\n");
    printf("  byte            Raw byte values\n");
    printf("  assembly        Assembly mnemonics\n");
    printf("  strings         Extract readable strings\n");
    printf("  hex             Hexadecimal dump\n");
    printf("  all             All formats (default)\n");
    printf("\nSupported File Types:\n");
    printf("  PE, ELF, APK, PDF, DOCX, PPTX, ZIP, TAR archives\n");
    printf("  Mach-O, Android DEX, Java Class, WebAssembly\n");
    printf("  PowerShell, Python, JavaScript scripts\n");
    printf("  Firmware images with packer detection\n");
    printf("\nExamples:\n");
    printf("  %s /bin/ls                      # Full analysis\n", program_name);
    printf("  %s -f hex /usr/bin/passwd       # Hex dump only\n", program_name);
    printf("  %s -f strings document.pdf      # Extract strings\n", program_name);
    printf("  %s -t pe -f assembly prog.exe   # Force PE, show assembly\n", program_name);
    printf("  %s -i                           # Interactive mode\n", program_name);
}

// Parse output format from string
OutputFormat parse_output_format(const char *format_str)
{
    if (strcmp(format_str, "byte") == 0)
        return OUTPUT_BYTE;
    if (strcmp(format_str, "assembly") == 0)
        return OUTPUT_ASSEMBLY;
    if (strcmp(format_str, "strings") == 0)
        return OUTPUT_STRINGS;
    if (strcmp(format_str, "hex") == 0)
        return OUTPUT_HEX;
    if (strcmp(format_str, "all") == 0)
        return OUTPUT_ALL;
    return OUTPUT_ALL; // Default
}

// Parse file format from string
FileFormat parse_file_format(const char *format_str)
{
    if (strcmp(format_str, "raw") == 0)
        return FORMAT_RAW;
    if (strcmp(format_str, "pe") == 0)
        return FORMAT_PE;
    if (strcmp(format_str, "elf") == 0)
        return FORMAT_ELF;
    if (strcmp(format_str, "apk") == 0)
        return FORMAT_APK;
    if (strcmp(format_str, "pdf") == 0)
        return FORMAT_PDF;
    if (strcmp(format_str, "docx") == 0)
        return FORMAT_DOCX;
    if (strcmp(format_str, "pptx") == 0)
        return FORMAT_PPTX;
    if (strcmp(format_str, "zip") == 0)
        return FORMAT_ZIP;
    if (strcmp(format_str, "tar") == 0)
        return FORMAT_TAR;
    if (strcmp(format_str, "macho") == 0)
        return FORMAT_MACHO;
    if (strcmp(format_str, "dex") == 0)
        return FORMAT_DEX;
    if (strcmp(format_str, "class") == 0)
        return FORMAT_CLASS;
    if (strcmp(format_str, "wasm") == 0)
        return FORMAT_WASM;
    if (strcmp(format_str, "powershell") == 0)
        return FORMAT_POWERSHELL;
    if (strcmp(format_str, "python") == 0)
        return FORMAT_PYTHON;
    if (strcmp(format_str, "javascript") == 0)
        return FORMAT_JAVASCRIPT;
    if (strcmp(format_str, "firmware") == 0)
        return FORMAT_FIRMWARE;
    return FORMAT_UNKNOWN;
}

int analyze_file(const char *filename, bool verbose, OutputFormat output_fmt, FileFormat force_format)
{
    printf("Analyzing file: %s\n", filename);

    int fd = open(filename, O_RDONLY);
    if (fd == -1)
    {
        perror("Error opening file");
        return 1;
    }

    struct stat st;
    if (fstat(fd, &st) == -1)
    {
        perror("Error getting file stats");
        close(fd);
        return 1;
    }

    if (st.st_size > 10485760)
    { // Limit to 10MB for safety
        printf("Warning: File is large (%ld bytes). Analyzing first 10MB only.\n", st.st_size);
        st.st_size = 10485760;
    }

    uint8_t *buffer = malloc(st.st_size);
    if (!buffer)
    {
        perror("Error allocating memory");
        close(fd);
        return 1;
    }

    ssize_t bytes_read = read(fd, buffer, st.st_size);
    if (bytes_read == -1)
    {
        perror("Error reading file");
        free(buffer);
        close(fd);
        return 1;
    }

    close(fd);

    printf("File size: %ld bytes\n", bytes_read);

    // Detect file format
    FileFormat detected_format = (force_format != FORMAT_UNKNOWN) ? force_format : detect_file_format(buffer, bytes_read);

    // Packer detection
    PackerResult packer_result = detect_packer(buffer, bytes_read);
    print_packer_info(&packer_result);

    // Process file format
    bool continue_disasm = process_file_format(buffer, bytes_read, detected_format);

    // Output in requested format
    switch (output_fmt)
    {
    case OUTPUT_BYTE:
        output_bytes(buffer, bytes_read);
        break;
    case OUTPUT_ASSEMBLY:
        output_assembly(buffer, bytes_read);
        break;
    case OUTPUT_STRINGS:
        output_strings(buffer, bytes_read);
        break;
    case OUTPUT_HEX:
        output_hex_dump(buffer, bytes_read);
        break;
    case OUTPUT_ALL:
    default:
        output_all_formats(buffer, bytes_read);
        break;
    }

    // Continue with disassembly and security analysis for raw binaries
    if (continue_disasm || detected_format == FORMAT_RAW)
    {
        printf("\n=== SECURITY ANALYSIS ===\n");
        disassemble_with_analysis(buffer, bytes_read);

        AnalysisResult result = perform_security_analysis(buffer, bytes_read);
        print_security_report(&result);

        if (verbose)
        {
            detect_encryption_patterns(buffer, bytes_read);
            analyze_control_flow(buffer, bytes_read);

            printf("\n=== ADVANCED ANALYSIS ===\n");
            if (is_potential_shellcode(buffer, bytes_read))
            {
                printf("⚠️  SHELLCODE PATTERNS DETECTED\n");
            }
            if (contains_rop_gadgets(buffer, bytes_read))
            {
                printf("⚠️  ROP GADGETS DETECTED\n");
            }
        }
    }

    free(buffer);
    return 0;
}

void interactive_mode()
{
    char command[256];
    char filename[256] = {0};
    uint8_t *buffer = NULL;
    size_t buffer_size = 0;
    bool verbose = false;

    printf("DisAsm Interactive Mode - Type 'help' for commands\n");
    printf("[0x00000000]> ");

    while (fgets(command, sizeof(command), stdin))
    {
        // Remove newline
        command[strcspn(command, "\n")] = 0;

        if (strlen(command) == 0)
        {
            printf("[0x%08zx]> ", buffer_size);
            continue;
        }

        // Parse commands
        if (strcmp(command, "help") == 0 || strcmp(command, "?") == 0)
        {
            printf("Commands:\n");
            printf("  load <file>    - Load binary file (e.g., load /bin/ls)\n");
            printf("  pd [n]         - Print disassembly (n bytes, default all)\n");
            printf("  aa             - Analyze code flow\n");
            printf("  afl            - Security analysis summary\n");
            printf("  info           - File information\n");
            printf("  verbose        - Toggle verbose mode\n");
            printf("  clear          - Clear screen\n");
            printf("  quit/q/exit    - Exit interactive mode\n");
            printf("\nExample: load /usr/bin/passwd, then pd 50, then afl\n");
        }
        else if (strncmp(command, "load ", 5) == 0)
        {
            strncpy(filename, command + 5, sizeof(filename) - 1);

            // Free previous buffer
            if (buffer)
            {
                free(buffer);
                buffer = NULL;
                buffer_size = 0;
            }

            // Load new file
            int fd = open(filename, O_RDONLY);
            if (fd == -1)
            {
                printf("Error: Cannot open file '%s'\n", filename);
            }
            else
            {
                struct stat st;
                if (fstat(fd, &st) == 0)
                {
                    if (st.st_size > 10485760)
                    {
                        printf("Warning: Large file, loading first 10MB\n");
                        st.st_size = 10485760;
                    }

                    buffer = malloc(st.st_size);
                    if (buffer)
                    {
                        ssize_t bytes_read = read(fd, buffer, st.st_size);
                        if (bytes_read > 0)
                        {
                            buffer_size = bytes_read;
                            printf("Loaded %ld bytes from '%s'\n", bytes_read, filename);
                        }
                        else
                        {
                            free(buffer);
                            buffer = NULL;
                            printf("Error reading file\n");
                        }
                    }
                    else
                    {
                        printf("Error: Cannot allocate memory\n");
                    }
                }
                else
                {
                    printf("Error: Cannot stat file\n");
                }
                close(fd);
            }
        }
        else if (strncmp(command, "pd", 2) == 0)
        {
            if (!buffer)
            {
                printf("No file loaded. Use 'load <file>' first\n");
            }
            else
            {
                size_t bytes_to_show = buffer_size;
                if (strlen(command) > 3)
                {
                    bytes_to_show = atoi(command + 3);
                    if (bytes_to_show > buffer_size)
                        bytes_to_show = buffer_size;
                }
                disassemble_with_analysis(buffer, bytes_to_show);
            }
        }
        else if (strcmp(command, "aa") == 0)
        {
            if (!buffer)
            {
                printf("No file loaded. Use 'load <file>' first\n");
            }
            else
            {
                analyze_code_flow(buffer, buffer_size);
            }
        }
        else if (strcmp(command, "afl") == 0)
        {
            if (!buffer)
            {
                printf("No file loaded. Use 'load <file>' first\n");
            }
            else
            {
                AnalysisResult result = perform_security_analysis(buffer, buffer_size);
                print_security_report(&result);
            }
        }
        else if (strcmp(command, "info") == 0)
        {
            if (!buffer)
            {
                printf("No file loaded\n");
            }
            else
            {
                printf("File: %s\n", filename[0] ? filename : "built-in test");
                printf("Size: %zu bytes\n", buffer_size);
                printf("Verbose: %s\n", verbose ? "on" : "off");
            }
        }
        else if (strcmp(command, "verbose") == 0)
        {
            verbose = !verbose;
            printf("Verbose mode: %s\n", verbose ? "on" : "off");
        }
        else if (strcmp(command, "clear") == 0)
        {
            printf("\033[2J\033[H"); // Clear screen
        }
        else if (strcmp(command, "quit") == 0 || strcmp(command, "q") == 0 || strcmp(command, "exit") == 0)
        {
            break;
        }
        else
        {
            printf("Unknown command: %s (type 'help' for available commands)\n", command);
        }

        printf("[0x%08zx]> ", buffer_size);
    }

    if (buffer)
    {
        free(buffer);
    }
    printf("Goodbye!\n");
}

int main(int argc, char *argv[])
{
    bool verbose = false;
    char *filename = NULL;
    bool interactive = false;
    OutputFormat output_fmt = OUTPUT_ALL;
    FileFormat force_format = FORMAT_UNKNOWN;

    // Parse command line arguments
    for (int i = 1; i < argc; i++)
    {
        if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0)
        {
            print_usage(argv[0]);
            return 0;
        }
        else if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--verbose") == 0)
        {
            verbose = true;
        }
        else if (strcmp(argv[i], "-f") == 0 || strcmp(argv[i], "--format") == 0)
        {
            if (i + 1 < argc)
            {
                output_fmt = parse_output_format(argv[++i]);
            }
            else
            {
                printf("Error: -f option requires a format (byte|assembly|strings|hex|all)\n");
                print_usage(argv[0]);
                return 1;
            }
        }
        else if (strcmp(argv[i], "-t") == 0 || strcmp(argv[i], "--type") == 0)
        {
            if (i + 1 < argc)
            {
                force_format = parse_file_format(argv[++i]);
                if (force_format == FORMAT_UNKNOWN)
                {
                    printf("Error: Unknown file type. Use: raw|pe|elf|apk|pdf|zip|tar|macho|dex|class|wasm|powershell|python|javascript|firmware\n");
                    return 1;
                }
            }
            else
            {
                printf("Error: -t option requires a file type\n");
                print_usage(argv[0]);
                return 1;
            }
        }
        else if (strcmp(argv[i], "-i") == 0 || strcmp(argv[i], "--interactive") == 0)
        {
            interactive = true;
        }
        else if (argv[i][0] != '-')
        {
            // Assume it's a filename if no option specified
            filename = argv[i];
        }
        else
        {
            printf("Unknown option: %s\n", argv[i]);
            print_usage(argv[0]);
            return 1;
        }
    }

    if (interactive)
    {
        interactive_mode();
        return 0;
    }

    if (filename)
    {
        return analyze_file(filename, verbose, output_fmt, force_format);
    }
    else
    {
        printf("Error: No binary file specified.\n");
        printf("Use --interactive mode or provide a binary file to analyze.\n\n");
        print_usage(argv[0]);
        return 1;
    }
}
