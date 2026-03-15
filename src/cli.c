#include "analysis_api.h"
#include "disasm_api.h"
#include "formats_api.h"
#include "module_registry.h"
#include "output_api.h"
#include "packer_api.h"
#include "plugin.h"

#include <fcntl.h>
#include <ctype.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static const size_t MAX_INTERACTIVE_FILE_SIZE = 10485760;

static bool parse_size_value(const char *text, size_t *out)
{
    if (text == NULL || out == NULL)
    {
        return false;
    }

    while (*text != '\0' && isspace((unsigned char)*text))
    {
        text++;
    }

    if (*text == '\0')
    {
        return false;
    }

    char *end = NULL;
    unsigned long long value = strtoull(text, &end, 0);
    if (end == text)
    {
        return false;
    }

    while (*end != '\0' && isspace((unsigned char)*end))
    {
        end++;
    }

    if (*end != '\0')
    {
        return false;
    }

    *out = (size_t)value;
    return true;
}

static size_t clamp_view_size(size_t cursor, size_t total_size, size_t requested)
{
    if (cursor >= total_size)
    {
        return 0;
    }

    const size_t remaining = total_size - cursor;
    if (requested == 0 || requested > remaining)
    {
        return remaining;
    }

    return requested;
}

static bool load_file_into_buffer(const char *path, uint8_t **buffer, size_t *buffer_size)
{
    if (path == NULL || buffer == NULL || buffer_size == NULL)
    {
        return false;
    }

    int fd = open(path, O_RDONLY);
    if (fd == -1)
    {
        return false;
    }

    struct stat st;
    if (fstat(fd, &st) != 0)
    {
        close(fd);
        return false;
    }

    if (st.st_size > (off_t)MAX_INTERACTIVE_FILE_SIZE)
    {
        st.st_size = (off_t)MAX_INTERACTIVE_FILE_SIZE;
    }

    uint8_t *tmp = malloc((size_t)st.st_size);
    if (tmp == NULL)
    {
        close(fd);
        return false;
    }

    ssize_t read_bytes = read(fd, tmp, (size_t)st.st_size);
    close(fd);

    if (read_bytes <= 0)
    {
        free(tmp);
        return false;
    }

    if (*buffer != NULL)
    {
        free(*buffer);
    }

    *buffer = tmp;
    *buffer_size = (size_t)read_bytes;
    return true;
}

static size_t parse_hex_pattern(const char *args, uint8_t *out, size_t out_cap)
{
    if (args == NULL || out == NULL || out_cap == 0)
    {
        return 0;
    }

    size_t count = 0;
    const char *p = args;

    while (*p != '\0' && count < out_cap)
    {
        while (*p != '\0' && isspace((unsigned char)*p))
        {
            p++;
        }

        if (*p == '\0')
        {
            break;
        }

        char token[16] = {0};
        size_t len = 0;
        while (*p != '\0' && !isspace((unsigned char)*p) && len < sizeof(token) - 1)
        {
            token[len++] = *p++;
        }

        token[len] = '\0';
        if (len == 0)
        {
            break;
        }

        char *end = NULL;
        unsigned long v = strtoul(token, &end, 16);
        if (end == token || *end != '\0' || v > 0xFF)
        {
            return 0;
        }

        out[count++] = (uint8_t)v;
    }

    return count;
}

static void interactive_help(void)
{
    printf("Commands:\n");
    printf("  load <file>     - Load binary file\n");
    printf("  i | info        - Show current file info\n");
    printf("  s [addr]        - Seek to absolute address (hex/dec)\n");
    printf("  s+ <delta>      - Seek forward\n");
    printf("  s- <delta>      - Seek backward\n");
    printf("  ni [n]          - Step cursor forward by n bytes (next-like)\n");
    printf("  si [n]          - Step cursor forward by n bytes (step-like)\n");
    printf("  pd [n]          - Disassemble n bytes from current seek\n");
    printf("  px [n]          - Hex dump n bytes from current seek\n");
    printf("  p8 [n]          - Raw byte output n bytes from current seek\n");
    printf("  ps [n]          - Extract strings from current seek window\n");
    printf("  iz              - Extract strings from full loaded buffer\n");
    printf("  aa [n]          - Analyze code flow for current window\n");
    printf("  afl             - Security analysis summary\n");
    printf("  /x <hex...>     - Find byte pattern (example: /x 90 90 c3)\n");
    printf("  sn | /xn        - Jump to next /x hit\n");
    printf("  sp | /xp        - Jump to previous /x hit\n");
    printf("  verbose         - Toggle verbose mode\n");
    printf("  clear           - Clear screen\n");
    printf("  q | quit | exit - Exit interactive mode\n");
    printf("\nExamples:\n");
    printf("  load /bin/ls\n");
    printf("  s 0x100\n");
    printf("  ni 4\n");
    printf("  pd 64\n");
    printf("  px 128\n");
    printf("  /x 55 48 89 e5\n");
    printf("  sn\n");
}

void print_usage(const char *program_name)
{
    printf("Usage: %s [options] <binary_file>\n", program_name);
    printf("Options:\n");
    printf("  -h, --help       Show this help message\n");
    printf("  -v, --verbose    Enable verbose output\n");
    printf("  -i, --interactive Start interactive mode\n");
    printf("  -f, --format     Output format: byte|assembly|strings|hex|all|<plugin-mode>\n");
    printf("  -t, --type       Force file type: raw|pe|elf|apk|pdf|zip|tar|macho|dex|class|wasm|powershell|python|javascript|text|firmware\n");
    printf("\nOutput Formats:\n");
    printf("  byte            Raw byte values\n");
    printf("  assembly        Assembly mnemonics\n");
    printf("  strings         Extract readable strings\n");
    printf("  hex             Hexadecimal dump\n");
    printf("  all             All formats (default)\n");
    printf("  <plugin-mode>   Any output mode registered by plugins\n");
    printf("\nSupported File Types:\n");
    printf("  PE, ELF, APK, PDF, DOCX, PPTX, ZIP, TAR archives\n");
    printf("  Mach-O, Android DEX, Java Class, WebAssembly\n");
    printf("  PowerShell, Python, JavaScript scripts\n");
    printf("  Firmware images with packer detection\n");
    printf("\nExamples:\n");
    printf("  %s /bin/ls                      # Full analysis\n", program_name);
    printf("  %s -f hex /usr/bin/passwd       # Hex dump only\n", program_name);
    printf("  %s -f entropy /bin/ls           # Plugin output mode (sample plugin)\n", program_name);
    printf("  %s -f strings document.pdf      # Extract strings\n", program_name);
    printf("  %s -t pe -f assembly prog.exe   # Force PE, show assembly\n", program_name);
    printf("  %s -i                           # Interactive mode\n", program_name);
}

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
    if (strcmp(format_str, "text") == 0)
        return FORMAT_TEXT;
    if (strcmp(format_str, "firmware") == 0)
        return FORMAT_FIRMWARE;
    return FORMAT_UNKNOWN;
}

int analyze_file(const char *filename, bool verbose, const char *output_mode, FileFormat force_format)
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
    {
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

    FileFormat detected_format = (force_format != FORMAT_UNKNOWN) ? force_format : detect_file_format(buffer, bytes_read);

    PackerResult packer_result = detect_packer(buffer, bytes_read);
    print_packer_info(&packer_result);

    bool continue_disasm = process_file_format(buffer, bytes_read, detected_format);

    if (!dispatch_output_handler_by_name(output_mode, buffer, bytes_read))
    {
        fprintf(stderr, "Warning: Unknown output mode '%s'. Falling back to 'all'.\n", output_mode);
        output_all_formats(buffer, bytes_read);
    }

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

void interactive_mode(const char *startup_file)
{
    char command[256];
    char history[128][256] = {{0}};
    size_t history_count = 0;
    ssize_t history_index = -1;
    char filename[256] = {0};
    uint8_t *buffer = NULL;
    size_t buffer_size = 0;
    size_t cursor = 0;
    size_t last_pd = 64;
    size_t last_px = 128;
    size_t last_ps = 256;
    size_t last_aa = 256;
    size_t search_hits[4096] = {0};
    size_t search_hit_count = 0;
    ssize_t search_hit_index = -1;
    bool verbose = false;

    printf("BinSect Interactive Mode (radare2-style) - Type '?' for commands\n");

    if (startup_file != NULL)
    {
        strncpy(filename, startup_file, sizeof(filename) - 1);
        filename[sizeof(filename) - 1] = '\0';

        if (load_file_into_buffer(filename, &buffer, &buffer_size))
        {
            cursor = 0;
            printf("Loaded %zu bytes from '%s'\n", buffer_size, filename);

            FileFormat format = detect_file_format(buffer, buffer_size);
            printf("Detected format: %s\n", get_format_name(format));

            if (verbose)
            {
                PackerResult p = detect_packer(buffer, buffer_size);
                print_packer_info(&p);
            }
        }
        else
        {
            printf("Error: Cannot open file '%s'\n", filename);
        }
    }

    while (1)
    {
        printf("[0x%08zx]> ", cursor);
        fflush(stdout);

        if (fgets(command, sizeof(command), stdin) == NULL)
        {
            break;
        }

        command[strcspn(command, "\n")] = '\0';

        if (command[0] == '\x1b')
        {
            const char *p = command;
            bool valid_history_nav = false;

            while (*p != '\0')
            {
                if (strncmp(p, "\x1b[A", 3) == 0)
                {
                    if (history_count > 0)
                    {
                        if (history_index < 0)
                        {
                            history_index = (ssize_t)history_count - 1;
                        }
                        else if (history_index > 0)
                        {
                            history_index--;
                        }
                        valid_history_nav = true;
                    }
                    p += 3;
                }
                else if (strncmp(p, "\x1b[B", 3) == 0)
                {
                    if (history_count > 0)
                    {
                        if (history_index < 0)
                        {
                            history_index = (ssize_t)history_count - 1;
                        }
                        else if (history_index < (ssize_t)history_count - 1)
                        {
                            history_index++;
                        }
                        valid_history_nav = true;
                    }
                    p += 3;
                }
                else
                {
                    valid_history_nav = false;
                    break;
                }
            }

            if (valid_history_nav && history_count > 0 && history_index >= 0)
            {
                strncpy(command, history[history_index], sizeof(command) - 1);
                command[sizeof(command) - 1] = '\0';
                printf("%s\n", command);
            }
            else
            {
                if (history_count == 0)
                {
                    printf("No command history\n");
                }
                else
                {
                    printf("Unsupported escape sequence\n");
                }
                continue;
            }
        }
        else
        {
            history_index = -1;
            if (command[0] != '\0')
            {
                if (history_count < (sizeof(history) / sizeof(history[0])))
                {
                    snprintf(history[history_count], sizeof(history[history_count]), "%s", command);
                    history_count++;
                }
                else
                {
                    memmove(history, history + 1, (sizeof(history) / sizeof(history[0]) - 1) * sizeof(history[0]));
                    snprintf(history[sizeof(history) / sizeof(history[0]) - 1], sizeof(history[0]), "%s", command);
                }
            }
        }

        if (strlen(command) == 0)
        {
            continue;
        }

        if (strcmp(command, "help") == 0 || strcmp(command, "?") == 0)
        {
            interactive_help();
        }
        else if (strncmp(command, "load ", 5) == 0)
        {
            strncpy(filename, command + 5, sizeof(filename) - 1);
            filename[sizeof(filename) - 1] = '\0';

            if (load_file_into_buffer(filename, &buffer, &buffer_size))
            {
                cursor = 0;
                printf("Loaded %zu bytes from '%s'\n", buffer_size, filename);

                FileFormat format = detect_file_format(buffer, buffer_size);
                printf("Detected format: %s\n", get_format_name(format));

                if (verbose)
                {
                    PackerResult p = detect_packer(buffer, buffer_size);
                    print_packer_info(&p);
                }
            }
            else
            {
                printf("Error: Cannot open file '%s'\n", filename);
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
                size_t bytes_to_show = last_pd;
                if (strlen(command) > 3)
                {
                    if (!parse_size_value(command + 3, &bytes_to_show))
                    {
                        printf("Invalid count. Example: pd 64\n");
                        continue;
                    }
                }

                bytes_to_show = clamp_view_size(cursor, buffer_size, bytes_to_show);
                if (bytes_to_show == 0)
                {
                    printf("Cursor is at EOF\n");
                }
                else
                {
                    last_pd = bytes_to_show;
                    printf("[seek 0x%08zx] pd %zu\n", cursor, bytes_to_show);
                    disassemble_with_analysis(buffer + cursor, bytes_to_show);
                }
            }
        }
        else if (strncmp(command, "px", 2) == 0)
        {
            if (!buffer)
            {
                printf("No file loaded. Use 'load <file>' first\n");
            }
            else
            {
                size_t bytes_to_show = last_px;
                if (strlen(command) > 3)
                {
                    if (!parse_size_value(command + 3, &bytes_to_show))
                    {
                        printf("Invalid count. Example: px 128\n");
                        continue;
                    }
                }

                bytes_to_show = clamp_view_size(cursor, buffer_size, bytes_to_show);
                if (bytes_to_show == 0)
                {
                    printf("Cursor is at EOF\n");
                }
                else
                {
                    last_px = bytes_to_show;
                    printf("[seek 0x%08zx] px %zu\n", cursor, bytes_to_show);
                    output_hex_dump(buffer + cursor, bytes_to_show);
                }
            }
        }
        else if (strncmp(command, "p8", 2) == 0)
        {
            if (!buffer)
            {
                printf("No file loaded. Use 'load <file>' first\n");
            }
            else
            {
                size_t bytes_to_show = 64;
                if (strlen(command) > 3)
                {
                    if (!parse_size_value(command + 3, &bytes_to_show))
                    {
                        printf("Invalid count. Example: p8 64\n");
                        continue;
                    }
                }

                bytes_to_show = clamp_view_size(cursor, buffer_size, bytes_to_show);
                if (bytes_to_show == 0)
                {
                    printf("Cursor is at EOF\n");
                }
                else
                {
                    printf("[seek 0x%08zx] p8 %zu\n", cursor, bytes_to_show);
                    output_bytes(buffer + cursor, bytes_to_show);
                }
            }
        }
        else if (strncmp(command, "ps", 2) == 0)
        {
            if (!buffer)
            {
                printf("No file loaded. Use 'load <file>' first\n");
            }
            else
            {
                size_t bytes_to_show = last_ps;
                if (strlen(command) > 3)
                {
                    if (!parse_size_value(command + 3, &bytes_to_show))
                    {
                        printf("Invalid count. Example: ps 256\n");
                        continue;
                    }
                }

                bytes_to_show = clamp_view_size(cursor, buffer_size, bytes_to_show);
                if (bytes_to_show == 0)
                {
                    printf("Cursor is at EOF\n");
                }
                else
                {
                    last_ps = bytes_to_show;
                    printf("[seek 0x%08zx] ps %zu\n", cursor, bytes_to_show);
                    output_strings(buffer + cursor, bytes_to_show);
                }
            }
        }
        else if (strcmp(command, "iz") == 0)
        {
            if (!buffer)
            {
                printf("No file loaded. Use 'load <file>' first\n");
            }
            else
            {
                output_strings(buffer, buffer_size);
            }
        }
        else if (strncmp(command, "aa", 2) == 0 || strcmp(command, "af") == 0)
        {
            if (!buffer)
            {
                printf("No file loaded. Use 'load <file>' first\n");
            }
            else
            {
                size_t bytes_to_analyze = last_aa;
                if (strlen(command) > 3)
                {
                    if (!parse_size_value(command + 3, &bytes_to_analyze))
                    {
                        printf("Invalid count. Example: aa 256\n");
                        continue;
                    }
                }

                bytes_to_analyze = clamp_view_size(cursor, buffer_size, bytes_to_analyze);
                if (bytes_to_analyze == 0)
                {
                    printf("Cursor is at EOF\n");
                }
                else
                {
                    last_aa = bytes_to_analyze;
                    printf("[seek 0x%08zx] aa %zu\n", cursor, bytes_to_analyze);
                    analyze_code_flow(buffer + cursor, bytes_to_analyze);
                }
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
        else if (strcmp(command, "i") == 0 || strcmp(command, "info") == 0)
        {
            if (!buffer)
            {
                printf("No file loaded\n");
            }
            else
            {
                printf("File: %s\n", filename[0] ? filename : "built-in test");
                printf("Size: %zu bytes\n", buffer_size);
                printf("Seek: 0x%08zx\n", cursor);
                printf("Format: %s\n", get_format_name(detect_file_format(buffer, buffer_size)));
                printf("Verbose: %s\n", verbose ? "on" : "off");
            }
        }
        else if (strcmp(command, "s") == 0)
        {
            printf("0x%08zx\n", cursor);
        }
        else if (strncmp(command, "s ", 2) == 0)
        {
            if (!buffer)
            {
                printf("No file loaded. Use 'load <file>' first\n");
            }
            else
            {
                size_t addr = 0;
                if (!parse_size_value(command + 2, &addr))
                {
                    printf("Invalid seek value. Example: s 0x100\n");
                }
                else if (addr > buffer_size)
                {
                    printf("Seek out of bounds (max 0x%08zx)\n", buffer_size);
                }
                else
                {
                    cursor = addr;
                }
            }
        }
        else if (strncmp(command, "s+ ", 3) == 0)
        {
            if (!buffer)
            {
                printf("No file loaded. Use 'load <file>' first\n");
            }
            else
            {
                size_t delta = 0;
                if (!parse_size_value(command + 3, &delta))
                {
                    printf("Invalid seek delta. Example: s+ 64\n");
                }
                else
                {
                    if (delta > buffer_size - cursor)
                    {
                        cursor = buffer_size;
                    }
                    else
                    {
                        cursor += delta;
                    }
                }
            }
        }
        else if (strncmp(command, "s- ", 3) == 0)
        {
            if (!buffer)
            {
                printf("No file loaded. Use 'load <file>' first\n");
            }
            else
            {
                size_t delta = 0;
                if (!parse_size_value(command + 3, &delta))
                {
                    printf("Invalid seek delta. Example: s- 64\n");
                }
                else
                {
                    if (delta > cursor)
                    {
                        cursor = 0;
                    }
                    else
                    {
                        cursor -= delta;
                    }
                }
            }
        }
        else if (strcmp(command, "ni") == 0 || strcmp(command, "si") == 0 ||
                 strncmp(command, "ni ", 3) == 0 || strncmp(command, "si ", 3) == 0)
        {
            if (!buffer)
            {
                printf("No file loaded. Use 'load <file>' first\n");
            }
            else
            {
                size_t step_count = 1;
                if (strlen(command) > 3)
                {
                    if (!parse_size_value(command + 3, &step_count))
                    {
                        printf("Invalid step count. Example: ni 4\n");
                        continue;
                    }
                }

                if (cursor >= buffer_size)
                {
                    printf("Cursor is at EOF\n");
                }
                else
                {
                    const size_t max_step = buffer_size - cursor;
                    if (step_count > max_step)
                    {
                        step_count = max_step;
                    }

                    cursor += step_count;
                    if (cursor >= buffer_size)
                    {
                        printf("Stepped to EOF at 0x%08zx\n", cursor);
                    }
                    else
                    {
                        printf("[0x%08zx] %02x %s\n", cursor, buffer[cursor], decode_instruction(buffer[cursor]));
                    }
                }
            }
        }
        else if (strncmp(command, "/x ", 3) == 0)
        {
            if (!buffer)
            {
                printf("No file loaded. Use 'load <file>' first\n");
            }
            else
            {
                uint8_t pattern[64] = {0};
                const size_t max_search_hits = sizeof(search_hits) / sizeof(search_hits[0]);
                size_t pattern_len = parse_hex_pattern(command + 3, pattern, sizeof(pattern));
                if (pattern_len == 0)
                {
                    printf("Invalid pattern. Example: /x 90 90 c3\n");
                    continue;
                }

                search_hit_count = 0;
                search_hit_index = -1;
                size_t total_hits = 0;
                size_t shown_hits = 0;
                for (size_t i = 0; i + pattern_len <= buffer_size; i++)
                {
                    if (memcmp(buffer + i, pattern, pattern_len) == 0)
                    {
                        if (search_hit_count < max_search_hits)
                        {
                            search_hits[search_hit_count] = i;
                            search_hit_count++;
                        }

                        if (shown_hits < 20)
                        {
                            printf("hit 0x%08zx\n", i);
                            shown_hits++;
                        }

                        total_hits++;
                    }
                }

                if (total_hits > shown_hits)
                {
                    printf("... (showing first 20 hits)\n");
                }

                if (total_hits > search_hit_count)
                {
                    printf("Stored first %zu hits for navigation\n", search_hit_count);
                }

                if (total_hits == 0)
                {
                    printf("No matches found\n");
                }
                else
                {
                    search_hit_index = 0;
                    cursor = search_hits[0];
                    printf("Current hit [1/%zu] at 0x%08zx\n", search_hit_count, cursor);
                }
            }
        }
        else if (strcmp(command, "sn") == 0 || strcmp(command, "/xn") == 0)
        {
            if (search_hit_count == 0)
            {
                printf("No /x search results. Run /x first\n");
            }
            else
            {
                search_hit_index = (search_hit_index + 1) % (ssize_t)search_hit_count;
                cursor = search_hits[search_hit_index];
                printf("Current hit [%zd/%zu] at 0x%08zx\n", search_hit_index + 1, search_hit_count, cursor);
            }
        }
        else if (strcmp(command, "sp") == 0 || strcmp(command, "/xp") == 0)
        {
            if (search_hit_count == 0)
            {
                printf("No /x search results. Run /x first\n");
            }
            else
            {
                search_hit_index--;
                if (search_hit_index < 0)
                {
                    search_hit_index = (ssize_t)search_hit_count - 1;
                }

                cursor = search_hits[search_hit_index];
                printf("Current hit [%zd/%zu] at 0x%08zx\n", search_hit_index + 1, search_hit_count, cursor);
            }
        }
        else if (strcmp(command, "verbose") == 0)
        {
            verbose = !verbose;
            printf("Verbose mode: %s\n", verbose ? "on" : "off");
        }
        else if (strcmp(command, "clear") == 0)
        {
            printf("\033[2J\033[H");
        }
        else if (strcmp(command, "quit") == 0 || strcmp(command, "q") == 0 || strcmp(command, "exit") == 0)
        {
            break;
        }
        else
        {
            printf("Unknown command: %s (type 'help' for available commands)\n", command);
        }
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
    char output_mode[64] = "all";
    FileFormat force_format = FORMAT_UNKNOWN;

    register_builtin_modules();

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
                strncpy(output_mode, argv[++i], sizeof(output_mode) - 1);
                output_mode[sizeof(output_mode) - 1] = '\0';
            }
            else
            {
                printf("Error: -f option requires a format (byte|assembly|strings|hex|all|<plugin-mode>)\n");
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
                    printf("Error: Unknown file type. Use: raw|pe|elf|apk|pdf|zip|tar|macho|dex|class|wasm|powershell|python|javascript|text|firmware\n");
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
        interactive_mode(filename);
        unload_plugins();
        return 0;
    }

    const int plugin_count = load_plugins_from_directory("plugins");
    if (plugin_count > 0 && verbose)
    {
        printf("Loaded %d plugin(s).\n", plugin_count);
    }

    if (filename)
    {
        int rc = analyze_file(filename, verbose, output_mode, force_format);
        unload_plugins();
        return rc;
    }

    printf("Error: No binary file specified.\n");
    printf("Use --interactive mode or provide a binary file to analyze.\n\n");
    print_usage(argv[0]);
    unload_plugins();
    return 1;
}
