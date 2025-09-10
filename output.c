#include "disassembler.h"
#include <stdlib.h>
#include <ctype.h>

// Output raw bytes
void output_bytes(uint8_t *code, size_t length)
{
    printf("\n=== BYTE OUTPUT ===\n");
    for (size_t i = 0; i < length; i++)
    {
        printf("%u", code[i]);
        if (i < length - 1)
            printf(" ");
        if ((i + 1) % 16 == 0)
            printf("\n");
    }
    if (length % 16 != 0)
        printf("\n");
}

// Output assembly mnemonics
void output_assembly(uint8_t *code, size_t length)
{
    printf("\n=== ASSEMBLY OUTPUT ===\n");
    for (size_t i = 0; i < length; i++)
    {
        char *instruction = decode_instruction(code[i]);
        printf("0x%04zx: %s\n", i, instruction ? instruction : "UNKNOWN");
    }
}

// Output hexadecimal dump
void output_hex_dump(uint8_t *code, size_t length)
{
    printf("\n=== HEX DUMP ===\n");
    printf("Offset    Hex                                              ASCII\n");
    printf("--------  -----------------------------------------------  ----------------\n");

    for (size_t i = 0; i < length; i += 16)
    {
        printf("%08zx  ", i);

        // Print hex bytes
        for (size_t j = 0; j < 16; j++)
        {
            if (i + j < length)
            {
                printf("%02x ", code[i + j]);
            }
            else
            {
                printf("   ");
            }
            if (j == 7)
                printf(" "); // Extra space in the middle
        }

        printf(" ");

        // Print ASCII representation
        for (size_t j = 0; j < 16 && i + j < length; j++)
        {
            char c = code[i + j];
            printf("%c", isprint(c) ? c : '.');
        }

        printf("\n");
    }
}

// Check if a character sequence is printable ASCII
bool is_printable_ascii(const char *str, size_t len)
{
    if (len < 4)
        return false; // Minimum string length

    for (size_t i = 0; i < len; i++)
    {
        if (!isprint(str[i]) && str[i] != '\t' && str[i] != '\n' && str[i] != '\r')
        {
            return false;
        }
    }
    return true;
}

// Check if data represents a Unicode string (simple UTF-16 detection)
bool is_unicode_string(uint8_t *data, size_t len)
{
    if (len < 8 || len % 2 != 0)
        return false;

    // Simple heuristic: check for null bytes in even positions (UTF-16LE)
    size_t null_even = 0, printable_odd = 0;
    for (size_t i = 0; i < len && i < 32; i += 2)
    {
        if (data[i + 1] == 0)
            null_even++;
        if (i + 1 < len && isprint(data[i]))
            printable_odd++;
    }

    return (null_even > len / 8) && (printable_odd > len / 8);
}

// Extract strings from binary data
StringResult *extract_strings(uint8_t *data, size_t length, size_t *count)
{
    StringResult *results = malloc(1000 * sizeof(StringResult)); // Initial allocation
    size_t result_count = 0;
    size_t capacity = 1000;

    // Extract ASCII strings
    for (size_t i = 0; i < length; i++)
    {
        if (isprint(data[i]))
        {
            size_t start = i;
            while (i < length && (isprint(data[i]) || data[i] == '\t'))
            {
                i++;
            }

            size_t str_len = i - start;
            if (str_len >= 4)
            { // Minimum meaningful string length
                if (result_count >= capacity)
                {
                    capacity *= 2;
                    results = realloc(results, capacity * sizeof(StringResult));
                }

                results[result_count].text = malloc(str_len + 1);
                memcpy(results[result_count].text, &data[start], str_len);
                results[result_count].text[str_len] = '\0';
                results[result_count].offset = start;
                results[result_count].length = str_len;
                results[result_count].is_ascii = true;
                results[result_count].is_unicode = false;
                result_count++;
            }
        }
    }

    // Extract Unicode strings (UTF-16LE)
    for (size_t i = 0; i < length - 1; i += 2)
    {
        if (isprint(data[i]) && data[i + 1] == 0)
        {
            size_t start = i;
            while (i < length - 1 && isprint(data[i]) && data[i + 1] == 0)
            {
                i += 2;
            }

            size_t str_len = (i - start) / 2;
            if (str_len >= 4)
            {
                if (result_count >= capacity)
                {
                    capacity *= 2;
                    results = realloc(results, capacity * sizeof(StringResult));
                }

                results[result_count].text = malloc(str_len + 1);
                for (size_t j = 0; j < str_len; j++)
                {
                    results[result_count].text[j] = data[start + j * 2];
                }
                results[result_count].text[str_len] = '\0';
                results[result_count].offset = start;
                results[result_count].length = str_len * 2;
                results[result_count].is_ascii = false;
                results[result_count].is_unicode = true;
                result_count++;
            }
        }
    }

    *count = result_count;
    return results;
}

// Free string results
void free_string_results(StringResult *results, size_t count)
{
    for (size_t i = 0; i < count; i++)
    {
        free(results[i].text);
    }
    free(results);
}

// Output extracted strings
void output_strings(uint8_t *code, size_t length)
{
    printf("\n=== STRING EXTRACTION ===\n");

    size_t string_count;
    StringResult *strings = extract_strings(code, length, &string_count);

    printf("Found %zu strings:\n\n", string_count);

    for (size_t i = 0; i < string_count; i++)
    {
        printf("Offset: 0x%04zx (%s, %zu bytes): \"%s\"\n",
               strings[i].offset,
               strings[i].is_unicode ? "Unicode" : "ASCII",
               strings[i].length,
               strings[i].text);
    }

    if (string_count == 0)
    {
        printf("No readable strings found.\n");
    }

    free_string_results(strings, string_count);
}

// Output all formats
void output_all_formats(uint8_t *code, size_t length)
{
    output_hex_dump(code, length);
    output_bytes(code, length);
    output_assembly(code, length);
    output_strings(code, length);
}
