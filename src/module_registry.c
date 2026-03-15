#include "module_registry.h"

#include <string.h>

#define MAX_OUTPUT_HANDLERS 32
#define MAX_FORMAT_HANDLERS 64
#define MAX_PACKER_DETECTORS 16

typedef struct
{
    OutputFormat format;
    const char *name;
    OutputHandlerFn handler;
} OutputRegistration;

typedef struct
{
    FileFormat format;
    const char *name;
    FormatHandlerFn handler;
} FormatRegistration;

typedef struct
{
    const char *name;
    PackerDetectorFn detector;
} PackerRegistration;

static OutputRegistration output_handlers[MAX_OUTPUT_HANDLERS];
static size_t output_handler_count = 0;

static FormatRegistration format_handlers[MAX_FORMAT_HANDLERS];
static size_t format_handler_count = 0;

static PackerRegistration packer_detectors[MAX_PACKER_DETECTORS];
static size_t packer_detector_count = 0;

static bool builtins_registered = false;

static bool analyze_powershell_script(uint8_t *data, size_t length)
{
    return analyze_script_format(data, length, FORMAT_POWERSHELL);
}

static bool analyze_python_script(uint8_t *data, size_t length)
{
    return analyze_script_format(data, length, FORMAT_PYTHON);
}

static bool analyze_javascript_script(uint8_t *data, size_t length)
{
    return analyze_script_format(data, length, FORMAT_JAVASCRIPT);
}

bool register_output_handler(OutputFormat format, const char *name, OutputHandlerFn handler)
{
    if (handler == NULL || name == NULL)
    {
        return false;
    }

    for (size_t i = 0; i < output_handler_count; i++)
    {
        if (output_handlers[i].name != NULL && strcmp(output_handlers[i].name, name) == 0)
        {
            output_handlers[i].format = format;
            output_handlers[i].name = name;
            output_handlers[i].handler = handler;
            return true;
        }
    }

    if (output_handler_count >= MAX_OUTPUT_HANDLERS)
    {
        return false;
    }

    output_handlers[output_handler_count].format = format;
    output_handlers[output_handler_count].name = name;
    output_handlers[output_handler_count].handler = handler;
    output_handler_count++;
    return true;
}

bool dispatch_output_handler(OutputFormat format, uint8_t *code, size_t length)
{
    for (size_t i = 0; i < output_handler_count; i++)
    {
        if (output_handlers[i].format == format && output_handlers[i].handler != NULL)
        {
            output_handlers[i].handler(code, length);
            return true;
        }
    }

    return false;
}

bool dispatch_output_handler_by_name(const char *name, uint8_t *code, size_t length)
{
    if (name == NULL)
    {
        return false;
    }

    for (size_t i = 0; i < output_handler_count; i++)
    {
        if (output_handlers[i].name != NULL && strcmp(output_handlers[i].name, name) == 0 && output_handlers[i].handler != NULL)
        {
            output_handlers[i].handler(code, length);
            return true;
        }
    }

    return false;
}

bool register_format_handler(FileFormat format, const char *name, FormatHandlerFn handler)
{
    if (handler == NULL || format_handler_count >= MAX_FORMAT_HANDLERS)
    {
        return false;
    }

    for (size_t i = 0; i < format_handler_count; i++)
    {
        if (format_handlers[i].format == format)
        {
            format_handlers[i].name = name;
            format_handlers[i].handler = handler;
            return true;
        }
    }

    format_handlers[format_handler_count].format = format;
    format_handlers[format_handler_count].name = name;
    format_handlers[format_handler_count].handler = handler;
    format_handler_count++;
    return true;
}

bool run_registered_format_handler(FileFormat format, uint8_t *data, size_t length, bool *continue_disassembly)
{
    for (size_t i = 0; i < format_handler_count; i++)
    {
        if (format_handlers[i].format == format && format_handlers[i].handler != NULL)
        {
            bool handled = format_handlers[i].handler(data, length);
            if (continue_disassembly != NULL)
            {
                *continue_disassembly = !handled;
            }
            return true;
        }
    }

    return false;
}

bool register_packer_detector(const char *name, PackerDetectorFn detector)
{
    if (detector == NULL || packer_detector_count >= MAX_PACKER_DETECTORS)
    {
        return false;
    }

    packer_detectors[packer_detector_count].name = name;
    packer_detectors[packer_detector_count].detector = detector;
    packer_detector_count++;
    return true;
}

PackerResult run_registered_packer_detectors(uint8_t *data, size_t length)
{
    PackerResult best_result = {PACKER_NONE, "None", 0.0f, NULL, false};

    for (size_t i = 0; i < packer_detector_count; i++)
    {
        PackerResult current = packer_detectors[i].detector(data, length);
        if (current.confidence >= best_result.confidence)
        {
            best_result = current;
        }
    }

    return best_result;
}

void register_builtin_modules(void)
{
    if (builtins_registered)
    {
        return;
    }

    builtins_registered = true;

    register_output_handler(OUTPUT_BYTE, "byte", output_bytes);
    register_output_handler(OUTPUT_ASSEMBLY, "assembly", output_assembly);
    register_output_handler(OUTPUT_STRINGS, "strings", output_strings);
    register_output_handler(OUTPUT_HEX, "hex", output_hex_dump);
    register_output_handler(OUTPUT_ALL, "all", output_all_formats);

    register_format_handler(FORMAT_MACHO, "macho", analyze_macho_format);
    register_format_handler(FORMAT_DEX, "dex", analyze_dex_format);
    register_format_handler(FORMAT_CLASS, "class", analyze_class_format);
    register_format_handler(FORMAT_WASM, "wasm", analyze_wasm_format);
    register_format_handler(FORMAT_POWERSHELL, "powershell", analyze_powershell_script);
    register_format_handler(FORMAT_PYTHON, "python", analyze_python_script);
    register_format_handler(FORMAT_JAVASCRIPT, "javascript", analyze_javascript_script);
    register_format_handler(FORMAT_FIRMWARE, "firmware", analyze_firmware_format);

    register_packer_detector("signature-db", detect_packer_signature);
}
