# Plugin Development Quick Guide

This guide shows the minimum contract for a BinSect plugin.

## Required Exports

A plugin shared object must export both symbols:

1. `uint32_t binsect_plugin_abi_version(void)`
2. `bool binsect_plugin_init(const BinSectPluginApi *api)`

The loader rejects a plugin if:

- either symbol is missing,
- `binsect_plugin_abi_version()` does not match `BINSECT_PLUGIN_ABI_VERSION`, or
- `binsect_plugin_init(...)` returns `false`.

## Start From Template

Use `plugins/plugin_template.c` as the base and update:

- output mode name (example: `template`),
- detector name (example: `template-detector`),
- output implementation,
- detector logic and confidence scoring.

## Build Example

Build a plugin from source:

```bash
gcc -Wall -Wextra -std=c99 -g -O2 -fPIC -shared -Iinclude \
  -o plugins/my_plugin.so plugins/my_plugin.c -lm
```

Or build the included sample plugin:

```bash
make plugins
```

## Run Example

```bash
./BinSect -f template /bin/ls
```

If your output mode is not found, BinSect falls back to `all` mode.


---

## Architecture

### Core Modules

- `src/cli.c`: Command-line interface and main entry point
- `src/disassemble.c`: x86-64 disassembly engine with pattern matching
- `src/analysis.c`: Security analysis algorithms and threat detection
- `src/formats.c`: File format detection and parsing
- `src/packer.c`: Packer detection and analysis
- `src/advanced_formats.c`: Advanced format handlers (Mach-O, DEX, WASM, etc.)
- `src/output.c`: Multiple output format generators
- `src/module_registry.c`: Runtime module registry (output, format analyzers, packer detectors)
- `src/plugin.c`: Dynamic plugin loader for `.so` extensions in `plugins/`

### Public Headers (Split By Domain)

- `include/core_types.h`: Shared enums and structs
- `include/disasm_api.h`: Disassembly interfaces
- `include/analysis_api.h`: Security analysis interfaces
- `include/output_api.h`: Output and string extraction interfaces
- `include/formats_api.h`: File format detection/processing interfaces
- `include/packer_api.h`: Packer detection interfaces
- `include/advanced_formats_api.h`: Advanced format analyzers
- `include/disassembler.h`: Compatibility umbrella header

### Modular Extension Model

BinSect now includes a module registry that decouples the CLI pipeline from concrete implementations.

- Output handlers are dispatched through `dispatch_output_handler(...)`
- Format analyzers can be added at runtime via `register_format_handler(...)`
- Packer detectors are composable via `register_packer_detector(...)`

This allows adding new analysis capabilities without editing central switch statements in the core flow.

### Plugin Interface

Plugins are shared objects loaded from the `plugins/` directory at startup.

1. Implement `binsect_plugin_abi_version()` and return `BINSECT_PLUGIN_ABI_VERSION`.
2. Implement `binsect_plugin_init(const BinSectPluginApi *api)` in your plugin.
3. Validate `api->abi_version` in plugin init.
4. Call API callbacks to register handlers.
5. Build as `.so` and drop into `plugins/`.

The loader now enforces a strict ABI version match before initialization.

Sample plugin included:

- Source: `plugins/sample_plugin.c`
- Registers output mode: `entropy`
- Registers detector: `sample-xor-detector`

Usage example:

```bash
make plugins
./binsect -f entropy /bin/ls
```

Reference headers:

- `include/plugin.h`
- `include/module_registry.h`

Plugin developer resources:

- `plugins/plugin_template.c`
- `docs/PLUGIN_DEVELOPMENT.md`
- `docs/COMMANDS.md`

The built-in modules are still registered by default, so existing behavior remains intact.

