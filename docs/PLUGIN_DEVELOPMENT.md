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
