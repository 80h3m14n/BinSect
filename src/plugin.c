#include "plugin.h"

#include <dirent.h>
#include <dlfcn.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

typedef struct
{
    void *handle;
    char path[PATH_MAX];
} LoadedPlugin;

#define MAX_PLUGINS 64

static LoadedPlugin loaded_plugins[MAX_PLUGINS];
static size_t loaded_plugin_count = 0;

static bool has_shared_object_extension(const char *name)
{
    size_t len = strlen(name);
    return len > 3 && strcmp(name + len - 3, ".so") == 0;
}

int load_plugins_from_directory(const char *directory)
{
    if (directory == NULL)
    {
        return 0;
    }

    DIR *dir = opendir(directory);
    if (dir == NULL)
    {
        return 0;
    }

    BinSectPluginApi api = {
        .abi_version = BINSECT_PLUGIN_ABI_VERSION,
        .register_output_handler = register_output_handler,
        .register_format_handler = register_format_handler,
        .register_packer_detector = register_packer_detector,
    };

    int loaded_now = 0;
    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL)
    {
        if (loaded_plugin_count >= MAX_PLUGINS)
        {
            break;
        }

        if (!has_shared_object_extension(entry->d_name))
        {
            continue;
        }

        char full_path[PATH_MAX];
        snprintf(full_path, sizeof(full_path), "%s/%s", directory, entry->d_name);

        void *handle = dlopen(full_path, RTLD_NOW | RTLD_LOCAL);
        if (handle == NULL)
        {
            continue;
        }

        BinSectPluginAbiVersionFn abi_fn = (BinSectPluginAbiVersionFn)dlsym(handle, "binsect_plugin_abi_version");
        if (abi_fn == NULL)
        {
            dlclose(handle);
            continue;
        }

        if (abi_fn() != BINSECT_PLUGIN_ABI_VERSION)
        {
            dlclose(handle);
            continue;
        }

        BinSectPluginInitFn init_fn = (BinSectPluginInitFn)dlsym(handle, "binsect_plugin_init");
        if (init_fn == NULL)
        {
            dlclose(handle);
            continue;
        }

        if (!init_fn(&api))
        {
            dlclose(handle);
            continue;
        }

        loaded_plugins[loaded_plugin_count].handle = handle;
        snprintf(loaded_plugins[loaded_plugin_count].path,
                 sizeof(loaded_plugins[loaded_plugin_count].path),
                 "%s",
                 full_path);
        loaded_plugin_count++;
        loaded_now++;
    }

    closedir(dir);
    return loaded_now;
}

void unload_plugins(void)
{
    for (size_t i = 0; i < loaded_plugin_count; i++)
    {
        if (loaded_plugins[i].handle != NULL)
        {
            dlclose(loaded_plugins[i].handle);
            loaded_plugins[i].handle = NULL;
        }
    }

    loaded_plugin_count = 0;
}
