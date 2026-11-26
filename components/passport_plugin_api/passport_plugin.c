#include "passport_plugin.h"

#include <string.h>

typedef struct {
    const passport_plugin_t *plugin;
    int app_id;
} plugin_slot_t;

static const passport_plugin_host_t *s_host = NULL;
static plugin_slot_t s_plugins[PASSPORT_MAX_PLUGINS];
static size_t s_plugin_count = 0;

void passport_plugin_set_host(const passport_plugin_host_t *host) {
    s_host = host;
}

const passport_plugin_host_t *passport_plugin_host(void) {
    return s_host;
}

int passport_plugin_register(const passport_plugin_t *plugin, int base_app_id) {
    if (!plugin || !plugin->id || !plugin->id[0] || base_app_id < 0) return -1;
    for (size_t i = 0; i < s_plugin_count; ++i) {
        if (strcmp(s_plugins[i].plugin->id, plugin->id) == 0) {
            return s_plugins[i].app_id;
        }
    }
    if (s_plugin_count >= PASSPORT_MAX_PLUGINS) return -1;
    const int assigned = base_app_id + (int)s_plugin_count;
    s_plugins[s_plugin_count].plugin = plugin;
    s_plugins[s_plugin_count].app_id = assigned;
    s_plugin_count++;
    return assigned;
}

size_t passport_plugin_count(void) {
    return s_plugin_count;
}

const passport_plugin_t *passport_plugin_at(size_t index, int *out_app_id) {
    if (index >= s_plugin_count) return NULL;
    if (out_app_id) *out_app_id = s_plugins[index].app_id;
    return s_plugins[index].plugin;
}

const passport_plugin_t *passport_plugin_find_by_app_id(int app_id) {
    for (size_t i = 0; i < s_plugin_count; ++i) {
        if (s_plugins[i].app_id == app_id) return s_plugins[i].plugin;
    }
    return NULL;
}

const passport_plugin_t *passport_plugin_find_by_alias(const char *alias, int *out_app_id) {
    if (!alias || !alias[0]) return NULL;
    for (size_t i = 0; i < s_plugin_count; ++i) {
        const passport_plugin_t *p = s_plugins[i].plugin;
        if (p->mcp_alias && strcmp(p->mcp_alias, alias) == 0) {
            if (out_app_id) *out_app_id = s_plugins[i].app_id;
            return p;
        }
    }
    return NULL;
}
