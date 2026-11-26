#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef ESP_PLATFORM
#include "esp_err.h"
#include "esp_http_server.h"
#include "lvgl.h"
#else
#ifndef ESP_ERR_T_DEFINED
typedef int esp_err_t;
#endif
typedef void *httpd_handle_t;
typedef struct httpd_req httpd_req_t;
#ifndef LV_OBJ_T_FWD
typedef struct lv_obj_t lv_obj_t;
typedef struct lv_font_t lv_font_t;
#endif
#endif

#ifdef __cplusplus
extern "C" {
#endif

#define PASSPORT_MAX_PLUGINS 4
#define PASSPORT_PLUGIN_ICON_ROWS 17

typedef enum {
    PASSPORT_PLUGIN_CAP_NONE = 0,
    PASSPORT_PLUGIN_CAP_HEAVY_HEAP = (1u << 0),
    PASSPORT_PLUGIN_CAP_BALANCED_WIFI = (1u << 1),
    PASSPORT_PLUGIN_CAP_OWNS_LONG_OK = (1u << 2),
} passport_plugin_cap_t;

// Host services provided by Passport OS core to plugins.
// Plugins depend ONLY on this vtable and standard ESP-IDF / BSP components,
// never on headers inside main/.
typedef struct {
    // UI & fonts
    const lv_font_t *font_16;
    const lv_font_t *font_20;
    lv_obj_t *(*pixel_label)(lv_obj_t *parent, const char *text, const lv_font_t *font, uint32_t color);
    void (*pixel_label_set_text)(lv_obj_t *label, const char *text);

    // Navigation & power
    void (*switch_to_home)(void);
    void (*switch_to_launcher)(void);
    void (*switch_to_wifi_setup)(void);
    void (*keep_awake)(void);

    // Settings & clock
    uint8_t (*get_volume)(void);
    bool (*save_volume)(uint8_t percent);
    int32_t (*tz_offset_sec)(void);
    bool (*clock_valid)(void);
    bool (*clock_running)(void);
    void (*clock_start)(void);
    void (*clock_stop)(void);
    void (*clock_format_time)(char *buf, size_t cap);

    // Shared SPIFFS (/storage) access serialized with background uploads/reads
    esp_err_t (*storage_acquire)(bool initialize_blank);
    void (*storage_release)(void);

    // Phone setup HTTP session token check
    bool (*http_token_ok)(httpd_req_t *req);

    // Audio Focus break-in for background voice plugins (e.g. FMO sentinel).
    // begin_breakin suspends active background/foreground music or radio and
    // yields audio_workspace + ES8311; end_breakin restores suspended media.
    bool (*audio_focus_begin_breakin)(uint32_t timeout_ms);
    void (*audio_focus_end_breakin)(void);
} passport_plugin_host_t;

typedef struct {
    const char *id;            // unique ASCII slug, e.g. "fmo"
    const char *name;          // Launcher display name (Chinese)
    const char *en_name;       // English label
    const char *desc;          // Short description
    const char *tag;           // Feature tag (e.g. "Wi-Fi")
    uint32_t theme_color;      // RGB888 accent color
    const char *const *icon_rows; // optional 17x17 '#' / '.' rows

    uint32_t caps;             // bitmask of passport_plugin_cap_t
    size_t heap_largest;       // minimum contiguous block if HEAVY_HEAP
    size_t heap_free;          // minimum free heap if HEAVY_HEAP

    const char *mcp_alias;     // optional voice-open alias (e.g. "fmo")
    const char *web_path;      // optional standalone config page path (e.g. "/fmo")
    const char *web_title;     // optional web portal card title
    const char *web_subtitle;  // optional web portal card subtitle

    // App lifecycle callbacks (matching passport_app_t)
    void (*init)(void);
    void (*start)(void);
    void (*stop)(void);
    void (*on_key)(uint8_t btn, uint8_t event, uint16_t mv);
    bool (*prepare_stop)(void);
    bool (*on_back)(void);

    // Optional HTTP portal extension callbacks
    bool (*register_http)(httpd_handle_t server);
    bool (*http_busy)(void);

    // Optional background sentinel lifecycle notification: called when Wi-Fi
    // readiness or foreground eligibility changes. When allow_sentinel is false
    // (e.g., entering the plugin itself, Xiaozhi, Voice, or Wi-Fi setup), the
    // plugin must stop any background sentinel/break-in synchronously.
    void (*on_system_state)(bool wifi_connected, bool allow_sentinel);
} passport_plugin_t;

void passport_plugin_set_host(const passport_plugin_host_t *host);
const passport_plugin_host_t *passport_plugin_host(void);

// Registers a plugin descriptor and returns its assigned app ID (>= base_app_id),
// or -1 on error / table full.
int passport_plugin_register(const passport_plugin_t *plugin, int base_app_id);

size_t passport_plugin_count(void);
const passport_plugin_t *passport_plugin_at(size_t index, int *out_app_id);
const passport_plugin_t *passport_plugin_find_by_app_id(int app_id);
const passport_plugin_t *passport_plugin_find_by_alias(const char *alias, int *out_app_id);

#ifdef __cplusplus
}
#endif
