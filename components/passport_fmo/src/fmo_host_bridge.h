#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef ESP_PLATFORM
#include "passport_plugin.h"
#include "esp_err.h"
#include "esp_http_server.h"
#include "lvgl.h"

// Button events (matching main/apps/app_base.h)
#ifndef FMO_BTN_EVENTS_DEFINED
#define FMO_BTN_EVENTS_DEFINED
enum {
    BTN_EVT_CLICK = 0,
    BTN_EVT_PRESS = 1,
    BTN_EVT_RELEASE = 2,
    BTN_EVT_LONG = 3,
    BTN_EVT_LONG_UP = 4,
    BTN_EVT_DOUBLE = 5,
};
using app_btn_event_t = uint8_t;
#endif

// Public libopus caller-storage API exported by esp_audio_codec 2.5.0
extern "C" {
struct OpusDecoder;
struct OpusEncoder;
int opus_encoder_get_size(int channels);
int opus_encoder_init(OpusEncoder *state, int32_t sample_rate, int channels, int application);
int opus_decoder_get_size(int channels);
int opus_decoder_init(OpusDecoder *state, int32_t sample_rate, int channels);
int opus_decode(OpusDecoder *state, const unsigned char *data, int32_t len,
                int16_t *pcm, int frame_size, int decode_fec);
}

inline const passport_plugin_host_t *fmo_host() { return passport_plugin_host(); }

inline esp_err_t fmo_storage_acquire(bool initialize_blank) {
    const auto *h = fmo_host();
    return (h && h->storage_acquire) ? h->storage_acquire(initialize_blank) : ESP_ERR_INVALID_STATE;
}
inline void fmo_storage_release() {
    const auto *h = fmo_host();
    if (h && h->storage_release) h->storage_release();
}

inline bool fmo_clock_valid() {
    const auto *h = fmo_host();
    return h && h->clock_valid && h->clock_valid();
}
inline bool fmo_clock_running() {
    const auto *h = fmo_host();
    return h && h->clock_running && h->clock_running();
}
inline void fmo_clock_start() {
    const auto *h = fmo_host();
    if (h && h->clock_start) h->clock_start();
}
inline void fmo_clock_stop() {
    const auto *h = fmo_host();
    if (h && h->clock_stop) h->clock_stop();
}
inline void fmo_clock_format_time(char *buf, size_t cap) {
    const auto *h = fmo_host();
    if (h && h->clock_format_time) h->clock_format_time(buf, cap);
    else if (buf && cap) buf[0] = '\0';
}
inline int32_t fmo_tz_offset_sec() {
    const auto *h = fmo_host();
    return (h && h->tz_offset_sec) ? h->tz_offset_sec() : 8 * 3600;
}

inline uint8_t fmo_get_volume() {
    const auto *h = fmo_host();
    return (h && h->get_volume) ? h->get_volume() : 50;
}
inline bool fmo_save_volume(uint8_t percent) {
    const auto *h = fmo_host();
    return h && h->save_volume && h->save_volume(percent);
}

inline void fmo_switch_to_home() {
    const auto *h = fmo_host();
    if (h && h->switch_to_home) h->switch_to_home();
}
inline void fmo_switch_to_launcher() {
    const auto *h = fmo_host();
    if (h && h->switch_to_launcher) h->switch_to_launcher();
}
inline void fmo_switch_to_wifi_setup() {
    const auto *h = fmo_host();
    if (h && h->switch_to_wifi_setup) h->switch_to_wifi_setup();
}
inline void fmo_keep_awake() {
    const auto *h = fmo_host();
    if (h && h->keep_awake) h->keep_awake();
}

inline const lv_font_t *fmo_font_16() {
    const auto *h = fmo_host();
    return h ? h->font_16 : nullptr;
}
inline const lv_font_t *fmo_font_20() {
    const auto *h = fmo_host();
    return h ? h->font_20 : nullptr;
}
inline lv_obj_t *fmo_pixel_label(lv_obj_t *parent, const char *text, const lv_font_t *font, uint32_t color) {
    const auto *h = fmo_host();
    return (h && h->pixel_label) ? h->pixel_label(parent, text, font, color) : nullptr;
}
inline void fmo_pixel_label_set_text(lv_obj_t *label, const char *text) {
    const auto *h = fmo_host();
    if (h && h->pixel_label_set_text) h->pixel_label_set_text(label, text);
}
inline bool fmo_http_token_ok(httpd_req_t *req) {
    const auto *h = fmo_host();
    return h && h->http_token_ok && h->http_token_ok(req);
}
inline bool fmo_audio_focus_begin_breakin(uint32_t timeout_ms) {
    const auto *h = fmo_host();
    return h && h->audio_focus_begin_breakin && h->audio_focus_begin_breakin(timeout_ms);
}
inline void fmo_audio_focus_end_breakin() {
    const auto *h = fmo_host();
    if (h && h->audio_focus_end_breakin) h->audio_focus_end_breakin();
}

#else
// Host regression test mode: pure alias macros to test-provided mocks
// (zero dependency on main/ headers during standalone plugin testing).
#if __has_include("apps/home/home_storage.h")
#include "apps/home/home_storage.h"
#else
extern "C" {
int home_storage_acquire(bool initialize_blank);
void home_storage_release(void);
}
#endif
#ifndef fmo_storage_acquire
#define fmo_storage_acquire home_storage_acquire
#define fmo_storage_release home_storage_release
#define fmo_clock_valid home_clock_valid
#define fmo_clock_running home_clock_running
#define fmo_clock_start home_clock_start
#define fmo_clock_stop home_clock_stop
#define fmo_clock_format_time home_clock_format_time
#define fmo_tz_offset_sec time_sync_tz_offset_sec
#define fmo_get_volume settings_get_volume
#define fmo_save_volume settings_save_volume
#define fmo_switch_to_home() app_registry_switch_to(APP_ID_HOME)
#define fmo_switch_to_launcher() app_registry_switch_to(APP_ID_LAUNCHER)
#define fmo_switch_to_wifi_setup() app_registry_switch_to(APP_ID_WIFI)
#define fmo_keep_awake app_registry_keep_awake
#define fmo_font_16() (&buddy_font_16)
#define fmo_font_20() (&ui_font_20)
#define fmo_pixel_label ui_pixel_label
#define fmo_pixel_label_set_text ui_pixel_label_set_text
#define fmo_audio_focus_begin_breakin(ms) ((void)(ms), true)
#define fmo_audio_focus_end_breakin() ((void)0)
#endif
#endif
