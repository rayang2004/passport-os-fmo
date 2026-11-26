// Minimal clock/weather home with one optional compressed background; no portrait/card UI.
#include "apps/home/app_home.h"
#include "apps/home/home_clock.h"
#include "apps/home/home_background.h"
#include "src/misc/cache/instance/lv_image_cache.h"
#include "esp_system.h"
#include <cstdlib>
#include "apps/home/home_profile.h"
#include "apps/home/home_weather.h"
#include "apps/voice/time_sync.h"
#include "launcher/app_registry.h"
#include "bsp_display.h"
#include "fonts/app_fonts.h"
#include "ui_pixel.h"
#include "wifi_manager.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include <atomic>
#include <cstdio>
#include <cstring>
#include <ctime>
namespace {
constexpr int64_t kWeatherFirstDelayMs = 15000;
constexpr int64_t kWeatherPeriodMs = 900000;
constexpr int64_t kAirPeriodMs = 1800000;
constexpr int64_t kWeatherRetryMs = 120000;
struct WeatherSchedule {
    static constexpr unsigned Weather = 1, Air = 2, Both = Weather | Air;
    int64_t weather_due_ms = -1, air_due_ms = -1;
    char lat[HOME_COORD_MAX]{}, lon[HOME_COORD_MAX]{};

    unsigned due(int64_t now, int64_t entered, bool force, const home_profile_t &profile) const {
        if (!profile.lat[0] || !profile.lon[0]) return 0;
        if (force || (lat[0] && (std::strcmp(lat, profile.lat) || std::strcmp(lon, profile.lon)))) return Both;
        if (weather_due_ms < 0 && air_due_ms < 0) return now - entered >= kWeatherFirstDelayMs ? Both : 0;
        return (weather_due_ms <= now ? Weather : 0u) | (air_due_ms <= now ? Air : 0u);
    }

    void begin(unsigned requests, int64_t now, const home_profile_t &profile) {
        std::snprintf(lat, sizeof(lat), "%s", profile.lat);
        std::snprintf(lon, sizeof(lon), "%s", profile.lon);
        // An interrupted request stays due when the next Home worker starts.
        if (requests & Weather) weather_due_ms = now;
        if (requests & Air) air_due_ms = now;
    }

    void finish(unsigned request, int64_t now, esp_err_t result) {
        const int64_t next = now + (request == Air ? kAirPeriodMs
                                    : result != ESP_OK ? kWeatherRetryMs : kWeatherPeriodMs);
        if (request == Weather) weather_due_ms = next;
        else air_due_ms = next;
    }
};
WeatherSchedule s_weather_schedule;


std::atomic<bool> s_running{false}, s_active{false}, s_ambient{false}, s_force{false};
TaskHandle_t s_worker = nullptr;
lv_font_t s_clock_font, s_temperature_font;
uint8_t *s_background_data = nullptr;
size_t s_background_bytes = 0;
lv_image_dsc_t s_background_descriptor{};
lv_obj_t *s_background_image = nullptr, *s_background_shade = nullptr;
lv_obj_t *s_screen, *s_time, *s_date, *s_city, *s_temperature, *s_weather, *s_age, *s_hint;
int64_t s_manual_ms = -30000;
lv_obj_t *line(int y, const lv_font_t *font, uint32_t color) {
    auto *label = ui_pixel_label(s_screen, "", font, color);
    lv_obj_set_pos(label, 12, y); lv_obj_set_width(label, 216);
    lv_obj_set_style_text_align(label, LV_TEXT_ALIGN_CENTER, 0);
    lv_label_set_long_mode(label, LV_LABEL_LONG_DOT);
    return label;
}
void render() {
    if (!s_screen) return;
    char text[128], date[24], weekday[16];
    home_clock_format_time(text, sizeof(text)); ui_pixel_label_set_text(s_time, text);
    home_clock_format_date(date, sizeof(date)); home_clock_format_weekday(weekday, sizeof(weekday));
    std::snprintf(text, sizeof(text), "%s  %s", date, weekday); ui_pixel_label_set_text(s_date, text);
    home_profile_t profile{}; home_profile_get(&profile);
    ui_pixel_label_set_text(s_city, profile.city[0] ? profile.city : "请设置城市");
    home_weather_t weather{};
    if (home_weather_get(&weather) && weather.valid) {
        std::snprintf(text, sizeof(text), "%d", weather.temp_c); ui_pixel_label_set_text(s_temperature, text);
        std::snprintf(text, sizeof(text), "%s · °C", home_weather_code_text(weather.code)); ui_pixel_label_set_text(s_weather, text);
        home_weather_age_text(weather.updated_at, home_clock_valid() ? time(nullptr) : 0, text, sizeof(text));
    } else {
        ui_pixel_label_set_text(s_temperature, "--"); ui_pixel_label_set_text(s_weather, "暂无天气");
        std::snprintf(text, sizeof(text), "%s", WifiManager::GetInstance().IsConnected() ? "等待更新" : "网络未连接");
    }
    ui_pixel_label_set_text(s_age, text);
    ui_pixel_label_set_text(s_hint, s_ambient.load() ? "" : "确定打开应用 · 上键更新");
}
void create_ui() {
    s_screen = lv_obj_create(nullptr); lv_obj_remove_flag(s_screen, LV_OBJ_FLAG_SCROLLABLE);
    lv_obj_set_style_bg_color(s_screen, lv_color_hex(0x000000), 0);
    lv_obj_set_style_bg_opa(s_screen, LV_OPA_COVER, 0);
    if (s_background_data) {
        s_background_descriptor = {};
        s_background_descriptor.header.magic = LV_IMAGE_HEADER_MAGIC;
        s_background_descriptor.header.cf = LV_COLOR_FORMAT_RAW;
        s_background_descriptor.header.w = HOME_BACKGROUND_W;
        s_background_descriptor.header.h = HOME_BACKGROUND_H;
        s_background_descriptor.data_size = s_background_bytes;
        s_background_descriptor.data = s_background_data;
        s_background_image = lv_image_create(s_screen);
        lv_image_set_src(s_background_image, &s_background_descriptor);
        lv_obj_set_pos(s_background_image, 0, 0);
        s_background_shade = lv_obj_create(s_screen);
        lv_obj_remove_style_all(s_background_shade);
        lv_obj_set_pos(s_background_shade, 0, 0);
        lv_obj_set_size(s_background_shade, HOME_BACKGROUND_W, HOME_BACKGROUND_H);
        lv_obj_set_style_bg_color(s_background_shade, lv_color_hex(0x000000), 0);
        lv_obj_set_style_bg_opa(s_background_shade, LV_OPA_60, 0);
    }
    s_clock_font = pomodoro_digits_48; s_clock_font.fallback = &buddy_font_16;
    s_temperature_font = ui_digits_32; s_temperature_font.fallback = &buddy_font_16;
    s_date = line(44, &buddy_font_16, 0x999999);
    s_time = line(78, &s_clock_font, 0xEEEEEE);
    s_city = line(151, &buddy_font_16, 0x999999);
    s_temperature = line(180, &s_temperature_font, 0xEEEEEE);
    s_weather = line(224, &buddy_font_16, 0xCCCCCC);
    s_age = line(252, &buddy_font_16, 0x777777);
    s_hint = line(286, &buddy_font_16, 0x999999);
}
void home_task(void *) {
    const int64_t entered = esp_timer_get_time() / 1000;
    bool clock_on = false;
    while (s_active.load()) {
        const bool ambient = s_ambient.load();
        if (bsp_lvgl_lock(1000)) {
            if (s_active.load()) {
                render();
                // Registry pauses the periodic refresh timer in ambient mode.
                // One bounded flush per minute keeps the clock live without 30Hz wakeups.
                if (ambient) lv_refr_now(lv_display_get_default());
            }
            bsp_lvgl_unlock();
        }
        const bool connected = WifiManager::GetInstance().IsConnected();
        if (connected && !clock_on) { home_clock_start(); clock_on = true; }
        else if (!connected && clock_on) { home_clock_stop(); clock_on = false; }
        home_profile_t profile{}; home_profile_get(&profile);
        const int64_t now = esp_timer_get_time() / 1000;
        const unsigned requests = connected && !ambient && app_registry_screen_is_on()
            ? s_weather_schedule.due(now, entered, s_force.load(), profile) : 0;
        if (requests) {
            s_force.store(false); s_weather_schedule.begin(requests, now, profile);
            // This home only displays weather; skip the separate air-quality TLS request.
            if (requests & WeatherSchedule::Weather) {
                const auto result = home_weather_refresh(profile.lat, profile.lon);
                if (s_active.load()) s_weather_schedule.finish(WeatherSchedule::Weather, esp_timer_get_time() / 1000, result);
            }
            s_weather_schedule.finish(WeatherSchedule::Air, now, ESP_OK);
        }
        // Notification makes cancellation/wake immediate even during the minute-long wait.
        if (s_active.load()) {
            const uint32_t wait_ms = ambient ? (60 - static_cast<unsigned>(time(nullptr) % 60)) * 1000 : 1000;
            ulTaskNotifyTake(pdTRUE, pdMS_TO_TICKS(wait_ms));
        }
    }
    home_clock_stop();
    // Owner deletes the parked task after the completion flag; never notify a freed handle.
    s_running.store(false); vTaskSuspend(nullptr);
}
void home_init() { home_profile_init(); home_weather_init(); time_sync_init(); }
void home_start() {
    home_weather_allow_requests(); s_active.store(true); s_ambient.store(false);
    // File IO stays outside the LVGL lock. Skip optional art if it consumes the weather/TLS reserve.
    home_background_load(&s_background_data, &s_background_bytes);
    if (s_background_data && esp_get_free_heap_size() < 48 * 1024) {
        std::free(s_background_data); s_background_data = nullptr; s_background_bytes = 0;
    }
    bsp_lvgl_lock(-1); create_ui(); render(); lv_screen_load(s_screen); bsp_lvgl_unlock();
    s_running.store(true);
    if (xTaskCreate(home_task, "home_app", 8192, nullptr, 4, &s_worker) != pdPASS) {
        s_running.store(false); s_worker = nullptr;
    }
}
bool home_prepare_stop() {
    s_active.store(false); home_weather_cancel_requests();
    if (s_worker) xTaskNotifyGive(s_worker);
    return !s_running.load();
}
void home_stop() {
    if (!home_prepare_stop()) return;
    if (s_worker) { vTaskDelete(s_worker); s_worker = nullptr; }
    bsp_lvgl_lock(-1);
    if (s_screen) lv_obj_delete(s_screen);
    lv_image_cache_drop(&s_background_descriptor);
    s_background_image = s_background_shade = nullptr;
    std::free(s_background_data); s_background_data = nullptr; s_background_bytes = 0;
    s_background_descriptor = {};
    s_screen = s_time = s_date = s_city = s_temperature = s_weather = s_age = s_hint = nullptr;
    bsp_lvgl_unlock();
}
void home_on_key(uint8_t button, app_btn_event_t event, uint16_t) {
    if (button == BSP_BTN_DOWN && event == BTN_EVT_LONG) { app_registry_switch_to(APP_ID_WIFI); return; }
    if (event != BTN_EVT_CLICK) return;
    if (button == BSP_BTN_OK) { app_registry_switch_to(APP_ID_LAUNCHER); return; }
    if (button == BSP_BTN_UP) {
        const auto now = esp_timer_get_time() / 1000;
        if (now - s_manual_ms >= 30000) { s_manual_ms = now; s_force.store(true); if (s_worker) xTaskNotifyGive(s_worker); }
    }
}
} // namespace
// Caller holds LVGL lock (often sys_mon with a small stack). Never run render()
// or lv_refr_now() synchronously here; wake home_task (8 KiB stack) to flush.
void home_set_ambient(bool enabled) {
    s_ambient.store(enabled);
    if (s_background_image) {
        lv_obj_set_flag(s_background_image, LV_OBJ_FLAG_HIDDEN, enabled);
        lv_obj_set_flag(s_background_shade, LV_OBJ_FLAG_HIDDEN, enabled);
        if (enabled) lv_image_cache_drop(&s_background_descriptor);
    }
    if (s_hint) ui_pixel_label_set_text(s_hint, enabled ? "" : "确定打开应用 · 上键更新");
    if (s_worker) xTaskNotifyGive(s_worker);
}
const passport_app_t g_home_app = {
    .id = APP_ID_HOME, .name = "首页", .en_name = "HOME", .desc = "时钟 · 天气",
    .tag = "Wi-Fi", .theme_color = 0xEEEEEE,
    .init = home_init, .start = home_start, .stop = home_stop,
    .on_key = home_on_key, .prepare_stop = home_prepare_stop,
};
