#!/usr/bin/env python3
"""Host regression tests for main/launcher/audio_focus.cc state transitions."""
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]

MOCK_HEADERS = {
    "bsp_button.h": r"""
#pragma once
#include <stdint.h>
typedef uint8_t bsp_btn_event_t;
""",
    "esp_log.h": r"""
#pragma once
#define ESP_LOGI(tag, fmt, ...) ((void)0)
#define ESP_LOGW(tag, fmt, ...) ((void)0)
#define ESP_LOGE(tag, fmt, ...) ((void)0)
""",
    "freertos/FreeRTOS.h": r"""
#pragma once
#include <stdint.h>
typedef uint32_t TickType_t;
typedef int BaseType_t;
typedef unsigned UBaseType_t;
#define pdTRUE 1
#define pdFALSE 0
#define pdPASS 1
#define pdMS_TO_TICKS(ms) (ms)
""",
    "freertos/semphr.h": r"""
#pragma once
#include "freertos/FreeRTOS.h"
typedef struct { int depth; } StaticSemaphore_t;
typedef StaticSemaphore_t *SemaphoreHandle_t;
static inline SemaphoreHandle_t xSemaphoreCreateRecursiveMutexStatic(StaticSemaphore_t *buf) {
    buf->depth = 0;
    return buf;
}
static inline BaseType_t xSemaphoreTakeRecursive(SemaphoreHandle_t h, TickType_t) {
    if (!h) return pdFALSE;
    ++h->depth;
    return pdTRUE;
}
static inline BaseType_t xSemaphoreGiveRecursive(SemaphoreHandle_t h) {
    if (!h || h->depth <= 0) return pdFALSE;
    --h->depth;
    return pdTRUE;
}
""",
    "freertos/task.h": r"""
#pragma once
#include "freertos/FreeRTOS.h"
typedef void (*TaskFunction_t)(void *);
typedef void *TaskHandle_t;
static inline void vTaskDelay(TickType_t) {}
static inline void vTaskDelete(TaskHandle_t) {}
static inline BaseType_t xTaskCreate(TaskFunction_t fn, const char *, uint32_t, void *arg, UBaseType_t, TaskHandle_t *) {
    // Run deferred resume worker inline during host test so state transitions are deterministic.
    fn(arg);
    return pdPASS;
}
""",
    "wifi_manager.h": r"""
#pragma once
enum class WifiPowerSaveLevel { PERFORMANCE, BALANCED, LOW_POWER, MAX_MODEM };
class WifiManager {
public:
    bool connected = true;
    WifiPowerSaveLevel ps_level = WifiPowerSaveLevel::MAX_MODEM;
    static WifiManager &GetInstance() { static WifiManager inst; return inst; }
    bool IsConnected() const { return connected; }
    void SetPowerSaveLevel(WifiPowerSaveLevel lvl) { ps_level = lvl; }
};
""",
    "launcher/app_registry.h": r"""
#pragma once
#include "apps/app_base.h"
extern passport_app_id_t g_mock_active_app;
extern int g_mock_breakin_begins;
extern int g_mock_breakin_ends;
static inline passport_app_id_t app_registry_get_active(void) { return g_mock_active_app; }
static inline void app_registry_on_breakin_begin(void) { ++g_mock_breakin_begins; }
static inline void app_registry_on_breakin_end(void) { ++g_mock_breakin_ends; }
""",
    "passport_plugin.h": r"""
#pragma once
#include <stdbool.h>
#include <stddef.h>
typedef struct passport_plugin_t {
    void (*on_system_state)(bool wifi_connected, bool allow_sentinel);
} passport_plugin_t;
extern passport_plugin_t g_mock_plugin;
static inline size_t passport_plugin_count(void) { return 1; }
static inline const passport_plugin_t *passport_plugin_at(size_t i, int *) {
    return i == 0 ? &g_mock_plugin : nullptr;
}
""",
}

HARNESS = r"""
#include "launcher/audio_focus.h"
#include "wifi_manager.h"
#include "launcher/app_registry.h"
#include "passport_plugin.h"
#include <cassert>
#include <cstdio>

passport_app_id_t g_mock_active_app = APP_ID_HOME;
int g_mock_breakin_begins = 0;
int g_mock_breakin_ends = 0;

static bool s_sentinel_wifi = false;
static bool s_sentinel_allowed = false;
static int s_sentinel_calls = 0;
static bool s_sentinel_reentrant_end = false;

static void mock_on_system_state(bool wifi, bool allow) {
    ++s_sentinel_calls;
    s_sentinel_wifi = wifi;
    s_sentinel_allowed = allow;
    // Verify calling into audio_focus while allow=false never deadlocks!
    if (!allow && s_sentinel_reentrant_end) {
        s_sentinel_reentrant_end = false;
        assert(audio_focus::breakin_active());
    }
}

passport_plugin_t g_mock_plugin = { .on_system_state = mock_on_system_state };

struct FakeMedia {
    bool running = false;
    bool playing = false;
    bool ui_attached = false;
    bool has_saved = false;
    int detach_calls = 0;
    int reattach_calls = 0;
    int suspend_calls = 0;
    int resume_calls = 0;
    int clear_calls = 0;
    bool last_save_flag = false;
};

static FakeMedia g_radio, g_netease;

static audio_focus::SourceOps make_ops(FakeMedia *m) {
    // Use per-instance trampolines via static helpers below.
    (void)m;
    return {};
}

#define DEFINE_OPS(PREFIX, OBJ) \
static bool PREFIX##_is_playing() { return OBJ.playing; } \
static bool PREFIX##_is_running() { return OBJ.running; } \
static void PREFIX##_detach_ui() { OBJ.ui_attached = false; ++OBJ.detach_calls; } \
static bool PREFIX##_reattach_ui() { if (!OBJ.running) return false; OBJ.ui_attached = true; ++OBJ.reattach_calls; return true; } \
static bool PREFIX##_suspend(bool save) { OBJ.last_save_flag = save; OBJ.has_saved = save; OBJ.running = false; OBJ.playing = false; OBJ.ui_attached = false; ++OBJ.suspend_calls; return true; } \
static bool PREFIX##_resume() { if (!OBJ.has_saved) return false; OBJ.running = true; OBJ.playing = true; OBJ.ui_attached = false; ++OBJ.resume_calls; return true; } \
static bool PREFIX##_has_saved() { return OBJ.has_saved; } \
static void PREFIX##_clear_saved() { OBJ.has_saved = false; ++OBJ.clear_calls; } \
static audio_focus::SourceOps PREFIX##_ops() { \
    return { PREFIX##_is_playing, PREFIX##_is_running, PREFIX##_detach_ui, PREFIX##_reattach_ui, \
             PREFIX##_suspend, PREFIX##_resume, PREFIX##_has_saved, PREFIX##_clear_saved }; \
}

DEFINE_OPS(radio, g_radio)
DEFINE_OPS(netease, g_netease)

int main() {
    (void)make_ops;
    audio_focus::init();
    audio_focus::register_source(audio_focus::Source::Radio, radio_ops());
    audio_focus::register_source(audio_focus::Source::NetEase, netease_ops());

    // 1. Radio playing -> switch to Home keeps Radio playing in background
    g_radio = { .running = true, .playing = true, .ui_attached = true };
    g_mock_active_app = APP_ID_RADIO;
    assert(audio_focus::will_keep_background(APP_ID_RADIO, APP_ID_HOME));
    assert(audio_focus::handle_leaving(APP_ID_RADIO, APP_ID_HOME));
    assert(g_radio.detach_calls == 1 && g_radio.suspend_calls == 0);
    assert(audio_focus::background_active());
    assert(audio_focus::active_source() == audio_focus::Source::Radio);
    assert(audio_focus::current_state() == audio_focus::State::Playing);
    assert(audio_focus::will_reattach(APP_ID_RADIO));

    g_mock_active_app = APP_ID_HOME;
    audio_focus::prepare_entering(APP_ID_HOME);
    audio_focus::on_foreground_ready(APP_ID_HOME);
    assert(s_sentinel_allowed && s_sentinel_wifi);

    // 2. Re-entering Radio re-attaches UI seamlessly without suspend/restart
    assert(audio_focus::will_reattach(APP_ID_RADIO));
    audio_focus::prepare_entering(APP_ID_RADIO);
    g_mock_active_app = APP_ID_RADIO;
    assert(audio_focus::try_reattach(APP_ID_RADIO));
    assert(g_radio.reattach_calls == 1 && g_radio.ui_attached);
    audio_focus::on_foreground_ready(APP_ID_RADIO);

    // 3. Leave Radio to Home, then open Xiaozhi -> suspends Radio + stops sentinel
    assert(audio_focus::handle_leaving(APP_ID_RADIO, APP_ID_HOME));
    g_mock_active_app = APP_ID_HOME;
    audio_focus::prepare_entering(APP_ID_HOME);
    audio_focus::on_foreground_ready(APP_ID_HOME);

    audio_focus::prepare_entering(APP_ID_XIAOZHI);
    assert(!s_sentinel_allowed);
    assert(g_radio.suspend_calls == 1 && g_radio.last_save_flag && g_radio.has_saved);
    assert(!audio_focus::background_active());
    assert(audio_focus::current_state() == audio_focus::State::SuspendedApp);
    g_mock_active_app = APP_ID_XIAOZHI;
    audio_focus::on_foreground_ready(APP_ID_XIAOZHI);

    // Exit Xiaozhi back to Home -> automatically resumes Radio and re-enables sentinel
    g_mock_active_app = APP_ID_HOME;
    audio_focus::prepare_entering(APP_ID_HOME);
    audio_focus::on_foreground_ready(APP_ID_HOME);
    assert(g_radio.resume_calls == 1 && g_radio.running && g_radio.playing);
    assert(audio_focus::current_state() == audio_focus::State::Playing);
    assert(audio_focus::background_active());
    audio_focus::tick();
    assert(s_sentinel_allowed);

    // 4. FMO voice break-in while Radio is playing on Home -> pauses Radio, resumes after end_breakin
    assert(audio_focus::begin_breakin(2500));
    assert(audio_focus::breakin_active());
    assert(g_radio.suspend_calls == 2 && g_radio.has_saved);
    assert(audio_focus::current_state() == audio_focus::State::SuspendedBreak);
    audio_focus::end_breakin();
    assert(!audio_focus::breakin_active());
    assert(g_radio.resume_calls == 2 && g_radio.playing);
    assert(audio_focus::current_state() == audio_focus::State::Playing);

    // 5. FMO break-in active, user enters Xiaozhi mid-breakin -> no deadlock, upgrades to SuspendedApp,
    //    and still resumes Radio when returning to Home!
    assert(audio_focus::begin_breakin(2500));
    assert(audio_focus::current_state() == audio_focus::State::SuspendedBreak);
    s_sentinel_reentrant_end = true;
    audio_focus::prepare_entering(APP_ID_XIAOZHI);
    assert(!s_sentinel_allowed && !audio_focus::breakin_active());
    assert(audio_focus::current_state() == audio_focus::State::SuspendedApp);
    g_mock_active_app = APP_ID_HOME;
    audio_focus::prepare_entering(APP_ID_HOME);
    audio_focus::on_foreground_ready(APP_ID_HOME);
    assert(g_radio.resume_calls == 3 && g_radio.playing);

    // 6. Opening NetEase while Radio is playing in background cleanly stops Radio (no resume saved)
    audio_focus::prepare_entering(APP_ID_NETEASE);
    assert(g_radio.suspend_calls == 4 && !g_radio.last_save_flag && !g_radio.has_saved);
    assert(audio_focus::current_state() == audio_focus::State::Idle);
    assert(audio_focus::active_source() == audio_focus::Source::None);

    // 7. NetEase background + break-in round-trip
    g_netease = { .running = true, .playing = true, .ui_attached = true };
    g_mock_active_app = APP_ID_NETEASE;
    assert(audio_focus::handle_leaving(APP_ID_NETEASE, APP_ID_POMODORO));
    g_mock_active_app = APP_ID_POMODORO;
    audio_focus::prepare_entering(APP_ID_POMODORO);
    audio_focus::on_foreground_ready(APP_ID_POMODORO);
    assert(audio_focus::active_source() == audio_focus::Source::NetEase);
    assert(audio_focus::begin_breakin(2500));
    assert(g_netease.suspend_calls == 1 && g_netease.has_saved);
    audio_focus::end_breakin();
    assert(g_netease.resume_calls == 1 && g_netease.playing);
    assert(audio_focus::is_app_playing(APP_ID_NETEASE));
    assert(!audio_focus::is_app_playing(APP_ID_RADIO));
    assert(g_mock_breakin_begins == 3 && g_mock_breakin_ends == 3);

    std::puts("Audio Focus state machine (background, reattach, Xiaozhi suspend/resume, FMO break-in): PASS");
    return 0;
}
"""

def main():
    with tempfile.TemporaryDirectory(prefix="audio-focus-test-") as td:
        tdir = Path(td)
        inc = tdir / "mocks"
        for rel, content in MOCK_HEADERS.items():
            p = inc / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(content, encoding="utf-8")
        harness = tdir / "harness.cc"
        harness.write_text(HARNESS, encoding="utf-8")
        out = tdir / "test_audio_focus"
        cmd = [
            "c++", "-std=c++20", "-Wall", "-Wextra", "-Werror",
            "-fsanitize=address,undefined", "-g",
            f"-I{inc}", f"-I{ROOT / 'main'}",
            str(ROOT / "main/launcher/audio_focus.cc"),
            str(harness),
            "-o", str(out),
        ]
        subprocess.run(cmd, check=True)
        subprocess.run([str(out)], check=True)

if __name__ == "__main__":
    main()
