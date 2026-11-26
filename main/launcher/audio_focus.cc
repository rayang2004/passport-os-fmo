#include "launcher/audio_focus.h"

#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "freertos/task.h"
#include "launcher/app_registry.h"
#include "passport_plugin.h"
#include "wifi_manager.h"

#include <atomic>

namespace audio_focus {

namespace {

constexpr char kTag[] = "audio_focus";

SemaphoreHandle_t s_mutex = nullptr;
StaticSemaphore_t s_mutex_buf;
SourceOps s_ops[3]{};

Source s_source = Source::None;
State s_state = State::Idle;
passport_app_id_t s_foreground = APP_ID_LAUNCHER;
bool s_last_wifi = false;
bool s_last_sentinel_allowed = false;
std::atomic<bool> s_bg_running{false};
std::atomic<bool> s_breakin{false};
std::atomic<bool> s_resume_pending{false};

struct Lock {
    bool ok = false;
    explicit Lock(TickType_t wait = pdMS_TO_TICKS(3000)) {
        if (!s_mutex) s_mutex = xSemaphoreCreateRecursiveMutexStatic(&s_mutex_buf);
        ok = s_mutex && xSemaphoreTakeRecursive(s_mutex, wait) == pdTRUE;
    }
    ~Lock() {
        if (ok && s_mutex) xSemaphoreGiveRecursive(s_mutex);
    }
};

Source source_for_app(passport_app_id_t id) {
    if (id == APP_ID_RADIO) return Source::Radio;
    if (id == APP_ID_NETEASE) return Source::NetEase;
    return Source::None;
}

passport_app_id_t app_for_source(Source src) {
    if (src == Source::Radio) return APP_ID_RADIO;
    if (src == Source::NetEase) return APP_ID_NETEASE;
    return APP_ID_COUNT;
}

const SourceOps *ops_for(Source src) {
    const auto idx = static_cast<size_t>(src);
    if (idx == 0 || idx >= 3) return nullptr;
    return s_ops[idx].suspend ? &s_ops[idx] : nullptr;
}

void notify_plugins_state(bool wifi_connected, bool allow_sentinel) {
    if (wifi_connected == s_last_wifi && allow_sentinel == s_last_sentinel_allowed) return;
    s_last_wifi = wifi_connected;
    s_last_sentinel_allowed = allow_sentinel;
    const size_t n = passport_plugin_count();
    for (size_t i = 0; i < n; ++i) {
        const passport_plugin_t *p = passport_plugin_at(i, nullptr);
        if (p && p->on_system_state) {
            p->on_system_state(wifi_connected, allow_sentinel);
        }
    }
}

void force_notify_plugins(bool allow_sentinel) {
    const bool wifi = WifiManager::GetInstance().IsConnected();
    s_last_wifi = wifi;
    s_last_sentinel_allowed = allow_sentinel;
    const size_t n = passport_plugin_count();
    for (size_t i = 0; i < n; ++i) {
        const passport_plugin_t *p = passport_plugin_at(i, nullptr);
        if (p && p->on_system_state) {
            p->on_system_state(wifi, allow_sentinel);
        }
    }
}

void update_bg_flag() {
    const auto *ops = ops_for(s_source);
    const bool running = (s_state == State::Playing) && ops && ops->is_running && ops->is_running();
    s_bg_running.store(running, std::memory_order_release);
}

void resume_worker_task(void *) {
    // Allow brief settle after exclusive app teardown or break-in stop.
    vTaskDelay(pdMS_TO_TICKS(200));
    if (s_resume_pending.exchange(false)) {
        // Scope Lock strictly inside a block so ~Lock() ALWAYS releases s_mutex
        // BEFORE vTaskDelete(nullptr) (which never unwinds the C++ stack!).
        Lock lock;
        if (lock.ok && !s_breakin.load() &&
            (s_state == State::SuspendedApp || s_state == State::SuspendedBreak)) {
            const passport_app_id_t fg = app_registry_get_active();
            const bool fg_matches_source = (fg == app_for_source(s_source));
            if (can_keep_background(fg) || fg_matches_source) {
                const auto *ops = ops_for(s_source);
                if (ops && ops->has_saved_resume && ops->has_saved_resume() && ops->resume_background) {
                    ESP_LOGI(kTag, "Auto-resuming suspended audio source=%d (fg=%d)", (int)s_source, (int)fg);
                    if (ops->resume_background()) {
                        s_state = State::Playing;
                        if (fg_matches_source && ops->reattach_ui) {
                            ops->reattach_ui();
                        }
                        // Ensure Wi-Fi stays BALANCED for live background audio
                        WifiManager::GetInstance().SetPowerSaveLevel(WifiPowerSaveLevel::BALANCED);
                    } else {
                        ESP_LOGW(kTag, "Auto-resume failed for source=%d", (int)s_source);
                        s_state = State::Idle;
                        s_source = Source::None;
                    }
                } else {
                    s_state = State::Idle;
                    s_source = Source::None;
                }
                update_bg_flag();
            }
        }
    }
    vTaskDelete(nullptr);
}

void schedule_resume() {
    if (s_resume_pending.exchange(true)) return;
    if (xTaskCreate(resume_worker_task, "af_resume", 3584, nullptr, 4, nullptr) != pdPASS) {
        s_resume_pending.store(false);
    }
}

}  // namespace

void init() {
    if (!s_mutex) s_mutex = xSemaphoreCreateRecursiveMutexStatic(&s_mutex_buf);
}

void register_source(Source src, const SourceOps &ops) {
    Lock lock;
    const auto idx = static_cast<size_t>(src);
    if (idx == 0 || idx >= 3) return;
    s_ops[idx] = ops;
}

bool can_keep_background(passport_app_id_t target_id) {
    switch (target_id) {
        case APP_ID_HOME:
        case APP_ID_LAUNCHER:
        case APP_ID_SETTINGS:
        case APP_ID_POMODORO:
        case APP_ID_STOPWATCH:
        case APP_ID_REMINDERS:
        case APP_ID_LISTS:
        case APP_ID_TETRIS:
            return true;
        default:
            return false;
    }
}

bool allows_sentinel(passport_app_id_t active_id) {
    if (can_keep_background(active_id)) return true;
    if (active_id == APP_ID_RADIO || active_id == APP_ID_NETEASE) return true;
    return false;
}

bool will_keep_background(passport_app_id_t prev_id, passport_app_id_t next_id) {
    Lock lock(pdMS_TO_TICKS(500));
    if (!lock.ok || !can_keep_background(next_id)) return false;
    const Source src = source_for_app(prev_id);
    const auto *ops = ops_for(src);
    return ops && ops->is_running && ops->is_running() && ops->is_playing && ops->is_playing();
}

bool will_reattach(passport_app_id_t next_id) {
    Lock lock(pdMS_TO_TICKS(500));
    if (!lock.ok) return false;
    const Source next_src = source_for_app(next_id);
    if (next_src == Source::None || next_src != s_source || s_state != State::Playing) return false;
    const auto *ops = ops_for(next_src);
    return ops && ops->is_running && ops->is_running();
}

bool handle_leaving(passport_app_id_t prev_id, passport_app_id_t next_id) {
    Lock lock;
    if (!lock.ok) return false;
    const Source prev_src = source_for_app(prev_id);
    if (prev_src == Source::None) return false;
    const auto *ops = ops_for(prev_src);
    if (!ops || !ops->is_running || !ops->is_running()) return false;

    const bool playing = ops->is_playing && ops->is_playing();
    if (playing && can_keep_background(next_id)) {
        ESP_LOGI(kTag, "Keeping source=%d playing in background while switching to app=%d",
                 (int)prev_src, (int)next_id);
        if (ops->detach_ui) ops->detach_ui();
        s_source = prev_src;
        s_state = State::Playing;
        update_bg_flag();
        return true;
    }

    // Switching directly from playing Radio/NetEase into an exclusive app (Xiaozhi/FMO/etc.):
    // save resume point unless user explicitly switched to the OTHER media player!
    const bool switching_to_other_media = (next_id == APP_ID_RADIO || next_id == APP_ID_NETEASE);
    if (playing && !switching_to_other_media) {
        ESP_LOGI(kTag, "Suspending playing source=%d for exclusive app=%d (will auto-resume)",
                 (int)prev_src, (int)next_id);
        s_resume_pending.store(false);
        ops->suspend(true);
        s_source = prev_src;
        s_state = State::SuspendedApp;
        update_bg_flag();
        return true;
    }

    // Not playing (paused/stopped) or explicitly switching to another media app:
    // clear any saved resume point and let normal prev->stop() run.
    if (s_source == prev_src) {
        if (ops->clear_saved_resume) ops->clear_saved_resume();
        s_source = Source::None;
        s_state = State::Idle;
        update_bg_flag();
    }
    return false;
}

void prepare_entering(passport_app_id_t next_id) {
    // 1. If the destination does not allow background sentinels (e.g. FMO itself,
    // Xiaozhi, Voice, WifiSetup, Muse), stop sentinel synchronously OUTSIDE the
    // audio_focus mutex BEFORE the destination starts so MQTT client IDs, heap,
    // audio_workspace, and break-in teardown can never deadlock or conflict.
    if (!allows_sentinel(next_id)) {
        force_notify_plugins(false);
    }

    Lock lock;
    if (!lock.ok) return;
    s_foreground = next_id;

    // If a plugin break-in was active and just got torn down by entering an
    // exclusive app, clear the break-in flag and promote SuspendedBreak to
    // SuspendedApp so background media still auto-resumes when the app exits.
    if (!allows_sentinel(next_id)) {
        s_breakin.store(false, std::memory_order_release);
        if (s_state == State::SuspendedBreak) {
            s_state = State::SuspendedApp;
        }
    }

    // 2. If user is re-entering the active background source, keep it running.
    const Source next_src = source_for_app(next_id);
    if (next_src != Source::None && next_src == s_source && s_state == State::Playing) {
        return;
    }

    // 3. If user enters an exclusive app (or a different media app) while
    // background audio is playing, suspend/stop the background player now so
    // audio_workspace and heap are 100% free before next_id starts.
    if (s_source != Source::None && s_state == State::Playing && !can_keep_background(next_id)) {
        const auto *ops = ops_for(s_source);
        const bool other_media = (next_src != Source::None && next_src != s_source);
        s_resume_pending.store(false);
        if (ops && ops->suspend) {
            ESP_LOGI(kTag, "Yielding background source=%d for app=%d (save_resume=%d)",
                     (int)s_source, (int)next_id, (int)!other_media);
            ops->suspend(!other_media);
        }
        if (other_media) {
            if (ops && ops->clear_saved_resume) ops->clear_saved_resume();
            s_source = Source::None;
            s_state = State::Idle;
        } else {
            s_state = State::SuspendedApp;
        }
        update_bg_flag();
    } else if (next_src != Source::None && next_src != s_source && s_state == State::SuspendedApp) {
        // User explicitly opened another media app; forget previous suspended source.
        const auto *ops = ops_for(s_source);
        if (ops && ops->clear_saved_resume) ops->clear_saved_resume();
        s_source = Source::None;
        s_state = State::Idle;
        update_bg_flag();
    }
}

bool try_reattach(passport_app_id_t next_id) {
    Lock lock;
    if (!lock.ok) return false;
    const Source next_src = source_for_app(next_id);
    if (next_src == Source::None || next_src != s_source || s_state != State::Playing) {
        return false;
    }
    const auto *ops = ops_for(next_src);
    if (!ops || !ops->is_running || !ops->is_running() || !ops->reattach_ui) {
        s_source = Source::None;
        s_state = State::Idle;
        update_bg_flag();
        return false;
    }
    ESP_LOGI(kTag, "Re-attaching foreground UI to running background source=%d", (int)next_src);
    const bool ok = ops->reattach_ui();
    if (!ok) {
        s_source = Source::None;
        s_state = State::Idle;
        update_bg_flag();
    }
    return ok;
}

void on_foreground_ready(passport_app_id_t active_id) {
    Lock lock;
    if (!lock.ok) return;
    s_foreground = active_id;

    // If we returned from an exclusive app (Xiaozhi/FMO) to a background-friendly
    // screen while media was suspended for that app, automatically resume it!
    if (s_state == State::SuspendedApp && can_keep_background(active_id)) {
        schedule_resume();
    }

    if (allows_sentinel(active_id)) {
        force_notify_plugins(true);
    }
}

bool begin_breakin(uint32_t timeout_ms) {
    (void)timeout_ms;
    Lock lock(pdMS_TO_TICKS(2000));
    if (!lock.ok) return false;
    const passport_app_id_t fg = app_registry_get_active();
    if (!allows_sentinel(fg)) return false;
    if (s_breakin.exchange(true)) return true;

    s_resume_pending.store(false);
    // Check whether Radio or NetEase is currently playing (either foreground or background)
    Source active_media = s_source;
    if (active_media == Source::None) {
        active_media = source_for_app(fg);
    }
    if (active_media != Source::None) {
        const auto *ops = ops_for(active_media);
        if (ops && ops->is_running && ops->is_running()) {
            const bool was_playing = ops->is_playing && ops->is_playing();
            ESP_LOGI(kTag, "Break-in suspending active media source=%d (was_playing=%d)",
                     (int)active_media, (int)was_playing);
            ops->suspend(was_playing);
            if (was_playing) {
                s_source = active_media;
                s_state = State::SuspendedBreak;
            } else {
                s_source = Source::None;
                s_state = State::Idle;
            }
            update_bg_flag();
        }
    }
    return true;
}

void end_breakin() {
    Lock lock(pdMS_TO_TICKS(2000));
    if (!lock.ok) {
        s_breakin.store(false);
        return;
    }
    if (!s_breakin.exchange(false)) return;
    ESP_LOGI(kTag, "Break-in ended (state=%d source=%d)", (int)s_state, (int)s_source);
    if (s_state == State::SuspendedBreak && s_source != Source::None) {
        schedule_resume();
    }
}

bool breakin_active() {
    return s_breakin.load(std::memory_order_acquire);
}

bool background_active() {
    return s_bg_running.load(std::memory_order_acquire) || s_breakin.load(std::memory_order_acquire);
}

Source active_source() {
    return s_source;
}

State current_state() {
    return s_state;
}

void tick() {
    static uint8_t s_pulse = 0;
    const passport_app_id_t fg = app_registry_get_active();
    const bool wifi = WifiManager::GetInstance().IsConnected();
    const bool allow = allows_sentinel(fg);
    // Periodic 5s pulse when Wi-Fi is up and sentinel is allowed lets
    // background sentinels start promptly after SNTP sync and refresh SAS4 auth.
    if (wifi && allow && ++s_pulse >= 5) {
        s_pulse = 0;
        force_notify_plugins(true);
        return;
    }
    if (!wifi || !allow) s_pulse = 0;
    notify_plugins_state(wifi, allow);
}

}  // namespace audio_focus
