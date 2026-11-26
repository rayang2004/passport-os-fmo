#pragma once

#include "apps/app_base.h"
#include <stdbool.h>
#include <stdint.h>

namespace audio_focus {

enum class Source : uint8_t {
    None = 0,
    Radio,
    NetEase,
};

enum class State : uint8_t {
    Idle = 0,
    Playing,
    SuspendedApp,
    SuspendedBreak,
};

struct SourceOps {
    bool (*is_playing)(void);
    bool (*is_running)(void);
    void (*detach_ui)(void);
    bool (*reattach_ui)(void);
    bool (*suspend)(bool save_resume_point);
    bool (*resume_background)(void);
    bool (*has_saved_resume)(void);
    void (*clear_saved_resume)(void);
};

void init();
void register_source(Source src, const SourceOps &ops);

// Returns true when navigating to target_id allows Radio/NetEase to continue
// streaming in the background without stopping audio_workspace.
bool can_keep_background(passport_app_id_t target_id);

// Returns true when a lightweight background sentinel (such as FMO MQTT RX)
// may remain connected while active_id is in the foreground.
bool allows_sentinel(passport_app_id_t active_id);

// True when leaving prev_id toward next_id will keep prev_id running in the
// background (so app_registry skips prepare_stop() and stop()).
bool will_keep_background(passport_app_id_t prev_id, passport_app_id_t next_id);

// True when entering next_id will re-attach UI to an already running
// background player (so app_registry must skip clean_launch heap checks).
bool will_reattach(passport_app_id_t next_id);

// Called by app_registry_switch_to() when leaving prev_id toward next_id.
// Returns true if prev_id's audio player should remain alive in the background
// (caller must NOT invoke prev->stop(); detach_to_background already hid UI).
bool handle_leaving(passport_app_id_t prev_id, passport_app_id_t next_id);

// Called by app_registry_switch_to() right before starting next_id (after prev
// has stopped or detached). Stops/suspends background audio and notifies
// plugins when entering an exclusive audio app.
void prepare_entering(passport_app_id_t next_id);

// Called when entering next_id: if next_id matches the active background
// player, re-attaches its UI directly and returns true (caller skips start()).
bool try_reattach(passport_app_id_t next_id);

// Called after next_id has started in the foreground: resumes suspended
// background audio if returning to a non-exclusive app, and updates plugins.
void on_foreground_ready(passport_app_id_t active_id);

// Plugin break-in API: suspends playing Radio/NetEase (saving its resume point)
// so a plugin voice alert (e.g. FMO incoming call) can own audio_workspace +
// ES8311 temporarily, then resumes automatically when end_breakin() is called.
bool begin_breakin(uint32_t timeout_ms);
void end_breakin();
bool breakin_active();

// True when background Radio/NetEase or a plugin break-in is currently active.
bool background_active();
Source active_source();
State current_state();

// Periodic 1 Hz tick (called from sys_mon) to propagate Wi-Fi connectivity
// changes to background plugin sentinels and service deferred resumes.
void tick();

}  // namespace audio_focus
