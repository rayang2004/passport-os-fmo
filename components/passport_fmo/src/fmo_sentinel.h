#pragma once

#include <stdbool.h>

// Lightweight background FMO/RAW MQTT sentinel and voice break-in playback.
// Runs only when Wi-Fi is connected, the active foreground app allows sentinels
// (Home, Launcher, Radio, NetEase, Pomodoro, etc.), and the user has enabled
// background break-in in FMO Quick Menu (persisted in NVS fmo_os/sentinel).
void fmo_sentinel_on_system_state(bool wifi_connected, bool allow_sentinel);
void fmo_sentinel_stop_sync(void);
bool fmo_sentinel_is_connected(void);
bool fmo_sentinel_is_breaking_in(void);
