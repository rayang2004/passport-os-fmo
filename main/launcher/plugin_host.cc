#include "launcher/plugin_host.h"

#include "sdkconfig.h"
#include "passport_plugin.h"
#include "apps/app_base.h"
#include "apps/home/home_clock.h"
#include "apps/home/home_profile.h"
#include "apps/home/home_upload.h"
#include "apps/voice/time_sync.h"
#include "fonts/app_fonts.h"
#include "launcher/app_registry.h"
#include "launcher/settings.h"
#include "ui_pixel.h"

#if defined(CONFIG_PASSPORT_PLUGIN_FMO) && CONFIG_PASSPORT_PLUGIN_FMO
extern "C" int passport_fmo_plugin_register(int base_app_id);
#endif

namespace {

void host_switch_to_home(void) { app_registry_switch_to(APP_ID_HOME); }
void host_switch_to_launcher(void) { app_registry_switch_to(APP_ID_LAUNCHER); }
void host_switch_to_wifi_setup(void) { app_registry_switch_to(APP_ID_WIFI); }

int32_t host_tz_offset_sec(void) {
    return static_cast<int32_t>(time_sync_tz_offset_sec());
}

void host_clock_format_time(char *buf, size_t cap) {
    home_clock_format_time(buf, cap);
}

const passport_plugin_host_t s_host = {
    .font_16 = &buddy_font_16,
    .font_20 = &ui_font_20,
    .pixel_label = ui_pixel_label,
    .pixel_label_set_text = ui_pixel_label_set_text,
    .switch_to_home = host_switch_to_home,
    .switch_to_launcher = host_switch_to_launcher,
    .switch_to_wifi_setup = host_switch_to_wifi_setup,
    .keep_awake = app_registry_keep_awake,
    .get_volume = settings_get_volume,
    .save_volume = settings_save_volume,
    .tz_offset_sec = host_tz_offset_sec,
    .clock_valid = home_clock_valid,
    .clock_running = home_clock_running,
    .clock_start = home_clock_start,
    .clock_stop = home_clock_stop,
    .clock_format_time = host_clock_format_time,
    .storage_acquire = home_profile_storage_acquire,
    .storage_release = home_profile_storage_release,
    .http_token_ok = home_upload_token_ok,
};

} // namespace

void passport_plugin_host_init(void) {
    passport_plugin_set_host(&s_host);
#if defined(CONFIG_PASSPORT_PLUGIN_FMO) && CONFIG_PASSPORT_PLUGIN_FMO
    passport_fmo_plugin_register(APP_ID_PLUGIN_BASE);
#endif
}
