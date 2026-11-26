#pragma once

#ifdef __cplusplus
extern "C" {
#endif

// Registers the FMO Passport plugin with the Passport OS Plugin Host.
// Returns the assigned app ID (>= base_app_id), or -1 on error.
int passport_fmo_plugin_register(int base_app_id);

#ifdef __cplusplus
}
#endif
