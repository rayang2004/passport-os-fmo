#pragma once

#ifdef __cplusplus
extern "C" {
#endif

// Initializes the Passport OS Plugin Host services vtable and registers any
// enabled compile-time plugins before app_registry_init().
void passport_plugin_host_init(void);

#ifdef __cplusplus
}
#endif
