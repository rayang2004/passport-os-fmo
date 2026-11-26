// Optional single JPEG background; independent of weather/radio location settings.
#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "esp_err.h"
#ifdef __cplusplus
extern "C" {
#endif
#define HOME_BACKGROUND_W 240
#define HOME_BACKGROUND_H 320
#define HOME_BACKGROUND_MAX_BYTES (24 * 1024)
// Lazy mount, never auto-format an existing storage partition.
esp_err_t home_background_info(bool *present, size_t *bytes);
// Caller owns the malloc'd compressed JPEG; no full-screen RGB buffer.
esp_err_t home_background_load(uint8_t **data, size_t *bytes);
esp_err_t home_background_write(const uint8_t *data, size_t len, bool first, bool last, size_t total);
void home_background_abort(void);
esp_err_t home_background_clear(void);
#ifdef __cplusplus
}
#endif
