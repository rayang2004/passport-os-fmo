#pragma once
#include <stdbool.h>
#include "esp_http_server.h"
esp_err_t fmo_http_settings(httpd_req_t *request);
esp_err_t fmo_http_ca(httpd_req_t *request);
esp_err_t fmo_http_stamp(httpd_req_t *request);
esp_err_t fmo_http_beep(httpd_req_t *request);
bool fmo_http_busy();
#ifdef ESP_PLATFORM
bool fmo_http_register(httpd_handle_t server);
#endif
