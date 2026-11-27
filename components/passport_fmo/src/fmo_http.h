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
bool fmo_http_start_lan(char *url_out, size_t url_cap);
void fmo_http_stop_lan();
bool fmo_http_lan_active();
#endif
