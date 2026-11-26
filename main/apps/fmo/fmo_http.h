#pragma once
#include "esp_http_server.h"
esp_err_t fmo_http_settings(httpd_req_t *request);
esp_err_t fmo_http_ca(httpd_req_t *request);
esp_err_t fmo_http_stamp(httpd_req_t *request);
esp_err_t fmo_http_beep(httpd_req_t *request);
bool fmo_http_busy();
