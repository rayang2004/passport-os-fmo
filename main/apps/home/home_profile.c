#include "apps/home/home_profile.h"

#include "esp_log.h"
#include "nvs.h"
#include "freertos/FreeRTOS.h"

#include <string.h>
#include <stdlib.h>
#include <math.h>

static const char *TAG = "home_profile";

#define NVS_NAMESPACE "home_profile"
// 资料读写在 httpd 任务与首页任务间并发,用临界区保护结构体。
// 单核 C3 上临界区会阻断其他任务,写路径(NVS IO)必须放在临界区外。
static portMUX_TYPE s_mux = portMUX_INITIALIZER_UNLOCKED;
static home_profile_t s_profile;

static bool utf8_len_ok(const char *s, size_t cap) {
    return s && strnlen(s, cap) < cap; /* strlen 已含结尾 0 之外的全部字节 */
}

static bool coordinate_valid(const char *s, double min, double max) {
    if (!s || !*s || strnlen(s, HOME_COORD_MAX) >= HOME_COORD_MAX) return false;
    const char *p = s;
    if (*p == '-' || *p == '+') ++p;
    bool digit = false, dot = false;
    for (; *p; ++p) {
        if (*p >= '0' && *p <= '9') digit = true;
        else if (*p == '.' && !dot) dot = true;
        else return false;
    }
    if (!digit) return false;
    const double n = strtod(s, NULL);
    return isfinite(n) && n >= min && n <= max;
}

bool home_profile_coordinates_valid(const char *lat, const char *lon) {
    return lat && lon && ((!lat[0] && !lon[0]) ||
        (coordinate_valid(lat, -90, 90) && coordinate_valid(lon, -180, 180)));
}

void home_profile_init(void) {
    memset(&s_profile, 0, sizeof(s_profile));
    nvs_handle_t handle;
    if (nvs_open(NVS_NAMESPACE, NVS_READONLY, &handle) != ESP_OK) {
        ESP_LOGI(TAG, "No profile stored yet, using empty profile");
        return;
    }
    size_t len;
    len = sizeof(s_profile.city);
    nvs_get_str(handle, "city", s_profile.city, &len);
    len = sizeof(s_profile.lat);
    nvs_get_str(handle, "lat", s_profile.lat, &len);
    len = sizeof(s_profile.lon);
    nvs_get_str(handle, "lon", s_profile.lon, &len);
    len = sizeof(s_profile.region);
    nvs_get_str(handle, "region", s_profile.region, &len);
    len = sizeof(s_profile.radio_city);
    nvs_get_str(handle, "radio_city", s_profile.radio_city, &len);
    len = sizeof(s_profile.country_code);
    nvs_get_str(handle, "country_code", s_profile.country_code, &len);
    nvs_close(handle);
    ESP_LOGI(TAG, "Location loaded: city='%s' lat='%s' lon='%s'",
             s_profile.city, s_profile.lat, s_profile.lon);
}

void home_profile_get(home_profile_t *out) {
    if (!out) return;
    portENTER_CRITICAL(&s_mux);
    *out = s_profile;
    portEXIT_CRITICAL(&s_mux);
}

esp_err_t home_profile_set_text(const home_profile_t *in) {
    if (!in) return ESP_ERR_INVALID_ARG;
    if (!utf8_len_ok(in->city, HOME_CITY_MAX) ||
        !utf8_len_ok(in->lat, HOME_COORD_MAX) ||
        !utf8_len_ok(in->lon, HOME_COORD_MAX) ||
        !utf8_len_ok(in->region, HOME_REGION_MAX) ||
        !utf8_len_ok(in->radio_city, HOME_CITY_MAX) ||
        !utf8_len_ok(in->country_code, sizeof(in->country_code))) {
        return ESP_ERR_INVALID_SIZE;
    }
    if (!home_profile_coordinates_valid(in->lat, in->lon) ||
        (in->country_code[0] && strcmp(in->country_code, "CN") &&
         strcmp(in->country_code, "HK") && strcmp(in->country_code, "MO") &&
         strcmp(in->country_code, "TW"))) return ESP_ERR_INVALID_ARG;

    // 先持久化再上屏:NVS 写失败时保持旧资料,UI 永远与存储一致。
    nvs_handle_t handle;
    esp_err_t err = nvs_open(NVS_NAMESPACE, NVS_READWRITE, &handle);
    if (err != ESP_OK) {
        ESP_LOGW(TAG, "nvs_open failed: %s", esp_err_to_name(err));
        return err;
    }
    do {
        if ((err = nvs_set_str(handle, "city", in->city)) != ESP_OK) break;
        if ((err = nvs_set_str(handle, "lat", in->lat)) != ESP_OK) break;
        if ((err = nvs_set_str(handle, "lon", in->lon)) != ESP_OK) break;
        if ((err = nvs_set_str(handle, "region", in->region)) != ESP_OK) break;
        if ((err = nvs_set_str(handle, "radio_city", in->radio_city)) != ESP_OK) break;
        if ((err = nvs_set_str(handle, "country_code", in->country_code)) != ESP_OK) break;
        err = nvs_commit(handle);
    } while (false);
    nvs_close(handle);
    if (err != ESP_OK) {
        ESP_LOGW(TAG, "Profile save failed: %s", esp_err_to_name(err));
        return err;
    }

    portENTER_CRITICAL(&s_mux);
    s_profile = *in;
    portEXIT_CRITICAL(&s_mux);
    ESP_LOGI(TAG, "Location updated: city='%s'", in->city);
    return ESP_OK;
}
