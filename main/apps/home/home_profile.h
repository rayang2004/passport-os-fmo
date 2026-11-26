// Weather/radio location settings; no image storage or personal profile.
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

#define HOME_CITY_MAX 48      /* UTF-8 字节数,含结尾 0 */
#define HOME_COORD_MAX 16     /* "39.9075" 字符串 */
#define HOME_REGION_MAX 32

typedef struct {
    char city[HOME_CITY_MAX];
    char lat[HOME_COORD_MAX];
    char lon[HOME_COORD_MAX];
    char region[HOME_REGION_MAX]; /* shared weather/radio province */
    char radio_city[HOME_CITY_MAX]; /* parent city when a county is selected */
    char country_code[4];
} home_profile_t;

// Strict decimal coordinates; empty latitude AND longitude disable weather.
bool home_profile_coordinates_valid(const char *lat, const char *lon);

// 从已有 NVS 键加载天气/收音机城市与坐标。
void home_profile_init(void);

// 线程安全拷贝当前资料(httpd 任务与首页任务都会调用)。
void home_profile_get(home_profile_t *out);

// 保存城市与坐标；字段为空串时清空对应设置。
// 内容超长会拒绝并返回 ESP_ERR_INVALID_SIZE,绝不静默截断用户输入。
esp_err_t home_profile_set_text(const home_profile_t *in);

#ifdef __cplusplus
}
#endif
