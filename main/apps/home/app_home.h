// Minimal time/weather home with a low-backlight, minute-refresh screensaver.
// 这是一个完整 App(而非 Launcher 的一部分),遵守 registry 的"stop 即删屏"
// 约定 —— 进应用时 Launcher 已释放界面,退出时本应用同样把 LVGL 对象全部删除。
#pragma once

#include "apps/app_base.h"

#ifdef __cplusplus
extern "C" {
#endif

extern const passport_app_t g_home_app;
// Caller must hold the LVGL lock.
void home_set_ambient(bool enabled);

#ifdef __cplusplus
}
#endif
