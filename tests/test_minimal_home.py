"""Exercise the production minimal Home UI, ambient rendering and worker lifecycle."""
from pathlib import Path
import re
import subprocess
import tempfile
root = Path(__file__).resolve().parents[1]
source = (root / 'main/apps/home/app_home.cc').read_text()
source = re.sub(r'^#include .*$', '', source, flags=re.M)
prelude = r'''
#include <cassert>
#include <atomic>
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <ctime>
#include <string>
#include <vector>
#include "apps/app_base.h"
#include "apps/home/home_profile.h"
#include "apps/home/home_background.h"
#include "apps/home/home_weather.h"
using TaskHandle_t = int*;
static int worker_token;
constexpr int pdTRUE=1, pdPASS=1;
#define pdMS_TO_TICKS(n) (n)
struct lv_font_t { const lv_font_t *fallback=nullptr; };
static lv_font_t buddy_font_16, pomodoro_digits_48, ui_digits_32;
struct lv_obj_t { std::string text; int y=0; bool hidden=false; const lv_font_t *font=nullptr; };
struct lv_image_dsc_t { struct { int magic=0,cf=0,w=0,h=0; } header; size_t data_size=0; const uint8_t *data=nullptr; };
constexpr int LV_IMAGE_HEADER_MAGIC=1,LV_COLOR_FORMAT_RAW=1,LV_OPA_60=153,LV_OBJ_FLAG_HIDDEN=2;
static bool mock_background=false;
static unsigned cache_drops=0, heap_free=100000;
static unsigned esp_get_free_heap_size(){return heap_free;}
extern "C" esp_err_t home_background_load(uint8_t **data,size_t *bytes){*data=mock_background?static_cast<uint8_t*>(malloc(16)):nullptr;*bytes=mock_background?16:0;return *data?ESP_OK:ESP_ERR_NOT_FOUND;}
constexpr int LV_TEXT_ALIGN_CENTER=0, LV_LABEL_LONG_DOT=0, LV_OBJ_FLAG_SCROLLABLE=0, LV_OPA_COVER=255;
static std::vector<lv_obj_t*> objects;
static lv_obj_t *active_screen;
static unsigned flushes, requests, task_deletes, task_notices;
static int64_t now_ms=0;
static unsigned wait_ms;
static bool connected=false, screen_on=true, clock_valid=false, fail_create=false;
static bool lock_held=false, stop_during_wait=false;
static passport_app_id_t opened=APP_ID_HOME;
static home_profile_t profile{};
static home_weather_t sample{};
static void home_profile_init(){} static void home_weather_init(){} static void time_sync_init(){}
static void home_clock_start(){} static void home_clock_stop(){}
static bool home_clock_valid(){return clock_valid;}
static void home_clock_format_time(char *out,size_t n){std::snprintf(out,n,"%s",clock_valid?"12:34":"--:--");}
static void home_clock_format_date(char *out,size_t n){std::snprintf(out,n,"11月23日");}
static void home_clock_format_weekday(char *out,size_t n){std::snprintf(out,n,"周一");}
static void home_weather_allow_requests(){} static void home_weather_cancel_requests(){}
static bool bsp_lvgl_lock(int){assert(!lock_held);lock_held=true;return true;}
static void bsp_lvgl_unlock(){assert(lock_held);lock_held=false;}
static lv_obj_t *lv_obj_create(void*){auto *o=new lv_obj_t;objects.push_back(o);return o;}
static lv_obj_t *ui_pixel_label(lv_obj_t*,const char *text,const lv_font_t *font,uint32_t){auto *o=lv_obj_create(nullptr);o->text=text;o->font=font;return o;}
static void ui_pixel_label_set_text(lv_obj_t *o,const char *s){assert(lock_held);o->text=s;}
static void lv_obj_set_pos(lv_obj_t *o,int,int y){o->y=y;}
static lv_obj_t *lv_image_create(lv_obj_t*){return lv_obj_create(nullptr);}
static void lv_image_set_src(lv_obj_t*,const void*){}
static void lv_image_cache_drop(const void*){++cache_drops;}
static void lv_obj_remove_style_all(lv_obj_t*){}
static void lv_obj_set_size(lv_obj_t*,int,int){}
static void lv_obj_set_flag(lv_obj_t *o,int,bool hidden){o->hidden=hidden;}
static void lv_obj_set_width(lv_obj_t*,int){} static void lv_obj_set_style_text_align(lv_obj_t*,int,int){}
static void lv_label_set_long_mode(lv_obj_t*,int){} static void lv_obj_remove_flag(lv_obj_t*,int){}
static int lv_color_hex(int n){return n;} static void lv_obj_set_style_bg_color(lv_obj_t*,int,int){}
static void lv_obj_set_style_bg_opa(lv_obj_t*,int,int){}
static void lv_screen_load(lv_obj_t *s){active_screen=s;}
static void *lv_display_get_default(){return nullptr;}
static void lv_refr_now(void*){assert(lock_held);++flushes;}
static void lv_obj_delete(lv_obj_t*){for(auto *o:objects)delete o;objects.clear();active_screen=nullptr;}
static int64_t esp_timer_get_time(){return now_ms*1000;}
static void xTaskNotifyGive(TaskHandle_t task){assert(task==&worker_token);++task_notices;}
static void vTaskDelete(TaskHandle_t task){assert(task==&worker_token);++task_deletes;}
struct Parked{};
static void vTaskSuspend(void*){throw Parked{};}
static int xTaskCreate(void(*)(void*),const char*,int,void*,int,TaskHandle_t *out){if(fail_create)return 0;*out=&worker_token;return pdPASS;}
static unsigned ulTaskNotifyTake(int,unsigned);
static bool app_registry_screen_is_on(){return screen_on;}
static void app_registry_switch_to(passport_app_id_t id){opened=id;}
enum class WifiPowerSaveLevel { LOW_POWER, BALANCED };
class WifiManager {public:static WifiManager &GetInstance(){static WifiManager w;return w;} bool IsConnected(){return connected;}};
extern "C" void home_profile_get(home_profile_t *p){*p=profile;}
extern "C" bool home_weather_get(home_weather_t *p){*p=sample;return sample.valid;}
extern "C" const char *home_weather_code_text(uint16_t){return "晴";}
extern "C" void home_weather_age_text(uint32_t,int64_t,char *out,size_t n){std::snprintf(out,n,"15分钟前");}
extern "C" esp_err_t home_weather_refresh(const char*,const char*){assert(!lock_held);++requests;return ESP_OK;}
'''
# Header declarations are extern while a few subsystem functions above are local test doubles.
prelude=prelude.replace('static void home_profile_init(){} static void home_weather_init(){}',
                       'extern "C" void home_profile_init(){} extern "C" void home_weather_init(){}')
prelude=prelude.replace('static void home_weather_allow_requests(){} static void home_weather_cancel_requests(){}',
                       'extern "C" void home_weather_allow_requests(){} extern "C" void home_weather_cancel_requests(){}')
tests = r'''
static unsigned ulTaskNotifyTake(int,unsigned timeout){wait_ms=timeout;if(stop_during_wait)s_active=false;return 0;}
static void run_one_worker_cycle(){stop_during_wait=true;try{home_task(nullptr);assert(false);}catch(Parked&){} assert(!s_running.load());}
int main(){
 std::snprintf(profile.city,sizeof(profile.city),"上海");
 std::snprintf(profile.lat,sizeof(profile.lat),"31.2");std::snprintf(profile.lon,sizeof(profile.lon),"121.5");
 home_init();home_start();assert(objects.size()==8&&active_screen==s_screen);
 assert(s_time->text=="--:--"&&s_temperature->text=="--");
 assert(s_time->font->fallback==&buddy_font_16&&s_temperature->font->fallback==&buddy_font_16);
 clock_valid=true;sample.valid=true;sample.temp_c=-12;
 bsp_lvgl_lock(-1);render();bsp_lvgl_unlock();
 assert(s_time->text=="12:34"&&s_temperature->text=="-12"&&s_city->text=="上海");
 assert(s_date->y==44&&s_time->y==78&&s_weather->y==224);
 const auto count=objects.size();const auto notices_before=task_notices;
 bsp_lvgl_lock(-1);home_set_ambient(true);bsp_lvgl_unlock();
 // Ambient entry must not invoke lv_refr_now() on sys_mon's small stack; home_task flushes.
 assert(s_ambient&&s_hint->text.empty()&&objects.size()==count&&flushes==0&&task_notices==notices_before+1);
 connected=true;screen_on=false;now_ms=1000000;
 run_one_worker_cycle();assert(requests==0&&wait_ms>0&&wait_ms<=60000&&flushes==1);
 assert(home_prepare_stop());home_stop();assert(objects.empty()&&task_deletes==1&&!s_worker);
 home_start();bsp_lvgl_lock(-1);home_set_ambient(false);bsp_lvgl_unlock();
 assert(!s_ambient&&!s_hint->text.empty());
 // Due weather is fetched once awake; cancellation remains bounded by a notification.
 screen_on=true;s_force=true;run_one_worker_cycle();assert(requests==1&&wait_ms==1000);
 home_stop();assert(objects.empty()&&task_deletes==2);
 mock_background=true;home_start();assert(objects.size()==10&&s_background_data);
 bsp_lvgl_lock(-1);home_set_ambient(true);bsp_lvgl_unlock();
 assert(s_background_image->hidden&&s_background_shade->hidden);
 bsp_lvgl_lock(-1);home_set_ambient(false);bsp_lvgl_unlock();assert(!s_background_image->hidden);
 run_one_worker_cycle();home_stop();assert(!s_background_data&&!s_background_image&&objects.empty()&&cache_drops>0);
 heap_free=40000;home_start();assert(!s_background_data&&objects.size()==8);
 run_one_worker_cycle();home_stop();heap_free=100000;mock_background=false;
 fail_create=true;home_start();assert(!s_running&&!s_worker);home_stop();assert(objects.empty());
 home_on_key(BSP_BTN_OK,BTN_EVT_CLICK,0);assert(opened==APP_ID_LAUNCHER);
 home_on_key(BSP_BTN_DOWN,BTN_EVT_LONG,0);assert(opened==APP_ID_WIFI);
 puts("Minimal Home: time/weather layout, missing/signed values, allocation-free ambient, no idle HTTP, cancellable minute waits, stop/reentry and creation failure PASS");
}
'''
with tempfile.TemporaryDirectory(prefix='passport-home-') as directory:
    cpp=Path(directory)/'home.cc';binary=Path(directory)/'home'
    (Path(directory)/'bsp_button.h').write_text('#pragma once\n#include <stdint.h>\nenum { BSP_BTN_UP=0, BSP_BTN_DOWN=1, BSP_BTN_OK=2 };\n')
    cpp.write_text(prelude+'\n'+source+'\n'+tests)
    subprocess.run(['c++','-std=c++20','-Wall','-Wextra','-Werror','-Wno-unused-variable',
                    '-fsanitize=address,undefined','-g','-I'+directory,
                    '-Itests/radio_mocks','-Imain',str(cpp),'-o',str(binary)],cwd=root,check=True)
    subprocess.run([str(binary)],check=True)
