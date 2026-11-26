"""Run the production backlight setup/scaling against LEDC fault-injection doubles."""
from pathlib import Path
import subprocess
import tempfile
root=Path(__file__).resolve().parents[1]
source=(root/'components/bsp/src/bsp_display.c').read_text()
pins=(root/'components/bsp/include/bsp_pins.h').read_text()
def function(signature):
    start=source.index(signature);end=source.index('{',start)+1;depth=1
    while depth:
        if source[end]=='{':depth+=1
        if source[end]=='}':depth-=1
        end+=1
    return source[start:end]
constants='\n'.join(line for line in pins.splitlines() if line.startswith('#define BSP_BL_LEDC_'))
code=r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
typedef int esp_err_t;
#define ESP_OK 0
#define ESP_LOGW(...) ((void)0)
#define ESP_LOGI(...) ((void)0)
#define ESP_LOGE(...) ((void)0)
#define BSP_LCD_BL 21
#define LEDC_TIMER_0 0
#define LEDC_CHANNEL_0 0
#define LEDC_LOW_SPEED_MODE 0
#define LEDC_TIMER_9_BIT 9
#define LEDC_USE_RC_FAST_CLK 1
#define LEDC_SLEEP_MODE_NO_ALIVE_NO_PD 0
#define LEDC_SLEEP_MODE_KEEP_ALIVE 1
typedef struct { int speed_mode,timer_num,duty_resolution,freq_hz,clk_cfg; bool deconfigure; } ledc_timer_config_t;
typedef struct { int gpio_num,speed_mode,channel,timer_sel,duty,hpoint,sleep_mode; } ledc_channel_config_t;
static bool s_bl_ready;
static uint8_t s_requested_brightness=100,s_master_brightness=80;
static ledc_timer_config_t timer_config;
static ledc_channel_config_t channel_config;
static unsigned duty, updates, stops;
static int fail_timer,fail_channel;
static esp_err_t ledc_timer_config(const ledc_timer_config_t *c){timer_config=*c;return fail_timer;}
static esp_err_t ledc_channel_config(const ledc_channel_config_t *c){channel_config=*c;return fail_channel;}
static esp_err_t ledc_stop(int mode,int channel,unsigned idle){(void)mode;(void)channel;(void)idle;++stops;return ESP_OK;}
static void ledc_set_duty(int mode,int channel,unsigned value){(void)mode;(void)channel;duty=value;}
static void ledc_update_duty(int mode,int channel){(void)mode;(void)channel;++updates;}
'''+constants+'\n'+'\n'.join(function(name) for name in [
    'static void backlight_init(void)', 'void bsp_display_backlight(uint8_t percent)',
    'void bsp_display_prepare_sleep(void)',
    'void bsp_display_set_master_brightness(uint8_t percent)', 'uint8_t bsp_display_get_master_brightness(void)'])+r'''
int main(void){
 fail_timer=-1;backlight_init();assert(!s_bl_ready);
 fail_timer=0;fail_channel=-1;backlight_init();assert(!s_bl_ready);
 fail_channel=0;backlight_init();assert(s_bl_ready);
 assert(timer_config.clk_cfg==LEDC_USE_RC_FAST_CLK&&channel_config.sleep_mode==LEDC_SLEEP_MODE_KEEP_ALIVE);
 assert(timer_config.freq_hz==20000&&timer_config.duty_resolution==9);
 // Even a conservative 17MHz RC clock can generate the unchanged 20kHz PWM at 9bit.
 assert((1u<<timer_config.duty_resolution)*(unsigned)timer_config.freq_hz<17000000);
 for(unsigned master=1;master<=100;++master){
  bsp_display_set_master_brightness(master);bsp_display_backlight(3);
  assert(duty>0&&duty<=16&&bsp_display_get_master_brightness()==master);
  bsp_display_backlight(0);assert(duty==0);
 }
 bsp_display_set_master_brightness(0);bsp_display_backlight(3);assert(duty==0);
 bsp_display_set_master_brightness(20);assert(duty==3);
 bsp_display_set_master_brightness(255);bsp_display_backlight(255);assert(duty==511);
 assert(updates>0);
 bsp_display_prepare_sleep();
 assert(!s_bl_ready&&stops==2&&channel_config.sleep_mode==LEDC_SLEEP_MODE_NO_ALIVE_NO_PD&&timer_config.deconfigure);
 bsp_display_prepare_sleep();assert(stops==2);
 puts("Backlight: RC_FAST/KEEP_ALIVE, sleep teardown, 20kHz clock budget, init failures, low-master ambient precision, zero/clamp and restore PASS");
}
'''
with tempfile.TemporaryDirectory(prefix='passport-display-') as directory:
    c=Path(directory)/'display.c';binary=c.with_suffix('');c.write_text(code)
    subprocess.run(['cc','-std=c11','-Wall','-Wextra','-Werror','-fsanitize=address,undefined',str(c),'-o',str(binary)],check=True)
    subprocess.run([str(binary)],check=True)
