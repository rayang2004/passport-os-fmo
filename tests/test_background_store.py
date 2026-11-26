"""Exercise real background storage with mount/NVS/codec fault injection (no ESP-IDF needed)."""
from pathlib import Path
import subprocess
import tempfile
root=Path(__file__).resolve().parents[1]
header=r'''
#pragma once
#include <stddef.h>
#include <stdint.h>
typedef struct { void *device; unsigned width,height; } JDEC;
typedef struct { unsigned left,right,top,bottom; } JRECT;
typedef int JRESULT;
#define JDR_OK 0
JRESULT jd_prepare(JDEC *,size_t (*)(JDEC *,uint8_t *,size_t),void *,size_t,void *);
JRESULT jd_decomp(JDEC *,int (*)(JDEC *,void *,JRECT *),uint8_t);
'''
code=r'''
#include "apps/home/home_background.h"
#include "apps/home/home_storage.h"
#include "esp_spiffs.h"
#include "esp_partition.h"
#include "nvs.h"
#include "src/libs/tjpgd/tjpgd.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
static int bank=-1,pending_bank=-1;
static bool fail_commit,fail_set,fail_read,immediate_set,fail_mount=true,erased,fail_partition_read,bad_codec;
static unsigned width=240,mount_calls,formats;
static esp_partition_t partition={1024};
esp_err_t nvs_open(const char *name,int mode,nvs_handle_t *handle){assert(!strcmp(name,"home_bg"));if(fail_read&&mode==NVS_READONLY)return ESP_FAIL;*handle=mode;pending_bank=bank;return ESP_OK;}
void nvs_close(nvs_handle_t handle){(void)handle;}
esp_err_t nvs_get_u8(nvs_handle_t handle,const char *key,uint8_t *out){(void)handle;assert(!strcmp(key,"bank"));if(bank<0)return ESP_ERR_NVS_NOT_FOUND;*out=bank;return ESP_OK;}
esp_err_t nvs_set_u8(nvs_handle_t handle,const char *key,uint8_t value){(void)handle;assert(!strcmp(key,"bank"));if(fail_set)return ESP_FAIL;pending_bank=value;if(immediate_set)bank=value;return ESP_OK;}
esp_err_t nvs_commit(nvs_handle_t handle){(void)handle;if(fail_commit)return ESP_FAIL;bank=pending_bank;return ESP_OK;}
esp_err_t nvs_erase_key(nvs_handle_t handle,const char *key){(void)handle;assert(!strcmp(key,"bank"));pending_bank=-1;return bank<0?ESP_ERR_NVS_NOT_FOUND:ESP_OK;}
esp_err_t esp_vfs_spiffs_register(const esp_vfs_spiffs_conf_t *config){++mount_calls;if(config->format_if_mount_failed){++formats;assert(erased);return ESP_OK;}return fail_mount?ESP_FAIL:ESP_OK;}
const esp_partition_t *esp_partition_find_first(int type,int subtype,const char *label){assert(type==1&&subtype==0x82&&!strcmp(label,"storage"));return &partition;}
esp_err_t esp_partition_read(const esp_partition_t *p,size_t at,void *out,size_t n){assert(p==&partition&&at+n<=p->size);if(fail_partition_read)return ESP_FAIL;memset(out,erased?0xFF:0xAA,n);return ESP_OK;}
JRESULT jd_prepare(JDEC *d,size_t (*input)(JDEC *,uint8_t *,size_t),void *work,size_t n,void *fp){(void)input;(void)work;assert(n==4096);d->device=fp;d->width=width;d->height=320;return 0;}
JRESULT jd_decomp(JDEC *d,int (*output)(JDEC *,void *,JRECT *),uint8_t scale){(void)d;(void)output;assert(!scale);return bad_codec?1:0;}
#include "HOME_SOURCE"
static const uint8_t jpeg[]={0xFF,0xD8,0xFF,0xE0,0,0x10,'J','F','I','F',0,1,1,0,0,0,1,1,0,0,0xFF,0xD9};
static void assert_current(void){uint8_t *data=NULL;size_t bytes=0;assert(home_background_load(&data,&bytes)==ESP_OK);assert(bytes==sizeof(jpeg)&&!memcmp(data,jpeg,bytes));free(data);}
int main(void){
 bool present=true;size_t bytes=99;
 assert(home_background_info(&present,&bytes)==ESP_OK&&!present&&!bytes&&!mount_calls);
 uint8_t *data=NULL;assert(home_background_load(&data,&bytes)==ESP_ERR_NOT_FOUND&&!data&&!mount_calls);
 FILE *legacy=fopen(BACKGROUND_BASE "/portrait.bin","wb");assert(legacy);fputs("legacy data",legacy);fclose(legacy);
 // Shared callers fail unlocked, never initialize during reads/startup,
 // and cannot format a nonblank partition even for an explicit user write.
 assert(home_storage_acquire(false)!=ESP_OK&&formats==0&&mutex->unused==0);
 assert(home_storage_acquire(true)!=ESP_OK&&formats==0&&mutex->unused==0);
 // Unknown nonblank data and failed reads cannot authorize a format.
 assert(home_background_write(jpeg,sizeof(jpeg),true,true,sizeof(jpeg))!=ESP_OK&&formats==0);
 erased=true;fail_partition_read=true;
 assert(home_background_write(jpeg,sizeof(jpeg),true,true,sizeof(jpeg))!=ESP_OK&&formats==0);
 assert(home_storage_acquire(true)!=ESP_OK&&formats==0&&mutex->unused==0);
 fail_partition_read=false;
 assert(home_storage_acquire(false)!=ESP_OK&&formats==0&&mutex->unused==0);
 assert(home_storage_acquire(true)==ESP_OK&&formats==1&&mutex->unused==1);home_storage_release();assert(mutex->unused==0);
 assert(home_storage_acquire(false)==ESP_OK&&formats==1&&mutex->unused==1);home_storage_release();
 assert(home_background_write(jpeg,sizeof(jpeg),true,true,sizeof(jpeg))==ESP_OK&&formats==1&&bank==0);assert_current();
 // Partial, truncated, oversized, bad-format, wrong-dimension and codec failures preserve the active bank.
 assert(home_background_write(jpeg,10,true,false,sizeof(jpeg))==ESP_OK);home_background_abort();assert_current();
 assert(home_background_write(jpeg,sizeof(jpeg)-1,true,true,sizeof(jpeg))!=ESP_OK);assert_current();
 assert(home_background_write(jpeg,sizeof(jpeg),true,true,HOME_BACKGROUND_MAX_BYTES+1)==ESP_ERR_INVALID_SIZE);assert_current();
 uint8_t bad[sizeof(jpeg)];memcpy(bad,jpeg,sizeof(jpeg));bad[0]=0;
 assert(home_background_write(bad,sizeof(bad),true,true,sizeof(bad))==ESP_ERR_INVALID_ARG);assert_current();
 width=1;assert(home_background_write(jpeg,sizeof(jpeg),true,true,sizeof(jpeg))==ESP_ERR_INVALID_ARG);width=240;assert_current();
 bad_codec=true;assert(home_background_write(jpeg,sizeof(jpeg),true,true,sizeof(jpeg))==ESP_ERR_INVALID_ARG);bad_codec=false;assert_current();
 fail_read=true;assert(home_background_write(jpeg,sizeof(jpeg),true,true,sizeof(jpeg))!=ESP_OK);fail_read=false;assert_current();
 fail_set=true;assert(home_background_write(jpeg,sizeof(jpeg),true,true,sizeof(jpeg))!=ESP_OK);fail_set=false;assert_current();
 // Simulate NVS publishing set_u8 before a failed commit: either bank remains complete and readable.
 immediate_set=true;fail_commit=true;
 assert(home_background_write(jpeg,sizeof(jpeg),true,true,sizeof(jpeg))!=ESP_OK&&bank==1);
 fail_commit=false;immediate_set=false;assert_current();
 struct stat st;assert(stat(paths[0],&st)==0&&stat(paths[1],&st)==0);
 fail_commit=true;assert(home_background_clear()!=ESP_OK);assert(stat(paths[bank],&st)==0);fail_commit=false;
 assert(home_background_clear()==ESP_OK&&bank==-1);
 assert(home_background_info(&present,&bytes)==ESP_OK&&!present&&!bytes);
 legacy=fopen(BACKGROUND_BASE "/portrait.bin","rb");assert(legacy);char text[12]={0};assert(fread(text,1,11,legacy)==11&&!strcmp(text,"legacy data"));fclose(legacy);
 puts("Background storage: blank-only initialization, existing-data preservation, bounded streaming, bank switching/abort, format/dimension/codec failures, NVS errors and safe clear PASS (codec mocked)");
}
'''
with tempfile.TemporaryDirectory(prefix='passport-background-') as directory:
    temporary=Path(directory);(temporary/'storage').mkdir()
    decoder=temporary/'src/libs/tjpgd/tjpgd.h';decoder.parent.mkdir(parents=True);decoder.write_text(header)
    semaphore=temporary/'freertos/semphr.h';semaphore.parent.mkdir(parents=True)
    semaphore_text=(root/'tests/home_mocks/freertos/semphr.h').read_text().replace('"FreeRTOS.h"','"freertos/FreeRTOS.h"')
    semaphore_text=semaphore_text.replace('(void)h; (void)ticks; return 1;','(void)ticks; assert(h->unused==0); h->unused=1; return 1;').replace('(void)h; return 1;','assert(h->unused==1); h->unused=0; return 1;')
    semaphore.write_text(semaphore_text)
    source=temporary/'background.c';binary=source.with_suffix('')
    source.write_text(code.replace('HOME_SOURCE',str(root/'main/apps/home/home_background.c')))
    subprocess.run(['cc','-std=c11','-D_POSIX_C_SOURCE=200809L','-Wall','-Wextra','-Werror',
                    '-fsanitize=address,undefined','-g','-I'+directory,'-Itests/home_mocks','-Itests/radio_mocks','-Imain',
                    '-DBACKGROUND_BASE="'+str(temporary/'storage')+'"',str(source),'-o',str(binary)],cwd=root,check=True)
    subprocess.run([str(binary)],check=True)
