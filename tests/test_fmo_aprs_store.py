"""Production APRS configuration codec: no network or real identity involved."""
from pathlib import Path
import ast,subprocess,tempfile
root=Path(__file__).resolve().parents[1]
tree=ast.parse((root/'tests/test_fmo_book.py').read_text())
header=next(ast.literal_eval(n.value) for n in tree.body if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='header' for t in n.targets))
source=r'''
#include "apps/fmo/fmo_aprs.h"
#include "apps/fmo/fmo_wire.h"
#include "nvs.h"
#include <vector>
#include <cstring>
#include <cassert>
#include <cstdio>
std::vector<uint8_t> committed,pending;bool fail_open=false,fail_read=false,fail_write=false,fail_commit=false;
int nvs_open(const char *ns,int,int *h){assert(!strcmp(ns,"fmo_os"));*h=1;return fail_open?-1:0;}
int nvs_get_blob(int,const char *key,void *out,size_t *n){assert(!strcmp(key,"aprs_v1"));if(fail_read)return -1;if(committed.empty())return ESP_ERR_NVS_NOT_FOUND;if(*n<committed.size())return -1;*n=committed.size();memcpy(out,committed.data(),*n);return 0;}
int nvs_set_blob(int,const char *key,const void *p,size_t n){assert(!strcmp(key,"aprs_v1"));if(fail_write)return -1;auto *b=static_cast<const uint8_t*>(p);pending.assign(b,b+n);return 0;}
int nvs_commit(int){if(fail_commit)return -1;committed=pending;return 0;}void nvs_close(int){}
using namespace fmo;
int main(){
 BroadcastConfig c;c.enabled=true;assert(load_broadcast_config(&c)&&!c.enabled&&!c.grid[0]&&!strcmp(c.rig,"AI Passport"));
 c.enabled=true;c.ssid=15;c.antenna_height=12;strcpy(c.grid,"PM06eb");strcpy(c.frequency,"438.5000");strcpy(c.antenna,"J");
 assert(save_broadcast_config(c)&&committed.size()==128);const auto good=committed;
 BroadcastConfig restored;assert(load_broadcast_config(&restored)&&restored.enabled&&restored.ssid==15&&restored.antenna_height==12&&!strcmp(restored.grid,"PM06eb"));
 for(size_t i=0;i<good.size();++i){committed=good;committed[i]^=1;restored.ssid=7;assert(!load_broadcast_config(&restored)&&restored.ssid==7);}
 for(unsigned field:{4u,5u,6u,7u,12u,87u}){committed=good;committed[field]=255;auto crc=crc32(committed.data(),124);for(unsigned i=0;i<4;++i)committed[124+i]=crc>>(8*i);assert(!load_broadcast_config(&restored));}
 for(unsigned size:{1u,127u,129u}){committed=good;committed.resize(size);assert(!load_broadcast_config(&restored));}
 committed=good;fail_read=true;assert(!load_broadcast_config(&restored));fail_read=false;
 fail_open=true;assert(!load_broadcast_config(&restored)&&!save_broadcast_config(c));fail_open=false;
 fail_write=true;assert(!save_broadcast_config(c)&&committed==good);fail_write=false;
 fail_commit=true;assert(!save_broadcast_config(c)&&committed==good);fail_commit=false;
 c.ssid=16;assert(!save_broadcast_config(c)&&committed==good);c.ssid=15;
 c.antenna_height=1000;assert(!save_broadcast_config(c));c.antenna_height=0;
 strcpy(c.frequency,"438.12345");assert(!broadcast_config_valid(c));strcpy(c.frequency,"1300.0000");assert(broadcast_config_valid(c));
 strcpy(c.frequency,"438.5\r\n");assert(!broadcast_config_valid(c));c.frequency[0]=0;
 strcpy(c.antenna,"bad,token");assert(!save_broadcast_config(c));c.antenna[0]=0;
 memset(c.grid,'X',sizeof(c.grid));assert(!save_broadcast_config(c));c={};assert(save_broadcast_config(c)&&load_broadcast_config(&restored)&&!restored.enabled);
 std::string login,call;assert(aprs_login("BI4TES",c,&login,&call)&&login.find("pass -1")!=std::string::npos);
 c.enabled=true;strcpy(c.grid,"PM06");assert(aprs_login("BI4TES",c,&login,&call)&&call=="BI4TES-15");
 assert(!aprs_login("BG0TEST",c,&login,&call));assert(!aprs_login("BI4TES/P",c,&login,&call));
 assert(!load_broadcast_config(nullptr));
 puts("FMO APRS config: default receive-only, opt-in roundtrip, corrupt/truncated/reserved/invalid fields, NVS read/write/commit faults and identity bounds PASS");
}
'''
with tempfile.TemporaryDirectory(prefix='fmo-aprs-store-') as d:
 p=Path(d);(p/'nvs.h').write_text(header);(p/'test.cc').write_text(source)
 subprocess.run(['c++','-std=c++17','-Wall','-Wextra','-Werror','-Wno-misleading-indentation','-fsanitize=address,undefined','-g','-Imain','-I'+d,str(p/'test.cc'),'main/apps/fmo/fmo_aprs.cc','main/apps/fmo/fmo_aprs_store.cc','main/apps/fmo/fmo_wire.cc','-o',str(p/'test')],cwd=root,check=True)
 subprocess.run([str(p/'test')],cwd=root,check=True)
