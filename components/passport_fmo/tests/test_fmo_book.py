"""Exercise the production contact model and NVS codec with fault injection."""
from pathlib import Path
import subprocess,tempfile
root=Path(__file__).resolve().parents[3]
header=r'''
#pragma once
#include <cstddef>
using nvs_handle_t=int;
constexpr int ESP_OK=0,ESP_ERR_NVS_NOT_FOUND=1,NVS_READONLY=0,NVS_READWRITE=1;
int nvs_open(const char*,int,nvs_handle_t*);
int nvs_get_blob(nvs_handle_t,const char*,void*,size_t*);
int nvs_set_blob(nvs_handle_t,const char*,const void*,size_t);
int nvs_commit(nvs_handle_t);
void nvs_close(nvs_handle_t);
'''
source=r'''
#include "fmo_book.h"
#include "fmo_stamp.h"
#include "fmo_wire.h"
#include "nvs.h"
#include <cassert>
#include <vector>
#include <cstring>
#include <cstdio>
#include <memory>
#include <new>
#include <string>
#include "cJSON.h"
namespace fmo {
static PeerStamps stored_styles;
static bool fail_styles=false;
const char *PeerStamps::find(const char *call) const {
 for(unsigned i=0;i<count;++i)if(!strcmp(entries[i].callsign,call))return entries[i].style_id;
 return nullptr;
}
bool PeerStamps::remember(const char *call,const char *style){
 if(count>=capacity||find(call)||!stamp_style_valid(style))return false;
 strcpy(entries[count].callsign,call);strcpy(entries[count++].style_id,style);return true;
}
bool stamp_style_valid(const char *style){return style&&(!strcmp(style,"G001")||!strcmp(style,"G002"));}
StampLoad load_peer_stamps(PeerStamps *out){*out=stored_styles;return out->count?StampLoad::Ready:StampLoad::Missing;}
bool save_peer_stamps(const PeerStamps &in){if(fail_styles)return false;stored_styles=in;return true;}
unsigned stamp_fallback_index(const char *s) { return s && *s ? unsigned(s[0]) % kBuiltinStampCount : 0; }
const char *stamp_builtin_id(unsigned i) { static const char *ids[]={"G001","G002","G003","G004","G005","G006","G007","G008","G009","G010","G011","G012"}; return ids[i%12]; }
}
using esp_err_t=int;struct httpd_req_t {};
using Json=std::unique_ptr<cJSON,decltype(&cJSON_Delete)>;
std::string response;
int send(httpd_req_t *,cJSON *j){char *p=cJSON_PrintUnformatted(j);assert(p);response=p;cJSON_free(p);return 0;}
int fail(httpd_req_t *,const char *){return -1;}
const char *field(const cJSON *j,const char *key){const auto *s=cJSON_GetObjectItemCaseSensitive(j,key);return cJSON_IsString(s)?s->valuestring:nullptr;}
HTTP_CONTACT_STATUS
std::vector<uint8_t> committed,pending;bool fail_open=false,fail_read=false,fail_write=false,fail_commit=false;
int nvs_open(const char *ns,int,int *h){assert(!strcmp(ns,"fmo_os"));*h=1;return fail_open?-1:0;}
int nvs_get_blob(int,const char *key,void *out,size_t *n){assert(!strcmp(key,"heard_v1"));if(fail_read)return -1;if(committed.empty())return ESP_ERR_NVS_NOT_FOUND;if(!out){*n=committed.size();return 0;}if(*n<committed.size())return -1;*n=committed.size();memcpy(out,committed.data(),*n);return 0;}
int nvs_set_blob(int,const char*,const void *p,size_t n){if(fail_write)return -1;auto *b=static_cast<const uint8_t*>(p);pending.assign(b,b+n);return 0;}
int nvs_commit(int){if(fail_commit)return -1;committed=pending;return 0;}void nvs_close(int){}
using namespace fmo;
int main(){
 ContactBook book;assert(load_contact_book(&book)==BookLoad::Missing&&book.count==0);
 constexpr uint32_t now=1800000000;
 assert(!book.heard(0,"BG0TEST",1,100,now));assert(!book.heard(1,"bad<script>",1,100,now));assert(!book.heard(1,"BG0TEST",0,100,now));assert(!book.heard(1,"BG0TEST",1,100,0));
 assert(book.heard(1,"BG0TEST",9,100,now));
 for(unsigned n=0;n<1000;++n)assert(!book.heard(1,"BG0TEST",9,100,now+1));
 assert(!book.heard(1,"BG0TEST",9,99,now+2));assert(book.contacts[0].receptions==1);
 assert(book.heard(1,"BG0TEST",10,200,now+10));assert(book.contacts[0].receptions==2&&book.contacts[0].first_seen==now&&book.contacts[0].relay_uid==10);
 assert(!book.heard(1,"BG0TEST",10,300,now)); // Clock must not move history backwards.
 assert(save_contact_book(book));const auto good=committed;
 // Wire format is stable across target struct padding and host ABI.
 assert(good.size()==52&&good[0]=='F'&&good[1]=='M'&&good[2]=='B'&&good[3]=='1');
 assert(good[4]==1&&good[12]==1&&good[16]==10&&!memcmp(good.data()+36,"BG0TEST",7));
 ContactBook restored;assert(load_contact_book(&restored)==BookLoad::Ready&&restored.count==1&&restored.contacts[0].receptions==2);
 assert(!restored.heard(1,"BG0TEST",9,200,now+20)); // Reboot does not count the same stream twice.
 for(size_t i=0;i<good.size();++i){committed=good;committed[i]^=0x80;ContactBook sentinel;sentinel.count=17;
  assert(load_contact_book(&sentinel)==BookLoad::Unavailable&&sentinel.count==17);
 }
 for(size_t n=1;n<good.size();++n){committed.assign(good.begin(),good.begin()+n);assert(load_contact_book(&restored)==BookLoad::Unavailable);}
 // Valid CRC is insufficient: malformed contact fields must still be rejected.
 for(unsigned offset:{12u,36u,48u}){committed=good;committed[offset]=offset==36?'!':0;
  if(offset==48)committed[48]='X';
  const auto checksum=crc32(committed.data()+12,committed.size()-12);for(unsigned b=0;b<4;++b)committed[8+b]=checksum>>(8*b);
  assert(load_contact_book(&restored)==BookLoad::Unavailable);
 }
 committed=good;
 fail_open=true;assert(load_contact_book(&restored)==BookLoad::Unavailable&&!save_contact_book(book));fail_open=false;
 fail_read=true;assert(load_contact_book(&restored)==BookLoad::Unavailable);fail_read=false;
 fail_write=true;assert(!save_contact_book(book)&&committed==good);fail_write=false;
 fail_commit=true;assert(!save_contact_book(book)&&committed==good);fail_commit=false;
 assert(book.heard(2,"BG0WRAP",9,0xfffffff0u,now));assert(book.heard(2,"BG0WRAP",9,0x10,now+1));
 assert(!book.heard(2,"BG0WRAP",9,0xfffffff0u,now+2));
 assert(book.heard(2,"BG0WRAP",9,0xf0000000u,now+25u*86400));
 for(unsigned uid=3;uid<=64;++uid){char call[13];snprintf(call,sizeof(call),"BG0T%u",uid);assert(book.heard(uid,call,9,100,now));}
 assert(book.count==64);assert(!book.heard(65,"BG0NEW",9,100,now));assert(book.count==64&&book.contacts[0].first_seen==now);
 assert(book.heard(1,"BG0TEST",9,300,now+30));assert(book.contacts[0].receptions==3);
 book.contacts[0].receptions=0xffffffffu;assert(book.heard(1,"BG0TEST",9,400,now+40)&&book.contacts[0].receptions==0xffffffffu);
 assert(save_contact_book(book)&&load_contact_book(&restored)==BookLoad::Ready&&restored.count==64);
 for(unsigned page=0;page<8;++page){assert(contact_status(nullptr,page)==0);Json j(cJSON_Parse(response.c_str()),cJSON_Delete);
  assert(cJSON_IsTrue(cJSON_GetObjectItemCaseSensitive(j.get(),"contacts_available")));
  assert(cJSON_GetObjectItemCaseSensitive(j.get(),"total")->valueint==64);
  const auto *entries=cJSON_GetObjectItemCaseSensitive(j.get(),"contacts");assert(cJSON_GetArraySize(entries)==8);
  const auto *first=cJSON_GetArrayItem(entries,0);assert(cJSON_GetObjectItemCaseSensitive(first,"uid")->valueint==int(book.contacts[page*8].uid));
  assert(!cJSON_GetObjectItemCaseSensitive(first,"last_stream")&&!cJSON_GetObjectItemCaseSensitive(first,"seed"));
 }
 fail_read=true;contact_status(nullptr,0);fail_read=false;{Json j(cJSON_Parse(response.c_str()),cJSON_Delete);assert(cJSON_IsFalse(cJSON_GetObjectItemCaseSensitive(j.get(),"contacts_available"))&&cJSON_GetArraySize(cJSON_GetObjectItemCaseSensitive(j.get(),"contacts"))==0);}
 auto snapshot=committed;book.contacts[1]=book.contacts[0];assert(!save_contact_book(book)&&committed==snapshot);
 committed.clear();
 Json backup(cJSON_Parse(R"({"v":1,"contacts":[{"uid":65,"relay_uid":9,"callsign":"BG0NEW","first_seen":1800000000,"last_seen":1800000001,"receptions":2}]})"),cJSON_Delete);
 assert(restore_contacts(nullptr,backup.get())==0&&load_contact_book(&restored)==BookLoad::Ready&&restored.count==1&&restored.contacts[0].receptions==2);
 snapshot=committed;
 auto *first_restore=cJSON_GetArrayItem(cJSON_GetObjectItem(backup.get(),"contacts"),0);
 cJSON_AddStringToObject(first_restore,"stamp_style","G001");
 fmo::fail_styles=true;
 assert(restore_contacts(nullptr,backup.get())==0&&committed==snapshot&&!fmo::stored_styles.count);
 assert(response.find("\"styles_saved\":false")!=std::string::npos);
 fmo::fail_styles=false;
 assert(restore_contacts(nullptr,backup.get())==0&&committed==snapshot);
 assert(fmo::stored_styles.count==1&&!strcmp(fmo::stored_styles.find("BG0NEW"),"G001"));
 cJSON_ReplaceItemInObject(first_restore,"stamp_style",cJSON_CreateString("G002"));
 assert(restore_contacts(nullptr,backup.get())==0&&!strcmp(fmo::stored_styles.find("BG0NEW"),"G001"));

 auto *entries=cJSON_GetObjectItem(backup.get(),"contacts");
 auto *second=cJSON_Duplicate(cJSON_GetArrayItem(entries,0),1);
 cJSON_ReplaceItemInObject(second,"uid",cJSON_CreateNumber(66));
 cJSON_AddItemToArray(entries,second);
 fail_write=true;assert(restore_contacts(nullptr,backup.get())==-1&&committed==snapshot);fail_write=false;
 cJSON_ReplaceItemInObject(second,"last_seen",cJSON_CreateNumber(0));
 assert(restore_contacts(nullptr,backup.get())==-1&&committed==snapshot);
 assert(load_contact_book(nullptr)==BookLoad::Unavailable);
 puts("FMO heard book: distinct-stream/replay/wrap/reboot, immutable first encounter, capacity preservation, stable codec, corruption and NVS failure safety PASS");
}
'''
http=(root/'components/passport_fmo/src/fmo_http.cc').read_text()
def extract(signature):
 start=http.index(signature);opening=http.index('{',start);depth=1;end=opening+1
 while depth:
  if http[end]=='{':depth+=1
  elif http[end]=='}':depth-=1
  end+=1
 return http[start:end]
source=source.replace('HTTP_CONTACT_STATUS','\n'.join(extract(s) for s in ('esp_err_t contact_status(', 'esp_err_t restore_contacts(')))
with tempfile.TemporaryDirectory(prefix='fmo-book-') as d:
 p=Path(d);(p/'nvs.h').write_text(header);(p/'test.cc').write_text(source)
 subprocess.run(['c++','-std=c++17','-Wall','-Wextra','-Werror','-fsanitize=address,undefined','-g','-Imain','-Icomponents/passport_fmo/src','-Itests/vendor/cjson','-I'+d,str(p/'test.cc'),'components/passport_fmo/src/fmo_book.cc','components/passport_fmo/src/fmo_wire.cc','tests/vendor/cjson/cJSON.c','-o',str(p/'test')],cwd=root,check=True)
 subprocess.run([str(p/'test')],cwd=root,check=True)
