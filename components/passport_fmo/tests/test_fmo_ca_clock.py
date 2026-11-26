"""Run the actual CA handler and SNTP lifecycle with bounded network doubles."""
from pathlib import Path
import subprocess,tempfile
root=Path(__file__).resolve().parents[3]
http=(root/'components/passport_fmo/src/fmo_http.cc').read_text()
clock=(root/'main/apps/home/home_clock.c').read_text()
def function(source,signature):
 start=source.index(signature);opening=source.index('{',start);depth=1;end=opening+1
 while depth:
  if source[end]=='{':depth+=1
  elif source[end]=='}':depth-=1
  end+=1
 return source[start:end]
prelude=r'''
#include <algorithm>
#include <atomic>
#include <cassert>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>
#include <sys/time.h>
constexpr int ESP_OK=0,ESP_FAIL=-1,HTTP_GET=0,HTTP_POST=1,HTTP_METHOD_GET=0,HTTP_METHOD_POST=1,SNTP_OPMODE_POLL=1,ESP_SNTP_OPMODE_POLL=1;
#define ESP_LOGI(...) do{}while(0)
#define CLOCK_EPOCH_MIN 1700000000LL
#define pdMS_TO_TICKS(ms) (ms)
std::atomic<bool> busy{false};
BUSY_TYPE
bool station_ip=true,ntp_running=false,has_identity=true;
int starts=0,stops=0,delays=0,sync_after=0,disconnect_after=0,identity_reads=0;
int opens=0,closes=0,writes=0,fetches=0,recv_calls=0,max_write=9999,close_headers=0;
int64_t mono=0,write_delay=0,recv_delay=0;time_t wall=1800000000;
bool fail_recv=false,fail_write=false,fail_open=false;
std::string failure,reply,request_url;
void (*clock_callback)(timeval*)=nullptr;
time_t fake_time(time_t*){return wall;}
int64_t esp_timer_get_time(){return mono;}
bool esp_sntp_enabled(){return ntp_running;}
void esp_sntp_setoperatingmode(int mode){assert(mode==SNTP_OPMODE_POLL);}
void esp_sntp_setservername(int n,const char *name){assert(!n&&!strcmp(name,"ntp.aliyun.com"));}
void esp_sntp_set_time_sync_notification_cb(void (*cb)(timeval*)){clock_callback=cb;}
void esp_sntp_init(){assert(!ntp_running);ntp_running=true;++starts;}
void esp_sntp_stop(){assert(busy);ntp_running=false;++stops;}
void time_sync_set_epoch(int64_t epoch){wall=epoch;}
void vTaskDelay(unsigned ms){assert(busy&&ms==100);mono+=ms*1000;++delays;
 if(disconnect_after&&delays>=disconnect_after)station_ip=false;
 if(sync_after&&delays>=sync_after&&ntp_running&&clock_callback){timeval tv{1800000000,0};clock_callback(&tv);}
}
struct WifiManager {static WifiManager &GetInstance(){static WifiManager w;return w;}bool HasStationIp(){return station_ip;}};
using esp_err_t=int;
struct httpd_req_t {int method=HTTP_GET,content_len=0;std::string body;size_t at=0;};
struct Client {std::string sent,response="{\"state\":\"none\"}";size_t at=0;} client;
using esp_http_client_handle_t=Client*;
void esp_crt_bundle_attach(){}
struct esp_http_client_config_t {const char *url=nullptr;int method=0;void (*crt_bundle_attach)()=nullptr;int timeout_ms=0,buffer_size=0,buffer_size_tx=0;bool disable_auto_redirect=false;};
int fail(httpd_req_t*,const char *text,const char * =nullptr){failure=text;return ESP_OK;}
Client *esp_http_client_init(const esp_http_client_config_t *c){assert(wall>1700000000&&c->crt_bundle_attach==esp_crt_bundle_attach&&c->disable_auto_redirect&&c->timeout_ms==12000);request_url=c->url;return &client;}
int esp_http_client_cleanup(Client*){++closes;return 0;}
int esp_http_client_set_header(Client*,const char *key,const char *value){assert(!strcmp(key,"Content-Type")&&!strcmp(value,"application/json"));return 0;}
int esp_http_client_open(Client*,int){assert(wall>1700000000);++opens;return fail_open?-1:0;}
int httpd_req_recv(httpd_req_t *r,char *out,size_t n){++recv_calls;mono+=recv_delay;if(fail_recv)return -1;n=std::min(n,r->body.size()-r->at);memcpy(out,r->body.data()+r->at,n);r->at+=n;return n;}
int esp_http_client_write(Client*,const char *data,int n){++writes;mono+=write_delay;if(fail_write)return -1;n=std::min(n,max_write);client.sent.append(data,n);return n;}
int esp_http_client_fetch_headers(Client*){++fetches;return client.response.size();}
int esp_http_client_read(Client*,char *out,size_t n){n=std::min(n,client.response.size()-client.at);memcpy(out,client.response.data()+client.at,n);client.at+=n;return n;}
bool esp_http_client_is_complete_data_received(Client*){return true;}
int esp_http_client_get_status_code(Client*){return 200;}
int httpd_resp_set_type(httpd_req_t*,const char *type){assert(!strcmp(type,"application/json"));return 0;}
int httpd_resp_set_hdr(httpd_req_t*,const char *key,const char *value){if(!strcmp(key,"Connection")){assert(!strcmp(value,"close"));++close_headers;}else assert(!strcmp(key,"Cache-Control")&&!strcmp(value,"no-store"));return 0;}
int httpd_resp_send(httpd_req_t*,const char *data,size_t n){reply.assign(data,n);return 0;}
namespace fmo {
struct Credential {uint32_t uid=0;uint8_t fingerprint[32]{};};
bool public_identity(std::string *pub,Credential *c,std::string*){assert(wall>1700000000);++identity_reads;*pub=has_identity?"public-key":"";c->uid=has_identity?123:0;return has_identity;}
std::string base64url(const uint8_t*,size_t){return "fingerprint";}
}
void reset(){station_ip=true;ntp_running=false;has_identity=true;starts=stops=delays=sync_after=disconnect_after=identity_reads=opens=closes=writes=fetches=recv_calls=0;max_write=9999;close_headers=0;mono=write_delay=recv_delay=0;wall=1800000000;fail_recv=fail_write=fail_open=false;failure.clear();reply.clear();request_url.clear();client=Client{};clock_callback=nullptr;busy=false;}
'''
busy_type=function(http,'struct Busy ')
prelude=prelude.replace('BUSY_TYPE',busy_type+';')
clock_code='\n#define time fake_time\n'+'\n'.join(function(clock,s) for s in ['static void on_time_sync(', 'void home_clock_start(', 'bool home_clock_running(', 'void home_clock_stop(', 'bool home_clock_valid('])+'\n#undef time\n'
body='#include "fmo_host_bridge.h"\n'+'\n'.join(function(http,s) for s in ['esp_err_t ca_fail(', 'const char *ensure_ca_clock(', 'const char *forward_photo(', 'esp_err_t fmo_http_ca('])
main=r'''
int main(){
 httpd_req_t get;
 reset();assert(fmo_http_ca(&get)==0&&!busy&&starts==0&&stops==0&&identity_reads==1&&opens==1&&closes==1&&request_url.find("&fp=fingerprint")!=std::string::npos);
 reset();wall=0;sync_after=3;assert(fmo_http_ca(&get)==0&&!busy&&starts==1&&stops==1&&!ntp_running&&delays==3&&mono==300000&&identity_reads==1&&opens==1);
 reset();wall=0;ntp_running=true;clock_callback=on_time_sync;sync_after=2;assert(fmo_http_ca(&get)==0&&!busy&&starts==0&&stops==0&&ntp_running); // Preserve another owner's SNTP.
 reset();wall=0;assert(fmo_http_ca(&get)==-1&&!busy&&starts==1&&stops==1&&opens==0&&identity_reads==0&&delays==100&&mono==10000000&&failure.find("校准")!=std::string::npos);
 reset();wall=0;ntp_running=true;clock_callback=on_time_sync;assert(fmo_http_ca(&get)==-1&&!busy&&starts==0&&stops==0&&ntp_running);
 reset();wall=0;disconnect_after=2;assert(fmo_http_ca(&get)==-1&&!busy&&stops==1&&opens==0&&delays==2&&failure.find("断开")!=std::string::npos);
 reset();station_ip=false;wall=0;assert(fmo_http_ca(&get)==-1&&!busy&&!starts&&!opens&&!identity_reads);
 reset();has_identity=false;assert(fmo_http_ca(&get)==-1&&!busy&&!opens&&!starts);
 reset();fail_open=true;assert(fmo_http_ca(&get)==-1&&!busy&&opens==1&&closes==1&&!writes);
 httpd_req_t post;post.method=HTTP_POST;post.body.assign(1301,'p');post.content_len=post.body.size();
 reset();max_write=7;assert(fmo_http_ca(&post)==0&&!busy&&client.sent==post.body&&recv_calls==3&&writes>3&&fetches==1&&closes==1);
 reset();post.at=0;max_write=1;write_delay=12000000;assert(fmo_http_ca(&post)==-1&&!busy&&writes==6&&mono<90000000&&fetches==0&&closes==1&&failure.find("超时")!=std::string::npos); // Old once-per-chunk deadline stalls >100 minutes.
 reset();post.at=0;fail_recv=true;assert(fmo_http_ca(&post)==-1&&!busy&&!writes&&closes==1);
 reset();post.at=0;fail_write=true;assert(fmo_http_ca(&post)==-1&&!busy&&writes==1&&closes==1);
 reset();post.at=0;wall=0;assert(fmo_http_ca(&post)==-1&&!busy&&!recv_calls&&!writes&&!opens&&close_headers==1); // Do not forward a photo before calibration.
 reset();post.at=0;post.content_len=196609;wall=0;assert(fmo_http_ca(&post)==-1&&!busy&&!starts&&!opens&&close_headers==1); // Reject size before clock/network work without SDK body purge.
 reset();post.at=0;post.content_len=post.body.size();recv_delay=101;assert(forward_photo(&post,&client,100)!=nullptr&&!writes);
 puts("FMO CA: actual handler/SNTP ownership, AP+STA clock bootstrap, timeout/disconnect, TLS verification retained, photo preconditions, exact partial writes and whole-request deadline PASS");
}
'''
with tempfile.TemporaryDirectory(prefix='fmo-ca-clock-') as d:
 p=Path(d);(p/'test.cc').write_text(prelude+clock_code+body+main)
 subprocess.run(['c++','-std=c++17','-Wall','-Wextra','-Werror','-Wno-misleading-indentation','-fsanitize=address,undefined','-g','-Icomponents/passport_fmo/src',str(p/'test.cc'),'-o',str(p/'test')],cwd=root,check=True)
 subprocess.run([str(p/'test')],cwd=root,check=True)

# Exercise the actual bounded CRL transport independently of CA/photo mocks.
download_prelude=prelude.replace('c->timeout_ms==12000','c->timeout_ms==5000')
download_prelude=download_prelude.replace('bool fail_recv=false', 'int response_code=200,declared=-2,read_limit=512;bool complete=true,bad_read=false,fail_init=false;int64_t read_pause=0;\nbool fail_recv=false')
download_prelude=download_prelude.replace('request_url=c->url;return &client;', 'request_url=c->url;return fail_init?nullptr:&client;')
download_prelude=download_prelude.replace('return client.response.size();','return declared>=-1?declared:int(client.response.size());')
download_prelude=download_prelude.replace('n=std::min(n,client.response.size()-client.at);memcpy(out,client.response.data()+client.at,n);','mono+=read_pause;if(bad_read)return -1;n=std::min({n,client.response.size()-client.at,size_t(read_limit)});memcpy(out,client.response.data()+client.at,n);')
download_prelude=download_prelude.replace('is_complete_data_received(Client*){return true;}','is_complete_data_received(Client*){return complete;}').replace('get_status_code(Client*){return 200;}','get_status_code(Client*){return response_code;}')
download_main=r'''
int main(){
 std::vector<uint8_t> buffer(32769);size_t used=0;const char *url="https://fmo.simy.live/ca/crl/test.json";
 reset();client.response.assign(20397,'a');assert(!download_crl(url,buffer.data(),buffer.size(),&used)&&used==20397&&closes==1&&writes==0);
 reset();declared=0;read_limit=7;client.response.assign(32768,'b');assert(!download_crl(url,buffer.data(),buffer.size(),&used)&&used==32768&&closes==1);
 reset();declared=0;client.response.assign(32769,'c');assert(download_crl(url,buffer.data(),buffer.size(),&used)&&used==32769&&closes==1);
 reset();declared=40000;assert(download_crl(url,buffer.data(),buffer.size(),&used)&&used==0&&closes==1);
 reset();declared=-1;assert(download_crl(url,buffer.data(),buffer.size(),&used)&&used==0&&closes==1);
 reset();declared=-2;response_code=302;assert(download_crl(url,buffer.data(),buffer.size(),&used)&&used==0&&closes==1);
 reset();response_code=200;complete=false;assert(download_crl(url,buffer.data(),buffer.size(),&used)&&closes==1);
 reset();complete=true;bad_read=true;assert(download_crl(url,buffer.data(),buffer.size(),&used)&&closes==1);
 reset();bad_read=false;fail_open=true;assert(download_crl(url,buffer.data(),buffer.size(),&used)&&closes==1);
 reset();fail_init=true;assert(download_crl(url,buffer.data(),buffer.size(),&used)&&closes==0);
 reset();fail_init=false;station_ip=false;assert(download_crl(url,buffer.data(),buffer.size(),&used)&&used==0&&closes==1);
 reset();read_limit=512;client.response.assign(2000,'d');read_pause=12000000;assert(download_crl(url,buffer.data(),buffer.size(),&used)&&used==1024&&closes==1);
 puts("FMO CRL HTTPS: real helper, verified TLS/no redirects, 20KB/32KB, partial/chunked reads, size/time bounds, disconnect/truncation/status/init/open/read failures and cleanup PASS");
}
'''
with tempfile.TemporaryDirectory(prefix='fmo-crl-download-') as d:
 p=Path(d);(p/'test.cc').write_text(download_prelude+function(http,'const char *download_crl(')+download_main)
 subprocess.run(['c++','-std=c++17','-Wall','-Wextra','-Werror','-Wno-misleading-indentation','-fsanitize=address,undefined','-g','-Icomponents/passport_fmo/src',str(p/'test.cc'),'-o',str(p/'test')],cwd=root,check=True)
 subprocess.run([str(p/'test')],cwd=root,check=True)
