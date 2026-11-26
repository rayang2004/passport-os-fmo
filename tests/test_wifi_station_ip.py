"""Exercise live AP+STA readiness and the production FMO certificate guard."""
from pathlib import Path
import subprocess,tempfile
root=Path(__file__).resolve().parents[1]
w=(root/'components/esp-wifi-connect/wifi_manager.cc').read_text()
method=w[w.index('bool WifiManager::HasStationIp() const'):w.index('std::string WifiManager::GetSsid() const')]
f=(root/'main/apps/fmo/fmo_http.cc').read_text();a=f.index('esp_err_t fmo_http_ca(httpd_req_t *r){');guard=f[a:f.index('    std::string pub,error;',a)]+'    return 123;\n}\n'
prelude=r'''
#include <cassert>
#include <mutex>
#include <string>
#include <cstdint>
#include <cstring>
constexpr int ESP_OK=0;
struct wifi_ap_record_t {};
struct esp_netif_t {};
struct esp_netif_ip_info_t {struct {uint32_t addr;} ip;};
static bool associated=true,netif_present=true,up=true,ip_read_ok=true;
static uint32_t ip=0xc0a80102;
static esp_netif_t netif;
int esp_wifi_sta_get_ap_info(wifi_ap_record_t*){return associated?0:-1;}
esp_netif_t *esp_netif_get_handle_from_ifkey(const char *key){assert(!strcmp(key,"WIFI_STA_DEF"));return netif_present?&netif:nullptr;}
bool esp_netif_is_netif_up(esp_netif_t*){return up;}
int esp_netif_get_ip_info(esp_netif_t*,esp_netif_ip_info_t *out){out->ip.addr=ip;return ip_read_ok?0:-1;}
struct WifiManager {
 mutable std::mutex mutex_;bool initialized_=true,station_active_=false,config_mode_active_=true;
 bool HasStationIp() const;
 bool IsConnected() const{return station_active_;} // normal station is intentionally stopped in config mode
 static WifiManager &GetInstance(){static WifiManager wifi;return wifi;}
};
using esp_err_t=int;constexpr int HTTP_POST=1;struct httpd_req_t {int method=0,content_len=0;};struct Busy {};
int64_t esp_timer_get_time(){return 0;}
const char *ensure_ca_clock(){return nullptr;}
static std::string failure,failure_code;
int ca_fail(httpd_req_t*,const char *text,const char *code=nullptr){failure=text;failure_code=code?code:"";return -1;}
'''
main=r'''
int main(){
 auto &w=WifiManager::GetInstance();httpd_req_t r;
 assert(!w.IsConnected()&&w.HasStationIp());assert(fmo_http_ca(&r)==123); // actual regression: config AP owns connected STA
 associated=false;assert(!w.HasStationIp()&&fmo_http_ca(&r)==-1&&failure_code=="wifi_required"); // phone on AP / stale UI success is not an uplink
 associated=true;ip=0;assert(!w.HasStationIp()&&fmo_http_ca(&r)==-1); // associated, DHCP pending
 ip=0xc0a80102;up=false;assert(!w.HasStationIp());up=true;
 netif_present=false;assert(!w.HasStationIp());netif_present=true;
 ip_read_ok=false;assert(!w.HasStationIp());ip_read_ok=true;
 w.config_mode_active_=false;assert(!w.HasStationIp());w.station_active_=true;assert(w.HasStationIp()&&fmo_http_ca(&r)==123);
 w.initialized_=false;assert(!w.HasStationIp());w.initialized_=true;
 associated=false;assert(fmo_http_ca(&r)==-1);associated=true;assert(fmo_http_ca(&r)==123); // reconnect observed live
}
'''
with tempfile.TemporaryDirectory(prefix='passport-sta-ip-') as d:
 p=Path(d);(p/'test.cc').write_text(prelude+method+guard+main)
 subprocess.run(['c++','-std=c++17','-Wall','-Wextra','-Werror','-Wno-unused-variable','-fsanitize=address,undefined',str(p/'test.cc'),'-o',str(p/'test')],cwd=root,check=True)
 subprocess.run([str(p/'test')],check=True)
print('STA IP / FMO gate: AP+STA success, no uplink, DHCP pending, disconnect/stale status, missing/down interface, read failure and reconnect PASS')
