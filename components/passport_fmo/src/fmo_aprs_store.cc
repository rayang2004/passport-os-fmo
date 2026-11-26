#include "fmo_aprs.h"
#include "fmo_wire.h"
#include "nvs.h"
#include <array>
#include <cstring>
#include <mutex>
namespace fmo {
namespace {
std::mutex config_mutex;
uint32_t get(const uint8_t *p){return uint32_t(p[0])|uint32_t(p[1])<<8|uint32_t(p[2])<<16|uint32_t(p[3])<<24;}
void put(uint8_t *p,uint32_t n){for(unsigned i=0;i<4;++i)p[i]=n>>(i*8);}
}
bool load_broadcast_config(BroadcastConfig *out){
    if(!out)return false;
    std::lock_guard<std::mutex> guard(config_mutex);nvs_handle_t h;
    auto e=nvs_open("fmo_os",NVS_READONLY,&h);if(e==ESP_ERR_NVS_NOT_FOUND){*out={};return true;}if(e!=ESP_OK)return false;
    std::array<uint8_t,128> bytes{};size_t n=bytes.size();e=nvs_get_blob(h,"aprs_v1",bytes.data(),&n);nvs_close(h);
    if(e==ESP_ERR_NVS_NOT_FOUND){*out={};return true;}
    if(e!=ESP_OK||n!=bytes.size()||get(bytes.data())!=0x31414d46||get(bytes.data()+124)!=crc32(bytes.data(),124)||bytes[4]>1||bytes[6]>1||bytes[7])return false;
    for(unsigned i=87;i<124;++i)if(bytes[i])return false;
    BroadcastConfig c{};c.enabled=bytes[4];c.ssid=bytes[5];c.legacy_beacon=bytes[6];c.antenna_height=get(bytes.data()+8);
    std::memcpy(c.grid,bytes.data()+12,9);std::memcpy(c.frequency,bytes.data()+21,16);std::memcpy(c.rig,bytes.data()+37,25);std::memcpy(c.antenna,bytes.data()+62,25);
    if(!broadcast_config_valid(c))return false;
    *out=c;return true;
}
bool save_broadcast_config(const BroadcastConfig &c){
    if(!broadcast_config_valid(c))return false;
    std::array<uint8_t,128> bytes{};put(bytes.data(),0x31414d46);bytes[4]=c.enabled;bytes[5]=c.ssid;bytes[6]=c.legacy_beacon;put(bytes.data()+8,c.antenna_height);
    std::memcpy(bytes.data()+12,c.grid,std::strlen(c.grid));std::memcpy(bytes.data()+21,c.frequency,std::strlen(c.frequency));std::memcpy(bytes.data()+37,c.rig,std::strlen(c.rig));std::memcpy(bytes.data()+62,c.antenna,std::strlen(c.antenna));put(bytes.data()+124,crc32(bytes.data(),124));
    std::lock_guard<std::mutex> guard(config_mutex);nvs_handle_t h;if(nvs_open("fmo_os",NVS_READWRITE,&h)!=ESP_OK)return false;
    auto e=nvs_set_blob(h,"aprs_v1",bytes.data(),bytes.size());if(e==ESP_OK)e=nvs_commit(h);nvs_close(h);return e==ESP_OK;
}
}
