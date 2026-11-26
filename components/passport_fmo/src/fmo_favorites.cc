#include "fmo_favorites.h"
#include "fmo_wire.h"
#include "nvs.h"
#include <array>
#include <mutex>
namespace fmo {
namespace {
std::mutex favorites_mutex;
constexpr size_t slot_size=52,max_size=12+slot_size*Favorites::capacity;
uint32_t get(const uint8_t *p){return uint32_t(p[0])|uint32_t(p[1])<<8|uint32_t(p[2])<<16|uint32_t(p[3])<<24;}
void put(uint8_t *p,uint32_t n){for(unsigned i=0;i<4;++i)p[i]=n>>(8*i);}
bool valid(const Favorites &list){
    if(list.count>Favorites::capacity)return false;
    for(unsigned i=0;i<list.count;++i){
        const auto &f=list.entries[i];const size_t n=strnlen(f.callsign,sizeof(f.callsign));
        if(!f.uid||!n||n>=sizeof(f.callsign))return false;
        unsigned nonzero=0;for(auto byte:f.fingerprint)nonzero|=byte;if(!nonzero)return false;
        for(size_t j=0;j<n;++j){const char c=f.callsign[j];if(!((c>='A'&&c<='Z')||(c>='0'&&c<='9')||c=='/'||c=='-'))return false;}
        for(unsigned j=0;j<i;++j)if(list.entries[j].uid==f.uid&&!std::memcmp(list.entries[j].fingerprint,f.fingerprint,32))return false;
    }
    return true;
}
}
FavoritesLoad load_favorites(Favorites *out){
    if(!out)return FavoritesLoad::Unavailable;
    std::lock_guard<std::mutex> guard(favorites_mutex);nvs_handle_t h;
    auto e=nvs_open("fmo_os",NVS_READONLY,&h);
    if(e==ESP_ERR_NVS_NOT_FOUND){*out=Favorites{};return FavoritesLoad::Missing;}
    if(e!=ESP_OK)return FavoritesLoad::Unavailable;
    std::array<uint8_t,max_size> bytes{};size_t n=bytes.size();e=nvs_get_blob(h,"favorites_v1",bytes.data(),&n);nvs_close(h);
    if(e==ESP_ERR_NVS_NOT_FOUND){*out=Favorites{};return FavoritesLoad::Missing;}
    if(e!=ESP_OK||n<12||std::memcmp(bytes.data(),"FFV1",4)||bytes[4]>Favorites::capacity||bytes[5]||bytes[6]||bytes[7]||n!=12+slot_size*bytes[4]||get(bytes.data()+n-4)!=crc32(bytes.data(),n-4))return FavoritesLoad::Unavailable;
    Favorites candidate;candidate.count=bytes[4];
    for(unsigned i=0;i<candidate.count;++i){const auto *p=bytes.data()+8+slot_size*i;auto &f=candidate.entries[i];f.uid=get(p);std::memcpy(f.fingerprint,p+4,32);std::memcpy(f.callsign,p+36,13);if(p[49]||p[50]||p[51])return FavoritesLoad::Unavailable;}
    if(!valid(candidate))return FavoritesLoad::Unavailable;
    *out=candidate;return FavoritesLoad::Ready;
}
bool save_favorites(const Favorites &list){
    if(!valid(list))return false;
    std::lock_guard<std::mutex> guard(favorites_mutex);std::array<uint8_t,max_size> bytes{};
    std::memcpy(bytes.data(),"FFV1",4);bytes[4]=list.count;const size_t n=12+slot_size*list.count;
    for(unsigned i=0;i<list.count;++i){auto *p=bytes.data()+8+slot_size*i;const auto &f=list.entries[i];put(p,f.uid);std::memcpy(p+4,f.fingerprint,32);std::strcpy(reinterpret_cast<char *>(p+36),f.callsign);}
    put(bytes.data()+n-4,crc32(bytes.data(),n-4));nvs_handle_t h;
    if(nvs_open("fmo_os",NVS_READWRITE,&h)!=ESP_OK)return false;
    const auto e=nvs_set_blob(h,"favorites_v1",bytes.data(),n);const bool ok=e==ESP_OK&&nvs_commit(h)==ESP_OK;nvs_close(h);return ok;
}
bool remember_connected_relay(Favorites *favorites,const Relay &relay,uint32_t signed_until,uint32_t now){
    if(!favorites||signed_until<=now)return false;
    Favorites updated=*favorites;
    if(!updated.add(relay)||!save_favorites(updated))return false;
    *favorites=updated;
    return true;
}
}
