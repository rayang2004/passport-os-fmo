#pragma once
#include "fmo_relay_list.h"
#include <cstring>
namespace fmo {
struct Favorite {
    uint32_t uid=0;
    uint8_t fingerprint[32]{};
    char callsign[13]{};
};
struct Favorites {
    static constexpr unsigned capacity=8;
    Favorite entries[capacity]{};
    unsigned count=0;
    int find(const Relay &relay)const{
        for(unsigned i=0;i<count;++i)if(entries[i].uid==relay.uid&&!std::memcmp(entries[i].fingerprint,relay.fingerprint,32))return i;
        return -1;
    }
    int resolve(unsigned which,const RelayList &list,uint32_t now)const{
        if(which>=count)return -1;
        const int i=list.find(entries[which].uid);
        if(i<0||!list.expires[i]||list.expires[i]<=now||std::memcmp(entries[which].fingerprint,list.relays[i].fingerprint,32)||std::strcmp(entries[which].callsign,list.relays[i].callsign))return -1;
        return i;
    }
    bool add(const Relay &relay){
        if(count>=capacity||find(relay)>=0||!relay.uid||strnlen(relay.callsign,13)==13||!relay.callsign[0])return false;
        auto &entry=entries[count++];entry.uid=relay.uid;std::memcpy(entry.fingerprint,relay.fingerprint,32);std::strcpy(entry.callsign,relay.callsign);return true;
    }
    bool erase(unsigned which){
        if(which>=count)return false;
        for(unsigned i=which+1;i<count;++i)entries[i-1]=entries[i];
        entries[--count]=Favorite{};return true;
    }
};
static_assert(sizeof(Favorites)<=512);
enum class FavoritesLoad { Missing, Ready, Unavailable };
FavoritesLoad load_favorites(Favorites *out);
bool save_favorites(const Favorites &favorites);
bool remember_connected_relay(Favorites *favorites,const Relay &relay,uint32_t signed_until,uint32_t now);
}
