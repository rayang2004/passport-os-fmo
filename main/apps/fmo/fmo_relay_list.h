#pragma once
#include "fmo_crypto.h"
#include <cstdint>
#include <algorithm>
#include <cstring>
namespace fmo {
// Worker-owned browsing model. Only signed, unexpired entries enter the cache.
struct RelayList {
    static constexpr unsigned capacity=8;
    Relay relays[capacity]{};
    uint32_t expires[capacity]{};
    StationStatus status[capacity]{};
    uint32_t count=0,index=0;
    int find(uint32_t uid) const {for(unsigned i=0;i<count;++i)if(relays[i].uid==uid)return i;return -1;}
    // Discovery may refresh an endpoint for the same verified identity.
    // A reused UID or a renewed certificate requires explicit selection.
    int refresh_saved_relay(Relay &saved,uint32_t now) const {
        const int slot=find(saved.uid);
        if(slot<0||expires[slot]<=now)return -1;
        const auto &candidate=relays[slot];
        if(std::strcmp(candidate.callsign,saved.callsign)||
           std::memcmp(candidate.fingerprint,saved.fingerprint,sizeof(saved.fingerprint)))return -1;
        saved=candidate;
        return slot;
    }
    bool prune(uint32_t now){
        const uint32_t selected=index<count?relays[index].uid:0;
        const unsigned before=count;unsigned kept=0;
        for(unsigned i=0;i<before;++i){
            if(expires[i]&&expires[i]<=now)continue;
            if(kept!=i){relays[kept]=relays[i];expires[kept]=expires[i];status[kept]=status[i];}
            ++kept;
        }
        count=kept;
        for(unsigned i=kept;i<before;++i){relays[i]={};expires[i]=0;status[i]={};}
        const int slot=find(selected);
        index=slot>=0?static_cast<unsigned>(slot):count?std::min(index,count-1):0;
        return before!=count;
    }
    bool add(const Relay &relay,uint32_t until,uint32_t now,const StationStatus *snapshot=nullptr){
        if(!relay.uid||(until&&until<=now))return false;
        if(snapshot&&(!until||snapshot->valid_until!=until))return false;
        int slot=find(relay.uid);
        if(slot<0){if(count==capacity)return false;slot=count++;}
        else if(until&&expires[slot]&&until<expires[slot])return false;
        else if(until==expires[slot]&&relay.uid==relays[slot].uid&&relay.port==relays[slot].port&&!std::strcmp(relay.host,relays[slot].host)&&!std::strcmp(relay.callsign,relays[slot].callsign)&&!std::strcmp(relay.name,relays[slot].name)&&!std::memcmp(relay.fingerprint,relays[slot].fingerprint,32)&&(!snapshot||(status[slot].online==snapshot->online&&status[slot].peak==snapshot->peak&&status[slot].range_km==snapshot->range_km&&status[slot].valid_until==snapshot->valid_until)))return false;
        relays[slot]=relay;expires[slot]=until;status[slot]=snapshot?*snapshot:StationStatus{};return true;
    }
    void move(int delta){if(count){const int n=count;index=(static_cast<int>(index)+delta%n+n)%n;}}
};
}
