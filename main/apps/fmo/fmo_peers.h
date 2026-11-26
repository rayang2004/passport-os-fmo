#pragma once
#include "fmo_crypto.h"
#include <cstring>
namespace fmo {
// Session-only signed events. This is neither a presence roster nor a QSO log.
struct PeerEvents {
    static constexpr unsigned capacity=8;
    PeerAnnouncement events[capacity]{};
    unsigned count=0;
    bool prune(uint32_t now){
        unsigned kept=0;
        for(unsigned i=0;i<count;++i)if(events[i].valid_until>now)events[kept++]=events[i];
        const bool changed=kept!=count;
        for(unsigned i=kept;i<count;++i)events[i]={};
        count=kept;return changed;
    }
    // Only pass results of peer_announcement. A replay must not reorder or
    // extend an event. A renewed certificate has a separate identity binding.
    bool add(const PeerAnnouncement &event,uint32_t now){
        if(!event.uid||event.valid_until<=now)return false;
        prune(now);
        unsigned slot=count;
        for(unsigned i=0;i<count;++i)if(events[i].uid==event.uid&&events[i].kind==event.kind&&
            !std::strcmp(events[i].callsign,event.callsign)&&!std::memcmp(events[i].fingerprint,event.fingerprint,32)){
            if(event.window<=events[i].window)return false;
            slot=i;break;
        }
        if(slot==count){if(count<capacity)++count;else slot=capacity-1;}
        for(unsigned i=slot;i>0;--i)events[i]=events[i-1];
        events[0]=event;return true;
    }
};
static_assert(sizeof(PeerEvents)<=1536);
}
