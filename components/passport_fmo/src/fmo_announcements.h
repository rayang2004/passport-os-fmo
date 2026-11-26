#pragma once
#include "fmo_crypto.h"
#include <algorithm>
#include <cstring>
namespace fmo {
// Two bounded, session-only announcements. Unauthenticated reverse-order
// bodies wait at most 30 seconds and never become visible without a proof.
struct Announcements {
    static constexpr unsigned capacity=2;
    EventProof pending[capacity]{};
    EventBody waiting[capacity]{};
    uint32_t waiting_until[capacity]{};
    EventNotice notices[capacity]{};
    unsigned count=0;
    bool prune(uint32_t now){
        auto current=[&](uint32_t window){return uint64_t(window)+1>=now/600&&window<=uint64_t(now/600)+1;};
        for(unsigned i=0;i<capacity;++i){
            if(pending[i].valid_until<=now||!current(pending[i].window))pending[i]=EventProof{};
            if(waiting_until[i]<=now||uint64_t(now)+30<waiting_until[i]){waiting[i]=EventBody{};waiting_until[i]=0;}
        }
        unsigned kept=0;
        for(unsigned i=0;i<count;++i)if(notices[i].valid_until>now&&current(notices[i].window))notices[kept++]=notices[i];
        const bool changed=kept!=count;
        for(unsigned i=kept;i<count;++i)notices[i]=EventNotice{};
        count=kept;return changed;
    }
private:
    bool publish(const EventNotice &notice){
        unsigned slot=count;
        for(unsigned i=0;i<count;++i)if(same(notices[i].body,notice.body)&&!std::memcmp(notices[i].fingerprint,notice.fingerprint,32)){
            if(notice.window<=notices[i].window)return false;
            slot=i;break;
        }
        if(slot==count){if(count<capacity)++count;else slot=capacity-1;}
        for(unsigned i=slot;i>0;--i)notices[i]=notices[i-1];
        notices[0]=notice;return true;
    }
public:
    // Keep the large matched-notice temporary off the worker/crypto caller's
    // persistent frame. It is only needed after signature verification returns.
    __attribute__((noinline)) bool proof(const EventProof &proof,uint32_t now){
        prune(now);if(!proof.uid||proof.valid_until<=now)return false;
        unsigned slot=capacity;
        for(unsigned i=0;i<capacity;++i)if(same(pending[i],proof)&&!std::memcmp(pending[i].fingerprint,proof.fingerprint,32)){
            if(proof.window<=pending[i].window)return false;
            slot=i;break;
        }
        if(slot==capacity){
            slot=0;
            for(unsigned i=0;i<capacity;++i){if(!pending[i].valid_until){slot=i;break;}if(pending[i].valid_until<pending[slot].valid_until)slot=i;}
        }
        pending[slot]=proof;
        for(unsigned i=0;i<capacity;++i){EventNotice notice;
            if(waiting_until[i]&&event_bind(proof,waiting[i],now,&notice)){
                waiting_until[i]=0;waiting[i]=EventBody{};return publish(notice);
            }
        }
        return false;
    }
    __attribute__((noinline)) bool body(const EventBody &body,uint32_t now){
        prune(now);
        for(unsigned i=0;i<capacity;++i){EventNotice notice;
            if(pending[i].valid_until&&event_bind(pending[i],body,now,&notice))return publish(notice);
        }
        // Replays do not extend the unsigned waiting lifetime.
        for(unsigned i=0;i<capacity;++i)if(waiting_until[i]&&same(waiting[i],body))return false;
        unsigned slot=0;
        for(unsigned i=0;i<capacity;++i){if(!waiting_until[i]){slot=i;break;}if(waiting_until[i]<waiting_until[slot])slot=i;}
        waiting[slot]=body;waiting_until[slot]=std::min<uint64_t>(UINT32_MAX,uint64_t(now)+30);return false;
    }
private:
    template<typename A,typename B> static bool same(const A &a,const B &b){
        return a.uid==b.uid&&a.ssid==b.ssid&&!std::strcmp(a.callsign,b.callsign)&&!std::memcmp(a.digest,b.digest,32);
    }
};
static_assert(sizeof(Announcements)<=3584);
}
