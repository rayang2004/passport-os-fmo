#pragma once
#include <atomic>
#include <cstdint>
#include <cstring>
#include <mutex>
namespace fmo {
enum class MqttConnection { Connecting, Online, AuthenticationRejected, BrokerRejected, TransportFailed, Disconnected, LocalSetupFailed };
enum class MqttKind { None, Voice, NodeConnections, MuteList };
// One MQTT PUBLISH is fragmented serially by esp-mqtt. Topics on the first
// fragment are authoritative; a new first fragment always abandons old data.
struct MqttInbox {
    char topic[256]{};
    char last_topic[256]{};
    size_t size=0,at=0;
    MqttKind kind=MqttKind::None;
    void reset(){topic[0]=0;size=at=0;kind=MqttKind::None;}
    static MqttKind route(const char *topic,size_t n){
        if(!topic)return MqttKind::None;
        if(n==7&&!std::memcmp(topic,"FMO/RAW",7))return MqttKind::Voice;
        constexpr char mute_prefix[]="FMO/REGU/MUTELIST/";
        constexpr size_t mp=sizeof(mute_prefix)-1;
        if(n>mp&&!std::memcmp(topic,mute_prefix,mp))return MqttKind::MuteList;
        constexpr char prefix[]="$SYS/brokers/",suffix[]="/stats/connections/count";
        constexpr size_t a=sizeof(prefix)-1,b=sizeof(suffix)-1;
        if(n<=a+b||std::memcmp(topic,prefix,a)||std::memcmp(topic+n-b,suffix,b))return MqttKind::None;
        for(size_t i=a;i<n-b;++i){const unsigned char c=topic[i];if(c<=32||c==127||c=='/'||c=='+'||c=='#')return MqttKind::None;}
        return MqttKind::NodeConnections;
    }
    MqttKind feed(const char *name,int name_size,const char *data,int bytes,int offset,int total,uint8_t *buffer,size_t capacity){
        if(name_size<0||bytes<0||offset<0||total<0||static_cast<size_t>(total)>capacity||!buffer||(!data&&bytes)){reset();return MqttKind::None;}
        if(!offset){
            reset();
            if(!name||!name_size||static_cast<size_t>(name_size)>=sizeof(topic)||static_cast<size_t>(total)>capacity)return MqttKind::None;
            kind=route(name,name_size);
            if(kind==MqttKind::None||(total==0&&kind!=MqttKind::MuteList)||(kind==MqttKind::NodeConnections&&total>10)||(kind==MqttKind::MuteList&&total>128)){reset();return MqttKind::None;}
            std::memcpy(topic,name,name_size);topic[name_size]=0;size=total;
        }else if(name_size&&(static_cast<size_t>(name_size)!=std::strlen(topic)||!name||std::memcmp(name,topic,name_size))){reset();return MqttKind::None;}
        if(kind==MqttKind::None||size!=static_cast<size_t>(total)||at!=static_cast<size_t>(offset)||static_cast<size_t>(bytes)>size-at){reset();return MqttKind::None;}
        if(bytes)std::memcpy(buffer+at,data,bytes);
        at+=bytes;
        if(at!=size)return MqttKind::None;
        std::strcpy(last_topic,topic);
        const auto result=kind;reset();return result;
    }
};
// Relay-published regulation mute list (FMO Passport v0.6.14: FMO/REGU/MUTELIST/<CALL>).
// Non-empty retained payload mutes the callsign; empty retained payload unmutes it.
struct MuteList {
    static constexpr unsigned capacity=32;
    mutable std::mutex mu;
    char entries[capacity][13]{};
    unsigned count=0;
    static void normalize(const char *src,size_t len,char out[13]){
        out[0]=0;
        if(!src||!len)return;
        if(len>=5&&(src[0]=='P'||src[0]=='p')&&src[1]=='-'){src+=2;len-=2;}
        size_t n=0;
        for(size_t i=0;i<len&&n<12;++i){
            unsigned char c=static_cast<unsigned char>(src[i]);
            if(c=='-'&&n>=3)break;
            if(c>='a'&&c<='z')c=c-'a'+'A';
            if(!((c>='A'&&c<='Z')||(c>='0'&&c<='9')||c=='/')){out[0]=0;return;}
            out[n++]=static_cast<char>(c);
        }
        if(n<3){out[0]=0;return;}
        out[n]=0;
    }
    void reset(){
        std::lock_guard<std::mutex> lock(mu);
        count=0;
    }
    bool apply_topic(const char *topic,const uint8_t *payload,size_t payload_len){
        constexpr char prefix[]="FMO/REGU/MUTELIST/";
        constexpr size_t p=sizeof(prefix)-1;
        if(!topic||std::strncmp(topic,prefix,p)!=0)return false;
        const char *sub=topic+p;
        const size_t slen=std::strlen(sub);
        if(!slen||std::strchr(sub,'/'))return false;
        char call[13]{};
        normalize(sub,slen,call);
        if(!call[0])return false;
        bool muted=(payload_len>0);
        if(muted&&payload){
            if((payload_len==1&&payload[0]=='0')||(payload_len==3&&!std::memcmp(payload,"del",3))||(payload_len==5&&!std::memcmp(payload,"false",5)))muted=false;
        }
        std::lock_guard<std::mutex> lock(mu);
        int idx=-1;
        for(unsigned i=0;i<count;++i)if(!std::strcmp(entries[i],call)){idx=int(i);break;}
        if(muted){
            if(idx>=0)return true;
            if(count>=capacity){
                std::memmove(entries,entries+1,(capacity-1)*sizeof(entries[0]));
                count=capacity-1;
            }
            std::strcpy(entries[count++],call);
            return true;
        }
        if(idx>=0){
            for(unsigned i=unsigned(idx)+1;i<count;++i)std::strcpy(entries[i-1],entries[i]);
            --count;
        }
        return true;
    }
    bool is_muted(const char *callsign)const{
        if(!callsign||!*callsign)return false;
        char call[13]{};
        normalize(callsign,std::strlen(callsign),call);
        if(!call[0])return false;
        std::lock_guard<std::mutex> lock(mu);
        for(unsigned i=0;i<count;++i)if(!std::strcmp(entries[i],call))return true;
        return false;
    }
    unsigned size()const{
        std::lock_guard<std::mutex> lock(mu);
        return count;
    }
};
inline bool node_connection_count(const uint8_t *text,size_t n,uint32_t *out){
    if(!text||!out||!n||n>10)return false;
    uint64_t value=0;
    for(size_t i=0;i<n;++i){if(text[i]<'0'||text[i]>'9')return false;value=value*10+text[i]-'0';if(value>UINT32_MAX)return false;}
    *out=static_cast<uint32_t>(value);return true;
}
// A broker-node connection count is not a count of human operators. The
// latest received node wins; do not sum unknown cluster membership.
struct NodeConnections {
    std::atomic<uint32_t> stamp{0},value{0};
    void reset(){stamp.store(0,std::memory_order_release);}
    void update(uint32_t count,int64_t now_us){
        if(now_us<0){reset();return;}
        stamp.store(0,std::memory_order_release);value.store(count,std::memory_order_relaxed);
        stamp.store(static_cast<uint32_t>(now_us/1000000)+1,std::memory_order_release);
    }
    bool read(int64_t now_us,uint32_t *count)const{
        if(!count||now_us<0)return false;
        const auto before=stamp.load(std::memory_order_acquire);if(!before)return false;
        const auto result=value.load(std::memory_order_relaxed),after=stamp.load(std::memory_order_acquire);
        const uint64_t now=uint64_t(now_us)/1000000+1;
        if(before!=after||now<before||now-before>120)return false;
        *count=result;return true;
    }
};
}
