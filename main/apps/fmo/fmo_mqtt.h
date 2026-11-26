#pragma once
#include <atomic>
#include <cstdint>
#include <cstring>
namespace fmo {
enum class MqttConnection { Connecting, Online, AuthenticationRejected, BrokerRejected, TransportFailed, Disconnected, LocalSetupFailed };
enum class MqttKind { None, Voice, NodeConnections };
// One MQTT PUBLISH is fragmented serially by esp-mqtt. Topics on the first
// fragment are authoritative; a new first fragment always abandons old data.
struct MqttInbox {
    char topic[256]{};
    size_t size=0,at=0;
    MqttKind kind=MqttKind::None;
    void reset(){topic[0]=0;size=at=0;kind=MqttKind::None;}
    static MqttKind route(const char *topic,size_t n){
        if(!topic)return MqttKind::None;
        if(n==7&&!std::memcmp(topic,"FMO/RAW",7))return MqttKind::Voice;
        constexpr char prefix[]="$SYS/brokers/",suffix[]="/stats/connections/count";
        constexpr size_t a=sizeof(prefix)-1,b=sizeof(suffix)-1;
        if(n<=a+b||std::memcmp(topic,prefix,a)||std::memcmp(topic+n-b,suffix,b))return MqttKind::None;
        for(size_t i=a;i<n-b;++i){const unsigned char c=topic[i];if(c<=32||c==127||c=='/'||c=='+'||c=='#')return MqttKind::None;}
        return MqttKind::NodeConnections;
    }
    MqttKind feed(const char *name,int name_size,const char *data,int bytes,int offset,int total,uint8_t *buffer,size_t capacity){
        if(name_size<0||bytes<0||offset<0||total<=0||static_cast<size_t>(total)>capacity||!buffer||(!data&&bytes)){reset();return MqttKind::None;}
        if(!offset){
            reset();
            if(!name||!name_size||static_cast<size_t>(name_size)>=sizeof(topic)||static_cast<size_t>(total)>capacity)return MqttKind::None;
            kind=route(name,name_size);
            if(kind==MqttKind::None||(kind==MqttKind::NodeConnections&&total>10)){reset();return MqttKind::None;}
            std::memcpy(topic,name,name_size);topic[name_size]=0;size=total;
        }else if(name_size&&(static_cast<size_t>(name_size)!=std::strlen(topic)||!name||std::memcmp(name,topic,name_size))){reset();return MqttKind::None;}
        if(kind==MqttKind::None||size!=static_cast<size_t>(total)||at!=static_cast<size_t>(offset)||static_cast<size_t>(bytes)>size-at){reset();return MqttKind::None;}
        if(bytes)std::memcpy(buffer+at,data,bytes);
        at+=bytes;
        if(at!=size)return MqttKind::None;
        const auto result=kind;reset();return result;
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
