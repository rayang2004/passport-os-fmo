#include "fmo_wire.h"
#include <cstring>
namespace fmo {
namespace {
uint16_t u16(const uint8_t *p) { return p[0] | uint16_t(p[1]) << 8; }
uint32_t u32(const uint8_t *p) { return u16(p) | uint32_t(u16(p+2)) << 16; }
void put16(uint8_t *p, uint16_t v) { p[0]=v; p[1]=v>>8; }
void put32(uint8_t *p, uint32_t v) { put16(p,v); put16(p+2,v>>16); }
bool callsign_ok(const char *s) {
    bool ended=false;
    for (size_t i=0;i<12;++i) {
        const unsigned char c=s[i];
        if (!c) { ended=true; continue; }
        if (ended || !((c>='A'&&c<='Z')||(c>='0'&&c<='9')||c=='-'||c=='/')) return false;
    }
    return s[0]!=0;
}
bool parse_rx_callsign(const uint8_t *raw, char out[13]) {
    std::memset(out, 0, 13);
    size_t len = 0;
    while (len < 12 && raw[len] != 0) ++len;
    size_t start = 0;
    while (start < len && raw[start] == ' ') ++start;
    while (len > start && raw[len - 1] == ' ') --len;
    if (start >= len) return false;
    size_t j = 0;
    for (size_t i = start; i < len; ++i) {
        unsigned char c = raw[i];
        if (c >= 'a' && c <= 'z') c = static_cast<unsigned char>(c - 'a' + 'A');
        if (!((c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '/' || c == '_')) {
            return false;
        }
        out[j++] = static_cast<char>(c);
    }
    out[j] = 0;
    return j > 0;
}
bool frame_ok_tx(const Frame &f) {
    return f.data && f.index && ((f.codec==1 && f.size && f.size<=1275) ||
        (f.codec==2 && f.size==328 && f.data[4]<=88 &&
         // Legacy senders truncated the two-byte adpcmBytes field to 64.
         (u16(f.data+6)==320 || f.data[6]==64)));
}
bool frame_ok_rx(const Frame &f) {
    return f.data && ((f.codec==1 && f.size && f.size<=1275) ||
        (f.codec==2 && f.size>=16 && f.size<=328 && f.data[4]<=88));
}
}
uint32_t crc32(const uint8_t *p, size_t n) {
    uint32_t c=0xffffffffu;
    while(n--) { c^=*p++; for(unsigned i=0;i<8;++i)c=(c>>1)^(0xedb88320u&(0u-(c&1))); }
    return ~c;
}
bool parse_packet(const uint8_t *p, size_t n, Packet *out) {
    if (!out) return false;
    *out={};
    if (!p || n<81 || n>kPacketMax || u16(p)!=1 || u32(p+30)!=n ||
        !u16(p+34) || u16(p+34)>kFrameMax || crc32(p+64,n-64)!=u32(p+36)) return false;
    Packet value{};
    if (!parse_rx_callsign(p+10, value.callsign)) return false;
    value.vendor=u32(p+2);value.uid=u32(p+6);value.stream_begin=u32(p+22);
    value.timestamp=u32(p+26);value.server_uid=u32(p+41);value.smeter=p[40];
    value.count=u16(p+34);size_t at=64;
    for (size_t i=0;i<value.count;++i) {
        if (n-at<16) return false;
        const size_t bytes=u16(p+at+2);
        const size_t sublen=u16(p+at+9);
        if (bytes<17 || bytes>n-at ||
            (sublen!=bytes-8 && sublen!=bytes-16 && sublen!=0)) return false;
        Frame f{p[at+8],p+at+16,bytes-16,u16(p+at)};
        if (!frame_ok_rx(f)) return false;
        value.frames[i]=f;at+=bytes;
    }
    if(at!=n) return false;
    *out=value;return true;
}
size_t write_packet(uint8_t *p, size_t cap, const Packet &v) {
    if(!p || !v.count || v.count>kFrameMax || !callsign_ok(v.callsign))return 0;
    size_t n=64;
    for(size_t i=0;i<v.count;++i){
        if(!frame_ok_tx(v.frames[i]) || (i&&v.frames[i].index!=uint16_t(v.frames[i-1].index+1)))return 0;
        n+=16+v.frames[i].size;
    }
    if(n>cap || n>kPacketMax)return 0;
    std::memset(p,0,n);put16(p,1);put32(p+2,v.vendor);put32(p+6,v.uid);
    std::memcpy(p+10,v.callsign,12);put32(p+22,v.stream_begin);put32(p+26,v.timestamp);
    put32(p+30,n);put16(p+34,v.count);p[40]=v.smeter;put32(p+41,v.server_uid);
    size_t at=64;
    for(size_t i=0;i<v.count;++i){const auto &f=v.frames[i];
        put16(p+at,f.index);put16(p+at+2,16+f.size);p[at+8]=f.codec;put16(p+at+9,8+f.size);
        std::memcpy(p+at+16,f.data,f.size);at+=16+f.size;
    }
    put32(p+36,crc32(p+64,n-64));return n;
}
}
