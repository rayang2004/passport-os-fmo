#pragma once
#include <cstddef>
#include <cstdint>
namespace fmo {
constexpr size_t kPacketMax = 1400, kFrameMax = 24;
struct Frame { uint8_t codec; const uint8_t *data; size_t size; uint16_t index; };
struct Packet {
    uint32_t vendor{}, uid{}, stream_begin{}, timestamp{}, server_uid{};
    char callsign[13]{};
    uint8_t smeter{};
    size_t count{};
    Frame frames[kFrameMax]{};
};
// AIRP-03 v1. Views borrow input memory. Invalid packets expose no frames.
bool parse_packet(const uint8_t *data, size_t size, Packet *out);
size_t write_packet(uint8_t *out, size_t capacity, const Packet &packet);
uint32_t crc32(const uint8_t *data, size_t size);
inline bool route_priority_preempts(uint32_t begin,uint32_t uid,uint32_t active_begin,uint32_t active_uid){
    const int32_t difference=static_cast<int32_t>(begin-active_begin);
    return (difference<0&&difference>=-2000)||(difference==0&&uid<active_uid);
}
}
