#include "fmo_stamp.h"
#include "fmo_wire.h"
#include "fmo_host_bridge.h"
#include "nvs.h"
#include <algorithm>
#include <array>
#include <cerrno>
#include <cmath>
#include <cstdio>
#include <cstring>
#include <mutex>
#include <memory>
#include <new>
#include <string>
#include <vector>
#include <sys/stat.h>
#include <unistd.h>

#ifndef FMO_STAMP_BASE
#define FMO_STAMP_BASE "/storage"
#endif

namespace fmo {
namespace {
std::mutex stamp_mutex;
constexpr size_t kConfigBlobSize = 48;
constexpr size_t kPeerSlotSize = 20;
constexpr size_t kPeerMaxSize = 12 + PeerStamps::capacity * kPeerSlotSize;

uint32_t get32(const uint8_t *p) {
    return uint32_t(p[0]) | (uint32_t(p[1]) << 8) | (uint32_t(p[2]) << 16) | (uint32_t(p[3]) << 24);
}
void put32(uint8_t *p, uint32_t n) {
    for (unsigned i = 0; i < 4; ++i) p[i] = static_cast<uint8_t>(n >> (8 * i));
}
uint16_t get16(const uint8_t *p) {
    return uint16_t(p[0]) | (uint16_t(p[1]) << 8);
}
void put16(uint8_t *p, uint16_t n) {
    p[0] = static_cast<uint8_t>(n & 0xFF);
    p[1] = static_cast<uint8_t>(n >> 8);
}

bool valid_call_key(const char *call) {
    if (!call) return false;
    const size_t n = strnlen(call, 13);
    if (n < 2 || n > 12) return false;
    for (size_t i = 0; i < n; ++i) {
        const char c = call[i];
        if (!((c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '/' || c == '-')) return false;
    }
    return true;
}

const char *strip_p_prefix(const char *call) {
    if (call && call[0] == 'P' && call[1] == '-' && strnlen(call, 13) >= 5) return call + 2;
    return call ? call : "";
}

std::string bank_path(unsigned bank) {
    return std::string(FMO_STAMP_BASE) + (bank ? "/fmo-stamp-b.bin" : "/fmo-stamp-a.bin");
}

struct StorageRelease {
    ~StorageRelease() { fmo_storage_release(); }
};

enum class FileRead { Ready, Missing, Invalid, Unavailable };

FileRead read_stamp_file(const std::string &path, uint8_t pixels[kStampPixelBytes], uint32_t *crc_out) {
    struct stat st{};
    if (stat(path.c_str(), &st) != 0) return errno == ENOENT ? FileRead::Missing : FileRead::Unavailable;
    if (!S_ISREG(st.st_mode) || st.st_size != static_cast<off_t>(kStampFileBytes)) return FileRead::Invalid;
    FILE *f = fopen(path.c_str(), "rb");
    if (!f) return FileRead::Unavailable;
    uint8_t hdr[kStampFileHeaderBytes];
    bool ok = fread(hdr, 1, sizeof(hdr), f) == sizeof(hdr);
    size_t used = 0;
    while (ok && used < kStampPixelBytes) {
        const size_t chunk = std::min<size_t>(512, kStampPixelBytes - used);
        const size_t got = fread(pixels + used, 1, chunk, f);
        if (!got) { ok = false; break; }
        used += got;
    }
    if (ferror(f)) ok = false;
    if (fclose(f) != 0) ok = false;
    if (!ok || used != kStampPixelBytes) return FileRead::Unavailable;
    if (std::memcmp(hdr, "FMS1", 4) != 0 || hdr[4] != 1 || hdr[5] != 4 ||
        get16(hdr + 6) != kStampWidth || get16(hdr + 8) != kStampHeight ||
        get16(hdr + 10) != 0 || get32(hdr + 12) != kStampPixelBytes) {
        return FileRead::Invalid;
    }
    if (get32(hdr + 28) != crc32(hdr, 28)) return FileRead::Invalid;
    const uint32_t expected_crc = get32(hdr + 16);
    if (expected_crc != crc32(pixels, kStampPixelBytes)) return FileRead::Invalid;
    if (!stamp_pixels_nonempty(pixels)) return FileRead::Invalid;
    if (crc_out) *crc_out = expected_crc;
    return FileRead::Ready;
}

bool write_stamp_file(const std::string &path, const uint8_t pixels[kStampPixelBytes], uint32_t payload_crc) {
    uint8_t hdr[kStampFileHeaderBytes]{};
    std::memcpy(hdr, "FMS1", 4);
    hdr[4] = 1;
    hdr[5] = 4;
    put16(hdr + 6, kStampWidth);
    put16(hdr + 8, kStampHeight);
    put16(hdr + 10, 0);
    put32(hdr + 12, kStampPixelBytes);
    put32(hdr + 16, payload_crc);
    put32(hdr + 28, crc32(hdr, 28));

    FILE *f = fopen(path.c_str(), "wb");
    if (!f) return false;
    bool ok = fwrite(hdr, 1, sizeof(hdr), f) == sizeof(hdr);
    size_t at = 0;
    while (ok && at < kStampPixelBytes) {
        const size_t chunk = std::min<size_t>(512, kStampPixelBytes - at);
        if (fwrite(pixels + at, 1, chunk, f) != chunk) { ok = false; break; }
        at += chunk;
    }
    if (fflush(f) != 0) ok = false;
    if (ok && fsync(fileno(f)) != 0) ok = false;
    if (fclose(f) != 0) ok = false;
    return ok;
}

bool save_config_locked(const StampConfig &cfg) {
    if (!stamp_style_valid(cfg.style_id) || !stamp_label_valid(cfg.label) || cfg.color_rgb > 0xFFFFFFu || cfg.custom_bank > 1) {
        return false;
    }
    std::array<uint8_t, kConfigBlobSize> blob{};
    std::memcpy(blob.data(), "FSM1", 4);
    blob[4] = 1;
    blob[5] = cfg.custom_present ? 1 : 0;
    blob[6] = cfg.custom_bank;
    blob[7] = 0;
    put32(blob.data() + 8, cfg.color_rgb);
    put32(blob.data() + 12, cfg.custom_present ? cfg.custom_crc : 0);
    std::strcpy(reinterpret_cast<char *>(blob.data() + 16), cfg.style_id);
    std::strcpy(reinterpret_cast<char *>(blob.data() + 24), cfg.label);
    put32(blob.data() + 44, crc32(blob.data(), 44));

    nvs_handle_t h;
    if (nvs_open("fmo_os", NVS_READWRITE, &h) != ESP_OK) return false;
    auto e = nvs_set_blob(h, "stamp_v1", blob.data(), blob.size());
    if (e == ESP_OK) e = nvs_commit(h);
    nvs_close(h);
    return e == ESP_OK;
}

StampLoad load_config_locked(StampConfig *out) {
    if (!out) return StampLoad::Unavailable;
    nvs_handle_t h;
    auto e = nvs_open("fmo_os", NVS_READONLY, &h);
    if (e == ESP_ERR_NVS_NOT_FOUND) { *out = StampConfig{}; return StampLoad::Missing; }
    if (e != ESP_OK) return StampLoad::Unavailable;
    std::array<uint8_t, kConfigBlobSize> blob{};
    size_t n = blob.size();
    e = nvs_get_blob(h, "stamp_v1", blob.data(), &n);
    nvs_close(h);
    if (e == ESP_ERR_NVS_NOT_FOUND) { *out = StampConfig{}; return StampLoad::Missing; }
    if (e != ESP_OK || n != blob.size() || std::memcmp(blob.data(), "FSM1", 4) != 0 ||
        blob[4] != 1 || blob[5] > 1 || blob[6] > 1 || blob[7] != 0 ||
        blob[41] != 0 || blob[42] != 0 || blob[43] != 0 ||
        get32(blob.data() + 44) != crc32(blob.data(), 44)) {
        return StampLoad::Unavailable;
    }
    if (blob[23] != 0 || blob[40] != 0) return StampLoad::Unavailable;
    StampConfig cfg{};
    cfg.custom_present = blob[5] == 1;
    cfg.custom_bank = blob[6];
    cfg.color_rgb = get32(blob.data() + 8);
    cfg.custom_crc = get32(blob.data() + 12);
    std::memcpy(cfg.style_id, blob.data() + 16, sizeof(cfg.style_id));
    std::memcpy(cfg.label, blob.data() + 24, sizeof(cfg.label));
    if (cfg.color_rgb > 0xFFFFFFu || !stamp_style_valid(cfg.style_id) || !stamp_label_valid(cfg.label)) {
        return StampLoad::Unavailable;
    }
    *out = cfg;
    return StampLoad::Ready;
}

// Signed distance helpers in 96x96 pixel space (center = 47.5, 47.5).
float sd_circle(float px, float py, float r) {
    return std::sqrt(px * px + py * py) - r;
}
float sd_rounded_box(float px, float py, float bx, float by, float r) {
    const float qx = std::fabs(px) - bx + r;
    const float qy = std::fabs(py) - by + r;
    const float ox = std::max(qx, 0.0f), oy = std::max(qy, 0.0f);
    return std::sqrt(ox * ox + oy * oy) + std::min(std::max(qx, qy), 0.0f) - r;
}
float sd_octagon(float px, float py, float r) {
    const float ax = std::fabs(px), ay = std::fabs(py);
    const float d1 = std::max(ax, ay) - r;
    const float d2 = (ax + ay) * 0.70710678f - r * 1.0823922f; // r / cos(22.5 deg) -> regular octagon
    return std::max(d1, d2);
}
float sd_hexagon(float px, float py, float r) {
    const float ax = std::fabs(px), ay = std::fabs(py);
    // Pointy-top regular hexagon matching G009 (50,2 -> 91.6,26 -> 91.6,74 -> 50,98)
    return std::max(ax - r * 0.8660254f, ax * 0.5f + ay * 0.8660254f - r * 0.8660254f);
}
float sd_diamond(float px, float py, float r) {
    return (std::fabs(px) + std::fabs(py)) * 0.70710678f - r * 0.70710678f;
}
float sd_shield(float px, float py, float w, float top_y, float mid_y, float bot_y) {
    // Upper rectangle [top_y..mid_y] tapering smoothly to bottom point (0, bot_y)
    const float ax = std::fabs(px);
    if (py <= mid_y) {
        return std::max(ax - w, top_y - py);
    }
    const float t = std::clamp((py - mid_y) / std::max(1.0f, bot_y - mid_y), 0.0f, 1.0f);
    const float half_w = w * (1.0f - t * t * 0.92f);
    const float d_side = (ax - half_w) * 0.82f;
    const float d_bot = py - bot_y;
    return std::max(d_side, d_bot);
}
float sd_heart(float px, float py, float scale) {
    // Classic normalized heart implicit curve mapped to approximate pixel SDF
    const float x = px / scale;
    const float y = -(py - 3.0f) / scale;
    const float a = x * x + y * y - 1.0f;
    const float f = a * a * a - x * x * y * y * y;
    // Approximate gradient magnitude for consistent pixel stroke width
    const float gx = 6.0f * x * a * a - 2.0f * x * y * y * y;
    const float gy = 6.0f * y * a * a - 3.0f * x * x * y * y;
    const float g = std::sqrt(gx * gx + gy * gy) + 1e-4f;
    return (f / g) * scale;
}
float sd_segment_h(float x, float y, float x1, float x2, float ly) {
    const float dx = x < x1 ? x1 - x : (x > x2 ? x - x2 : 0.0f);
    const float dy = y - ly;
    return std::sqrt(dx * dx + dy * dy);
}
float stroke_alpha(float sd, float half_width) {
    const float d = std::fabs(sd) - half_width;
    return std::clamp(0.5f - d, 0.0f, 1.0f);
}
} // namespace

bool stamp_style_valid(const char *style_id) {
    if (!style_id) return false;
    const size_t n = strnlen(style_id, 8);
    if (n == 6 && std::strcmp(style_id, "CUSTOM") == 0) return true;
    if (n != 4) return false;
    const char c = style_id[0];
    if (c < 'A' || c > 'Z') return false;
    for (unsigned i = 1; i < 4; ++i) {
        if (style_id[i] < '0' || style_id[i] > '9') return false;
    }
    const unsigned num = unsigned(style_id[1] - '0') * 100u + unsigned(style_id[2] - '0') * 10u + unsigned(style_id[3] - '0');
    return num >= 1 && num <= 999;
}

bool stamp_label_valid(const char *label) {
    if (!label) return false;
    const size_t n = strnlen(label, 17);
    if (n > 16) return false;
    for (size_t i = 0; i < n; ) {
        const unsigned char c = static_cast<unsigned char>(label[i]);
        if (c < 0x20 || c == 0x7F || c == ',') return false;
        const unsigned w = c < 0x80 ? 1 : (c >= 0xC2 && c <= 0xDF) ? 2 : (c >= 0xE0 && c <= 0xEF) ? 3 : (c >= 0xF0 && c <= 0xF4) ? 4 : 0;
        if (!w || i + w > n) return false;
        for (unsigned j = 1; j < w; ++j) {
            if ((static_cast<unsigned char>(label[i + j]) & 0xC0) != 0x80) return false;
        }
        i += w;
    }
    return true;
}

bool stamp_is_custom_style(const char *style_id) {
    return style_id && std::strcmp(style_id, "CUSTOM") == 0;
}

int stamp_builtin_index(const char *style_id) {
    if (!style_id || style_id[0] != 'G' || strnlen(style_id, 8) != 4) return -1;
    for (unsigned i = 1; i < 4; ++i) if (style_id[i] < '0' || style_id[i] > '9') return -1;
    const unsigned num = unsigned(style_id[1] - '0') * 100u + unsigned(style_id[2] - '0') * 10u + unsigned(style_id[3] - '0');
    if (num < 1 || num > kBuiltinStampCount) return -1;
    return static_cast<int>(num - 1);
}

unsigned stamp_fallback_index(const char *callsign) {
    const char *bare = strip_p_prefix(callsign);
    uint32_t h = 2166136261u;
    for (const char *p = bare; *p; ++p) {
        h ^= static_cast<unsigned char>(*p);
        h *= 16777619u;
    }
    return h % kBuiltinStampCount;
}

const char *stamp_builtin_id(unsigned index) {
    static constexpr const char *kIds[kBuiltinStampCount] = {
        "G001", "G002", "G003", "G004", "G005", "G006",
        "G007", "G008", "G009", "G010", "G011", "G012"
    };
    return kIds[index % kBuiltinStampCount];
}

const char *stamp_builtin_name(unsigned index) {
    static constexpr const char *kNames[kBuiltinStampCount] = {
        "双环圆章", "邮戳齿圆", "圆角方章", "方中带圆",
        "粗边圆章", "圆中带方", "八角印章", "徽章盾牌",
        "六角蜂巢", "爱心印章", "菱形印章", "邮票方章"
    };
    return kNames[index % kBuiltinStampCount];
}

bool parse_pat1_stamp(const char *line, size_t size, char callsign[13], char style_id[8]) {
    if (!line || !callsign || !style_id || !size || size > 510) return false;
    callsign[0] = 0;
    style_id[0] = 0;
    const std::string raw(line, size);
    const auto gt = raw.find('>'), colon = raw.find(':');
    if (gt == std::string::npos || colon == std::string::npos || colon < gt) return false;
    if (raw.compare(gt + 1, 6, "APPASP") != 0) return false;
    std::string call = raw.substr(0, gt);
    const auto dash = call.rfind('-');
    if (dash != std::string::npos) call.resize(dash);
    if (!valid_call_key(call.c_str())) return false;
    const auto pat = raw.find("PAT-1,", colon + 1);
    if (pat == std::string::npos) return false;
    const auto st = raw.find("ST:", pat + 6);
    if (st == std::string::npos) return false;
    const size_t val_start = st + 3;
    const auto comma = raw.find(',', val_start);
    const std::string id = raw.substr(val_start, comma == std::string::npos ? std::string::npos : comma - val_start);
    if (!stamp_style_valid(id.c_str())) return false;
    std::strcpy(callsign, call.c_str());
    std::strcpy(style_id, id.c_str());
    return true;
}

void stamp_build_palette(uint32_t color_rgb, uint8_t palette[kStampPaletteBytes]) {
    const uint32_t r = (color_rgb >> 16) & 0xFFu;
    const uint32_t g = (color_rgb >> 8) & 0xFFu;
    const uint32_t b = color_rgb & 0xFFu;
    for (unsigned i = 0; i < 16; ++i) {
        palette[i * 4 + 0] = static_cast<uint8_t>(b);
        palette[i * 4 + 1] = static_cast<uint8_t>(g);
        palette[i * 4 + 2] = static_cast<uint8_t>(r);
        palette[i * 4 + 3] = static_cast<uint8_t>((255u * i + 7u) / 15u);
    }
}

void stamp_render_builtin(unsigned index, uint8_t pixels[kStampPixelBytes]) {
    index %= kBuiltinStampCount;
    std::memset(pixels, 0, kStampPixelBytes);
    constexpr float cx = 47.5f, cy = 47.5f;
    for (unsigned y = 0; y < kStampHeight; ++y) {
        const float py = float(y) - cy;
        for (unsigned x = 0; x < kStampWidth; ++x) {
            const float px = float(x) - cx;
            float a = 0.0f;
            const float y1 = 35.5f, y2 = 74.5f;
            switch (index) {
            case 0: { // G001: double circle
                a = std::max(stroke_alpha(sd_circle(px, py, 43.0f), 2.1f),
                             stroke_alpha(sd_circle(px, py, 36.2f), 0.75f));
                a = std::max(a, stroke_alpha(sd_segment_h(float(x), float(y), 27.0f, 68.0f, y1), 0.9f));
                a = std::max(a, stroke_alpha(sd_segment_h(float(x), float(y), 27.0f, 68.0f, y2), 0.9f));
                break;
            }
            case 1: { // G002: perforated dotted outer circle + inner circle
                const float ang = std::atan2(py, px) + 3.14159265f;
                const float dash_phase = std::fmod(ang * 40.0f / 6.2831853f, 1.0f);
                const float dash = dash_phase < 0.42f ? 1.0f : 0.0f;
                a = std::max(stroke_alpha(sd_circle(px, py, 41.2f), 4.0f) * dash,
                             stroke_alpha(sd_circle(px, py, 34.5f), 0.75f));
                a = std::max(a, stroke_alpha(sd_segment_h(float(x), float(y), 27.0f, 68.0f, y1), 0.9f));
                a = std::max(a, stroke_alpha(sd_segment_h(float(x), float(y), 27.0f, 68.0f, y2), 0.9f));
                break;
            }
            case 2: { // G003: double rounded square
                a = std::max(stroke_alpha(sd_rounded_box(px, py, 42.0f, 42.0f, 5.0f), 2.1f),
                             stroke_alpha(sd_rounded_box(px, py, 30.8f, 30.8f, 3.0f), 0.75f));
                a = std::max(a, stroke_alpha(sd_segment_h(float(x), float(y), 25.0f, 70.0f, y1), 0.9f));
                a = std::max(a, stroke_alpha(sd_segment_h(float(x), float(y), 25.0f, 70.0f, y2), 0.9f));
                break;
            }
            case 3: { // G004: rounded square outer + circle inner
                a = std::max(stroke_alpha(sd_rounded_box(px, py, 43.0f, 43.0f, 8.5f), 2.1f),
                             stroke_alpha(sd_circle(px, py, 31.6f), 1.0f));
                a = std::max(a, stroke_alpha(sd_segment_h(float(x), float(y), 29.0f, 66.0f, y1), 0.9f));
                a = std::max(a, stroke_alpha(sd_segment_h(float(x), float(y), 29.0f, 66.0f, y2), 0.9f));
                break;
            }
            case 4: { // G005: bold thick circle + inner circle
                a = std::max(stroke_alpha(sd_circle(px, py, 42.5f), 3.7f),
                             stroke_alpha(sd_circle(px, py, 32.5f), 1.0f));
                a = std::max(a, stroke_alpha(sd_segment_h(float(x), float(y), 27.0f, 68.0f, y1), 0.9f));
                a = std::max(a, stroke_alpha(sd_segment_h(float(x), float(y), 27.0f, 68.0f, y2), 0.9f));
                break;
            }
            case 5: { // G006: outer circle + rounded square inner
                a = std::max(stroke_alpha(sd_circle(px, py, 43.0f), 2.1f),
                             stroke_alpha(sd_rounded_box(px, py, 31.5f, 31.5f, 3.0f), 0.75f));
                a = std::max(a, stroke_alpha(sd_segment_h(float(x), float(y), 27.0f, 68.0f, y1), 0.9f));
                a = std::max(a, stroke_alpha(sd_segment_h(float(x), float(y), 27.0f, 68.0f, y2), 0.9f));
                break;
            }
            case 6: { // G007: double octagon
                a = std::max(stroke_alpha(sd_octagon(px, py, 43.5f), 2.1f),
                             stroke_alpha(sd_octagon(px, py, 32.0f), 0.75f));
                a = std::max(a, stroke_alpha(sd_segment_h(float(x), float(y), 27.0f, 68.0f, y1), 0.9f));
                a = std::max(a, stroke_alpha(sd_segment_h(float(x), float(y), 27.0f, 68.0f, y2), 0.9f));
                break;
            }
            case 7: { // G008: double shield
                a = std::max(stroke_alpha(sd_shield(px, py, 40.5f, -40.0f, 8.0f, 44.5f), 2.1f),
                             stroke_alpha(sd_shield(px, py, 31.5f, -31.5f, 8.0f, 37.0f), 0.75f));
                a = std::max(a, stroke_alpha(sd_segment_h(float(x), float(y), 28.0f, 67.0f, y1), 0.9f));
                a = std::max(a, stroke_alpha(sd_segment_h(float(x), float(y), 28.0f, 67.0f, y2), 0.9f));
                break;
            }
            case 8: { // G009: double hexagon
                a = std::max(stroke_alpha(sd_hexagon(px, py, 45.5f), 2.1f),
                             stroke_alpha(sd_hexagon(px, py, 37.5f), 0.75f));
                a = std::max(a, stroke_alpha(sd_segment_h(float(x), float(y), 26.0f, 69.0f, y1), 0.9f));
                a = std::max(a, stroke_alpha(sd_segment_h(float(x), float(y), 26.0f, 69.0f, y2), 0.9f));
                break;
            }
            case 9: { // G010: double heart
                a = std::max(stroke_alpha(sd_heart(px, py, 33.0f), 1.9f),
                             stroke_alpha(sd_heart(px, py, 27.5f), 0.75f));
                a = std::max(a, stroke_alpha(sd_segment_h(float(x), float(y), 35.0f, 60.0f, 68.0f), 0.9f));
                break;
            }
            case 10: { // G011: double diamond
                a = std::max(stroke_alpha(sd_diamond(px, py, 44.5f), 2.1f),
                             stroke_alpha(sd_diamond(px, py, 34.5f), 0.75f));
                a = std::max(a, stroke_alpha(sd_segment_h(float(x), float(y), 30.0f, 65.0f, y1), 0.9f));
                a = std::max(a, stroke_alpha(sd_segment_h(float(x), float(y), 30.0f, 65.0f, y2), 0.9f));
                break;
            }
            default: { // G012: postage-stamp perforated square
                const float perimeter = (std::fabs(px) > std::fabs(py)) ? py : px;
                const float dash = std::fmod(perimeter + 100.0f, 6.5f) < 2.6f ? 1.0f : 0.0f;
                a = std::max(stroke_alpha(sd_rounded_box(px, py, 42.5f, 42.5f, 0.5f), 2.8f) * dash,
                             stroke_alpha(sd_rounded_box(px, py, 32.5f, 32.5f, 2.0f), 0.75f));
                a = std::max(a, stroke_alpha(sd_segment_h(float(x), float(y), 25.0f, 70.0f, y1), 0.9f));
                a = std::max(a, stroke_alpha(sd_segment_h(float(x), float(y), 25.0f, 70.0f, y2), 0.9f));
                break;
            }
            }
            const uint8_t level = static_cast<uint8_t>(std::clamp(int(std::lround(a * 15.0f)), 0, 15));
            const size_t idx = (y * kStampWidth + x) / 2;
            if ((x & 1u) == 0) pixels[idx] |= static_cast<uint8_t>(level << 4);
            else pixels[idx] |= level;
        }
    }
}

bool stamp_pixels_nonempty(const uint8_t pixels[kStampPixelBytes]) {
    if (!pixels) return false;
    unsigned ink = 0;
    for (size_t i = 0; i < kStampPixelBytes; ++i) {
        if ((pixels[i] >> 4) >= 3) ++ink;
        if ((pixels[i] & 0x0Fu) >= 3) ++ink;
        if (ink >= 16) return true;
    }
    return false;
}

StampLoad load_stamp_config(StampConfig *out) {
    std::lock_guard<std::mutex> guard(stamp_mutex);
    return load_config_locked(out);
}

bool save_stamp_config(const StampConfig &cfg) {
    std::lock_guard<std::mutex> guard(stamp_mutex);
    // Appearance edits may have been prepared before an image upload or clear.
    // Only the image operations may change the committed bank and checksum.
    StampConfig current{};
    if (load_config_locked(&current) == StampLoad::Unavailable) return false;
    if (cfg.custom_present != current.custom_present ||
        cfg.custom_bank != current.custom_bank ||
        cfg.custom_crc != current.custom_crc) return false;
    return save_config_locked(cfg);
}

StampLoad load_custom_stamp_image(const StampConfig &cfg, uint8_t pixels[kStampPixelBytes]) {
    if (!pixels) return StampLoad::Unavailable;
    if (!cfg.custom_present) return StampLoad::Missing;
    std::lock_guard<std::mutex> guard(stamp_mutex);
    if (fmo_storage_acquire(false) != ESP_OK) return StampLoad::Unavailable;
    StorageRelease release;
    for (unsigned attempt = 0; attempt < 2; ++attempt) {
        const unsigned bank = (cfg.custom_bank ^ (attempt ? 1u : 0u)) & 1u;
        uint32_t file_crc = 0;
        if (read_stamp_file(bank_path(bank), pixels, &file_crc) == FileRead::Ready && file_crc == cfg.custom_crc) {
            return StampLoad::Ready;
        }
    }
    return StampLoad::Unavailable;
}

bool save_custom_stamp_image(const uint8_t pixels[kStampPixelBytes], StampConfig *cfg, bool initialize_blank) {
    if (!pixels || !stamp_pixels_nonempty(pixels)) return false;
    std::lock_guard<std::mutex> guard(stamp_mutex);
    StampConfig current{};
    const auto prev_load = load_config_locked(&current);
    if (prev_load == StampLoad::Unavailable) return false;
    if (cfg) {
        if (cfg->color_rgb <= 0xFFFFFFu) current.color_rgb = cfg->color_rgb;
        if (stamp_label_valid(cfg->label)) std::strcpy(current.label, cfg->label);
    }
    const uint32_t payload_crc = crc32(pixels, kStampPixelBytes);
    std::unique_ptr<uint8_t[]> scratch(new(std::nothrow) uint8_t[kStampPixelBytes]);
    if (!scratch) return false;
    if (fmo_storage_acquire(initialize_blank) != ESP_OK) return false;
    StorageRelease release;

    unsigned target_bank = current.custom_present ? (current.custom_bank ^ 1u) : 0u;
    if (current.custom_present) {
        uint32_t existing_crc = 0;
        const auto active = read_stamp_file(bank_path(current.custom_bank), scratch.get(), &existing_crc);
        if (active == FileRead::Unavailable) return false;
        if (active != FileRead::Ready || existing_crc != current.custom_crc) {
            const auto backup = read_stamp_file(bank_path(current.custom_bank ^ 1u), scratch.get(), &existing_crc);
            if (backup == FileRead::Unavailable) return false;
            if (backup == FileRead::Ready && existing_crc == current.custom_crc) {
                target_bank = current.custom_bank;
            }
        }
    }

    const auto path = bank_path(target_bank);
    if (!write_stamp_file(path, pixels, payload_crc)) return false;
    uint32_t readback_crc = 0;
    if (read_stamp_file(path, scratch.get(), &readback_crc) != FileRead::Ready ||
        readback_crc != payload_crc || std::memcmp(scratch.get(), pixels, kStampPixelBytes) != 0) {
        return false;
    }

    current.custom_present = true;
    current.custom_bank = static_cast<uint8_t>(target_bank);
    current.custom_crc = payload_crc;
    std::strcpy(current.style_id, "CUSTOM");
    if (!save_config_locked(current)) return false;
    if (cfg) *cfg = current;
    return true;
}

bool clear_custom_stamp_image(StampConfig *cfg) {
    std::lock_guard<std::mutex> guard(stamp_mutex);
    StampConfig current{};
    const auto prev_load = load_config_locked(&current);
    if (prev_load == StampLoad::Unavailable) return false;
    current.custom_present = false;
    current.custom_bank = 0;
    current.custom_crc = 0;
    if (stamp_is_custom_style(current.style_id)) std::strcpy(current.style_id, "G001");
    if (!save_config_locked(current)) return false;
    if (fmo_storage_acquire(false) == ESP_OK) {
        StorageRelease release;
        unlink(bank_path(0).c_str());
        unlink(bank_path(1).c_str());
    }
    if (cfg) *cfg = current;
    return true;
}

const char *PeerStamps::find(const char *callsign) const {
    const char *bare = strip_p_prefix(callsign);
    if (!bare[0]) return nullptr;
    for (unsigned i = 0; i < count && i < capacity; ++i) {
        if (std::strcmp(entries[i].callsign, bare) == 0) return entries[i].style_id;
    }
    return nullptr;
}

bool PeerStamps::remember(const char *callsign, const char *style_id) {
    const char *bare = strip_p_prefix(callsign);
    if (!valid_call_key(bare) || !stamp_style_valid(style_id) || count > capacity) return false;
    for (unsigned i = 0; i < count; ++i) {
        if (std::strcmp(entries[i].callsign, bare) == 0) {
            if (std::strcmp(entries[i].style_id, style_id) == 0) return false;
            std::strcpy(entries[i].style_id, style_id);
            return true;
        }
    }
    if (count == capacity) {
        // Shift oldest out to keep recently active peer styles fresh.
        for (unsigned i = 1; i < capacity; ++i) entries[i - 1] = entries[i];
        --count;
    }
    auto &e = entries[count++];
    e = {};
    std::strcpy(e.callsign, bare);
    std::strcpy(e.style_id, style_id);
    return true;
}

StampLoad load_peer_stamps(PeerStamps *out) {
    if (!out) return StampLoad::Unavailable;
    std::lock_guard<std::mutex> guard(stamp_mutex);
    nvs_handle_t h;
    auto e = nvs_open("fmo_os", NVS_READONLY, &h);
    if (e == ESP_ERR_NVS_NOT_FOUND) { *out = PeerStamps{}; return StampLoad::Missing; }
    if (e != ESP_OK) return StampLoad::Unavailable;
    size_t n = 0;
    e = nvs_get_blob(h, "psty_v1", nullptr, &n);
    if (e == ESP_ERR_NVS_NOT_FOUND) { nvs_close(h); *out = PeerStamps{}; return StampLoad::Missing; }
    if (e != ESP_OK || n < 12 || n > kPeerMaxSize) { nvs_close(h); return StampLoad::Unavailable; }
    std::vector<uint8_t> bytes(n);
    const size_t expected = n;
    e = nvs_get_blob(h, "psty_v1", bytes.data(), &n);
    nvs_close(h);
    if (e != ESP_OK || n != expected || std::memcmp(bytes.data(), "FPS1", 4) != 0 ||
        bytes[4] > PeerStamps::capacity || bytes[5] || bytes[6] || bytes[7] ||
        n != 12 + bytes[4] * kPeerSlotSize ||
        get32(bytes.data() + n - 4) != crc32(bytes.data(), n - 4)) {
        return StampLoad::Unavailable;
    }
    PeerStamps loaded{};
    loaded.count = bytes[4];
    for (unsigned i = 0; i < loaded.count; ++i) {
        const uint8_t *p = bytes.data() + 8 + i * kPeerSlotSize;
        if (p[12] != 0 || p[19] != 0) return StampLoad::Unavailable;
        std::memcpy(loaded.entries[i].callsign, p, 13);
        std::memcpy(loaded.entries[i].style_id, p + 13, 7);
        loaded.entries[i].style_id[7] = 0;
        if (!valid_call_key(loaded.entries[i].callsign) || !stamp_style_valid(loaded.entries[i].style_id)) {
            return StampLoad::Unavailable;
        }
    }
    *out = loaded;
    return StampLoad::Ready;
}

bool save_peer_stamps(const PeerStamps &stamps) {
    if (stamps.count > PeerStamps::capacity) return false;
    const size_t n = 12 + stamps.count * kPeerSlotSize;
    std::vector<uint8_t> bytes(n, 0);
    std::memcpy(bytes.data(), "FPS1", 4);
    bytes[4] = static_cast<uint8_t>(stamps.count);
    for (unsigned i = 0; i < stamps.count; ++i) {
        const auto &e = stamps.entries[i];
        if (!valid_call_key(e.callsign) || !stamp_style_valid(e.style_id)) return false;
        uint8_t *p = bytes.data() + 8 + i * kPeerSlotSize;
        std::strcpy(reinterpret_cast<char *>(p), e.callsign);
        std::strcpy(reinterpret_cast<char *>(p + 13), e.style_id);
    }
    put32(bytes.data() + n - 4, crc32(bytes.data(), n - 4));
    std::lock_guard<std::mutex> guard(stamp_mutex);
    nvs_handle_t h;
    if (nvs_open("fmo_os", NVS_READWRITE, &h) != ESP_OK) return false;
    const auto e = nvs_set_blob(h, "psty_v1", bytes.data(), bytes.size());
    const bool ok = e == ESP_OK && nvs_commit(h) == ESP_OK;
    nvs_close(h);
    return ok;
}
} // namespace fmo
