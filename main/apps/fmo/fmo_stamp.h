#pragma once
#include <cstddef>
#include <cstdint>
namespace fmo {
constexpr unsigned kStampWidth = 96;
constexpr unsigned kStampHeight = 96;
constexpr size_t kStampPaletteBytes = 16 * 4;
constexpr size_t kStampPixelBytes = (kStampWidth * kStampHeight) / 2; // 4608 B (4-bit I4)
constexpr size_t kStampImageBytes = kStampPaletteBytes + kStampPixelBytes; // 4672 B (LVGL I4)
constexpr size_t kStampFileHeaderBytes = 32;
constexpr size_t kStampFileBytes = kStampFileHeaderBytes + kStampPixelBytes; // 4640 B
constexpr unsigned kBuiltinStampCount = 12;
constexpr uint32_t kDefaultStampColor = 0xFF7A1Au; // FMO Passport brand orange

struct StampConfig {
    char style_id[8]{"G001"};
    uint32_t color_rgb = kDefaultStampColor;
    char label[17]{"AI PASSPORT"};
    bool custom_present = false;
    uint8_t custom_bank = 0;
    uint32_t custom_crc = 0;
};

struct PeerStampEntry {
    char callsign[13]{};
    char style_id[8]{};
};

struct PeerStamps {
    static constexpr unsigned capacity = 64;
    PeerStampEntry entries[capacity]{};
    unsigned count = 0;
    const char *find(const char *callsign) const;
    bool remember(const char *callsign, const char *style_id);
};

enum class StampLoad { Missing, Ready, Unavailable };

bool stamp_style_valid(const char *style_id);
bool stamp_label_valid(const char *label);
bool stamp_is_custom_style(const char *style_id);
// Returns 0..11 if style_id is G001..G012, otherwise -1.
int stamp_builtin_index(const char *style_id);
// Deterministic fallback 0..11 derived from callsign when peer has no known G001..G012 style.
unsigned stamp_fallback_index(const char *callsign);
const char *stamp_builtin_id(unsigned index);
const char *stamp_builtin_name(unsigned index);

// Parse `CALL>APPASP,...:...PAT-1,ST:<ID>,...` (informational visual stamp only).
bool parse_pat1_stamp(const char *line, size_t size, char callsign[13], char style_id[8]);

// Build LVGL v9 LV_COLOR_FORMAT_I4 16-entry BGRA8888 palette tinted to color_rgb on black bg.
void stamp_build_palette(uint32_t color_rgb, uint8_t palette[kStampPaletteBytes]);
// Rasterize one of the 12 built-in geometric passport stamps into 96x96 4-bit I4 pixels.
void stamp_render_builtin(unsigned index, uint8_t pixels[kStampPixelBytes]);
// Check whether a custom 4-bit bitmap has at least some visible ink pixels.
bool stamp_pixels_nonempty(const uint8_t pixels[kStampPixelBytes]);

StampLoad load_stamp_config(StampConfig *out);
bool save_stamp_config(const StampConfig &cfg);
StampLoad load_custom_stamp_image(const StampConfig &cfg, uint8_t pixels[kStampPixelBytes]);
bool save_custom_stamp_image(const uint8_t pixels[kStampPixelBytes], StampConfig *cfg, bool initialize_blank);
bool clear_custom_stamp_image(StampConfig *cfg);

StampLoad load_peer_stamps(PeerStamps *out);
bool save_peer_stamps(const PeerStamps &stamps);
}
