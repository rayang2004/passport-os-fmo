#pragma once
#include <cstddef>
#include <cstdint>

namespace fmo {

constexpr uint32_t kBeepSampleRate = 8000;
constexpr uint32_t kBeepFrameSamples = 320;      // 40 ms @ 8 kHz (one Opus frame)
constexpr uint32_t kBeepPttStartSamples = 360;   // 45 ms @ 8 kHz (1200 Hz PTT start chirp, v0.6.11)
constexpr uint32_t kBeepBuiltinSamples = 2560;   // 320 ms (960 Hz 120ms + 30ms + 640 Hz 160ms + 10ms)
constexpr uint32_t kBeepMaxCustomSamples = 24000; // 3.0 s max (48,000 B PCM)
constexpr size_t kBeepHeaderBytes = 16;          // "FBEP" + ver(1) + id(1) + rsv(2) + samples(4) + crc32(4)
constexpr size_t kBeepMaxFileBytes = kBeepHeaderBytes + kBeepMaxCustomSamples * sizeof(int16_t);

struct BeepConfig {
    bool enabled = true;
    bool use_custom = false;
    bool custom_present = false;
    uint8_t custom_id = 0;
    uint8_t custom_bank = 0;
    uint32_t custom_samples = 0;
    uint32_t custom_crc = 0;
};

enum class BeepLoad { Ready, Missing, Unavailable };

// Built-in dual-tone Roger Beep matching FMO Passport v0.6.11 (960 Hz -> 640 Hz, 8 kHz s16le).
void beep_render_builtin(uint32_t sample_offset, int16_t *out, uint32_t count);
// Built-in PTT start chirp matching FMO Passport v0.6.11 (1200 Hz, 45 ms = 360 samples @ 8 kHz).
void beep_render_ptt_start(int16_t *out, uint32_t count = kBeepPttStartSamples);
// Friendly label for known official cloud beep IDs (1..6), or nullptr if unknown.
const char *beep_cloud_name(uint8_t id);

// Validate an FBEP binary blob (header + payload length + frame alignment + CRC32).
bool beep_parse_fbep(const uint8_t *data, size_t size, uint8_t *id_out, uint32_t *samples_out, uint32_t *crc_out);

using BeepChunkReader = int (*)(void *ctx, uint8_t *buf, size_t max_len);

BeepLoad load_beep_config(BeepConfig *out);
bool save_beep_config(const BeepConfig &cfg);
bool save_custom_beep_fbep(const uint8_t *data, size_t size, BeepConfig *cfg, bool allow_format = true);
bool save_custom_beep_stream(size_t total_size, uint8_t expected_id, BeepChunkReader reader, void *ctx,
                             BeepConfig *cfg, bool allow_format = true);
bool clear_custom_beep(BeepConfig *cfg);

// Streaming reader for transmitting or playing a Roger Beep frame-by-frame without
// holding the entire custom PCM buffer in ESP32-C3 SRAM. Falls back to built-in tone
// if the custom file cannot be verified.
class BeepStream {
public:
    BeepStream() = default;
    ~BeepStream();
    BeepStream(const BeepStream &) = delete;
    BeepStream &operator=(const BeepStream &) = delete;

    void open(const BeepConfig &cfg);
    void close();
    uint32_t total_samples() const { return total_; }
    bool is_custom() const { return custom_; }
    void read_samples(uint32_t sample_offset, int16_t *out, uint32_t count);

private:
    unsigned bank_ = 0;
    bool custom_ = false;
    uint32_t total_ = kBeepBuiltinSamples;
};

} // namespace fmo
