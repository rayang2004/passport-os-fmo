#include "fmo_beep.h"
#include "fmo_wire.h"
#include "fmo_host_bridge.h"
#include "nvs.h"
#include <algorithm>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <mutex>
#include <string>
#include <sys/stat.h>
#include <unistd.h>

#ifndef FMO_BEEP_BASE
#define FMO_BEEP_BASE "/storage"
#endif

namespace fmo {
namespace {

std::mutex beep_mutex;
unsigned active_readers[2]{};
constexpr size_t kBeepConfigBlobSize = 24;
constexpr uint32_t kBeepConfigMagic = 0x46425031u; // "FBP1"
constexpr uint32_t kBeepConfigVersion = 1;

uint16_t get16(const uint8_t *p) {
    return uint16_t(p[0]) | (uint16_t(p[1]) << 8);
}
uint32_t get32(const uint8_t *p) {
    return uint32_t(p[0]) | (uint32_t(p[1]) << 8) | (uint32_t(p[2]) << 16) | (uint32_t(p[3]) << 24);
}
void put32(uint8_t *p, uint32_t n) {
    for (unsigned i = 0; i < 4; ++i) p[i] = static_cast<uint8_t>(n >> (8 * i));
}

// 64-entry sine LUT scaled to amplitude 10000 (~-10.3 dBFS, clean for Opus & speaker).
constexpr int16_t kSine64[64] = {
        0,   980,  1951,  2903,  3827,  4714,  5556,  6344,
     7071,  7730,  8315,  8819,  9239,  9569,  9808,  9952,
    10000,  9952,  9808,  9569,  9239,  8819,  8315,  7730,
     7071,  6344,  5556,  4714,  3827,  2903,  1951,   980,
        0,  -980, -1951, -2903, -3827, -4714, -5556, -6344,
    -7071, -7730, -8315, -8819, -9239, -9569, -9808, -9952,
   -10000, -9952, -9808, -9569, -9239, -8819, -8315, -7730,
    -7071, -6344, -5556, -4714, -3827, -2903, -1951,  -980,
};

int16_t synth_tone_sample(uint32_t local_idx, uint32_t total_len, uint32_t freq_hz) {
    if (local_idx >= total_len || !total_len) return 0;
    // Phase index in [0..63] with 16-bit fractional step: phase_step = freq * 64 / 8000
    const uint64_t phase = (uint64_t(local_idx) * uint64_t(freq_hz) * 64u) / kBeepSampleRate;
    int32_t sample = kSine64[phase & 63u];
    // 40-sample (5 ms) linear attack and release envelope to avoid clicks.
    constexpr uint32_t kFade = 40;
    if (local_idx < kFade) {
        sample = (sample * int32_t(local_idx)) / int32_t(kFade);
    } else if (total_len - 1u - local_idx < kFade) {
        sample = (sample * int32_t(total_len - 1u - local_idx)) / int32_t(kFade);
    }
    return static_cast<int16_t>(sample);
}

std::string bank_path(unsigned bank) {
    return std::string(FMO_BEEP_BASE) + (bank ? "/fmo-beep-b.bin" : "/fmo-beep-a.bin");
}

struct StorageRelease {
    ~StorageRelease() { fmo_storage_release(); }
};

uint32_t crc32_update(uint32_t state, const uint8_t *p, size_t n) {
    uint32_t c = state;
    while (n--) {
        c ^= *p++;
        for (unsigned i = 0; i < 8; ++i) c = (c >> 1) ^ (0xedb88320u & (0u - (c & 1u)));
    }
    return c;
}

bool verify_beep_file(const std::string &path, uint8_t expected_id, uint32_t expected_samples, uint32_t expected_crc) {
    struct stat st{};
    if (stat(path.c_str(), &st) != 0 || !S_ISREG(st.st_mode)) return false;
    const size_t expected_size = kBeepHeaderBytes + size_t(expected_samples) * sizeof(int16_t);
    if (st.st_size != static_cast<off_t>(expected_size)) return false;
    FILE *f = fopen(path.c_str(), "rb");
    if (!f) return false;
    uint8_t hdr[kBeepHeaderBytes];
    bool ok = fread(hdr, 1, sizeof(hdr), f) == sizeof(hdr);
    if (ok) {
        const uint8_t ver = hdr[4], id = hdr[5];
        const uint16_t rsv = get16(hdr + 6);
        const uint32_t samples = get32(hdr + 8);
        const uint32_t hdr_crc = get32(hdr + 12);
        if (std::memcmp(hdr, "FBEP", 4) != 0 || ver != 1 || id != expected_id || rsv != 0 ||
            samples != expected_samples || hdr_crc != expected_crc) {
            ok = false;
        }
    }
    uint32_t crc = 0xffffffffu;
    size_t remaining = size_t(expected_samples) * sizeof(int16_t);
    uint8_t buf[512];
    while (ok && remaining > 0) {
        const size_t chunk = std::min(sizeof(buf), remaining);
        const size_t got = fread(buf, 1, chunk, f);
        if (!got) { ok = false; break; }
        crc = crc32_update(crc, buf, got);
        remaining -= got;
    }
    if (ferror(f)) ok = false;
    if (fclose(f) != 0) ok = false;
    return ok && remaining == 0 && (~crc) == expected_crc;
}

bool write_beep_file(const std::string &path, const uint8_t *data, size_t size) {
    FILE *f = fopen(path.c_str(), "wb");
    if (!f) return false;
    size_t written = 0;
    bool ok = true;
    while (written < size) {
        const size_t chunk = std::min<size_t>(512, size - written);
        if (fwrite(data + written, 1, chunk, f) != chunk) { ok = false; break; }
        written += chunk;
    }
    if (ok && fflush(f) != 0) ok = false;
    if (fclose(f) != 0) ok = false;
    return ok && written == size;
}

BeepLoad load_config_locked(BeepConfig *out) {
    nvs_handle_t h;
    auto e = nvs_open("fmo_os", NVS_READONLY, &h);
    if (e == ESP_ERR_NVS_NOT_FOUND) { *out = BeepConfig{}; return BeepLoad::Missing; }
    if (e != ESP_OK) return BeepLoad::Unavailable;
    uint8_t blob[kBeepConfigBlobSize]{};
    size_t n = sizeof(blob);
    e = nvs_get_blob(h, "beep_v1", blob, &n);
    nvs_close(h);
    if (e == ESP_ERR_NVS_NOT_FOUND) { *out = BeepConfig{}; return BeepLoad::Missing; }
    if (e != ESP_OK || n != sizeof(blob)) return BeepLoad::Unavailable;
    if (get32(blob) != kBeepConfigMagic || blob[4] != kBeepConfigVersion) return BeepLoad::Unavailable;
    if (get32(blob + 20) != crc32(blob, 20)) return BeepLoad::Unavailable;
    const uint8_t flags = blob[5];
    if (flags & ~0x07u) return BeepLoad::Unavailable;
    const uint8_t custom_id = blob[6];
    const uint8_t bank = blob[7];
    const uint32_t samples = get32(blob + 8);
    const uint32_t pcrc = get32(blob + 12);
    if (bank > 1 || get32(blob + 16) != 0) return BeepLoad::Unavailable;
    const bool present = (flags & 0x04u) != 0;
    const bool use_custom = (flags & 0x02u) != 0;
    if (present) {
        if (!custom_id || samples < kBeepFrameSamples || samples > kBeepMaxCustomSamples || (samples % kBeepFrameSamples) != 0) {
            return BeepLoad::Unavailable;
        }
    } else if (use_custom || custom_id || samples || pcrc) {
        return BeepLoad::Unavailable;
    }
    BeepConfig cfg{};
    cfg.enabled = (flags & 0x01u) != 0;
    cfg.use_custom = use_custom;
    cfg.custom_present = present;
    cfg.custom_id = custom_id;
    cfg.custom_bank = bank;
    cfg.custom_samples = samples;
    cfg.custom_crc = pcrc;
    *out = cfg;
    return BeepLoad::Ready;
}

bool save_config_locked(const BeepConfig &cfg) {
    if (cfg.custom_bank > 1) return false;
    if (cfg.use_custom && !cfg.custom_present) return false;
    if (cfg.custom_present) {
        if (!cfg.custom_id || cfg.custom_samples < kBeepFrameSamples ||
            cfg.custom_samples > kBeepMaxCustomSamples || (cfg.custom_samples % kBeepFrameSamples) != 0) {
            return false;
        }
    }
    uint8_t blob[kBeepConfigBlobSize]{};
    put32(blob, kBeepConfigMagic);
    blob[4] = kBeepConfigVersion;
    blob[5] = (cfg.enabled ? 0x01u : 0u) | (cfg.use_custom ? 0x02u : 0u) | (cfg.custom_present ? 0x04u : 0u);
    blob[6] = cfg.custom_present ? cfg.custom_id : 0;
    blob[7] = cfg.custom_present ? cfg.custom_bank : 0;
    put32(blob + 8, cfg.custom_present ? cfg.custom_samples : 0);
    put32(blob + 12, cfg.custom_present ? cfg.custom_crc : 0);
    put32(blob + 16, 0);
    put32(blob + 20, crc32(blob, 20));
    nvs_handle_t h;
    auto e = nvs_open("fmo_os", NVS_READWRITE, &h);
    if (e != ESP_OK) return false;
    e = nvs_set_blob(h, "beep_v1", blob, sizeof(blob));
    if (e == ESP_OK) e = nvs_commit(h);
    nvs_close(h);
    return e == ESP_OK;
}

} // namespace

void beep_render_builtin(uint32_t sample_offset, int16_t *out, uint32_t count) {
    if (!out || !count) return;
    for (uint32_t i = 0; i < count; ++i) {
        const uint32_t idx = sample_offset + i;
        if (idx < 960u) {
            out[i] = synth_tone_sample(idx, 960u, 960u);
        } else if (idx >= 1200u && idx < 2480u) {
            out[i] = synth_tone_sample(idx - 1200u, 1280u, 640u);
        } else {
            out[i] = 0;
        }
    }
}

void beep_render_ptt_start(int16_t *out, uint32_t count) {
    if (!out || !count) return;
    const uint32_t total = std::min(count, kBeepPttStartSamples);
    for (uint32_t i = 0; i < total; ++i) {
        out[i] = synth_tone_sample(i, total, 1200u);
    }
    for (uint32_t i = total; i < count; ++i) out[i] = 0;
}

const char *beep_cloud_name(uint8_t id) {
    switch (id) {
        case 1: return "模拟信令";
        case 2: return "羊叫";
        case 3: return "蛙叫";
        case 4: return "鸭呱呱";
        case 5: return "牛叫";
        case 6: return "鸭子叫";
        default: return nullptr;
    }
}

bool beep_parse_fbep(const uint8_t *data, size_t size, uint8_t *id_out, uint32_t *samples_out, uint32_t *crc_out) {
    if (!data || size < kBeepHeaderBytes + kBeepFrameSamples * sizeof(int16_t) || size > kBeepMaxFileBytes) return false;
    if (std::memcmp(data, "FBEP", 4) != 0) return false;
    const uint8_t ver = data[4];
    const uint8_t id = data[5];
    const uint16_t rsv = get16(data + 6);
    const uint32_t samples = get32(data + 8);
    const uint32_t hdr_crc = get32(data + 12);
    if (ver != 1 || id == 0 || rsv != 0) return false;
    if (samples < kBeepFrameSamples || samples > kBeepMaxCustomSamples || (samples % kBeepFrameSamples) != 0) return false;
    const size_t expected_size = kBeepHeaderBytes + size_t(samples) * sizeof(int16_t);
    if (size != expected_size) return false;
    const uint32_t actual_crc = crc32(data + kBeepHeaderBytes, size - kBeepHeaderBytes);
    if (actual_crc != hdr_crc) return false;
    if (id_out) *id_out = id;
    if (samples_out) *samples_out = samples;
    if (crc_out) *crc_out = hdr_crc;
    return true;
}

BeepLoad load_beep_config(BeepConfig *out) {
    if (!out) return BeepLoad::Unavailable;
    std::lock_guard<std::mutex> guard(beep_mutex);
    return load_config_locked(out);
}

bool save_beep_config(const BeepConfig &cfg) {
    std::lock_guard<std::mutex> guard(beep_mutex);
    BeepConfig current{};
    const auto loaded = load_config_locked(&current);
    if (loaded == BeepLoad::Unavailable) return false;
    if (cfg.custom_present != current.custom_present ||
        cfg.custom_id != current.custom_id ||
        cfg.custom_bank != current.custom_bank ||
        cfg.custom_samples != current.custom_samples ||
        cfg.custom_crc != current.custom_crc) {
        return false;
    }
    return save_config_locked(cfg);
}

bool save_custom_beep_fbep(const uint8_t *data, size_t size, BeepConfig *cfg, bool allow_format) {
    uint8_t id = 0;
    uint32_t samples = 0, payload_crc = 0;
    if (!beep_parse_fbep(data, size, &id, &samples, &payload_crc)) return false;

    std::lock_guard<std::mutex> guard(beep_mutex);
    BeepConfig current{};
    if (load_config_locked(&current) == BeepLoad::Unavailable) return false;
    if (fmo_storage_acquire(allow_format) != ESP_OK) return false;
    StorageRelease release;

    unsigned target_bank = 0;
    if (current.custom_present) {
        const unsigned active = current.custom_bank ? 1u : 0u;
        target_bank = verify_beep_file(bank_path(active), current.custom_id, current.custom_samples, current.custom_crc)
                          ? (active ^ 1u)
                          : active;
    }
    if (active_readers[target_bank]) return false;
    const auto path = bank_path(target_bank);
    if (!write_beep_file(path, data, size)) return false;
    if (!verify_beep_file(path, id, samples, payload_crc)) {
        unlink(path.c_str());
        return false;
    }
    current.enabled = true;
    current.use_custom = true;
    current.custom_present = true;
    current.custom_id = id;
    current.custom_bank = static_cast<uint8_t>(target_bank);
    current.custom_samples = samples;
    current.custom_crc = payload_crc;
    if (!save_config_locked(current)) return false;
    if (cfg) *cfg = current;
    return true;
}

bool save_custom_beep_stream(size_t total_size, uint8_t expected_id, BeepChunkReader reader, void *ctx,
                             BeepConfig *cfg, bool allow_format) {
    if (!reader || total_size < kBeepHeaderBytes + kBeepFrameSamples * sizeof(int16_t) ||
        total_size > kBeepMaxFileBytes) {
        return false;
    }
    uint8_t hdr[kBeepHeaderBytes]{};
    size_t got = 0;
    while (got < sizeof(hdr)) {
        const int n = reader(ctx, hdr + got, sizeof(hdr) - got);
        if (n <= 0) return false;
        got += static_cast<size_t>(n);
    }
    const uint8_t ver = hdr[4], id = hdr[5];
    const uint16_t rsv = get16(hdr + 6);
    const uint32_t samples = get32(hdr + 8);
    const uint32_t payload_crc = get32(hdr + 12);
    if (std::memcmp(hdr, "FBEP", 4) != 0 || ver != 1 || id == 0 || rsv != 0) return false;
    if (expected_id != 0 && id != expected_id) return false;
    if (samples < kBeepFrameSamples || samples > kBeepMaxCustomSamples || (samples % kBeepFrameSamples) != 0) {
        return false;
    }
    if (total_size != kBeepHeaderBytes + size_t(samples) * sizeof(int16_t)) return false;

    std::lock_guard<std::mutex> guard(beep_mutex);
    BeepConfig current{};
    if (load_config_locked(&current) == BeepLoad::Unavailable) return false;
    if (fmo_storage_acquire(allow_format) != ESP_OK) return false;
    StorageRelease release;

    unsigned target_bank = 0;
    if (current.custom_present) {
        const unsigned active = current.custom_bank ? 1u : 0u;
        target_bank = verify_beep_file(bank_path(active), current.custom_id, current.custom_samples, current.custom_crc)
                          ? (active ^ 1u)
                          : active;
    }
    if (active_readers[target_bank]) return false;
    const auto path = bank_path(target_bank);
    FILE *f = fopen(path.c_str(), "wb");
    if (!f) return false;
    bool ok = fwrite(hdr, 1, sizeof(hdr), f) == sizeof(hdr);
    size_t remaining = total_size - sizeof(hdr);
    uint8_t buf[512];
    while (ok && remaining > 0) {
        const size_t want = std::min(sizeof(buf), remaining);
        const int n = reader(ctx, buf, want);
        if (n <= 0 || static_cast<size_t>(n) > want) { ok = false; break; }
        if (fwrite(buf, 1, static_cast<size_t>(n), f) != static_cast<size_t>(n)) { ok = false; break; }
        remaining -= static_cast<size_t>(n);
    }
    if (ok && fflush(f) != 0) ok = false;
    if (fclose(f) != 0) ok = false;
    if (!ok || remaining != 0 || !verify_beep_file(path, id, samples, payload_crc)) {
        unlink(path.c_str());
        return false;
    }
    current.enabled = true;
    current.use_custom = true;
    current.custom_present = true;
    current.custom_id = id;
    current.custom_bank = static_cast<uint8_t>(target_bank);
    current.custom_samples = samples;
    current.custom_crc = payload_crc;
    if (!save_config_locked(current)) return false;
    if (cfg) *cfg = current;
    return true;
}

bool clear_custom_beep(BeepConfig *cfg) {
    std::lock_guard<std::mutex> guard(beep_mutex);
    BeepConfig current{};
    if (load_config_locked(&current) == BeepLoad::Unavailable) return false;
    current.use_custom = false;
    current.custom_present = false;
    current.custom_id = 0;
    current.custom_bank = 0;
    current.custom_samples = 0;
    current.custom_crc = 0;
    if (!save_config_locked(current)) return false;
    if (fmo_storage_acquire(false) == ESP_OK) {
        StorageRelease release;
        for (unsigned bank = 0; bank < 2; ++bank) {
            if (!active_readers[bank]) unlink(bank_path(bank).c_str());
        }
    }
    if (cfg) *cfg = current;
    return true;
}

BeepStream::~BeepStream() {
    close();
}

void BeepStream::open(const BeepConfig &cfg) {
    close();
    custom_ = false;
    total_ = kBeepBuiltinSamples;
    if (!cfg.use_custom || !cfg.custom_present || cfg.custom_samples < kBeepFrameSamples ||
        cfg.custom_samples > kBeepMaxCustomSamples || (cfg.custom_samples % kBeepFrameSamples) != 0) {
        return;
    }
    std::lock_guard<std::mutex> guard(beep_mutex);
    if (fmo_storage_acquire(false) != ESP_OK) return;
    StorageRelease release;
    bank_ = cfg.custom_bank ? 1u : 0u;
    if (!verify_beep_file(bank_path(bank_), cfg.custom_id, cfg.custom_samples, cfg.custom_crc)) return;
    ++active_readers[bank_];
    custom_ = true;
    total_ = cfg.custom_samples;
}

void BeepStream::close() {
    if (custom_) {
        std::lock_guard<std::mutex> guard(beep_mutex);
        --active_readers[bank_];
    }
    custom_ = false;
    total_ = kBeepBuiltinSamples;
}

void BeepStream::read_samples(uint32_t sample_offset, int16_t *out, uint32_t count) {
    if (!out || !count) return;
    if (!custom_) {
        beep_render_builtin(sample_offset, out, count);
        return;
    }
    if (sample_offset >= total_) {
        std::memset(out, 0, count * sizeof(int16_t));
        return;
    }
    const long byte_offset = static_cast<long>(kBeepHeaderBytes + size_t(sample_offset) * sizeof(int16_t));
    const uint32_t avail = std::min(count, total_ - sample_offset);
    bool ok = false;
    if (fmo_storage_acquire(false) == ESP_OK) {
        StorageRelease release;
        FILE *file = fopen(bank_path(bank_).c_str(), "rb");
        if (file) {
            ok = fseek(file, byte_offset, SEEK_SET) == 0
                 && fread(out, sizeof(int16_t), avail, file) == avail;
            fclose(file);
        }
    }
    if (!ok) {
        // Fallback safely to built-in dual-tone on flash read error.
        beep_render_builtin(sample_offset, out, count);
        return;
    }
    if (avail < count) {
        std::memset(out + avail, 0, (count - avail) * sizeof(int16_t));
    }
}

} // namespace fmo
