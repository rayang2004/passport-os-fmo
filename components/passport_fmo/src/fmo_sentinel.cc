#include "fmo_sentinel.h"

#ifdef ESP_PLATFORM

#include "bsp_audio.h"
#include "bsp_audio_workspace.h"
#include "bsp_display.h"
#include "esp_heap_caps.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "fmo_aprs.h"
#include "fmo_crypto.h"
#include "fmo_host_bridge.h"
#include "fmo_mqtt.h"
#include "fmo_revocation.h"
#include "fmo_store.h"
#include "fmo_wire.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "freertos/task.h"
#include "mqtt_client.h"
#include <sodium.h>

#include <algorithm>
#include <atomic>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <new>
#include <string>

extern const char fmo_root_start[] asm("_binary_passport_root_json_start");

namespace {

constexpr char kTag[] = "fmo_sentinel";
// Compact variable-length byte ring: holds ~55-75 Opus frames (~2.2-3.0s) in
// only 5.1 KiB, absorbing initial Wi-Fi MAX_MODEM wakeup bursts and Radio/NetEase
// audio yield latency without dropping opening syllables.
constexpr size_t kRingCapacityBytes = 5120;
constexpr size_t kMaxFrameBytes = 336;  // covers both Opus (~80 B) and RADPCM (328 B)
constexpr int64_t kBreakinSilenceUs = 3500000;  // 3.5 seconds silence before auto-resume
constexpr uint32_t kBreakinTaskStack = 6144;
// Require generous headroom before spawning the 6 KB fmo_sinit crypto/MQTT
// handshake so sentinel startup NEVER collides with NetEase/Radio TLS peaks
// or trips app_registry's s_heap_strained clean-launch reboot flag.
constexpr size_t kMinFreeHeapToStart = 36 * 1024;
constexpr size_t kMinLargestBlockToStart = 16 * 1024;

struct FrameHeader {
    uint32_t uid;
    uint32_t stream_begin;
    uint16_t size;
    uint8_t codec;
    char callsign[13];
};

struct QueuedFrame {
    uint32_t uid = 0;
    uint32_t stream_begin = 0;
    uint16_t size = 0;
    uint8_t codec = 1;
    char callsign[13]{};
    uint8_t data[kMaxFrameBytes]{};
};

struct FrameRing {
    uint8_t buf[kRingCapacityBytes]{};
    size_t head = 0;
    size_t tail = 0;
    size_t used = 0;
    uint32_t dropped = 0;

    void write_bytes(const void *src, size_t n) {
        const auto *p = static_cast<const uint8_t *>(src);
        const size_t first = std::min(n, kRingCapacityBytes - tail);
        std::memcpy(buf + tail, p, first);
        if (n > first) std::memcpy(buf, p + first, n - first);
        tail = (tail + n) % kRingCapacityBytes;
        used += n;
    }
    void read_bytes(void *dst, size_t n) {
        auto *p = static_cast<uint8_t *>(dst);
        const size_t first = std::min(n, kRingCapacityBytes - head);
        std::memcpy(p, buf + head, first);
        if (n > first) std::memcpy(p + first, buf, n - first);
        head = (head + n) % kRingCapacityBytes;
        used -= n;
    }
    void skip_bytes(size_t n) {
        head = (head + n) % kRingCapacityBytes;
        used -= n;
    }
    void drop_oldest() {
        if (used < sizeof(FrameHeader)) { head = tail = used = 0; return; }
        FrameHeader h{};
        read_bytes(&h, sizeof(h));
        if (h.size <= used) skip_bytes(h.size);
        else { head = tail = used = 0; }
        ++dropped;
    }
    void push_frame(uint32_t uid, uint32_t stream_begin, uint8_t codec,
                    const char *callsign, const uint8_t *data, uint16_t size) {
        const size_t need = sizeof(FrameHeader) + size;
        if (need > kRingCapacityBytes) return;
        while (kRingCapacityBytes - used < need) drop_oldest();
        FrameHeader h{};
        h.uid = uid;
        h.stream_begin = stream_begin;
        h.size = size;
        h.codec = codec;
        std::snprintf(h.callsign, sizeof(h.callsign), "%.12s", callsign ? callsign : "");
        write_bytes(&h, sizeof(h));
        write_bytes(data, size);
    }
    bool pop(QueuedFrame *out) {
        if (!out || used < sizeof(FrameHeader)) return false;
        FrameHeader h{};
        read_bytes(&h, sizeof(h));
        if (h.size > kMaxFrameBytes || h.size > used) {
            head = tail = used = 0;
            return false;
        }
        out->uid = h.uid;
        out->stream_begin = h.stream_begin;
        out->size = h.size;
        out->codec = h.codec;
        std::memcpy(out->callsign, h.callsign, sizeof(out->callsign));
        read_bytes(out->data, h.size);
        return true;
    }
};

StaticSemaphore_t s_ctrl_mutex_buf;
SemaphoreHandle_t s_ctrl_mutex = nullptr;
StaticSemaphore_t s_ring_mutex_buf;
SemaphoreHandle_t s_ring_mutex = nullptr;

esp_mqtt_client_handle_t s_mqtt = nullptr;
uint8_t *s_assembly = nullptr;
FrameRing *s_ring = nullptr;
fmo::MqttInbox s_inbox;
fmo::Relay s_relay{};
bool s_relay_builtin = false;
uint32_t s_self_uid = 0;
int64_t s_last_connect_try_us = 0;

std::atomic<bool> s_mqtt_connected{false};
std::atomic<bool> s_mqtt_error{false};
std::atomic<bool> s_stop_requested{false};
std::atomic<bool> s_suppressed_by_host{false};
std::atomic<bool> s_breakin_running{false};
std::atomic<bool> s_start_task_running{false};
std::atomic<bool> s_want_sentinel{false};

// On-demand top-layer LVGL callsign banner (zero heap when idle).
lv_obj_t *s_banner_card = nullptr;
lv_obj_t *s_banner_call = nullptr;
lv_obj_t *s_banner_relay = nullptr;

void breakin_banner_show(const char *callsign, const char *relay_tag) {
    if (!callsign || !callsign[0]) return;
    if (!bsp_lvgl_lock(60)) return;
    fmo_wake_for_notice();
    if (!s_banner_card) {
        s_banner_card = lv_obj_create(lv_layer_top());
        if (s_banner_card) {
            lv_obj_remove_flag(s_banner_card, LV_OBJ_FLAG_SCROLLABLE);
            lv_obj_set_pos(s_banner_card, 10, 8);
            lv_obj_set_size(s_banner_card, 220, 62);
            lv_obj_set_style_radius(s_banner_card, 10, 0);
            lv_obj_set_style_bg_color(s_banner_card, lv_color_hex(0x145C40), 0);
            lv_obj_set_style_bg_opa(s_banner_card, LV_OPA_COVER, 0);
            lv_obj_set_style_border_width(s_banner_card, 2, 0);
            lv_obj_set_style_border_color(s_banner_card, lv_color_hex(0x2EA073), 0);
            lv_obj_set_style_pad_all(s_banner_card, 0, 0);

            lv_obj_t *dot = lv_obj_create(s_banner_card);
            lv_obj_remove_flag(dot, LV_OBJ_FLAG_SCROLLABLE);
            lv_obj_set_pos(dot, 10, 10);
            lv_obj_set_size(dot, 8, 8);
            lv_obj_set_style_radius(dot, 4, 0);
            lv_obj_set_style_bg_color(dot, lv_color_hex(0x7EF0C2), 0);
            lv_obj_set_style_bg_opa(dot, LV_OPA_COVER, 0);
            lv_obj_set_style_border_width(dot, 0, 0);

            lv_obj_t *tag = fmo_pixel_label(s_banner_card, "FMO 守听插播", fmo_font_16(), 0xD9F7EA);
            if (tag) {
                lv_obj_set_pos(tag, 24, 5);
                lv_obj_set_size(tag, 112, 20);
            }

            s_banner_relay = fmo_pixel_label(s_banner_card, "", fmo_font_16(), 0xA9E5CE);
            if (s_banner_relay) {
                lv_obj_set_pos(s_banner_relay, 134, 5);
                lv_obj_set_size(s_banner_relay, 76, 20);
                lv_obj_set_style_text_align(s_banner_relay, LV_TEXT_ALIGN_RIGHT, 0);
                lv_label_set_long_mode(s_banner_relay, LV_LABEL_LONG_DOT);
            }

            s_banner_call = fmo_pixel_label(s_banner_card, "", fmo_font_20(), 0xFFFFFF);
            if (s_banner_call) {
                lv_obj_set_pos(s_banner_call, 10, 29);
                lv_obj_set_size(s_banner_call, 200, 26);
                lv_obj_set_style_text_align(s_banner_call, LV_TEXT_ALIGN_CENTER, 0);
                lv_label_set_long_mode(s_banner_call, LV_LABEL_LONG_DOT);
            }
        }
    }
    if (s_banner_call) fmo_pixel_label_set_text(s_banner_call, callsign);
    if (s_banner_relay) fmo_pixel_label_set_text(s_banner_relay, relay_tag ? relay_tag : "");
    bsp_lvgl_unlock();
}

void breakin_banner_hide() {
    if (!bsp_lvgl_lock(500)) return;
    if (s_banner_card) {
        lv_obj_delete(s_banner_card);
        s_banner_card = nullptr;
        s_banner_call = nullptr;
        s_banner_relay = nullptr;
    }
    bsp_lvgl_unlock();
}

void ensure_mutexes() {
    if (!s_ctrl_mutex) s_ctrl_mutex = xSemaphoreCreateMutexStatic(&s_ctrl_mutex_buf);
    if (!s_ring_mutex) s_ring_mutex = xSemaphoreCreateMutexStatic(&s_ring_mutex_buf);
}

int decode_radpcm(const uint8_t *data, size_t size, int16_t *pcm) {
    static constexpr int steps[] = {
        7,8,9,10,11,12,13,14,16,17,19,21,23,25,28,31,34,37,41,45,50,55,60,66,73,80,88,97,107,
        118,130,143,157,173,190,209,230,253,279,307,337,371,408,449,494,544,598,658,724,796,
        876,963,1060,1166,1282,1411,1552,1707,1878,2066,2272,2499,2749,3024,3327,3660,4026,
        4428,4871,5358,5894,6484,7132,7845,8630,9493,10442,11487,12635,13899,15289,16818,
        18500,20350,22385,24623,27086,29794,32767
    };
    static constexpr int indices[] = {-1, -1, -1, -1, 2, 4, 6, 8};
    if (!data || size != 328 || data[4] > 88) return -1;
    int predictor = static_cast<int16_t>(data[2] | (uint16_t(data[3]) << 8));
    int index = data[4];
    for (unsigned i = 0; i < 640; ++i) {
        const unsigned nibble = (data[8 + i / 2] >> (i % 2 ? 0 : 4)) & 15;
        int step = steps[index];
        int diff = step >> 3;
        if (nibble & 1) diff += step >> 2;
        if (nibble & 2) diff += step >> 1;
        if (nibble & 4) diff += step;
        predictor = std::clamp(predictor + ((nibble & 8) ? -diff : diff), -32768, 32767);
        index = std::clamp(index + indices[nibble & 7], 0, 88);
        pcm[i] = static_cast<int16_t>(predictor);
    }
    return 640;
}

bool pop_frame(QueuedFrame *out) {
    if (!s_ring_mutex || !s_ring) return false;
    bool ok = false;
    if (xSemaphoreTake(s_ring_mutex, pdMS_TO_TICKS(10)) == pdTRUE) {
        ok = s_ring->pop(out);
        xSemaphoreGive(s_ring_mutex);
    }
    return ok;
}

void free_ring() {
    if (!s_ring_mutex) return;
    if (xSemaphoreTake(s_ring_mutex, pdMS_TO_TICKS(50)) == pdTRUE) {
        delete s_ring;
        s_ring = nullptr;
        xSemaphoreGive(s_ring_mutex);
    }
}

void breakin_task(void *) {
    ESP_LOGI(kTag, "Voice break-in requested; acquiring audio focus...");
    bool focus_acquired = false;
    bool workspace_acquired = false;
    bool audio_open = false;
    uint32_t frames_played = 0;
    char speaker[13]{};

    if (!s_stop_requested.load(std::memory_order_acquire)) {
        focus_acquired = fmo_audio_focus_begin_breakin(2500);
    }
    if (!focus_acquired || s_stop_requested.load(std::memory_order_acquire)) {
        ESP_LOGW(kTag, "Voice break-in aborted before focus (focus=%d stop=%d)",
                 (int)focus_acquired, (int)s_stop_requested.load());
        free_ring();
        const bool suppressed = s_suppressed_by_host.load(std::memory_order_acquire);
        s_breakin_running.store(false, std::memory_order_release);
        if (focus_acquired && !suppressed) fmo_audio_focus_end_breakin();
        vTaskDelete(nullptr);
        return;
    }

    for (int waited = 0; waited < 1000 && !s_stop_requested.load(std::memory_order_acquire); waited += 20) {
        if (audio_workspace::acquire(audio_workspace::Owner::Plugin)) {
            workspace_acquired = true;
            break;
        }
        vTaskDelay(pdMS_TO_TICKS(20));
    }

    const int dec_bytes = opus_decoder_get_size(1);
    const size_t aligned_dec = (dec_bytes > 0) ? ((static_cast<size_t>(dec_bytes) + 15u) & ~size_t(15u)) : 0;
    const size_t pcm_bytes = 640 * sizeof(int16_t);
    if (!workspace_acquired || dec_bytes <= 0 || aligned_dec + pcm_bytes > audio_workspace::kBytes) {
        ESP_LOGE(kTag, "Break-in workspace unavailable (acq=%d dec=%d)", (int)workspace_acquired, dec_bytes);
        if (workspace_acquired) audio_workspace::release(audio_workspace::Owner::Plugin);
        free_ring();
        const bool suppressed = s_suppressed_by_host.load(std::memory_order_acquire);
        s_breakin_running.store(false, std::memory_order_release);
        if (!suppressed) fmo_audio_focus_end_breakin();
        vTaskDelete(nullptr);
        return;
    }

    auto *decoder = reinterpret_cast<OpusDecoder *>(audio_workspace::storage);
    auto *pcm = reinterpret_cast<int16_t *>(audio_workspace::storage + aligned_dec);
    bool decoder_ready = false;

    audio_open = (bsp_audio_init_playback() == ESP_OK) && (bsp_audio_set_format(8000, 16, 1) == ESP_OK);
    if (!audio_open) {
        ESP_LOGE(kTag, "Break-in ES8311 init failed");
        bsp_audio_deinit();
    } else {
        bsp_audio_set_volume(100);
        fmo_keep_awake();
        uint32_t last_uid = 0;
        uint32_t last_stream = 0;
        int64_t last_rx_us = esp_timer_get_time();
        int64_t last_awake_us = last_rx_us;
        QueuedFrame f{};

        while (!s_stop_requested.load(std::memory_order_acquire)) {
            if (!pop_frame(&f)) {
                const int64_t now = esp_timer_get_time();
                if (now - last_rx_us >= kBreakinSilenceUs) break;
                vTaskDelay(pdMS_TO_TICKS(5));
                continue;
            }
            const int64_t now = esp_timer_get_time();
            if (last_uid && f.uid != last_uid && now - last_rx_us < 1500000 &&
                !fmo::route_priority_preempts(f.stream_begin, f.uid, last_stream, last_uid)) {
                continue;
            }
            if (last_uid != f.uid || last_stream != f.stream_begin) {
                decoder_ready = false;
                last_uid = f.uid;
                last_stream = f.stream_begin;
                std::snprintf(speaker, sizeof(speaker), "%.12s", f.callsign);
                ESP_LOGI(kTag, "Voice break-in RX from %s (uid=%lu)", speaker, (unsigned long)f.uid);
                breakin_banner_show(speaker, s_relay.callsign);
            }
            last_rx_us = now;
            if (now - last_awake_us >= 2000000) {
                fmo_keep_awake();
                last_awake_us = now;
            }
            int samples = -1;
            if (f.codec == 1) {
                if (!decoder_ready) decoder_ready = (opus_decoder_init(decoder, 8000, 1) == 0);
                if (decoder_ready) samples = opus_decode(decoder, f.data, f.size, pcm, 640, 0);
            } else {
                samples = decode_radpcm(f.data, f.size, pcm);
                decoder_ready = false;
            }
            if (samples > 0 && samples <= 640) {
                if (bsp_audio_write(pcm, static_cast<size_t>(samples) * sizeof(int16_t)) == ESP_OK) {
                    ++frames_played;
                }
            }
        }
        bsp_audio_deinit();
    }

    breakin_banner_hide();
    sodium_memzero(audio_workspace::storage, audio_workspace::kBytes);
    audio_workspace::release(audio_workspace::Owner::Plugin);
    uint32_t dropped = 0;
    if (s_ring_mutex && xSemaphoreTake(s_ring_mutex, pdMS_TO_TICKS(50)) == pdTRUE) {
        if (s_ring) dropped = s_ring->dropped;
        delete s_ring;
        s_ring = nullptr;
        xSemaphoreGive(s_ring_mutex);
    }

    ESP_LOGI(kTag, "Voice break-in ended: speaker=%s frames=%lu dropped=%lu stack_hwm=%u free=%u",
             speaker[0] ? speaker : "-",
             (unsigned long)frames_played,
             (unsigned long)dropped,
             (unsigned)uxTaskGetStackHighWaterMark(nullptr),
             (unsigned)esp_get_free_heap_size());

    const bool suppressed = s_suppressed_by_host.load(std::memory_order_acquire);
    s_breakin_running.store(false, std::memory_order_release);
    if (!suppressed) {
        fmo_audio_focus_end_breakin();
    }
    vTaskDelete(nullptr);
}

void on_mqtt_event(void *, esp_event_base_t, int32_t id, void *data) {
    auto *e = static_cast<esp_mqtt_event_handle_t>(data);
    if (id == MQTT_EVENT_CONNECTED) {
        s_inbox.reset();
        s_mqtt_error.store(false, std::memory_order_release);
        s_mqtt_connected.store(true, std::memory_order_release);
        esp_mqtt_client_subscribe(e->client, "FMO/RAW", 0);
        ESP_LOGI(kTag, "MQTT connected to %s:%u (%s) free=%u",
                 s_relay.host, (unsigned)s_relay.port,
                 s_relay_builtin ? "guest-jwt" : "sas4",
                 (unsigned)esp_get_free_heap_size());
    } else if (id == MQTT_EVENT_DISCONNECTED || id == MQTT_EVENT_ERROR) {
        if (s_mqtt_connected.exchange(false, std::memory_order_acq_rel)) {
            ESP_LOGW(kTag, "MQTT disconnected (evt=%ld)", (long)id);
        }
        if (id == MQTT_EVENT_ERROR) {
            s_mqtt_error.store(true, std::memory_order_release);
        }
        s_inbox.reset();
    } else if (id == MQTT_EVENT_DATA) {
        if (s_stop_requested.load(std::memory_order_acquire) || !s_assembly) return;
        const auto kind = s_inbox.feed(e->topic, e->topic_len, e->data, e->data_len,
                                       e->current_data_offset, e->total_data_len,
                                       s_assembly, fmo::kPacketMax);
        if (kind != fmo::MqttKind::Voice) return;

        fmo::Packet pkt{};
        if (!fmo::parse_packet(s_assembly, static_cast<size_t>(e->total_data_len), &pkt)) return;
        if (!pkt.count || pkt.uid == s_self_uid) return;
        if (!s_relay_builtin && pkt.server_uid != s_relay.uid) return;

        bool pushed = false;
        if (s_ring_mutex && xSemaphoreTake(s_ring_mutex, pdMS_TO_TICKS(5)) == pdTRUE) {
            if (!s_ring) s_ring = new (std::nothrow) FrameRing();
            if (s_ring) {
                for (size_t i = 0; i < pkt.count; ++i) {
                    const auto &fr = pkt.frames[i];
                    if (!fr.data || !fr.size || fr.size > kMaxFrameBytes) continue;
                    s_ring->push_frame(pkt.uid, pkt.stream_begin, fr.codec, pkt.callsign,
                                       fr.data, static_cast<uint16_t>(fr.size));
                    pushed = true;
                }
            }
            xSemaphoreGive(s_ring_mutex);
        }

        if (pushed && !s_breakin_running.exchange(true, std::memory_order_acq_rel)) {
            if (xTaskCreate(breakin_task, "fmo_breakin", kBreakinTaskStack, nullptr, 5, nullptr) != pdPASS) {
                ESP_LOGE(kTag, "Failed to spawn break-in task (free=%u)", (unsigned)esp_get_free_heap_size());
                s_breakin_running.store(false, std::memory_order_release);
            }
        }
    }
}

void stop_locked(bool suppressed_by_host) {
    s_suppressed_by_host.store(suppressed_by_host, std::memory_order_release);
    s_stop_requested.store(true, std::memory_order_release);
    s_mqtt_connected.store(false, std::memory_order_release);
    if (s_mqtt) {
        esp_mqtt_client_stop(s_mqtt);
        esp_mqtt_client_destroy(s_mqtt);
        s_mqtt = nullptr;
    }
    s_inbox.reset();

    // Wait synchronously for any active voice break-in playback task to release
    // ES8311 and audio_workspace before full FMO / Xiaozhi / Voice launches.
    for (int waited = 0; s_breakin_running.load(std::memory_order_acquire) && waited < 3500; waited += 20) {
        vTaskDelay(pdMS_TO_TICKS(20));
    }
    if (s_breakin_running.load(std::memory_order_acquire)) {
        ESP_LOGW(kTag, "Break-in task still exiting after 3.5s");
        return;  // Keep buffers alive until it exits to avoid use-after-free
    }
    if (s_ring_mutex && xSemaphoreTake(s_ring_mutex, pdMS_TO_TICKS(50)) == pdTRUE) {
        delete s_ring;
        s_ring = nullptr;
        xSemaphoreGive(s_ring_mutex);
    }
    if (s_assembly) {
        sodium_memzero(s_assembly, fmo::kPacketMax);
        delete[] s_assembly;
        s_assembly = nullptr;
    }
    s_suppressed_by_host.store(false, std::memory_order_release);
}

void start_locked() {
    if (!fmo::sentinel_enabled()) return;
    if (s_mqtt && !s_mqtt_error.load(std::memory_order_acquire)) {
        // Already running or connecting cleanly
        if (s_mqtt_connected.load(std::memory_order_acquire)) return;
        const int64_t now = esp_timer_get_time();
        if (now - s_last_connect_try_us < 25000000) return;
        // Stale disconnected handle: tear down cleanly before re-authenticating
        stop_locked(false);
    } else if (s_mqtt) {
        stop_locked(false);
    }

    const int64_t now_us = esp_timer_get_time();
    if (s_last_connect_try_us && now_us - s_last_connect_try_us < 15000000) return;
    s_last_connect_try_us = now_us;

    const time_t now_s = time(nullptr);
    if (now_s < 1700000000) {
        // Wait for SNTP time sync before signing SAS4 / guest JWT
        return;
    }

    const size_t free_heap = esp_get_free_heap_size();
    const size_t largest = heap_caps_get_largest_free_block(MALLOC_CAP_INTERNAL);
    if (free_heap < kMinFreeHeapToStart || largest < kMinLargestBlockToStart) {
        ESP_LOGW(kTag, "Deferring sentinel start (free=%u largest=%u)", (unsigned)free_heap, (unsigned)largest);
        return;
    }

    fmo::Credential identity{};
    uint8_t secret[64]{};
    std::string error;
    if (!fmo::load_identity(&identity, secret, &error)) {
        sodium_memzero(secret, sizeof(secret));
        return;
    }
    if (static_cast<uint64_t>(now_s) >= identity.expires) {
        sodium_memzero(secret, sizeof(secret));
        return;
    }
    const auto restored = fmo::revocation_restore(identity, fmo_root_start, static_cast<uint32_t>(now_s));
    if (fmo::revocation_session_state(identity, restored.epoch, static_cast<uint32_t>(now_s)) !=
        fmo::SessionRevocation::Allowed) {
        sodium_memzero(secret, sizeof(secret));
        return;
    }

    fmo::Relay relay{};
    if (!fmo::load_relay(&relay)) {
        relay = fmo::builtin_relay();
    }
    const bool builtin = fmo::is_builtin_relay(relay);

    std::string password;
    const bool auth_ok = builtin
        ? fmo::guest_jwt_password(identity, static_cast<uint32_t>(now_s), &password)
        : fmo::auth_password(identity, secret, relay, static_cast<uint32_t>(now_s), &password);
    sodium_memzero(secret, sizeof(secret));
    if (!auth_ok) {
        if (!password.empty()) sodium_memzero(password.data(), password.size());
        return;
    }

    if (!s_assembly) s_assembly = new (std::nothrow) uint8_t[fmo::kPacketMax]();
    if (!s_assembly) {
        if (!password.empty()) sodium_memzero(password.data(), password.size());
        stop_locked(false);
        return;
    }

    s_relay = relay;
    s_relay_builtin = builtin;
    s_self_uid = identity.uid;
    s_stop_requested.store(false, std::memory_order_release);
    s_suppressed_by_host.store(false, std::memory_order_release);
    s_mqtt_error.store(false, std::memory_order_release);
    s_mqtt_connected.store(false, std::memory_order_release);
    s_inbox.reset();

    const std::string uri = "mqtt://" + std::string(relay.host) + ":" + std::to_string(relay.port);
    char client_id[32]{};
    char username[20]{};
    std::snprintf(client_id, sizeof(client_id), "PASSPORT-%.12s", fmo::bare_callsign(identity.callsign));
    fmo::mqtt_username_for_relay(identity, relay, username);

    esp_mqtt_client_config_t config{};
    config.broker.address.uri = uri.c_str();
    config.credentials.client_id = client_id;
    config.credentials.username = username;
    config.credentials.authentication.password = password.c_str();
    config.session.keepalive = 30;
    config.session.protocol_ver = MQTT_PROTOCOL_V_3_1_1;
    config.network.disable_auto_reconnect = true;
    config.network.timeout_ms = 2000;
    config.task.stack_size = 4096;
    config.buffer.size = 2048;
    // FMO 4.0 SAS4 CONNECT carries full user+intermediate cert JSON (~2-3 KB).
    config.buffer.out_size = 3584;

    // Re-check free heap right before creating MQTT client & task (~12 KB total)
    // in case background Radio/NetEase resumed during identity verification.
    if (esp_get_free_heap_size() < 24 * 1024 ||
        heap_caps_get_largest_free_block(MALLOC_CAP_INTERNAL) < 10 * 1024) {
        if (!password.empty()) sodium_memzero(password.data(), password.size());
        stop_locked(false);
        return;
    }

    s_mqtt = esp_mqtt_client_init(&config);
    if (!password.empty()) sodium_memzero(password.data(), password.size());
    if (!s_mqtt) {
        stop_locked(false);
        return;
    }
    if (esp_mqtt_client_register_event(s_mqtt, static_cast<esp_mqtt_event_id_t>(ESP_EVENT_ANY_ID),
                                       on_mqtt_event, nullptr) != ESP_OK ||
        esp_mqtt_client_start(s_mqtt) != ESP_OK) {
        esp_mqtt_client_destroy(s_mqtt);
        s_mqtt = nullptr;
        stop_locked(false);
        return;
    }
    ESP_LOGI(kTag, "Starting sentinel MQTT -> %s:%u (%s)",
             relay.host, (unsigned)relay.port, builtin ? "guest-jwt" : "sas4");
}

void sentinel_start_task(void *) {
    ensure_mutexes();
    if (s_ctrl_mutex && xSemaphoreTake(s_ctrl_mutex, pdMS_TO_TICKS(3000)) == pdTRUE) {
        if (s_want_sentinel.load(std::memory_order_acquire) &&
            !s_stop_requested.load(std::memory_order_acquire)) {
            start_locked();
        }
        xSemaphoreGive(s_ctrl_mutex);
    }
    s_start_task_running.store(false, std::memory_order_release);
    vTaskDelete(nullptr);
}

}  // namespace

void fmo_sentinel_on_system_state(bool wifi_connected, bool allow_sentinel) {
    ensure_mutexes();
    const bool want = wifi_connected && allow_sentinel && fmo::sentinel_enabled();
    s_want_sentinel.store(want, std::memory_order_release);
    if (want) {
        // Fast non-blocking check on caller's small stack (e.g. sys_mon 2.5 KB):
        // Never run Ed25519 / cJSON / CBOR certificate verification on sys_mon!
        if (s_mqtt && s_mqtt_connected.load(std::memory_order_acquire) &&
            !s_mqtt_error.load(std::memory_order_acquire)) {
            return;
        }
        const int64_t now_us = esp_timer_get_time();
        if (s_last_connect_try_us && now_us - s_last_connect_try_us < 15000000) return;
        if (time(nullptr) < 1700000000) return;
        if (!s_start_task_running.exchange(true, std::memory_order_acq_rel)) {
            s_stop_requested.store(false, std::memory_order_release);
            if (xTaskCreate(sentinel_start_task, "fmo_sinit", 6144, nullptr, 3, nullptr) != pdPASS) {
                s_start_task_running.store(false, std::memory_order_release);
            }
        }
        return;
    }

    // Teardown path: wait for any in-flight start task, then synchronously stop
    // MQTT and any active voice break-in (tiny stack footprint < 512 B).
    s_stop_requested.store(true, std::memory_order_release);
    for (int waited = 0; s_start_task_running.load(std::memory_order_acquire) && waited < 3000; waited += 20) {
        vTaskDelay(pdMS_TO_TICKS(20));
    }
    if (!s_ctrl_mutex || xSemaphoreTake(s_ctrl_mutex, pdMS_TO_TICKS(4000)) != pdTRUE) return;
    if (s_mqtt || s_breakin_running.load(std::memory_order_acquire) || s_assembly || s_ring) {
        ESP_LOGI(kTag, "Stopping sentinel (wifi=%d allow=%d enabled=%d)",
                 (int)wifi_connected, (int)allow_sentinel, (int)fmo::sentinel_enabled());
        stop_locked(!allow_sentinel);
    }
    xSemaphoreGive(s_ctrl_mutex);
}

void fmo_sentinel_stop_sync(void) {
    ensure_mutexes();
    s_want_sentinel.store(false, std::memory_order_release);
    s_stop_requested.store(true, std::memory_order_release);
    for (int waited = 0; s_start_task_running.load(std::memory_order_acquire) && waited < 3000; waited += 20) {
        vTaskDelay(pdMS_TO_TICKS(20));
    }
    if (!s_ctrl_mutex || xSemaphoreTake(s_ctrl_mutex, pdMS_TO_TICKS(4000)) != pdTRUE) return;
    if (s_mqtt || s_breakin_running.load(std::memory_order_acquire) || s_assembly || s_ring) {
        stop_locked(true);
    }
    xSemaphoreGive(s_ctrl_mutex);
}

bool fmo_sentinel_is_connected(void) {
    return s_mqtt_connected.load(std::memory_order_acquire);
}

bool fmo_sentinel_is_breaking_in(void) {
    return s_breakin_running.load(std::memory_order_acquire);
}

#else

void fmo_sentinel_on_system_state(bool, bool) {}
void fmo_sentinel_stop_sync(void) {}
bool fmo_sentinel_is_connected(void) { return false; }
bool fmo_sentinel_is_breaking_in(void) { return false; }

#endif
