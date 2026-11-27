#!/usr/bin/env python3
"""Host ASan/UBSan tests for FMO Roger Beep (FBEP + built-in dual-tone + dual-bank SPIFFS)
and PASSPORT built-in relay guest-jwt HS256 compatibility."""
from pathlib import Path
import base64, hashlib, hmac, os, struct, subprocess, tempfile, zlib

root = Path(__file__).resolve().parents[3]

GUEST_SECRET = b"938eb6723056378f06de33994b026f0f99280f3bbd62e5dae974b6e3db944ba7"
JWT_HEADER = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"

def b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")

def expected_guest_jwt(callsign: str, uid: int, now: int) -> str:
    bare = callsign[2:] if callsign.startswith("P-") and len(callsign) >= 5 else callsign
    user = f"P-{bare}"
    if now >= 1700000000:
        payload = f'{{"sub":"{user}","username":"{user}","client_attrs":{{"callsign":"{user}","uid":"{uid}"}},"exp":{now + 86400}}}'
    else:
        payload = f'{{"sub":"{user}","username":"{user}","client_attrs":{{"callsign":"{user}","uid":"{uid}"}}}}'
    signing_input = f"{JWT_HEADER}.{b64url(payload.encode())}"
    sig = hmac.new(GUEST_SECRET, signing_input.encode(), hashlib.sha256).digest()
    return f"{signing_input}.{b64url(sig)}"

def make_fbep(bid: int, pcm_samples: list[int]) -> bytes:
    pcm = struct.pack(f"<{len(pcm_samples)}h", *pcm_samples)
    crc = zlib.crc32(pcm) & 0xFFFFFFFF
    hdr = struct.pack("<4sBBHII", b"FBEP", 1, bid, 0, len(pcm_samples), crc)
    return hdr + pcm

with tempfile.TemporaryDirectory(prefix="fmo-beep-test.") as td:
    tmp = Path(td)
    storage = tmp / "storage"
    storage.mkdir()
    mocks = tmp / "mocks"
    (mocks / "apps/home").mkdir(parents=True)

    (mocks / "nvs.h").write_text(r"""
#pragma once
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <map>
#include <string>
#include <vector>
using esp_err_t = int;
using nvs_handle_t = int;
constexpr esp_err_t ESP_OK = 0;
constexpr esp_err_t ESP_FAIL = -1;
constexpr esp_err_t ESP_ERR_NVS_NOT_FOUND = 0x1102;
enum { NVS_READONLY = 1, NVS_READWRITE = 2 };
inline std::map<std::string, std::vector<uint8_t>> mock_nvs;
inline bool mock_nvs_fail_open = false, mock_nvs_fail_write = false, mock_nvs_fail_commit = false;
inline esp_err_t nvs_open(const char *ns, int, nvs_handle_t *h) {
    if (mock_nvs_fail_open) return ESP_FAIL;
    (void)ns; *h = 1; return ESP_OK;
}
inline esp_err_t nvs_get_blob(nvs_handle_t, const char *key, void *out, size_t *len) {
    auto it = mock_nvs.find(key);
    if (it == mock_nvs.end()) return ESP_ERR_NVS_NOT_FOUND;
    if (!out) { *len = it->second.size(); return ESP_OK; }
    if (*len < it->second.size()) return ESP_FAIL;
    *len = it->second.size();
    std::memcpy(out, it->second.data(), *len);
    return ESP_OK;
}
inline esp_err_t nvs_set_blob(nvs_handle_t, const char *key, const void *data, size_t len) {
    if (mock_nvs_fail_write) return ESP_FAIL;
    auto *p = static_cast<const uint8_t *>(data);
    mock_nvs[key].assign(p, p + len);
    return ESP_OK;
}
inline esp_err_t nvs_commit(nvs_handle_t) { return mock_nvs_fail_commit ? ESP_FAIL : ESP_OK; }
inline void nvs_close(nvs_handle_t) {}
""")

    (mocks / "apps/home/home_storage.h").write_text(r"""
#pragma once
#include "nvs.h"
inline int mock_storage_refs = 0;
inline bool mock_storage_fail = false;
inline esp_err_t home_storage_acquire(bool) {
    if (mock_storage_fail) return ESP_FAIL;
    ++mock_storage_refs;
    return ESP_OK;
}
inline void home_storage_release(void) {
    if (mock_storage_refs > 0) --mock_storage_refs;
}
""")

    fbep6 = make_fbep(6, [(i * 137) % 10000 - 5000 for i in range(640)])
    fbep2 = make_fbep(2, [(i * 73) % 8000 - 4000 for i in range(960)])
    jwt1 = expected_guest_jwt("BG0TEST", 9610042, 1800000000)
    jwt2 = expected_guest_jwt("P-BG0TEST", 9610042, 1800000000)
    jwt3 = expected_guest_jwt("P-BG0TEST", 9610042, 0)
    assert jwt1 == jwt2

    (tmp / "fbep6.bin").write_bytes(fbep6)
    (tmp / "fbep2.bin").write_bytes(fbep2)

    driver = tmp / "test_beep_driver.cc"
    driver.write_text(f'''
#include "fmo_beep.h"
#include "fmo_crypto.h"
#include "fmo_wire.h"
#include "nvs.h"
#include "apps/home/home_storage.h"
#include <cassert>
#include <cmath>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <string>
#include <vector>

static std::vector<uint8_t> read_all(const char *path) {{
    std::ifstream f(path, std::ios::binary);
    return std::vector<uint8_t>((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
}}

int main() {{
    // 1. Built-in dual-tone Roger Beep synthesis verification (960 Hz -> 30ms gap -> 640 Hz -> 10ms tail).
    std::vector<int16_t> builtin(fmo::kBeepBuiltinSamples, 0);
    fmo::beep_render_builtin(0, builtin.data(), fmo::kBeepBuiltinSamples);
    assert(builtin[0] == 0);
    int peak1 = 0, peak_gap = 0, peak2 = 0, peak_tail = 0;
    for (uint32_t i = 0; i < 960; ++i) peak1 = std::max(peak1, std::abs(int(builtin[i])));
    for (uint32_t i = 960; i < 1200; ++i) peak_gap = std::max(peak_gap, std::abs(int(builtin[i])));
    for (uint32_t i = 1200; i < 2480; ++i) peak2 = std::max(peak2, std::abs(int(builtin[i])));
    for (uint32_t i = 2480; i < 2560; ++i) peak_tail = std::max(peak_tail, std::abs(int(builtin[i])));
    assert(peak1 >= 9000 && peak1 <= 10000);
    assert(peak_gap == 0);
    assert(peak2 >= 9000 && peak2 <= 10000);
    assert(peak_tail == 0);
    assert(builtin[959] == 0 && builtin[1200] == 0 && builtin[2479] == 0);

    int16_t frame[fmo::kBeepFrameSamples]{{}};
    for (uint32_t off = 0; off < fmo::kBeepBuiltinSamples; off += fmo::kBeepFrameSamples) {{
        fmo::beep_render_builtin(off, frame, fmo::kBeepFrameSamples);
        assert(std::memcmp(frame, builtin.data() + off, sizeof(frame)) == 0);
    }}
    std::vector<int16_t> chirp(fmo::kBeepPttStartSamples);
    fmo::beep_render_ptt_start(chirp.data(), fmo::kBeepPttStartSamples);
    int16_t chirp_peak = 0;
    for (int16_t s : chirp) chirp_peak = std::max<int16_t>(chirp_peak, std::abs(s));
    assert(chirp.front() == 0 && chirp.back() == 0 && chirp_peak >= 9000);
    assert(std::strcmp(fmo::beep_cloud_name(1), "模拟信令") == 0 && fmo::beep_cloud_name(99) == nullptr);

    // 2. FBEP parser strict validation.
    auto fbep6 = read_all("{tmp / 'fbep6.bin'}");
    auto fbep2 = read_all("{tmp / 'fbep2.bin'}");
    uint8_t id = 0; uint32_t samples = 0, crc = 0;
    assert(fmo::beep_parse_fbep(fbep6.data(), fbep6.size(), &id, &samples, &crc));
    assert(id == 6 && samples == 640);
    auto bad = fbep6; bad[0] = 'X'; assert(!fmo::beep_parse_fbep(bad.data(), bad.size(), nullptr, nullptr, nullptr));
    bad = fbep6; bad[4] = 2; assert(!fmo::beep_parse_fbep(bad.data(), bad.size(), nullptr, nullptr, nullptr));
    bad = fbep6; bad[5] = 0; assert(!fmo::beep_parse_fbep(bad.data(), bad.size(), nullptr, nullptr, nullptr));
    bad = fbep6; bad[6] = 1; assert(!fmo::beep_parse_fbep(bad.data(), bad.size(), nullptr, nullptr, nullptr));
    bad = fbep6; bad.back() ^= 1; assert(!fmo::beep_parse_fbep(bad.data(), bad.size(), nullptr, nullptr, nullptr));
    assert(!fmo::beep_parse_fbep(fbep6.data(), fbep6.size() - 2, nullptr, nullptr, nullptr));

    // 3. Default NVS load & save + dual-bank SPIFFS atomic persistence.
    fmo::BeepConfig cfg{{}};
    assert(fmo::load_beep_config(&cfg) == fmo::BeepLoad::Missing);
    assert(cfg.enabled && !cfg.use_custom && !cfg.custom_present);

    assert(fmo::save_custom_beep_fbep(fbep6.data(), fbep6.size(), &cfg, true));
    assert(cfg.enabled && cfg.use_custom && cfg.custom_present && cfg.custom_id == 6 && cfg.custom_bank == 0 && cfg.custom_samples == 640);
    assert(mock_storage_refs == 0);

    {{
        fmo::BeepStream st;
        st.open(cfg);
        assert(st.is_custom() && st.total_samples() == 640);
        std::vector<int16_t> out(640);
        st.read_samples(0, out.data(), 320);
        st.read_samples(320, out.data() + 320, 320);
        assert(std::memcmp(out.data(), fbep6.data() + fmo::kBeepHeaderBytes, 640 * sizeof(int16_t)) == 0);
    }}
    assert(mock_storage_refs == 0);

    fmo::BeepConfig stale = cfg;
    assert(fmo::save_custom_beep_fbep(fbep2.data(), fbep2.size(), &cfg, true));
    assert(cfg.custom_bank == 1 && cfg.custom_id == 2 && cfg.custom_samples == 960);
    assert(!fmo::save_beep_config(stale));
    cfg.enabled = false;
    assert(fmo::save_beep_config(cfg));
    fmo::BeepConfig reloaded{{}};
    assert(fmo::load_beep_config(&reloaded) == fmo::BeepLoad::Ready && !reloaded.enabled && reloaded.custom_id == 2);

    {{
        std::ofstream corrupt("{storage / 'fmo-beep-b.bin'}", std::ios::binary | std::ios::trunc);
        corrupt << "CORRUPT";
    }}
    reloaded.enabled = true;
    reloaded.use_custom = true;
    {{
        fmo::BeepStream st;
        st.open(reloaded);
        assert(!st.is_custom() && st.total_samples() == fmo::kBeepBuiltinSamples);
        st.read_samples(0, frame, fmo::kBeepFrameSamples);
        assert(std::memcmp(frame, builtin.data(), sizeof(frame)) == 0);
    }}
    assert(mock_storage_refs == 0);

    assert(fmo::clear_custom_beep(&cfg));
    assert(!cfg.custom_present && !cfg.use_custom);

    // 3b. Streaming FBEP save (512B chunked, zero 48KB RAM peak) + error/corruption rejection.
    {{
        struct VecReader {{ const std::vector<uint8_t> *v; size_t pos; size_t step; }};
        auto read_fn = [](void *ctx, uint8_t *buf, size_t max_len) -> int {{
            auto *r = static_cast<VecReader *>(ctx);
            if (r->pos >= r->v->size()) return 0;
            const size_t avail = r->v->size() - r->pos;
            const size_t n = std::min(max_len, std::min(r->step, avail));
            std::memcpy(buf, r->v->data() + r->pos, n);
            r->pos += n;
            return static_cast<int>(n);
        }};
        VecReader r1{{&fbep6, 0, 17}};
        assert(fmo::save_custom_beep_stream(fbep6.size(), 6, read_fn, &r1, &cfg));
        assert(cfg.custom_present && cfg.use_custom && cfg.custom_id == 6 && cfg.custom_samples == 640);
        // Wrong expected_id must fail without corrupting active beep.
        VecReader r_wrong_id{{&fbep2, 0, 64}};
        assert(!fmo::save_custom_beep_stream(fbep2.size(), 6, read_fn, &r_wrong_id, &cfg));
        // Corrupted payload must fail CRC verification and keep previous valid bank intact.
        auto bad_b2 = fbep2;
        bad_b2[30] ^= 0xFF;
        VecReader r_bad{{&bad_b2, 0, 64}};
        assert(!fmo::save_custom_beep_stream(bad_b2.size(), 2, read_fn, &r_bad, &cfg));
        // Any valid ID with expected_id == 0 (local custom upload) succeeds and swaps bank.
        VecReader r2{{&fbep2, 0, 128}};
        assert(fmo::save_custom_beep_stream(fbep2.size(), 0, read_fn, &r2, &cfg));
        assert(cfg.custom_present && cfg.custom_id == 2 && cfg.custom_bank == 1);
        assert(mock_storage_refs == 0);
        assert(fmo::clear_custom_beep(&cfg));
    }}

    mock_nvs_fail_write = true;
    assert(!fmo::save_beep_config(cfg));
    mock_nvs_fail_write = false;

    // 4. Built-in PASSPORT relay & guest-jwt HS256 exact match against Python RFC 2104 HMAC-SHA256.
    const auto br = fmo::builtin_relay();
    assert(fmo::is_builtin_relay(br));
    assert(br.uid == 0 && br.port == 1883 && std::strcmp(br.host, "fmo.simy.asia") == 0);
    fmo::Relay non_builtin = br; non_builtin.uid = 1; assert(!fmo::is_builtin_relay(non_builtin));

    fmo::Credential c{{}};
    std::strcpy(c.callsign, "BG0TEST"); c.uid = 9610042;
    std::string jwt;
    assert(fmo::guest_jwt_password(c, 1800000000u, &jwt));
    assert(jwt == "{jwt1}");
    char user[20]{{}};
    fmo::mqtt_username_for_relay(c, br, user);
    assert(std::strcmp(user, "P-BG0TEST") == 0);

    std::strcpy(c.callsign, "P-BG0TEST");
    assert(fmo::guest_jwt_password(c, 1800000000u, &jwt));
    assert(jwt == "{jwt2}");
    fmo::mqtt_username_for_relay(c, br, user);
    assert(std::strcmp(user, "P-BG0TEST") == 0);

    assert(fmo::guest_jwt_password(c, 0u, &jwt));
    assert(jwt == "{jwt3}");

    std::puts("FMO Roger Beep (builtin dual-tone, FBEP parser, dual-bank SPIFFS, fallback) + builtin relay guest-jwt HS256: PASS");
    return 0;
}}
''')

    exe = tmp / "test_beep"
    cxx = os.environ.get("CXX", "c++")
    cjson_inc = str(root / "tests/vendor/cjson")
    cjson_src = str(root / "tests/vendor/cjson/cJSON.c")
    subprocess.check_call([
        cxx, "-std=c++17", "-Wall", "-Wextra", "-Werror",
        "-fsanitize=address,undefined", "-g",
        f'-DFMO_BEEP_BASE="{storage}"',
        f"-I{mocks}", f"-I{root / 'main'}", f"-I{root / 'components/passport_fmo/src'}", f"-I{cjson_inc}",
        str(driver),
        str(root / "components/passport_fmo/src/fmo_beep.cc"),
        str(root / "components/passport_fmo/src/fmo_wire.cc"),
        str(root / "components/passport_fmo/src/fmo_crypto.cc"),
        str(root / "components/passport_fmo/src/fmo_aprs.cc"),
        cjson_src,
        "-lsodium", "-o", str(exe),
    ])
    subprocess.check_call([str(exe)])

    # 5. Static audit of fmo_setup.html: no missing DOM IDs and no undefined JS helper calls.
    import re
    html = (root / "components/passport_fmo/fmo_setup.html").read_text(encoding="utf-8")
    dom_ids = set(re.findall(r'id="([^"]+)"', html))
    used_ids = set(re.findall(r"\$\('([^']+)'\)", html))
    missing_ids = sorted(used_ids - dom_ids)
    assert not missing_ids, f"Missing DOM IDs in fmo_setup.html: {missing_ids}"
    script = html.split("<script>", 1)[1].split("</script>", 1)[0]
    defs = set(re.findall(r"(?:async\s+)?function\s+([A-Za-z_]\w*)", script))
    defs |= set(re.findall(r"(?:const|let|var)\s+([A-Za-z_]\w*)", script))
    calls = set(re.findall(r"(?<![.\w])([A-Za-z_]\w*)\s*\(", script))
    builtins = {
        "if","for","while","switch","catch","return","typeof","new","Error","Number","String",
        "Boolean","Array","Object","Math","Date","JSON","Blob","File","FileReader","URL",
        "Image","Audio","Set","Uint8Array","Int16Array","Float32Array","DataView","ArrayBuffer",
        "TextEncoder","TextDecoder","URLSearchParams","Promise","Option","AudioContext",
        "OfflineAudioContext","setTimeout","clearTimeout","fetch","encodeURIComponent",
        "decodeURIComponent","parseInt","parseFloat","isNaN","isFinite","atob","btoa",
        "console","alert","confirm","Function","async","fn","work","resolve","reject","AC","OAC",
    }
    undef_calls = sorted(calls - defs - builtins)
    assert not undef_calls, f"Undefined JS calls in fmo_setup.html: {undef_calls}"
    print("FMO setup HTML static audit (DOM IDs + JS calls): PASS")
