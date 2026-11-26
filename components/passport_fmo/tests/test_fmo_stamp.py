"""Host ASan/UBSan regression tests for FMO custom stamps, peer stamps, favorites,
and strictly read-only fmo_cred legacy identity migration."""
from pathlib import Path
import base64, json, struct, subprocess, tempfile
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

root = Path(__file__).resolve().parents[3]

def cb(v):
    def head(m, n):
        if n < 24: return bytes([m * 32 + n])
        for lim, k, fmt in [(256, 24, '>B'), (65536, 25, '>H'), (2**32, 26, '>I'), (2**64, 27, '>Q')]:
            if n < lim: return bytes([m * 32 + k]) + struct.pack(fmt, n)
    if v is True: return b'\xf5'
    if isinstance(v, int): return head(0, v)
    if isinstance(v, bytes): return head(2, len(v)) + v
    if isinstance(v, str): b = v.encode(); return head(3, len(b)) + b
    if isinstance(v, list): return head(4, len(v)) + b''.join(map(cb, v))
    raise TypeError(v)

def b64(b): return base64.urlsafe_b64encode(b).decode().rstrip('=')
def key(n): return Ed25519PrivateKey.from_private_bytes(bytes([n]) * 32)
def pk(k): return k.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
def sign(obj, values, k): obj['signature'] = b64(k.sign(cb(values))); return obj

now = 1800000000
rk, ik, uk, sk_srv = map(key, [11, 12, 13, 14])
rpk, ipk, upk, spk = map(pk, [rk, ik, uk, sk_srv])
rt = ['FMO', 4, 'rootCA', 1, 'Test Root', 'root@example.test', 'Test Root', rpk, True, 1, 'https://fmo.simy.live/ca/crl/root-1.json', '', 'test', now - 100, now + 10000]
r_cert = sign(dict(sn=1, type='rootCA', issuer=dict(name='Test Root', email='root@example.test'), subject=dict(name='Test Root', publicKey=b64(rpk)), extensions=dict(isCA=True, pathLen=1, crl='https://fmo.simy.live/ca/crl/root-1.json', license='', keyId='test'), iat=now - 100, exp=now + 10000), rt, rk)
it = ['FMO', 4, 'intermediateCA', 2, 1, 'Test Root', rpk, 'Test CA', 'ca@example.test', ipk, True, 0, 'test', 'https://fmo.simy.live/ca/crl/inter-2.json', '', 9610000, 9699999, ['CN'], now - 90, now + 9000]
i_cert = sign(dict(sn=2, type='intermediateCA', issuer=dict(sn=1, name='Test Root', publicKey=b64(rpk)), subject=dict(name='Test CA', email='ca@example.test', publicKey=b64(ipk)), extensions=dict(isCA=True, pathLen=0, keyId='test', crl='https://fmo.simy.live/ca/crl/inter-2.json', license='', uidRange=dict(start=9610000, end=9699999), issuingCountries=['CN']), iat=now - 90, exp=now + 9000), it, rk)
# Real FMO Passport v0.6.10 subject callsigns carry the "P-" prefix.
ut = ['FMO', 4, 'userCert', 2, 'P-BG0TST', 9610123, upk, now - 80, now + 8000]
u_cert = sign(dict(type='userCert', issuerSn=2, subject=dict(callsign='P-BG0TST', uid=9610123, publicKey=b64(upk)), iat=now - 80, exp=now + 8000), ut, ik)

# Also build an APPASP station announcement with P- prefixed station cert!
st_ut = ['FMO', 4, 'userCert', 2, 'P-BG0SRV', 9610200, spk, now - 80, now + 8000]
st_sig = ik.sign(cb(st_ut))
st_blob = cb(st_ut + [st_sig])
import hashlib
st_vals = ['FMO', 4, 'STATION', 'BG0SRV', 15, '3037.98N', '11932.20E', hashlib.sha256(st_blob).digest(), 'CN', 'PASSPORT中继', 'relay.example.test', 1883, 300, 8, 50, now // 600]
appasp_station = f"BG0SRV-15>APPASP,TCPIP*:=3037.98NF11932.20EiFMO-V4,STATION,CERT:{b64(st_blob)},CN,PASSPORT中继,relay.example.test,P1883,F300KM,U8/50,SIG:{b64(sk_srv.sign(cb(st_vals)))}"

harness = r'''
#include "fmo_stamp.h"
#include "fmo_beep.h"
#include "fmo_wire.h"
#include "fmo_store.h"
#include "fmo_favorites.h"
#include "fmo_aprs.h"
#include "fmo_crypto.h"
#include <sodium.h>
#include <cassert>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <fstream>
#include <map>
#include <string>
#include <vector>

extern "C" {
#include "nvs.h"
#include "esp_random.h"
extern "C" {
esp_err_t home_storage_acquire(bool initialize_blank);
void home_storage_release(void);
}
}

// Provide the root JSON symbol expected by fmo_store.cc.
extern char fmo_root_start[4096] asm("_binary_passport_root_json_start");
char fmo_root_start[4096]{};

static std::map<std::string, std::map<std::string, std::vector<uint8_t>>> g_nvs;
static std::map<int, std::pair<std::string, nvs_open_mode_t>> g_handles;
static int g_next_handle = 1;
static bool g_legacy_write_attempted = false;
static bool g_storage_locked = false;
static bool g_storage_fail = false;
static bool g_stamp_metadata_write_fail = false;
static bool g_last_init_blank = false;

extern "C" {
void esp_fill_random(void *buf, size_t len) {
    memset(buf, 0x5A, len);
}
esp_err_t home_storage_acquire(bool initialize_blank) {
    assert(!g_storage_locked);
    g_last_init_blank = initialize_blank;
    if (g_storage_fail) return ESP_FAIL;
    g_storage_locked = true;
    return ESP_OK;
}
void home_storage_release(void) {
    assert(g_storage_locked);
    g_storage_locked = false;
}
esp_err_t nvs_open(const char *ns, nvs_open_mode_t mode, nvs_handle_t *out) {
    if (strcmp(ns, "fmo_cred") == 0 && mode == NVS_READWRITE) {
        g_legacy_write_attempted = true;
        return ESP_FAIL;
    }
    if (mode == NVS_READONLY && g_nvs.find(ns) == g_nvs.end()) return ESP_ERR_NVS_NOT_FOUND;
    int h = g_next_handle++;
    g_handles[h] = {ns, mode};
    *out = h;
    return ESP_OK;
}
esp_err_t nvs_get_blob(nvs_handle_t h, const char *key, void *out, size_t *len) {
    auto it = g_handles.find(h);
    if (it == g_handles.end()) return ESP_FAIL;
    auto &ns = g_nvs[it->second.first];
    auto kit = ns.find(key);
    if (kit == ns.end()) return ESP_ERR_NVS_NOT_FOUND;
    if (!out) { *len = kit->second.size(); return ESP_OK; }
    if (*len < kit->second.size()) return ESP_FAIL;
    *len = kit->second.size();
    memcpy(out, kit->second.data(), *len);
    return ESP_OK;
}
esp_err_t nvs_get_str(nvs_handle_t h, const char *key, char *out, size_t *len) {
    return nvs_get_blob(h, key, out, len);
}
esp_err_t nvs_set_blob(nvs_handle_t h, const char *key, const void *data, size_t len) {
    if (g_stamp_metadata_write_fail && strcmp(key, "stamp_v1") == 0) return ESP_FAIL;
    auto it = g_handles.find(h);
    if (it == g_handles.end() || it->second.second != NVS_READWRITE) return ESP_FAIL;
    auto *p = static_cast<const uint8_t *>(data);
    g_nvs[it->second.first][key].assign(p, p + len);
    return ESP_OK;
}
esp_err_t nvs_erase_key(nvs_handle_t h, const char *key) {
    const auto it = g_handles.find(h);
    if (it == g_handles.end() || it->second.second != NVS_READWRITE) return ESP_FAIL;
    return g_nvs[it->second.first].erase(key) ? ESP_OK : ESP_ERR_NVS_NOT_FOUND;
}
esp_err_t nvs_commit(nvs_handle_t) { return ESP_OK; }
void nvs_close(nvs_handle_t h) { g_handles.erase(h); }
}

static std::string read_file_str(const char *path) {
    std::ifstream f(path, std::ios::binary);
    return std::string((std::istreambuf_iterator<char>(f)), {});
}

int main(int argc, char **argv) {
    assert(argc == 6 && sodium_init() >= 0);
    std::string base = argv[1];
    std::string root_json = read_file_str(argv[2]);
    std::string inter_json = read_file_str(argv[3]);
    std::string user_json = read_file_str(argv[4]);
    std::string station_line = read_file_str(argv[5]);
    assert(root_json.size() < sizeof(fmo_root_start));
    strcpy(fmo_root_start, root_json.c_str());

    {
        fmo::BeepConfig cfg;
        assert(fmo::load_beep_config(&cfg) == fmo::BeepLoad::Missing && cfg.enabled);
        std::vector<uint8_t> pcm(16 + 2 * fmo::kBeepFrameSamples, 0x11);
        auto put32 = [&](size_t offset, uint32_t value) {
            for (unsigned i = 0; i < 4; ++i) pcm[offset + i] = uint8_t(value >> (8 * i));
        };
        memcpy(pcm.data(), "FBEP", 4);
        pcm[4] = 1; pcm[5] = 2; pcm[6] = pcm[7] = 0;
        put32(8, fmo::kBeepFrameSamples);
        put32(12, fmo::crc32(pcm.data() + 16, pcm.size() - 16));
        assert(!fmo::beep_parse_fbep(pcm.data(), pcm.size()-1, nullptr, nullptr, nullptr));
        pcm.back() ^= 1;
        assert(!fmo::save_custom_beep_fbep(pcm.data(), pcm.size(), &cfg));
        pcm.back() ^= 1;
        assert(fmo::save_custom_beep_fbep(pcm.data(), pcm.size(), &cfg));
        fmo::BeepStream stream;
        stream.open(cfg);
        assert(stream.is_custom() && !g_storage_locked);
        int16_t chunk[320]{};
        stream.read_samples(0, chunk, 320);
        assert(chunk[0] == 0x1111 && chunk[319] == 0x1111 && !g_storage_locked);
        pcm[5] = 3;
        assert(fmo::save_custom_beep_fbep(pcm.data(), pcm.size(), &cfg));
        pcm[5] = 5;
        assert(!fmo::save_custom_beep_fbep(pcm.data(), pcm.size(), &cfg));
        assert(fmo::clear_custom_beep(&cfg));
        stream.read_samples(319, chunk, 320);
        assert(chunk[0] == 0x1111 && chunk[1] == 0 && !g_storage_locked);
        stream.close();
        assert(fmo::save_custom_beep_fbep(pcm.data(), pcm.size(), &cfg));
        puts("FMO beep: FBEP CRC, sliced samples, pinned bank replacement and storage release PASS");
    }

    // 1. Built-in 12 stamps: validation, rendering, palette, PAT-1 parsing.
    for (unsigned i = 0; i < fmo::kBuiltinStampCount; ++i) {
        const char *id = fmo::stamp_builtin_id(i);
        assert(fmo::stamp_style_valid(id));
        assert(fmo::stamp_builtin_index(id) == int(i));
        assert(strlen(fmo::stamp_builtin_name(i)) > 0);
        uint8_t px[fmo::kStampPixelBytes]{};
        fmo::stamp_render_builtin(i, px);
        assert(fmo::stamp_pixels_nonempty(px));
    }
    assert(fmo::stamp_style_valid("CUSTOM") && fmo::stamp_is_custom_style("CUSTOM"));
    assert(!fmo::stamp_style_valid("bad") && !fmo::stamp_style_valid("G000") && !fmo::stamp_style_valid(""));
    assert(fmo::stamp_label_valid("AI PASSPORT") && fmo::stamp_label_valid("北京PM01") && !fmo::stamp_label_valid("bad,label"));
    uint8_t pal[fmo::kStampPaletteBytes]{};
    fmo::stamp_build_palette(0xFF7A1A, pal);
    assert(pal[0] == 0 && pal[1] == 0 && pal[2] == 0 && pal[3] == 255);
    assert(pal[60] == 0x1A && pal[61] == 0x7A && pal[62] == 0xFF && pal[63] == 255);

    char pc[13]{}, ps[8]{};
    const char *pat1 = "BG0PEER-15>APPASP,TCPIP*:=3037.98NF11932.20EiPAT-1,ST:G009,VER:0.6.10,FREQ:438.5000";
    assert(fmo::parse_pat1_stamp(pat1, strlen(pat1), pc, ps) && !strcmp(pc, "BG0PEER") && !strcmp(ps, "G009"));
    assert(!fmo::parse_pat1_stamp("BG0PEER>APFMO4,TCPIP*:=3037.98NF11932.20EiPAT-1,ST:G009", 55, pc, ps));

    // 2. Dual-bank custom stamp persistence + corruption recovery + coexistence.
    {
        std::ofstream bg(base + "/home-bg-a.jpg", std::ios::binary);
        bg << "KEEP_BG";
    }
    fmo::StampConfig cfg{};
    assert(fmo::load_stamp_config(&cfg) == fmo::StampLoad::Missing);
    uint8_t img_a[fmo::kStampPixelBytes]{}, img_b[fmo::kStampPixelBytes]{}, loaded[fmo::kStampPixelBytes]{};
    assert(!fmo::save_custom_stamp_image(img_a, &cfg, true)); // Rejects empty image.
    memset(img_a, 0xA5, sizeof(img_a));
    memset(img_b, 0x5A, sizeof(img_b));
    cfg.color_rgb = 0x2E8B57;
    strcpy(cfg.label, "MY STAMP");
    assert(fmo::save_custom_stamp_image(img_a, &cfg, true));
    assert(g_last_init_blank == true && !g_storage_locked);
    assert(cfg.custom_present && cfg.custom_bank == 0 && !strcmp(cfg.style_id, "CUSTOM"));
    assert(fmo::load_custom_stamp_image(cfg, loaded) == fmo::StampLoad::Ready && memcmp(loaded, img_a, sizeof(img_a)) == 0);
    // Second write flips to bank 1 while leaving bank 0 intact until committed.
    auto stale_appearance = cfg;
    strcpy(stale_appearance.style_id, "G002");
    assert(fmo::save_custom_stamp_image(img_b, &cfg, true));
    assert(cfg.custom_bank == 1);
    assert(!fmo::save_stamp_config(stale_appearance));
    fmo::StampConfig after_edit{};
    assert(fmo::load_stamp_config(&after_edit) == fmo::StampLoad::Ready);
    assert(after_edit.custom_bank == cfg.custom_bank && after_edit.custom_crc == cfg.custom_crc);
    assert(fmo::save_stamp_config(after_edit));
    assert(fmo::load_custom_stamp_image(cfg, loaded) == fmo::StampLoad::Ready && memcmp(loaded, img_b, sizeof(img_b)) == 0);
    // Corrupt active bank 1 -> load fails cleanly (CRC mismatch), and next write preserves/recovers.
    {
        std::fstream f(base + "/fmo-stamp-b.bin", std::ios::in | std::ios::out | std::ios::binary);
        f.seekp(64);
        char bad = 0;
        f.write(&bad, 1);
    }
    assert(fmo::load_custom_stamp_image(cfg, loaded) == fmo::StampLoad::Unavailable);
    // Restore a matching copy on the alternate bank. If writing a replacement
    // succeeds but publishing its metadata fails, the matching copy must survive.
    const auto valid_b = read_file_str((base + "/fmo-stamp-b.bin").c_str());
    auto recovered = valid_b;
    recovered[64] = 0x5A;
    {
        std::ofstream backup(base + "/fmo-stamp-a.bin", std::ios::binary);
        backup.write(recovered.data(), recovered.size());
        assert(backup.good());
    }
    assert(fmo::load_custom_stamp_image(cfg, loaded) == fmo::StampLoad::Ready);
    assert(memcmp(loaded, img_b, sizeof(img_b)) == 0);
    g_stamp_metadata_write_fail = true;
    assert(!fmo::save_custom_stamp_image(img_a, &cfg, true));
    g_stamp_metadata_write_fail = false;
    assert(!g_storage_locked);
    assert(fmo::load_stamp_config(&cfg) == fmo::StampLoad::Ready);
    assert(fmo::load_custom_stamp_image(cfg, loaded) == fmo::StampLoad::Ready);
    assert(memcmp(loaded, img_b, sizeof(img_b)) == 0);
    // Existing home background file was never touched.
    assert(read_file_str((base + "/home-bg-a.jpg").c_str()) == "KEEP_BG");
    // Corrupt NVS metadata prevents accidental overwrite.
    g_nvs["fmo_os"]["stamp_v1"][10] ^= 0xFF;
    assert(fmo::load_stamp_config(&cfg) == fmo::StampLoad::Unavailable);
    assert(!fmo::save_custom_stamp_image(img_a, &cfg, true));
    // Restore valid metadata and clear custom stamp cleanly.
    g_nvs["fmo_os"]["stamp_v1"][10] ^= 0xFF;
    assert(fmo::clear_custom_stamp_image(&cfg) && !cfg.custom_present && !strcmp(cfg.style_id, "G001"));
    assert(!fmo::save_stamp_config(after_edit));

    // 3. PeerStamps NVS persistence & corruption check.
    fmo::PeerStamps peers{};
    assert(fmo::load_peer_stamps(&peers) == fmo::StampLoad::Missing);
    assert(peers.remember("P-BG0ONE", "G005"));
    assert(peers.remember("BG0TWO", "G011"));
    assert(!strcmp(peers.find("BG0ONE"), "G005") && !strcmp(peers.find("P-BG0TWO"), "G011"));
    assert(fmo::save_peer_stamps(peers));
    fmo::PeerStamps peers2{};
    assert(fmo::load_peer_stamps(&peers2) == fmo::StampLoad::Ready && peers2.count == 2 && !strcmp(peers2.find("BG0ONE"), "G005"));
    g_nvs["fmo_os"]["psty_v1"][10] ^= 0x55;
    assert(fmo::load_peer_stamps(&peers2) == fmo::StampLoad::Unavailable);

    // 4. Favorites NVS persistence & corruption check.
    fmo::Favorites favs{};
    assert(fmo::load_favorites(&favs) == fmo::FavoritesLoad::Missing);
    fmo::Relay r1{}; r1.uid = 101; strcpy(r1.callsign, "BG0SRV"); memset(r1.fingerprint, 0x33, 32);
    assert(favs.add(r1) && !favs.add(r1) && fmo::save_favorites(favs));
    fmo::Favorites favs2{};
    assert(fmo::load_favorites(&favs2) == fmo::FavoritesLoad::Ready && favs2.count == 1 && favs2.find(r1) == 0);
    auto r2 = r1;
    ++r2.uid;
    assert(!fmo::remember_connected_relay(&favs2, r2, 0, 1800000000));
    assert(!fmo::remember_connected_relay(&favs2, r2, 1800000000, 1800000000));
    assert(fmo::remember_connected_relay(&favs2, r2, 1800000600, 1800000000));
    assert(!fmo::remember_connected_relay(&favs2, r2, 1800000600, 1800000000));
    assert(fmo::load_favorites(&favs2) == fmo::FavoritesLoad::Ready && favs2.count == 2 && favs2.find(r2) == 1);
    g_nvs["fmo_os"]["favorites_v1"][8] ^= 0xAA;
    assert(fmo::load_favorites(&favs2) == fmo::FavoritesLoad::Unavailable);

    // 5. Read-only fmo_cred legacy migration + P- prefix + APPASP station verification.
    assert(!fmo::legacy_identity_available(nullptr, nullptr));
    std::vector<uint8_t> legacy_seed(32, 13);
    g_nvs["fmo_cred"]["seed"] = legacy_seed;
    g_nvs["fmo_cred"]["inter"].assign(inter_json.begin(), inter_json.end());
    g_nvs["fmo_cred"]["inter"].push_back(0);
    g_nvs["fmo_cred"]["user"].assign(user_json.begin(), user_json.end());
    g_nvs["fmo_cred"]["user"].push_back(0);

    std::string lcall; uint32_t luid = 0;
    assert(fmo::legacy_identity_available(&lcall, &luid) && lcall == "P-BG0TST" && luid == 9610123);
    std::string err;
    assert(fmo::import_legacy_identity(&err));
    assert(!g_legacy_write_attempted); // fmo_cred was NEVER opened READWRITE!
    // Second import refuses to overwrite existing valid fmo_os cert.
    assert(!fmo::import_legacy_identity(&err) && err.find("未覆盖") != std::string::npos);

    fmo::Credential loaded_cred{}; uint8_t sk[64]{};
    assert(fmo::load_identity(&loaded_cred, sk, &err) && !strcmp(loaded_cred.callsign, "P-BG0TST") && loaded_cred.uid == 9610123);
    // APRS login works for P- prefixed cert!
    fmo::BroadcastConfig bc{}; bc.enabled = true; bc.ssid = 15; strcpy(bc.grid, "PM06"); strcpy(bc.frequency, "438.5");
    std::string login, llogin_call;
    assert(fmo::aprs_login(loaded_cred.callsign, bc, &login, &llogin_call) && llogin_call == "BG0TST-15");
    // APPASP station announcement with P- prefixed cert passes full Ed25519 + CA verification!
    fmo::Relay discovered{}; uint32_t until = 0; fmo::StationStatus st{};
    assert(fmo::station_announcement(station_line.data(), station_line.size(), loaded_cred, fmo_root_start, 1800000000, &discovered, &until, &st));
    assert(discovered.uid == 9610200 && !strcmp(discovered.callsign, "P-BG0SRV") && st.online == 8 && st.peak == 50);
    sodium_memzero(sk, sizeof(sk));
    puts("FMO stamp dual-bank/raster/peers, favorites, read-only fmo_cred import, P- APRS and APPASP station: PASS");
    return 0;
}
'''

with tempfile.TemporaryDirectory() as td:
    p = Path(td)
    storage = p / 'storage'
    storage.mkdir()
    mocks = p / 'mocks'
    mocks.mkdir()
    (mocks / 'nvs.h').write_text('''#pragma once
#include <stddef.h>
#include <stdint.h>
#include "esp_err.h"
typedef int nvs_handle_t;
typedef enum { NVS_READONLY = 1, NVS_READWRITE = 2 } nvs_open_mode_t;
#define ESP_ERR_NVS_NOT_FOUND 0x1102
#ifdef __cplusplus
extern "C" {
#endif
esp_err_t nvs_open(const char *ns, nvs_open_mode_t mode, nvs_handle_t *out);
esp_err_t nvs_get_blob(nvs_handle_t h, const char *key, void *out, size_t *len);
esp_err_t nvs_get_str(nvs_handle_t h, const char *key, char *out, size_t *len);
esp_err_t nvs_set_blob(nvs_handle_t h, const char *key, const void *data, size_t len);
esp_err_t nvs_erase_key(nvs_handle_t h, const char *key);
esp_err_t nvs_commit(nvs_handle_t h);
void nvs_close(nvs_handle_t h);
#ifdef __cplusplus
}
#endif
''')
    (mocks / 'esp_err.h').write_text('''#pragma once
typedef int esp_err_t;
#define ESP_OK 0
#define ESP_FAIL -1
''')
    (mocks / 'esp_random.h').write_text('''#pragma once
#include <stddef.h>
#ifdef __cplusplus
extern "C" {
#endif
void esp_fill_random(void *buf, size_t len);
#ifdef __cplusplus
}
#endif
''')
    # Override time() inside fmo_store.cc via a tiny wrapper header or -Dtime=test_time
    (p / 'root.json').write_text(json.dumps(r_cert))
    (p / 'inter.json').write_text(json.dumps(i_cert))
    (p / 'user.json').write_text(json.dumps(u_cert))
    (p / 'station.txt').write_text(appasp_station)
    (p / 'test.cc').write_text(harness)
    # Compile fmo_store.cc with fixed test clock so cert validity is deterministic regardless of host wall clock.
    store_src = (root / 'components/passport_fmo/src/fmo_store.cc').read_text()
    store_src = store_src.replace('time(nullptr)', '1800000000u')
    (p / 'fmo_store_test.cc').write_text(store_src)
    subprocess.run([
        'c++', '-std=c++17', '-Wall', '-Wextra', '-Werror',
        '-fsanitize=address,undefined', '-g',
        f'-DFMO_STAMP_BASE="{storage}"',
        f'-DFMO_BEEP_BASE="{storage}"',
        '-I' + str(mocks), '-Imain', '-Icomponents/passport_fmo/src', '-Itests/vendor/cjson',
        str(p / 'test.cc'),
        str(p / 'fmo_store_test.cc'),
        'components/passport_fmo/src/fmo_stamp.cc',
        'components/passport_fmo/src/fmo_beep.cc',
        'components/passport_fmo/src/fmo_favorites.cc',
        'components/passport_fmo/src/fmo_crypto.cc',
        'components/passport_fmo/src/fmo_aprs.cc',
        'components/passport_fmo/src/fmo_wire.cc',
        'tests/vendor/cjson/cJSON.c',
        '-lsodium', '-lm', '-o', str(p / 'test_stamp')
    ], cwd=root, check=True)
    subprocess.run([
        str(p / 'test_stamp'),
        str(storage), str(p / 'root.json'), str(p / 'inter.json'), str(p / 'user.json'), str(p / 'station.txt')
    ], cwd=root, check=True)
