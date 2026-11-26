#include "apps/home/home_upload.h"

#include "apps/home/home_profile.h"
#include "apps/home/home_background.h"
#include "apps/fmo/fmo_http.h"
#include "esp_http_server.h"
#include "esp_log.h"
#include <esp_random.h>      // esp_fill_random():每次开启上传窗口换一个一次性 token
#include "wifi_manager.h"

#include <cJSON.h>
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <cerrno>
#include <climits>
#include <atomic>
#include <algorithm>
#include <new>
#include <string>
#include "ssid_manager.h"
#include "home_wifi_selection.h"
#include <mutex>
#include "esp_timer.h"
#include "phone_time.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

static const char *TAG = "home_upload";

static httpd_handle_t s_server;
static char s_url[32];

// 2026-09-13 修复(B8):上传接口原先完全无鉴权,同一局域网任何人都能 POST
// /api/profile 改写城市。每次开启设置窗口生成一个
// 一次性 token,页面里通过 window.__T 带上,所有写入接口都校验 ?t=。
// 这不是强认证(设备没有账号体系),但足以挡住"随手扫一下端口就能改"的滥用。
static uint32_t s_token = 0;

// 从 req->uri 的 query 里取 t= 并比对。URL 形如 /api/profile?t=123456
static bool token_ok(httpd_req_t *req) {
    if (s_token == 0) return false;
    char query[96], token[16];
    if (httpd_req_get_url_query_str(req, query, sizeof(query)) != ESP_OK ||
        httpd_query_key_value(query, "t", token, sizeof(token)) != ESP_OK) return false;
    for (const char *p = token; *p; ++p) if (*p < '0' || *p > '9') return false;
    char *end = nullptr;
    errno = 0;
    const unsigned long value = std::strtoul(token, &end, 10);
    return token[0] && end && !*end && errno != ERANGE && value <= UINT32_MAX &&
           static_cast<uint32_t>(value) == s_token;
}

// ---------------------------------------------------------------------------
// Offline phone configuration page and city directory.
// ---------------------------------------------------------------------------
extern const char phone_page_start[] asm("_binary_phone_setup_html_gz_start");
extern const char phone_page_end[] asm("_binary_phone_setup_html_gz_end");
extern const char cities_start[] asm("_binary_cities_json_gz_start");
extern const char cities_end[] asm("_binary_cities_json_gz_end");
static std::atomic<int> s_network_state{0}; // 0 idle, 1 connecting, 2 verified, 3 failed
static std::atomic<int64_t> s_finish_at{0};
static bool s_had_saved = false;
static std::string s_target_ssid;
static std::mutex s_network_mutex;
static std::vector<SsidItem> s_saved_networks;

// ---------------------------------------------------------------------------
// 处理器
// ---------------------------------------------------------------------------

static esp_err_t send_json(httpd_req_t *req, int status, const char *json) {
    httpd_resp_set_type(req, "application/json");
    httpd_resp_set_hdr(req, "Cache-Control", "no-store, max-age=0");
    httpd_resp_set_status(req, status == 200 ? "200 OK" :
                              status == 401 ? "401 Unauthorized" : "400 Bad Request");
    httpd_resp_send(req, json, HTTPD_RESP_USE_STRLEN);
    return ESP_OK;
}

static esp_err_t handler_captive(httpd_req_t *req) {
    httpd_resp_set_status(req, "302 Found");
    httpd_resp_set_hdr(req, "Location", "http://192.168.4.1/");
    httpd_resp_set_hdr(req, "Cache-Control", "no-store, max-age=0");
    return httpd_resp_send(req, nullptr, 0);
}

static esp_err_t handler_index(httpd_req_t *req) {
    char host[64];
    if (httpd_req_get_hdr_value_str(req, "Host", host, sizeof(host)) != ESP_OK ||
        (strcmp(host, "192.168.4.1") && strcmp(host, "192.168.4.1:80")))
        return handler_captive(req);
    httpd_resp_set_type(req, "text/html; charset=utf-8");
    httpd_resp_set_hdr(req, "Cache-Control", "no-store, max-age=0");
    httpd_resp_set_hdr(req, "Content-Encoding", "gzip");
    // 页面在 flash 中已 gzip,无法再原样注入;一次性 token 改由 cookie 交给页面脚本
    // (页面读出后仍走 t= 参数鉴权,cookie 本身不参与鉴权,不引入 CSRF)。
    char cookie[48];
    std::snprintf(cookie, sizeof(cookie), "pt=%lu; Path=/; SameSite=Strict",
                  (unsigned long)s_token);
    httpd_resp_set_hdr(req, "Set-Cookie", cookie);
    return httpd_resp_send(req, phone_page_start, phone_page_end - phone_page_start);
}

static esp_err_t handler_cities(httpd_req_t *req) {
    httpd_resp_set_type(req, "application/json; charset=utf-8");
    httpd_resp_set_hdr(req, "Content-Encoding", "gzip");
    httpd_resp_set_hdr(req, "Cache-Control", "no-store");
    // Browser decompresses; serve straight from flash, never inflate in C3 RAM.
    return httpd_resp_send(req, cities_start, cities_end - cities_start);
}

static esp_err_t handler_profile_get(httpd_req_t *req) {
    if (!token_ok(req)) return send_json(req, 401, "{\"error\":\"unauthorized\"}");
    home_profile_t profile;
    home_profile_get(&profile);
    cJSON *root = cJSON_CreateObject();
    cJSON_AddStringToObject(root, "city", profile.city);
    cJSON_AddStringToObject(root, "lat", profile.lat);
    cJSON_AddStringToObject(root, "lon", profile.lon);
    cJSON_AddStringToObject(root, "region", profile.region);
    cJSON_AddStringToObject(root, "radio_city", profile.radio_city);
    cJSON_AddStringToObject(root, "country_code", profile.country_code);
    char *json = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    if (!json) return send_json(req, 400, "{\"error\":\"oom\"}");
    esp_err_t err = send_json(req, 200, json);
    cJSON_free(json);
    return err;
}

static esp_err_t handler_profile_post(httpd_req_t *req) {
    if (!token_ok(req)) return send_json(req, 401, "{\"error\":\"unauthorized\"}");
    char body[1024];
    const size_t len = (size_t)req->content_len;
    if (len == 0 || len > sizeof(body) - 1) {
        return send_json(req, 400, "{\"error\":\"bad size\"}");
    }
    int received = 0;
    while (received < (int)len) {
        int n = httpd_req_recv(req, body + received, len - received);
        if (n <= 0) return send_json(req, 400, "{\"error\":\"recv\"}");
        received += n;
    }
    body[received] = '\0';

    cJSON *root = cJSON_Parse(body);
    if (!root) return send_json(req, 400, "{\"error\":\"json\"}");

    // 只接受网页会填的字段;缺省按空串处理,等于允许清空资料
    home_profile_t in = {};
    const auto grab = [&](const char *key, char *dst, size_t cap) {
        const cJSON *item = cJSON_GetObjectItemCaseSensitive(root, key);
        const char *value = cJSON_IsString(item) ? item->valuestring : "";
        if (std::strlen(value) >= cap) return false;
        std::memcpy(dst, value, std::strlen(value) + 1);
        return true;
    };
    const bool valid = grab("city", in.city, HOME_CITY_MAX) &&
        grab("lat", in.lat, HOME_COORD_MAX) &&
        grab("lon", in.lon, HOME_COORD_MAX) &&
        grab("region", in.region, HOME_REGION_MAX) &&
        grab("radio_city", in.radio_city, HOME_CITY_MAX) &&
        grab("country_code", in.country_code, sizeof(in.country_code));
    cJSON_Delete(root);
    if (!valid) return send_json(req, 400, "{\"error\":\"text too long\"}");

    esp_err_t err = home_profile_set_text(&in);
    return send_json(req, err == ESP_OK ? 200 : 400,
                     err == ESP_OK ? "{\"ok\":true}" : "{\"error\":\"invalid\"}");
}

static esp_err_t handler_background_get(httpd_req_t *req) {
    if (!token_ok(req)) return send_json(req, 401, "{\"error\":\"unauthorized\"}");
    bool present = false; size_t bytes = 0;
    const auto result = home_background_info(&present, &bytes);
    char json[160];
    std::snprintf(json, sizeof(json), "{\"present\":%s,\"available\":%s,\"bytes\":%u,\"max_bytes\":%u}",
        present ? "true" : "false", result == ESP_OK ? "true" : "false",
        static_cast<unsigned>(bytes), static_cast<unsigned>(HOME_BACKGROUND_MAX_BYTES));
    return send_json(req, 200, json);
}
static esp_err_t handler_background_post(httpd_req_t *req) {
    if (!token_ok(req)) return send_json(req, 401, "{\"error\":\"unauthorized\"}");
    if (req->content_len <= 0 || req->content_len > HOME_BACKGROUND_MAX_BYTES)
        return send_json(req, 400, "{\"error\":\"background_size\"}");
    const size_t total = req->content_len;
    size_t received = 0; char chunk[512];
    const int64_t deadline = esp_timer_get_time() + 60000000; // first upload may initialize a blank SPIFFS partition
    while (received < total) {
        if (esp_timer_get_time() > deadline) {
            home_background_abort(); return send_json(req, 400, "{\"error\":\"background_recv\"}");
        }
        const int count = httpd_req_recv(req, chunk, std::min(sizeof(chunk), total - received));
        if (count <= 0) {
            home_background_abort(); return send_json(req, 400, "{\"error\":\"background_recv\"}");
        }
        const auto result = home_background_write(reinterpret_cast<const uint8_t *>(chunk), count,
            received == 0, received + count == total, total);
        if (result != ESP_OK) {
            home_background_abort();
            return send_json(req, 400, result == ESP_ERR_INVALID_ARG ? "{\"error\":\"background_image\"}"
                : "{\"error\":\"background_store\"}");
        }
        received += count;
    }
    return send_json(req, 200, "{\"ok\":true}");
}
static esp_err_t handler_background_delete(httpd_req_t *req) {
    if (!token_ok(req)) return send_json(req, 401, "{\"error\":\"unauthorized\"}");
    const auto result = home_background_clear();
    return send_json(req, result == ESP_OK ? 200 : 400,
        result == ESP_OK ? "{\"ok\":true}" : "{\"error\":\"background_store\"}");
}

struct NetworkJob { std::vector<SsidItem> candidates; };

static void network_worker(void *arg) {
    auto *job = static_cast<NetworkJob *>(arg);
    bool ok = false;
    for (auto &candidate : job->candidates) {
        {
            std::lock_guard<std::mutex> lock(s_network_mutex);
            s_target_ssid = candidate.ssid;
        }
        if (WifiManager::GetInstance().ConfigureNetwork(candidate.ssid, candidate.password, true)) {
            ok = true;
            break;
        }
    }
    // Do not log credentials; dispose of the request before publishing completion.
    for (auto &candidate : job->candidates)
        std::fill(candidate.password.begin(), candidate.password.end(), '\0');
    delete job;
    s_network_state.store(ok ? 2 : 3);
    vTaskDelete(nullptr);
}

static esp_err_t reply_object(httpd_req_t *req, cJSON *root) {
    if (!root) return send_json(req, 400, "{\"error\":\"oom\"}");
    char *json = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    if (!json) return send_json(req, 400, "{\"error\":\"oom\"}");
    auto err = send_json(req, 200, json);
    cJSON_free(json);
    return err;
}

static esp_err_t handler_setup(httpd_req_t *req) {
    if (!token_ok(req)) return send_json(req, 401, "{\"error\":\"unauthorized\"}");
    auto *root = cJSON_CreateObject();
    const bool sta_ip = WifiManager::GetInstance().HasStationIp();
    int st = s_network_state.load();
    if (st == 2 && !sta_ip) st = 0; // Live STA IP dropped; never report stale connected state.
    const char *states[] = {"idle", "connecting", "connected", "failed"};
    cJSON_AddStringToObject(root, "state", states[st]);
    cJSON_AddBoolToObject(root, "sta_connected", sta_ip);
    const std::string live_ssid = sta_ip ? WifiManager::GetInstance().GetSsid() : "";
    cJSON_AddStringToObject(root, "sta_ssid", live_ssid.c_str());
    cJSON_AddBoolToObject(root, "saved_network", s_had_saved);
    auto *saved = cJSON_AddArrayToObject(root, "saved_networks");
    for (const auto &item : s_saved_networks)
        cJSON_AddItemToArray(saved, cJSON_CreateString(item.ssid.c_str()));
    cJSON_AddBoolToObject(root, "finishing", s_finish_at.load() != 0);
    {
        std::lock_guard<std::mutex> lock(s_network_mutex);
        cJSON_AddStringToObject(root, "ssid", !live_ssid.empty() ? live_ssid.c_str() : s_target_ssid.c_str());
    }
    cJSON_AddStringToObject(root, "hotspot", WifiManager::GetInstance().GetApSsid().c_str());
    return reply_object(req, root);
}

static esp_err_t handler_networks(httpd_req_t *req) {
    if (!token_ok(req)) return send_json(req, 401, "{\"error\":\"unauthorized\"}");
    auto aps = WifiManager::GetInstance().GetConfigAccessPoints();
    std::sort(aps.begin(), aps.end(), [](const auto &a, const auto &b) { return a.rssi > b.rssi; });
    auto *root = cJSON_CreateArray();
    std::vector<std::string> seen;
    for (const auto &ap : aps) {
        const std::string ssid(reinterpret_cast<const char *>(ap.ssid), strnlen(reinterpret_cast<const char *>(ap.ssid), 32));
        if (ssid.empty() || std::find(seen.begin(), seen.end(), ssid) != seen.end()) continue;
        if (seen.size() >= 20) break;
        seen.push_back(ssid);
        auto *item = cJSON_CreateObject();
        cJSON_AddStringToObject(item, "ssid", ssid.c_str());
        cJSON_AddNumberToObject(item, "rssi", ap.rssi);
        cJSON_AddBoolToObject(item, "secure", ap.authmode != WIFI_AUTH_OPEN);
        cJSON_AddItemToArray(root, item);
    }
    return reply_object(req, root);
}

static esp_err_t handler_connect(httpd_req_t *req) {
    if (!token_ok(req)) return send_json(req, 401, "{\"error\":\"unauthorized\"}");
    if (s_network_state.load() == 1 || s_finish_at.load()) return send_json(req, 400, "{\"error\":\"busy\"}");
    char body[768];
    if (req->content_len <= 0 || req->content_len >= (int)sizeof(body)) return send_json(req, 400, "{\"error\":\"size\"}");
    int received = 0;
    while (received < req->content_len) {
        int n = httpd_req_recv(req, body + received, req->content_len - received);
        if (n <= 0) return send_json(req, 400, "{\"error\":\"recv\"}");
        received += n;
    }
    body[received] = 0;
    auto *root = cJSON_Parse(body);
    if (!root) return send_json(req, 400, "{\"error\":\"json\"}");
    auto *job = new (std::nothrow) NetworkJob;
    if (!job) { cJSON_Delete(root); return send_json(req, 400, "{\"error\":\"oom\"}"); }
    bool valid = false;
    const bool reuse = cJSON_IsTrue(cJSON_GetObjectItemCaseSensitive(root, "saved"));
    if (reuse) {
        const auto *selected = cJSON_GetObjectItemCaseSensitive(root, "ssid");
        if (!selected || cJSON_IsString(selected)) {
            job->candidates = home_wifi_candidates(s_saved_networks,
                WifiManager::GetInstance().GetConfigAccessPoints(), selected ? selected->valuestring : "");
            valid = !job->candidates.empty();
        }
    } else {
        const auto *ssid = cJSON_GetObjectItemCaseSensitive(root, "ssid");
        const auto *password = cJSON_GetObjectItemCaseSensitive(root, "password");
        if (cJSON_IsString(ssid) && cJSON_IsString(password)) {
            const std::string name = ssid->valuestring, key = password->valuestring;
            const auto n = key.size();
            const bool hex_key = n == 64 && key.find_first_not_of("0123456789abcdefABCDEF") == std::string::npos;
            valid = !name.empty() && name.size() <= 32 && (n == 0 || (n >= 8 && n <= 63) || hex_key);
            if (valid) job->candidates.push_back({name, key});
        }
    }
    if (valid) wifi_phone_time_apply(root);
    cJSON_Delete(root);
    memset(body, 0, sizeof(body));
    if (!valid) { delete job; return send_json(req, 400, reuse ? "{\"error\":\"saved_not_found\"}" : "{\"error\":\"credentials\"}"); }
    s_network_state = 1;
    if (xTaskCreate(network_worker, "phone_wifi", 4096, job, 4, nullptr) != pdPASS) {
        delete job; s_network_state = 3;
        return send_json(req, 400, "{\"error\":\"oom\"}");
    }
    return send_json(req, 200, "{\"ok\":true}");
}

static esp_err_t handler_finish(httpd_req_t *req) {
    if (!token_ok(req)) return send_json(req, 401, "{\"error\":\"unauthorized\"}");
    const auto state = s_network_state.load();
    if (state == 1 || (!s_had_saved && state != 2)) return send_json(req, 400, "{\"error\":\"network_required\"}");
    // Let the phone receive confirmation before the system task tears down HTTP/AP.
    s_finish_at = esp_timer_get_time() + 3500000;
    return send_json(req, 200, "{\"ok\":true}");
}

static esp_err_t handler_time(httpd_req_t *req) {
    if (!token_ok(req)) return send_json(req, 401, "{\"error\":\"unauthorized\"}");
    char body[160];
    if (req->content_len <= 0 || req->content_len >= (int)sizeof(body))
        return send_json(req, 400, "{\"error\":\"size\"}");
    int received = 0;
    while (received < req->content_len) {
        int n = httpd_req_recv(req, body + received, req->content_len - received);
        if (n <= 0) return send_json(req, 400, "{\"error\":\"recv\"}");
        received += n;
    }
    body[received] = '\0';
    auto *root = cJSON_Parse(body);
    if (!root) return send_json(req, 400, "{\"error\":\"json\"}");
    wifi_phone_time_apply(root);
    cJSON_Delete(root);
    return send_json(req, 200, "{\"ok\":true}");
}
static esp_err_t handler_fmo(httpd_req_t *req) {
    if (!token_ok(req)) return send_json(req,401,"{\"error\":\"unauthorized\"}");
    if (s_finish_at.load()) return send_json(req,400,"{\"error\":\"finishing\"}");
    return fmo_http_settings(req);
}
static esp_err_t handler_fmo_ca(httpd_req_t *req) {
    if (!token_ok(req)) return send_json(req,401,"{\"error\":\"unauthorized\"}");
    if (s_finish_at.load()) return send_json(req,400,"{\"error\":\"finishing\"}");
    return fmo_http_ca(req);
}
static esp_err_t handler_fmo_stamp(httpd_req_t *req) {
    if (!token_ok(req)) return send_json(req,401,"{\"error\":\"unauthorized\"}");
    if (s_finish_at.load()) return send_json(req,400,"{\"error\":\"finishing\"}");
    return fmo_http_stamp(req);
}
static esp_err_t handler_fmo_beep(httpd_req_t *req) {
    if (!token_ok(req)) return send_json(req,401,"{\"error\":\"unauthorized\"}");
    if (s_finish_at.load()) return send_json(req,400,"{\"error\":\"finishing\"}");
    return fmo_http_beep(req);
}

esp_err_t home_upload_start(void) {
    if (s_server) return ESP_OK;
    if (!WifiManager::GetInstance().IsConfigMode()) return ESP_ERR_INVALID_STATE;
    s_network_state = 0; s_finish_at = 0; s_target_ssid.clear();
    s_saved_networks = SsidManager::GetInstance().GetSsidList();
    s_had_saved = !s_saved_networks.empty();

    // 每个上传窗口换一个 token(见 token_ok 注释)。用 esp_fill_random 而非
    // esp_random():后者在同批 IDF 头文件组合下出现过未声明的编译问题,
    // 而 xiaozhi 侧已稳定使用 esp_fill_random。
    esp_fill_random(&s_token, sizeof(s_token));
    s_token &= 0x7fffffffu;
    if (s_token == 0) s_token = 1;   /* 0 被 token_ok 当作"未启用" */

    httpd_config_t config = HTTPD_DEFAULT_CONFIG();
    config.stack_size = 12288; // bounded certificate parsing and Ed25519 verification
    config.max_uri_handlers = 28;
    // 10 lwIP sockets total: leave room for DNS, SNTP, control/listen sockets,
    // and a new accept before LRU eviction. Phone OS probes also use HTTP.
    config.max_open_sockets = 3;
    config.recv_wait_timeout = 5;
    config.send_wait_timeout = 5;
    config.lru_purge_enable = true;
    config.uri_match_fn = httpd_uri_match_wildcard;

    esp_err_t err = httpd_start(&s_server, &config);
    if (err != ESP_OK) {
        ESP_LOGW(TAG, "httpd_start failed: %s", esp_err_to_name(err));
        s_server = NULL;
        return err;
    }

    const httpd_uri_t index_uri = {"/", HTTP_GET, handler_index, NULL};
    const httpd_uri_t cities_uri = {"/api/cities", HTTP_GET, handler_cities, NULL};
    const httpd_uri_t profile_get = {"/api/profile", HTTP_GET, handler_profile_get, NULL};
    const httpd_uri_t profile_post = {"/api/profile", HTTP_POST, handler_profile_post, NULL};
    const httpd_uri_t background_get = {"/api/background", HTTP_GET, handler_background_get, NULL};
    const httpd_uri_t background_post = {"/api/background", HTTP_POST, handler_background_post, NULL};
    const httpd_uri_t background_delete = {"/api/background", HTTP_DELETE, handler_background_delete, NULL};
    const httpd_uri_t setup_uri = {"/api/setup", HTTP_GET, handler_setup, NULL};
    const httpd_uri_t networks_uri = {"/api/networks", HTTP_GET, handler_networks, NULL};
    const httpd_uri_t connect_uri = {"/api/connect", HTTP_POST, handler_connect, NULL};
    const httpd_uri_t time_uri = {"/api/time", HTTP_POST, handler_time, NULL};
    const httpd_uri_t finish_uri = {"/api/finish", HTTP_POST, handler_finish, NULL};
    const httpd_uri_t fmo_get = {"/api/fmo", HTTP_GET, handler_fmo, NULL};
    const httpd_uri_t fmo_post = {"/api/fmo", HTTP_POST, handler_fmo, NULL};
    const httpd_uri_t fmo_ca_get = {"/api/fmo/ca", HTTP_GET, handler_fmo_ca, NULL};
    const httpd_uri_t fmo_ca_post = {"/api/fmo/ca", HTTP_POST, handler_fmo_ca, NULL};
    const httpd_uri_t fmo_stamp_get = {"/api/fmo/stamp", HTTP_GET, handler_fmo_stamp, NULL};
    const httpd_uri_t fmo_stamp_post = {"/api/fmo/stamp", HTTP_POST, handler_fmo_stamp, NULL};
    const httpd_uri_t fmo_stamp_delete = {"/api/fmo/stamp", HTTP_DELETE, handler_fmo_stamp, NULL};
    const httpd_uri_t fmo_beep_get = {"/api/fmo/beep", HTTP_GET, handler_fmo_beep, NULL};
    const httpd_uri_t fmo_beep_post = {"/api/fmo/beep", HTTP_POST, handler_fmo_beep, NULL};
    const httpd_uri_t fmo_beep_delete = {"/api/fmo/beep", HTTP_DELETE, handler_fmo_beep, NULL};
    const httpd_uri_t captive_uri = {"/*", HTTP_GET, handler_captive, NULL};
    // 2026-09-13 修复(B8):注册返回值必须检查。原来四个 handler 全丢返回值,
    // 注册失败时页面直接 404 且日志里一行痕迹都没有。
    struct { const httpd_uri_t *uri; const char *name; } routes[] = {
        {&index_uri, "/"}, {&cities_uri, "GET /api/cities"}, {&profile_get, "GET /api/profile"},
        {&profile_post, "POST /api/profile"},
        {&background_get, "GET /api/background"}, {&background_post, "POST /api/background"},
        {&background_delete, "DELETE /api/background"},
        {&setup_uri, "GET /api/setup"}, {&networks_uri, "GET /api/networks"},
        {&connect_uri, "POST /api/connect"}, {&time_uri, "POST /api/time"},
        {&finish_uri, "POST /api/finish"},
        {&fmo_get, "GET /api/fmo"}, {&fmo_post, "POST /api/fmo"},
        {&fmo_ca_get, "GET /api/fmo/ca"}, {&fmo_ca_post, "POST /api/fmo/ca"},
        {&fmo_stamp_get, "GET /api/fmo/stamp"}, {&fmo_stamp_post, "POST /api/fmo/stamp"},
        {&fmo_stamp_delete, "DELETE /api/fmo/stamp"},
        {&fmo_beep_get, "GET /api/fmo/beep"}, {&fmo_beep_post, "POST /api/fmo/beep"},
        {&fmo_beep_delete, "DELETE /api/fmo/beep"},
        {&captive_uri, "captive portal"},
    };
    for (const auto &r : routes) {
        esp_err_t e = httpd_register_uri_handler(s_server, r.uri);
        if (e != ESP_OK) {
            ESP_LOGE(TAG, "register %s failed: %s", r.name, esp_err_to_name(e));
            httpd_stop(s_server);
            s_server = nullptr;
            s_token = 0;
            return e;
        }
    }

    snprintf(s_url, sizeof(s_url), "http://%s",
             "192.168.4.1");
    ESP_LOGI(TAG, "Upload server started at %s", s_url);
    return ESP_OK;
}

void home_upload_stop(void) {
    if (!s_server) return;
    httpd_stop(s_server); // 内部 join 处理器任务后释放
    home_background_abort();
    s_server = NULL;
    while (s_network_state.load() == 1) vTaskDelay(pdMS_TO_TICKS(20));
    for (auto &item : s_saved_networks) std::fill(item.password.begin(), item.password.end(), '\0');
    s_saved_networks.clear();
    s_finish_at = 0;
    s_token = 0;          // 窗口关闭即作废,旧链接立刻失效
    ESP_LOGI(TAG, "Upload server stopped");
}

bool home_upload_active(void) { return s_server != NULL; }

const char *home_upload_url(void) { return s_server ? s_url : ""; }

bool home_upload_busy(void) { return s_network_state.load() == 1 || fmo_http_busy(); }
bool home_upload_network_verified(void) { return s_network_state.load() == 2; }
bool home_upload_finished(void) {
    const auto deadline = s_finish_at.load();
    return deadline != 0 && esp_timer_get_time() >= deadline && !fmo_http_busy();
}
