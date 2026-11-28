#pragma once
#include "fmo_crypto.h"
#include <string_view>
namespace fmo {
struct AprsMessage {
    char sender[10]{}, index[6]{}, body[68]{};
};
struct AprsInbox {
    static constexpr unsigned capacity=6;
    AprsMessage messages[capacity]{};
    unsigned count=0;
    bool receive(std::string_view line,std::string_view login);
};
enum class BroadcastKind { CQ, Beacon };
struct BroadcastConfig {
    bool enabled=false,legacy_beacon=false;
    uint8_t ssid=15;
    uint32_t antenna_height=0;
    char grid[9]{},frequency[16]{},rig[25]{"AI Passport"},antenna[25]{};
};
struct BroadcastGate {
    bool identity_ready=false,config_available=false,tx_capable=false,network_connected=false;
    bool aprs_connected=false,aprs_verified=false,relay_connected=false;
    int64_t now_us=0,last_rx_us=0,last_sent_us=-60000000;
};
const char *broadcast_block_reason(const BroadcastConfig &config,BroadcastKind kind,const BroadcastGate &gate);
bool broadcast_config_valid(const BroadcastConfig &config);
bool load_broadcast_config(BroadcastConfig *config);
bool save_broadcast_config(const BroadcastConfig &config);
// Coordinates are the chosen grid's centre, never the weather/GPS position.
bool grid_position(const char *grid,char lat[9],char lon[10]);
// Exact APRS coordinates only, including valid poles/dateline. No distance is
// inferred for ambiguous/invalid positions or a missing explicitly chosen grid.
bool aprs_distance_m(const char *grid,const char *lat,const char *lon,uint32_t *distance_m);
bool aprs_distance_bearing(const char *grid,const char *lat,const char *lon,uint32_t *distance_m,uint16_t *bearing_deg);
bool aprs_coords_to_grid(const char *lat,const char *lon,char grid_out[7]);
bool aprs_coords_to_qth(const char *lat,const char *lon,char *out,size_t cap);
bool grid_to_qth(const char *grid,char *out,size_t cap);
bool nearby_beacon(const PeerAnnouncement &event,const char *grid,uint32_t *distance_m);
struct PeerMeta {
    char callsign[11]{};
    char latitude[9]{};
    char longitude[10]{};
    char frequency[10]{};
    char rig[17]{};
    char antenna[13]{};
    char qth[25]{};
    char relay_name[29]{};
    uint32_t seen_utc=0;
};
struct PeerMetaCache {
    static constexpr unsigned capacity=96;
    PeerMeta entries[capacity]{};
    unsigned count=0;
    void remember(const PeerMeta &meta);
    const PeerMeta *find(const char *callsign) const;
};
size_t serialize_peer_meta_cache(const PeerMetaCache &cache,uint8_t *out,size_t cap);
bool deserialize_peer_meta_cache(const uint8_t *data,size_t size,PeerMetaCache *out);
// Extract position/frequency/rig/antenna/QTH/listening-relay from APFMO2,
// APFMO4, or APPASP peer beacons (excluding STATION/JOINT) for QSO RX HUD.
bool parse_aprs_peer_meta(const char *line,size_t size,uint32_t now,PeerMeta *out);
// Strip FMO Passport "P-" subject prefix when deriving an APRS-IS bare callsign.
const char *bare_callsign(const char *callsign);
bool aprs_login(const char *callsign,const BroadcastConfig &config,std::string *login,std::string *login_call);
bool aprs_login_verified(const char *line,const char *login_call);
// Credential must have already passed the pinned-chain validation. Output
// includes CRLF and is bounded to the APRS-IS 512-byte limit.
// Optional stamp_style (e.g. "G001") replaces ST:ONLINE on legacy APPASP/PAT-1 beacons.
bool broadcast_frame(const Credential &identity,const uint8_t secret[64],const BroadcastConfig &config,
                     BroadcastKind kind,uint32_t server_uid,uint32_t utc,std::string *frame,
                     const char *stamp_style=nullptr);
}
