#pragma once
#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>
namespace fmo {
struct Credential {
    std::string user_json, intermediate_json;
    char callsign[13]{};
    uint32_t uid{}, expires{};
    uint8_t fingerprint[32]{},intermediate_fingerprint[32]{},root_fingerprint[32]{};
};
struct Relay {
    char host[128]{}, callsign[13]{};
    char name[64]{};
    uint32_t uid{};
    uint16_t port{1883};
    uint8_t fingerprint[32]{};
};
struct StationStatus {
    uint32_t online=0,peak=0,range_km=0,valid_until=0;
};
std::string base64url(const uint8_t *data, size_t size);
bool unbase64(const char *text, uint8_t *out, size_t capacity, size_t *size);
// Accept public certificates only; any private material in a provider bundle is ignored.
// Both signatures, the pinned root, local key binding, time and UID constraints are verified.
bool verify_bundle(const uint8_t *data, size_t size, const char *root_json,
                   const uint8_t public_key[32], uint32_t now,
                   Credential *out, std::string *error);
struct CrlStatus {
    uint32_t number=0,next_update=0;
    bool revoked=false;
    uint32_t this_update=0,revoked_at=0;
};
// Verify a bounded Intermediate CRL against the pinned root and user's chain.
// A successful result is a signed snapshot, not proof a newer CRL is absent.
// Callers must supply their highest accepted number to prevent rollback.
// False leaves status empty; callers must distinguish unavailable from clear.
bool verify_user_crl(const uint8_t *data,size_t size,const Credential &identity,
                     const char *root_json,uint32_t now,uint32_t minimum_number,
                     CrlStatus *status,std::vector<uint8_t> *proof=nullptr);
// Root CRL matches the intermediate's serial number AND canonical TBS hash.
bool verify_root_crl(const uint8_t *data,size_t size,const Credential &identity,
                     const char *root_json,uint32_t now,uint32_t minimum_number,
                     CrlStatus *status,std::vector<uint8_t> *proof=nullptr);
// Compact proof retains the complete canonical CBOR and original signature.
// No private key or unsigned cached boolean is stored. Expected tier is checked.
// allow_stale verifies an expired signed snapshot for cache recovery; it never
// makes next_update fresh. Caller must use the returned times, not just true.
bool verify_crl_proof(const uint8_t *data,size_t size,bool root_crl,const Credential &identity,
                      const char *root_json,uint32_t now,uint32_t minimum_number,
                      CrlStatus *status,bool allow_stale=false);
bool auth_password(const Credential &credential, const uint8_t secret_key[64],
                   const Relay &relay, uint32_t now, std::string *out);
// Built-in FMO Passport guest fallback relay (fmo.simy.asia:1883, HS256 guest-jwt).
constexpr char kBuiltinRelayHost[] = "fmo.simy.asia";
constexpr uint16_t kBuiltinRelayPort = 1883;
constexpr char kBuiltinRelayCallsign[] = "PASSPORT";
constexpr char kBuiltinRelayName[] = "PASSPORT内置中继台";
constexpr uint32_t kBuiltinRelayBookUid = 9610000u;
constexpr char kOfficialInteropCallsign[] = "BI4TES";
Relay builtin_relay();
bool is_builtin_relay(const Relay &relay);
bool is_official_interop_relay(const char *callsign);
bool is_own_relay(const char *relay_callsign, const char *own_callsign);
bool guest_jwt_password(const Credential &credential, uint32_t now, std::string *out);
void mqtt_username_for_relay(const Credential &credential, const Relay &relay, char out[20]);
// Optional public discovery chain is supplied by the caller, never by APRS.
// Each candidate is verified against its configured root before acceptance.
struct DiscoveryChain { const char *root_json; const char *intermediate_json; };
enum class PeerKind { CQ, OldFriendCQ, Vocal, Online, Beacon };
struct PeerAnnouncement {
    char callsign[13]{},latitude[9]{},longitude[10]{};
    uint32_t uid=0,server_uid=0,window=0,valid_until=0;
    uint8_t ssid=0,fingerprint[32]{};
    PeerKind kind=PeerKind::CQ;
    char frequency[16]{},rig[25]{},antenna[25]{};
    uint32_t antenna_height=0,distance_m=0;
};
// Signed CQ-family/BEACON events are not a real-time presence roster. Line
// excludes CRLF. Uses the same trust configuration as station discovery.
// BEACON callers must apply nearby_beacon using the explicitly selected grid
// before display/storage. Equipment fields retain a bounded UTF-8 prefix.
bool peer_announcement(const char *line,size_t size,const Credential &identity,const char *root_json,uint32_t now,PeerAnnouncement *out,const DiscoveryChain *extra_chain=nullptr);
struct EventProof {
    char callsign[13]{};
    uint8_t ssid=0;
    uint32_t uid=0,window=0,valid_until=0;
    uint8_t fingerprint[32]{},digest[32]{};
};
struct EventBody {
    char callsign[13]{};
    uint8_t ssid=0;
    uint32_t uid=0;
    uint8_t digest[32]{};
    char topic[129]{},content[561]{};
};
struct EventNotice {
    EventBody body{};
    uint32_t window=0,valid_until=0;
    uint8_t fingerprint[32]{};
};
// A STATUS body alone is unauthenticated. Never display or execute it until
// event_bind matches its full raw-payload hash to a verified JOINT proof.
bool joint_announcement(const char *line,size_t size,const Credential &identity,const char *root_json,uint32_t now,EventProof *out,const DiscoveryChain *extra_chain=nullptr);
bool event_status(const char *line,size_t size,EventBody *out);
bool event_bind(const EventProof &proof,const EventBody &body,uint32_t now,EventNotice *out);
// Rejection details describe an unverified packet, never a trusted station.
enum class StationRejection { NotStation, Malformed, UnknownIssuer, CertificateInvalid, SignatureInvalid, None };
bool station_announcement(const char *line, size_t size, const Credential &identity,
                          const char *root_json, uint32_t now, Relay *relay, uint32_t *valid_until=nullptr,
                          StationStatus *status=nullptr,StationRejection *rejection=nullptr,
                          const DiscoveryChain *extra_chain=nullptr,uint32_t *unknown_issuer=nullptr);
// Parse an external-CA FMO-V4,STATION broadcast (e.g. official CA issuerSn=1001):
// verifies canonical CBOR cert format, callsign binding, validity window, and the
// station's own Ed25519 frame signature + 10-minute replay window, returning the
// canonical serverFingerprint for 4.0 SAS authentication. Callers must gate
// connectability via is_official_interop_relay / is_own_relay / APPASP peer proof.
bool interop_station_announcement(const char *line, size_t size, uint32_t now,
                                  Relay *relay, uint32_t *valid_until=nullptr,
                                  StationStatus *status=nullptr, uint32_t *issuer_out=nullptr);
// Parse FMO Passport APPASP listening status beacon:
// "%s>APPASP,TCPIP*:>正在 <relay_name>(<relay_callsign>) 上守听"
bool parse_appasp_listening(const char *line, size_t size,
                            char relay_name[48], char relay_callsign[13]);
}
