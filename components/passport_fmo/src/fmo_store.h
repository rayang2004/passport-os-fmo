#pragma once
#include "fmo_crypto.h"
#include "fmo_relay_list.h"
#include <string>
namespace fmo {
// These operations never export private keys or overwrite the original fmo_cred namespace.
bool public_identity(std::string *public_key, Credential *credential, std::string *error);
bool create_identity(std::string *error);
bool import_certificate(const uint8_t *data, size_t size, std::string *error);
bool load_identity(Credential *credential, uint8_t secret[64], std::string *error);
// Strictly read-only inspection and one-way import from an existing FMO Passport fmo_cred namespace.
bool legacy_identity_available(std::string *callsign, uint32_t *uid);
bool import_legacy_identity(std::string *error);
bool load_relay(Relay *relay);
bool save_relay(const Relay &relay, std::string *error);
bool clear_relay(std::string *error);
bool load_relay_cache(RelayList *list,uint32_t now);
bool save_relay_cache(const RelayList &list,uint32_t now);
// Background sentinel (FMO/RAW voice break-in while Radio/NetEase/Home is active).
// Boot auto-start defaults to false in NVS fmo_os/sentinel_boot; "转后台守听"
// arms a RAM-only session flag so background listening works even when boot auto-start is off.
bool sentinel_boot_enabled();
bool set_sentinel_boot_enabled(bool enabled);
void set_sentinel_session_armed(bool armed);
bool sentinel_enabled();
bool set_sentinel_enabled(bool enabled);
}
