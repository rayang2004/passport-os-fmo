#pragma once
#include "fmo_revocation.h"
#include <memory>
namespace fmo {
enum class CrlCacheLoad { Missing, Ready, Unavailable };
struct CrlCacheRecord {
    std::unique_ptr<uint8_t[]> data;
    size_t size=0;
    CrlStatus status{};
};
// Failure clears the output. Startup reads never initialize storage.
// Ready includes authenticated stale
// snapshots: callers must preserve next_update and must not call them current.
CrlCacheLoad load_crl_cache(CrlLevel level,const Credential &identity,const char *root_json,uint32_t now,CrlCacheRecord *out);
// The proof is reverified before writing and after readback. Metadata is
// switched only after a complete flushed bank exists. True initialization is
// reserved for an explicit user write to a verified-erased partition.
bool save_crl_cache(CrlLevel level,const Credential &identity,const char *root_json,uint32_t now,
                    const uint8_t *proof,size_t size,bool initialize_blank=false);
}
