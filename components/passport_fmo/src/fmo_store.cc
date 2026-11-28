#include "fmo_store.h"
#include "fmo_wire.h"
#include "esp_random.h"
#include "nvs.h"
#include <sodium.h>
#include <cJSON.h>
#include <ctime>
#include <atomic>
#include <cstring>
#include <mutex>
#include <memory>
#include <vector>
extern const char fmo_root_start[] asm("_binary_passport_root_json_start");
namespace fmo {
namespace {
std::mutex mutex;
constexpr char kNamespace[]="fmo_os";
bool failure(std::string *out,const char *text){if(out)*out=text;return false;}
bool read_seed(uint8_t *seed){nvs_handle_t h;size_t n=32;sodium_memzero(seed,32);if(nvs_open(kNamespace,NVS_READONLY,&h)!=ESP_OK)return false;const auto e=nvs_get_blob(h,"seed",seed,&n);nvs_close(h);if(e==ESP_OK&&n==32)return true;sodium_memzero(seed,32);return false;}
bool read_cert(const uint8_t pk[32],Credential *c,std::string *error){
    nvs_handle_t h;if(nvs_open(kNamespace,NVS_READONLY,&h)!=ESP_OK)return failure(error,"请先申请设备证书");
    size_t n=0;auto e=nvs_get_blob(h,"cert",nullptr,&n);if(e!=ESP_OK||n>12288||!n){nvs_close(h);return failure(error,"请先申请设备证书");}
    std::vector<uint8_t> data(n);e=nvs_get_blob(h,"cert",data.data(),&n);nvs_close(h);
    return e==ESP_OK&&verify_bundle(data.data(),n,fmo_root_start,pk,time(nullptr),c,error);
}
}
bool create_identity(std::string *error){
    std::lock_guard<std::mutex> guard(mutex);uint8_t seed[32];
    if(read_seed(seed)){sodium_memzero(seed,sizeof(seed));return true;}
    // Do not replace a corrupt/unreadable or partially persisted identity.
    nvs_handle_t h;auto e=nvs_open(kNamespace,NVS_READWRITE,&h);if(e!=ESP_OK)return failure(error,"身份存储不可用");
    size_t n=0;e=nvs_get_blob(h,"seed",nullptr,&n);if(e!=ESP_ERR_NVS_NOT_FOUND){nvs_close(h);return failure(error,"已有身份无法读取，未替换密钥");}
    esp_fill_random(seed,sizeof(seed));e=nvs_set_blob(h,"seed",seed,sizeof(seed));if(e==ESP_OK)e=nvs_commit(h);nvs_close(h);sodium_memzero(seed,sizeof(seed));
    return e==ESP_OK||failure(error,"身份保存未确认，请重试");
}
bool public_identity(std::string *pub,Credential *c,std::string *error){
    std::lock_guard<std::mutex> guard(mutex);uint8_t seed[32],pk[32],sk[64];
    if(!read_seed(seed)){if(pub)pub->clear();return failure(error,"请先初始化FMO身份");}
    crypto_sign_seed_keypair(pk,sk,seed);sodium_memzero(seed,sizeof(seed));sodium_memzero(sk,sizeof(sk));if(pub)*pub=base64url(pk,32);
    return read_cert(pk,c,error);
}
bool import_certificate(const uint8_t *data,size_t n,std::string *error){
    std::lock_guard<std::mutex> guard(mutex);uint8_t seed[32],pk[32],sk[64];
    if(!read_seed(seed))return failure(error,"本机没有设备密钥，请先初始化身份");
    crypto_sign_seed_keypair(pk,sk,seed);sodium_memzero(seed,sizeof(seed));sodium_memzero(sk,sizeof(sk));Credential c;
    if(!verify_bundle(data,n,fmo_root_start,pk,time(nullptr),&c,error))return false;
    // Keep only verified public certificates; never retain provider seed/key fields.
    const std::string normalized="["+c.intermediate_json+","+c.user_json+"]";
    nvs_handle_t h;auto e=nvs_open(kNamespace,NVS_READWRITE,&h);if(e!=ESP_OK)return failure(error,"证书存储不可用");
    e=nvs_set_blob(h,"cert",normalized.data(),normalized.size());if(e==ESP_OK)e=nvs_commit(h);nvs_close(h);
    return e==ESP_OK||failure(error,"证书保存未确认，原设备身份未改动");
}
bool load_identity(Credential *c,uint8_t sk[64],std::string *error){
    std::lock_guard<std::mutex> guard(mutex);uint8_t seed[32],pk[32];
    if(!read_seed(seed))return failure(error,"请先在手机设置中申请FMO证书");
    crypto_sign_seed_keypair(pk,sk,seed);sodium_memzero(seed,sizeof(seed));
    if(read_cert(pk,c,error)) return true;
    sodium_memzero(sk,64);
    return false;
}
namespace {
constexpr char kLegacyNamespace[]="fmo_cred";
bool read_nvs_str_bounded(nvs_handle_t h,const char *key,size_t max_len,std::string *out){
    size_t n=0;auto e=nvs_get_str(h,key,nullptr,&n);
    if(e!=ESP_OK||n<2||n>max_len)return false;
    std::string buf(n,'\0');
    e=nvs_get_str(h,key,buf.data(),&n);
    if(e!=ESP_OK||n<2)return false;
    while(!buf.empty()&&buf.back()=='\0')buf.pop_back();
    if(buf.empty())return false;
    *out=std::move(buf);return true;
}
bool read_legacy_verified(uint8_t seed_out[32],Credential *cred_out,std::string *error){
    uint8_t seed[32]{},pk[32]{},sk[64]{};
    nvs_handle_t h;
    if(nvs_open(kLegacyNamespace,NVS_READONLY,&h)!=ESP_OK)return failure(error,"未检测到原 FMO 固件证书");
    size_t sn=sizeof(seed);
    const auto se=nvs_get_blob(h,"seed",seed,&sn);
    std::string inter,user;
    const bool ok_str=se==ESP_OK&&sn==sizeof(seed)&&read_nvs_str_bounded(h,"inter",4096,&inter)&&read_nvs_str_bounded(h,"user",2048,&user);
    nvs_close(h);
    if(!ok_str){sodium_memzero(seed,sizeof(seed));return failure(error,"原 FMO 固件证书不完整");}
    crypto_sign_seed_keypair(pk,sk,seed);
    sodium_memzero(sk,sizeof(sk));
    const std::string bundle="["+inter+","+user+"]";
    Credential verified;
    const bool ok=verify_bundle(reinterpret_cast<const uint8_t *>(bundle.data()),bundle.size(),fmo_root_start,pk,time(nullptr),&verified,error);
    if(ok){
        if(seed_out)std::memcpy(seed_out,seed,sizeof(seed));
        if(cred_out)*cred_out=std::move(verified);
    }
    sodium_memzero(seed,sizeof(seed));
    return ok;
}
}
bool legacy_identity_available(std::string *callsign,uint32_t *uid){
    std::lock_guard<std::mutex> guard(mutex);
    Credential verified;
    if(!read_legacy_verified(nullptr,&verified,nullptr))return false;
    if(callsign)*callsign=verified.callsign;
    if(uid)*uid=verified.uid;
    return true;
}
bool import_legacy_identity(std::string *error){
    std::lock_guard<std::mutex> guard(mutex);
    // Refuse to overwrite an already-valid Passport OS FMO certificate.
    uint8_t existing_seed[32]{},existing_pk[32]{},existing_sk[64]{};
    if(read_seed(existing_seed)){
        crypto_sign_seed_keypair(existing_pk,existing_sk,existing_seed);
        sodium_memzero(existing_seed,sizeof(existing_seed));sodium_memzero(existing_sk,sizeof(existing_sk));
        Credential existing_cred;
        if(read_cert(existing_pk,&existing_cred,nullptr))return failure(error,"本机已有有效证书，未覆盖");
    }
    uint8_t legacy_seed[32]{};Credential verified;
    if(!read_legacy_verified(legacy_seed,&verified,error)){sodium_memzero(legacy_seed,sizeof(legacy_seed));return false;}
    const std::string normalized="["+verified.intermediate_json+","+verified.user_json+"]";
    nvs_handle_t h;auto e=nvs_open(kNamespace,NVS_READWRITE,&h);
    if(e!=ESP_OK){sodium_memzero(legacy_seed,sizeof(legacy_seed));return failure(error,"证书存储不可用");}
    e=nvs_set_blob(h,"seed",legacy_seed,sizeof(legacy_seed));
    if(e==ESP_OK)e=nvs_set_blob(h,"cert",normalized.data(),normalized.size());
    if(e==ESP_OK)e=nvs_commit(h);
    nvs_close(h);
    sodium_memzero(legacy_seed,sizeof(legacy_seed));
    return e==ESP_OK||failure(error,"证书导入保存未确认，原固件凭据未改动");
}
bool load_relay(Relay *r){std::lock_guard<std::mutex> guard(mutex);nvs_handle_t h;size_t n=sizeof(*r);if(nvs_open(kNamespace,NVS_READONLY,&h)!=ESP_OK)return false;const auto e=nvs_get_blob(h,"relay",r,&n);nvs_close(h);return e==ESP_OK&&n==sizeof(*r)&&r->host[sizeof(r->host)-1]==0&&r->callsign[12]==0&&r->port&&r->uid;}
bool save_relay(const Relay &r,std::string *error){
    if(!r.host[0]||r.host[127]||!r.callsign[0]||r.callsign[12]||!r.uid||!r.port)return failure(error,"中继参数无效");
    for(const char *p=r.host;*p;++p)if(!((*p>='a'&&*p<='z')||(*p>='A'&&*p<='Z')||(*p>='0'&&*p<='9')||*p=='.'||*p=='-'||*p==':'))return failure(error,"中继地址无效");
    for(const char *p=r.callsign;*p;++p)if(!((*p>='A'&&*p<='Z')||(*p>='0'&&*p<='9')||*p=='/'||*p=='-'))return failure(error,"中继呼号无效");
    std::lock_guard<std::mutex> guard(mutex);nvs_handle_t h;auto e=nvs_open(kNamespace,NVS_READWRITE,&h);if(e!=ESP_OK)return failure(error,"中继存储不可用");
    e=nvs_set_blob(h,"relay",&r,sizeof(r));if(e==ESP_OK)e=nvs_commit(h);nvs_close(h);return e==ESP_OK||failure(error,"中继设置保存未确认");
}
bool clear_relay(std::string *error){
    std::lock_guard<std::mutex> guard(mutex);nvs_handle_t h;auto e=nvs_open(kNamespace,NVS_READWRITE,&h);
    if(e==ESP_ERR_NVS_NOT_FOUND)return true;
    if(e!=ESP_OK)return failure(error,"中继存储不可用");
    e=nvs_erase_key(h,"relay");
    if(e==ESP_ERR_NVS_NOT_FOUND)e=ESP_OK;
    if(e==ESP_OK)e=nvs_commit(h);
    nvs_close(h);
    return e==ESP_OK||failure(error,"切换内置中继未确认");
}

namespace {
struct SavedRelays {uint32_t magic=0x46524c31,count=0;Relay relays[RelayList::capacity]{};uint32_t expires[RelayList::capacity]{};};
// Keep the original relay-cache blob unchanged. Optional snapshot metadata is
// separately versioned, checksummed and bound to the relay key and time window.
struct SavedStatus {uint32_t uid=0;uint8_t fingerprint[32]{};StationStatus status{};};
struct SavedRelayStats {uint32_t magic=0x46525331,count=0;SavedStatus records[RelayList::capacity]{};uint32_t crc=0;};
static_assert(sizeof(SavedStatus)==52&&sizeof(SavedRelayStats)==428);
bool cache_record_ok(const Relay &r){return r.uid&&r.port&&r.host[0]&&r.host[127]==0&&r.callsign[0]&&r.callsign[12]==0&&r.name[63]==0;}
}
bool load_relay_cache(RelayList *list,uint32_t now){
    if(!list||now<1700000000)return false;
    std::lock_guard<std::mutex> guard(mutex);nvs_handle_t h;size_t n=sizeof(SavedRelays);
    if(nvs_open(kNamespace,NVS_READONLY,&h)!=ESP_OK)return false;
    auto saved=std::make_unique<SavedRelays>();const auto e=nvs_get_blob(h,"relay_cache",saved.get(),&n);
    auto stats=std::make_unique<SavedRelayStats>();size_t stats_bytes=sizeof(*stats);const auto stats_error=nvs_get_blob(h,"relay_stats",stats.get(),&stats_bytes);nvs_close(h);
    if(e!=ESP_OK||n!=sizeof(SavedRelays)||saved->magic!=0x46524c31||saved->count>RelayList::capacity)return false;
    for(unsigned i=0;i<saved->count;++i)if(cache_record_ok(saved->relays[i])&&saved->expires[i]>now&&uint64_t(saved->expires[i])<=uint64_t(now)+1200)list->add(saved->relays[i],saved->expires[i],now);
    const bool stats_ok=stats_error==ESP_OK&&stats_bytes==sizeof(*stats)&&stats->magic==0x46525331&&stats->count<=RelayList::capacity&&stats->crc==crc32(reinterpret_cast<const uint8_t *>(stats.get()),sizeof(*stats)-4);
    if(stats_ok)for(unsigned i=0;i<stats->count;++i){const auto &r=stats->records[i];const int slot=list->find(r.uid);
        if(slot>=0&&r.status.valid_until==list->expires[slot]&&r.status.valid_until>now&&!std::memcmp(r.fingerprint,list->relays[slot].fingerprint,32))list->status[slot]=r.status;
    }
    return true;
}
bool save_relay_cache(const RelayList &list,uint32_t now){
    if(list.count>RelayList::capacity||now<1700000000)return false;
    auto saved=std::make_unique<SavedRelays>();
    auto stats=std::make_unique<SavedRelayStats>();
    for(unsigned i=0;i<list.count;++i)if(list.expires[i]>now&&cache_record_ok(list.relays[i])){const auto slot=saved->count++;saved->relays[slot]=list.relays[i];saved->expires[slot]=list.expires[i];}
    for(unsigned i=0;i<list.count;++i)if(list.status[i].valid_until>now&&list.status[i].valid_until==list.expires[i]&&cache_record_ok(list.relays[i])){auto &r=stats->records[stats->count++];r.uid=list.relays[i].uid;std::memcpy(r.fingerprint,list.relays[i].fingerprint,32);r.status=list.status[i];}
    stats->crc=crc32(reinterpret_cast<const uint8_t *>(stats.get()),sizeof(*stats)-4);
    std::lock_guard<std::mutex> guard(mutex);nvs_handle_t h;auto e=nvs_open(kNamespace,NVS_READWRITE,&h);if(e!=ESP_OK)return false;
    e=nvs_set_blob(h,"relay_cache",saved.get(),sizeof(SavedRelays));if(e==ESP_OK)e=nvs_set_blob(h,"relay_stats",stats.get(),sizeof(*stats));if(e==ESP_OK)e=nvs_commit(h);nvs_close(h);return e==ESP_OK;
}
static std::atomic<bool> s_sentinel_armed{false};
bool sentinel_boot_enabled(){
    std::lock_guard<std::mutex> guard(mutex);
    nvs_handle_t h;
    if(nvs_open(kNamespace,NVS_READONLY,&h)!=ESP_OK)return false;
    uint8_t val=0;
    size_t n=sizeof(val);
    const auto e=nvs_get_blob(h,"sentinel_boot",&val,&n);
    nvs_close(h);
    return (e==ESP_OK&&n==sizeof(val))?(val!=0):false;
}
bool set_sentinel_boot_enabled(bool enabled){
    std::lock_guard<std::mutex> guard(mutex);
    nvs_handle_t h;
    auto e=nvs_open(kNamespace,NVS_READWRITE,&h);
    if(e!=ESP_OK)return false;
    const uint8_t val=enabled?1:0;
    e=nvs_set_blob(h,"sentinel_boot",&val,sizeof(val));
    if(e==ESP_OK)e=nvs_commit(h);
    nvs_close(h);
    return e==ESP_OK;
}
void set_sentinel_session_armed(bool armed){
    s_sentinel_armed.store(armed,std::memory_order_release);
}
bool sentinel_enabled(){
    return s_sentinel_armed.load(std::memory_order_acquire)||sentinel_boot_enabled();
}
bool set_sentinel_enabled(bool enabled){
    if(!enabled)s_sentinel_armed.store(false,std::memory_order_release);
    return set_sentinel_boot_enabled(enabled);
}
bool compat_tx_enabled(){
    std::lock_guard<std::mutex> guard(mutex);
    nvs_handle_t h;
    if(nvs_open(kNamespace,NVS_READONLY,&h)!=ESP_OK)return false;
    uint8_t val=0;
    size_t n=sizeof(val);
    const auto e=nvs_get_blob(h,"compat_tx",&val,&n);
    nvs_close(h);
    return (e==ESP_OK&&n==sizeof(val))?(val!=0):false;
}
bool set_compat_tx_enabled(bool enabled){
    std::lock_guard<std::mutex> guard(mutex);
    nvs_handle_t h;
    auto e=nvs_open(kNamespace,NVS_READWRITE,&h);
    if(e!=ESP_OK)return false;
    const uint8_t val=enabled?1:0;
    e=nvs_set_blob(h,"compat_tx",&val,sizeof(val));
    if(e==ESP_OK)e=nvs_commit(h);
    nvs_close(h);
    return e==ESP_OK;
}
}
