#include "fmo_crl_store.h"
#include "fmo_wire.h"
#include "apps/home/home_storage.h"
#include "nvs.h"
#include <sodium.h>
#include <array>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <new>
#include <mutex>
#include <string>
#include <sys/stat.h>
#include <unistd.h>
#ifndef FMO_CRL_BASE
#define FMO_CRL_BASE "/storage"
#endif
namespace fmo {
namespace {
constexpr size_t kMetaSize=96,kProofMax=12940;
std::mutex store_mutex;
using Metadata=std::array<uint8_t,kMetaSize>;
const char *key(CrlLevel level){return level==CrlLevel::Root?"crl_root":"crl_user";}
const uint8_t *scope(CrlLevel level,const Credential &identity){return level==CrlLevel::Root?identity.root_fingerprint:identity.intermediate_fingerprint;}
uint32_t read32(const uint8_t *p){return uint32_t(p[0])|(uint32_t(p[1])<<8)|(uint32_t(p[2])<<16)|(uint32_t(p[3])<<24);}
void write32(uint8_t *p,uint32_t n){for(unsigned i=0;i<4;++i)p[i]=n>>(8*i);}
// 1 = absent, 0 = complete, -1 = invalid or inaccessible. Never convert an
// inaccessible/corrupt version floor into an empty record that can be erased.
int read_metadata(CrlLevel level,Metadata *out){
    nvs_handle_t handle;const auto opened=nvs_open("fmo_os",NVS_READONLY,&handle);
    if(opened==ESP_ERR_NVS_NOT_FOUND)return 1;
    if(opened!=ESP_OK)return -1;
    size_t size=out->size();const auto result=nvs_get_blob(handle,key(level),out->data(),&size);nvs_close(handle);
    if(result==ESP_ERR_NVS_NOT_FOUND)return 1;
    if(result!=ESP_OK||size!=out->size()||std::memcmp(out->data(),"FCM1",4)||(*out)[4]!=(level==CrlLevel::Root?0:1)||(*out)[5]>1||(*out)[6]||(*out)[7])return -1;
    for(unsigned i=76;i<92;++i)if((*out)[i])return -1;
    return read32(out->data()+92)==crc32(out->data(),92)?0:-1;
}
std::string path(CrlLevel level,unsigned bank){return std::string(FMO_CRL_BASE)+(level==CrlLevel::Root?"/fmo-crl-root-":"/fmo-crl-user-")+(bank?"b.fcp":"a.fcp");}
struct Release {~Release(){home_storage_release();}};
enum class BankRead { Ready, Missing, Invalid, Unavailable };
BankRead read_bank(const std::string &name,CrlCacheRecord *record){
    struct stat st;
    if(stat(name.c_str(),&st))return errno==ENOENT?BankRead::Missing:BankRead::Unavailable;
    if(!S_ISREG(st.st_mode)||st.st_size<77||st.st_size>static_cast<off_t>(kProofMax))return BankRead::Invalid;
    std::unique_ptr<uint8_t[]> bytes(new(std::nothrow) uint8_t[st.st_size]);if(!bytes)return BankRead::Unavailable;
    FILE *file=fopen(name.c_str(),"rb");if(!file)return BankRead::Unavailable;
    size_t used=0;bool ok=true;
    while(used<static_cast<size_t>(st.st_size)){
        const size_t remaining=st.st_size-used,count=remaining<512?remaining:512;
        const size_t got=fread(bytes.get()+used,1,count,file);
        if(!got){ok=false;break;}used+=got;
    }
    if(ferror(file))ok=false;
    if(fclose(file))ok=false;
    if(!ok||used!=static_cast<size_t>(st.st_size))return BankRead::Unavailable;
    record->data=std::move(bytes);record->size=used;return BankRead::Ready;
}
bool matches_metadata(const CrlCacheRecord &record,const Metadata &metadata){
    uint8_t digest[32];crypto_hash_sha256(digest,record.data.get(),record.size);
    return !sodium_memcmp(digest,metadata.data()+44,32);
}
}
CrlCacheLoad load_crl_cache(CrlLevel level,const Credential &identity,const char *root_json,uint32_t now,CrlCacheRecord *out){
    std::lock_guard<std::mutex> lock(store_mutex);
    if(!out)return CrlCacheLoad::Unavailable;
    *out={};Metadata metadata{};const int found=read_metadata(level,&metadata);
    if(found>0)return CrlCacheLoad::Missing;
    if(found<0)return CrlCacheLoad::Unavailable;
    if(sodium_memcmp(metadata.data()+12,scope(level,identity),32))return CrlCacheLoad::Missing;
    if(home_storage_acquire(false)!=ESP_OK)return CrlCacheLoad::Unavailable;
    Release release;
    for(unsigned attempt=0;attempt<2;++attempt){
        CrlCacheRecord candidate;
        if(read_bank(path(level,metadata[5]^(attempt?1:0)),&candidate)!=BankRead::Ready||!matches_metadata(candidate,metadata))continue;
        if(!verify_crl_proof(candidate.data.get(),candidate.size,level==CrlLevel::Root,identity,root_json,now,read32(metadata.data()+8),&candidate.status,true)||candidate.status.number!=read32(metadata.data()+8))continue;
        *out=std::move(candidate);return CrlCacheLoad::Ready;
    }
    return CrlCacheLoad::Unavailable;
}
bool save_crl_cache(CrlLevel level,const Credential &identity,const char *root_json,uint32_t now,const uint8_t *proof,size_t size,bool initialize_blank){
    std::lock_guard<std::mutex> lock(store_mutex);
    Metadata previous{};const int found=read_metadata(level,&previous);
    if(found<0)return false;
    const bool same_scope=found==0&&!sodium_memcmp(previous.data()+12,scope(level,identity),32);
    CrlStatus status;
    if(!verify_crl_proof(proof,size,level==CrlLevel::Root,identity,root_json,now,same_scope?read32(previous.data()+8):0,&status))return false;
    uint8_t digest[32];crypto_hash_sha256(digest,proof,size);
    if(same_scope&&status.number==read32(previous.data()+8)&&sodium_memcmp(digest,previous.data()+44,32))return false;
    if(home_storage_acquire(initialize_blank)!=ESP_OK)return false;
    Release release;
    unsigned bank=found==0?previous[5]^1:0;
    if(found==0){
        CrlCacheRecord existing;
        const auto active=read_bank(path(level,previous[5]),&existing);
        if(active==BankRead::Unavailable)return false;
        if(active!=BankRead::Ready||!matches_metadata(existing,previous)){
            existing={};
            const auto backup=read_bank(path(level,previous[5]^1),&existing);
            if(backup==BankRead::Unavailable)return false;
            // Preserve the sole metadata-matching copy when the nominal
            // active bank is damaged. A failed replacement must not erase it.
            if(backup==BankRead::Ready&&matches_metadata(existing,previous))bank=previous[5];
        }
    }
    const auto name=path(level,bank);FILE *file=fopen(name.c_str(),"wb");if(!file)return false;
    bool ok=true;size_t at=0;
    while(at<size){
        const size_t count=size-at<512?size-at:512;
        if(fwrite(proof+at,1,count,file)!=count){ok=false;break;}at+=count;
    }
    if(fflush(file))ok=false;
    if(ok&&fsync(fileno(file)))ok=false;
    if(fclose(file))ok=false;
    if(!ok)return false; // Only inactive data was touched; metadata is unchanged.
    CrlCacheRecord check;
    if(read_bank(name,&check)!=BankRead::Ready||check.size!=size||std::memcmp(check.data.get(),proof,size)||
       !verify_crl_proof(check.data.get(),check.size,level==CrlLevel::Root,identity,root_json,now,status.number,&check.status))return false;
    Metadata next{};std::memcpy(next.data(),"FCM1",4);next[4]=level==CrlLevel::Root?0:1;next[5]=bank;
    write32(next.data()+8,status.number);std::memcpy(next.data()+12,scope(level,identity),32);std::memcpy(next.data()+44,digest,32);
    write32(next.data()+92,crc32(next.data(),92));
    nvs_handle_t handle;if(nvs_open("fmo_os",NVS_READWRITE,&handle)!=ESP_OK)return false;
    auto result=nvs_set_blob(handle,key(level),next.data(),next.size());
    if(result==ESP_OK)result=nvs_commit(handle);
    nvs_close(handle);
    // set_blob can publish before a failed commit. Keep the validated bank so
    // either persisted metadata value remains readable; never delete it here.
    return result==ESP_OK;
}
}
