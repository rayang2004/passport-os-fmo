#include "fmo_revocation.h"
#include "fmo_crl_store.h"
#include <mutex>
namespace fmo {
namespace {
std::mutex revocation_mutex;
RevocationTracker tracker;
uint32_t generation=0;
}
uint32_t revocation_bind(const Credential &identity){
    std::lock_guard<std::mutex> lock(revocation_mutex);
    if(!tracker.matches(identity)){
        ++generation;
        if(!generation)++generation;
    }
    tracker.bind(identity);
    return generation;
}
SessionRevocation revocation_session_state(const Credential &identity,uint32_t epoch,uint32_t now){
    std::lock_guard<std::mutex> lock(revocation_mutex);
    if(epoch!=generation||!tracker.matches(identity))return SessionRevocation::Reconfigured;
    return tracker.state(identity,now)==RevocationState::Revoked?SessionRevocation::Revoked:SessionRevocation::Allowed;
}
uint32_t revocation_minimum(CrlLevel level,const Credential &identity){
    std::lock_guard<std::mutex> lock(revocation_mutex);
    return tracker.matches(identity)?tracker.minimum_number(level):0;
}
bool revocation_accept(CrlLevel level,const Credential &identity,const CrlStatus &verified,uint32_t now){
    std::lock_guard<std::mutex> lock(revocation_mutex);
    return tracker.accept(level,identity,verified,now);
}
RevocationState revocation_state(const Credential &identity,uint32_t now){
    std::lock_guard<std::mutex> lock(revocation_mutex);
    return tracker.state(identity,now);
}
CrlRestoreReport revocation_restore(const Credential &identity,const char *root_json,uint32_t now){
    CrlRestoreReport report;report.epoch=revocation_bind(identity);
    for(unsigned n=0;n<2;++n){
        const auto level=n?CrlLevel::User:CrlLevel::Root;auto &result=n?report.user:report.root;
        CrlCacheRecord cached;const auto loaded=load_crl_cache(level,identity,root_json,now,&cached);
        if(loaded==CrlCacheLoad::Missing)continue;
        result=CrlRestoreResult::Unavailable;
        if(loaded!=CrlCacheLoad::Ready)continue;
        // File I/O and signature checks finish before taking the state mutex.
        std::lock_guard<std::mutex> lock(revocation_mutex);
        if(generation==report.epoch&&tracker.matches(identity)&&tracker.restore(level,identity,cached.status,now))result=CrlRestoreResult::Restored;
    }
    return report;
}

}
