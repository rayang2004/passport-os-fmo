#pragma once
#include "fmo_crypto.h"
#include <cstring>
namespace fmo {
enum class CrlLevel { Root, User };
enum class RevocationState { Unknown, Current, Revoked };
// Worker-owned, volatile cache of already verified results. This is not a
// signature verifier or persistent cache. Failed downloads never call accept.
class RevocationTracker {
    struct Snapshot { CrlStatus status{};bool present=false; } root_,user_;
    uint8_t root_fingerprint_[32]{},intermediate_[32]{},user_fingerprint_[32]{};
    uint32_t root_floor_=0,user_floor_=0;
    bool bound_=false;
    bool same_intermediate(const Credential &identity) const {
        return bound_&&!std::memcmp(root_fingerprint_,identity.root_fingerprint,32)&&
            !std::memcmp(intermediate_,identity.intermediate_fingerprint,32);
    }
    bool same_user(const Credential &identity) const {
        return same_intermediate(identity)&&!std::memcmp(user_fingerprint_,identity.fingerprint,32);
    }
    static bool revoked(const Snapshot &snapshot,uint32_t now){
        return snapshot.present&&now>=snapshot.status.this_update&&
            (snapshot.status.revoked_at?now>=snapshot.status.revoked_at:snapshot.status.revoked);
    }
    static bool current(const Snapshot &snapshot,uint32_t now){
        return snapshot.present&&snapshot.status.this_update<=now&&now<snapshot.status.next_update;
    }
public:
    // Input must be a credential returned by verify_bundle, never APRS metadata.
    void bind(const Credential &identity){
        if(!bound_||std::memcmp(root_fingerprint_,identity.root_fingerprint,32)){root_floor_=0;user_floor_=0;root_={};user_={};}
        else if(!same_intermediate(identity)){root_={};user_={};user_floor_=0;}
        else if(!same_user(identity))user_={};
        std::memcpy(root_fingerprint_,identity.root_fingerprint,32);
        std::memcpy(intermediate_,identity.intermediate_fingerprint,32);
        std::memcpy(user_fingerprint_,identity.fingerprint,32);bound_=true;
    }
    bool matches(const Credential &identity) const {return same_user(identity);}
    uint32_t minimum_number(CrlLevel level) const {
        return level==CrlLevel::Root?root_floor_:user_floor_;
    }
    // Call only after verify_root_crl/verify_user_crl succeeds. The exact
    // accepted version survives expiry; equal versions cannot change results.
private:
    bool apply(CrlLevel level,const Credential &identity,const CrlStatus &status,uint32_t now,bool allow_stale){
        if(!same_user(identity)||now<1700000000u||status.this_update>now||status.next_update<=status.this_update||(!allow_stale&&now>=status.next_update))return false;
        if(status.revoked_at&&status.revoked!=(status.revoked_at<=now))return false;
        auto &s=level==CrlLevel::Root?root_:user_;
        auto &floor=level==CrlLevel::Root?root_floor_:user_floor_;
        if(status.number<floor)return false;
        if(s.present){
            if(status.number<s.status.number)return false;
            if(status.number==s.status.number)return status.next_update==s.status.next_update&&
                status.this_update==s.status.this_update&&status.revoked_at==s.status.revoked_at&&
                (status.revoked_at||status.revoked==s.status.revoked);
        }
        s={status,true};floor=status.number;return true;
    }
public:
    bool accept(CrlLevel level,const Credential &identity,const CrlStatus &verified,uint32_t now){return apply(level,identity,verified,now,false);}
    // Only for a reverified stored proof. Stale data retains its original
    // expiry and can preserve revocation/floors, never a fresh clear assurance.
    bool restore(CrlLevel level,const Credential &identity,const CrlStatus &verified,uint32_t now){return apply(level,identity,verified,now,true);}
    RevocationState state(const Credential &identity,uint32_t now) const {
        if(!same_user(identity)||now<1700000000u||now>=identity.expires)return RevocationState::Unknown;
        // Expiry removes a clear assurance, never erases known revocation.
        if(revoked(root_,now)||revoked(user_,now))return RevocationState::Revoked;
        return current(root_,now)&&current(user_,now)?RevocationState::Current:RevocationState::Unknown;
    }
};
// Shared volatile service. Only refresh binds/applies verified results; session
// readers never rebind, so querying another identity cannot erase the cache.
enum class SessionRevocation { Allowed, Revoked, Reconfigured };
uint32_t revocation_bind(const Credential &identity);
SessionRevocation revocation_session_state(const Credential &identity,uint32_t epoch,uint32_t now);
uint32_t revocation_minimum(CrlLevel level,const Credential &identity);
bool revocation_accept(CrlLevel level,const Credential &identity,const CrlStatus &verified,uint32_t now);
RevocationState revocation_state(const Credential &identity,uint32_t now);

enum class CrlRestoreResult { Missing, Restored, Unavailable };
struct CrlRestoreReport {uint32_t epoch=0;CrlRestoreResult root=CrlRestoreResult::Missing,user=CrlRestoreResult::Missing;};
CrlRestoreReport revocation_restore(const Credential &identity,const char *root_json,uint32_t now);

}
