#include "fmo_utf8.h"
// Independent AIRP-01 / AIRP-04 implementation. Field order follows bg5esn.com/docs/.
#include "fmo_crypto.h"
#include "fmo_aprs.h"
#include <cJSON.h>
#include <sodium.h>
#include <algorithm>
#include <cstring>
#include <memory>
#include <vector>
#include <cstdio>
#include <cstdlib>
namespace fmo {
namespace {
using Json=std::unique_ptr<cJSON,decltype(&cJSON_Delete)>;
using Bytes=std::vector<uint8_t>;
const cJSON *get(const cJSON *o,const char *k){return cJSON_GetObjectItemCaseSensitive(o,k);}
const char *text(const cJSON *o,const char *k){const auto *v=get(o,k);return cJSON_IsString(v)?v->valuestring:nullptr;}
bool num(const cJSON *o,const char *k,uint32_t *v){const auto *n=get(o,k);if(!cJSON_IsNumber(n)||n->valuedouble<0||n->valuedouble>UINT32_MAX||n->valuedouble!=static_cast<uint32_t>(n->valuedouble))return false;*v=n->valuedouble;return true;}
void head(Bytes &b,uint8_t major,uint64_t n){
    if(n<24)b.push_back((major<<5)|n);
    else{unsigned bytes=n<=255?1:n<=65535?2:n<=UINT32_MAX?4:8;b.push_back((major<<5)|(bytes==1?24:bytes==2?25:bytes==4?26:27));for(int i=bytes-1;i>=0;--i)b.push_back(n>>(8*i));}
}
void integer(Bytes &b,uint32_t v){head(b,0,v);}
void string(Bytes &b,const char *s){head(b,3,std::strlen(s));b.insert(b.end(),s,s+std::strlen(s));}
void binary(Bytes &b,const uint8_t *p,size_t n){head(b,2,n);b.insert(b.end(),p,p+n);}
void prefix(Bytes &b,size_t n,const char *kind){head(b,4,n);string(b,"FMO");integer(b,4);string(b,kind);}
bool field(Bytes &b,const cJSON *o,const char *k,size_t max=256){const char *s=text(o,k);if(!s||std::strlen(s)>max)return false;string(b,s);return true;}
bool number(Bytes &b,const cJSON *o,const char *k){uint32_t n;if(!num(o,k,&n))return false;integer(b,n);return true;}
bool decode_field(const cJSON *o,const char *k,uint8_t *p,size_t n){size_t bytes=0;const auto *s=text(o,k);return s&&unbase64(s,p,n,&bytes)&&bytes==n;}
bool key(Bytes &b,const cJSON *o,const char *k,uint8_t *out){if(!decode_field(o,k,out,32))return false;binary(b,out,32);return true;}
std::string print(const cJSON *o){char *s=cJSON_PrintUnformatted(o);std::string r=s?s:"";cJSON_free(s);return r;}
bool signature(const cJSON *o,const Bytes &tbs,const uint8_t *pk){uint8_t sig[64];return decode_field(o,"signature",sig,64)&&crypto_sign_verify_detached(sig,tbs.data(),tbs.size(),pk)==0;}
bool validity(const cJSON *o,uint32_t now,uint32_t *iat,uint32_t *exp){return num(o,"iat",iat)&&num(o,"exp",exp)&&*iat<=now&&now<*exp;}
bool callsign(const char *s){if(!s||!s[0]||std::strlen(s)>12)return false;for(;*s;++s)if(!((*s>='A'&&*s<='Z')||(*s>='0'&&*s<='9')||*s=='/'||*s=='-'))return false;return true;}
// Locate JSON records inside either JSON packages or the provider's binary envelope.
// Bound nesting before cJSON, which otherwise permits far deeper recursive structures.
Json object_at(const uint8_t *data,size_t size){
    bool quoted=false,escaped=false;unsigned depth=0;
    for(size_t i=0;i<size;++i){const auto c=data[i];if(!c)return Json(nullptr,cJSON_Delete);
        if(quoted){if(escaped)escaped=false;else if(c=='\\')escaped=true;else if(c=='"')quoted=false;continue;}
        if(c=='"')quoted=true;
        else if(c=='{'||c=='['){if(++depth>24)return Json(nullptr,cJSON_Delete);}
        else if(c=='}'||c==']'){if(!depth)return Json(nullptr,cJSON_Delete);if(!--depth)return Json(cJSON_ParseWithLength(reinterpret_cast<const char *>(data),i+1),cJSON_Delete);}
    }return Json(nullptr,cJSON_Delete);
}
// Parse only one scalar or flat entry at a time. Never build the entire CRL
// JSON tree: provider lists already exceed 160 entries on non-PSRAM devices.
struct CrlCursor {
    const uint8_t *p,*end;
    void space(){while(p<end&&(*p==' '||*p=='\t'||*p=='\r'||*p=='\n'))++p;}
    bool take(uint8_t c){space();if(p==end||*p!=c)return false;++p;return true;}
    Json value(){
        space();const auto *start=p;bool quoted=false,escaped=false;unsigned depth=0;
        if(p==end)return Json(nullptr,cJSON_Delete);
        const bool composite=*p=='{';
        while(p<end&&size_t(p-start)<512){
            const auto c=*p;
            if(quoted){if(!escaped&&c=='\\'&&size_t(end-p)>=6&&!std::memcmp(p,"\\u0000",6))return Json(nullptr,cJSON_Delete);++p;if(escaped)escaped=false;else if(c=='\\')escaped=true;else if(c=='"'){quoted=false;if(!composite)break;}continue;}
            if(c=='"'){quoted=true;++p;continue;}
            if(c=='{'||c=='['){if(!composite||++depth>1)return Json(nullptr,cJSON_Delete);++p;continue;}
            if(c=='}'||c==']'){if(!composite)break;++p;if(!--depth)break;continue;}
            if(!composite&&(c==','||c==':'||c==' '||c=='\t'||c=='\r'||c=='\n'))break;
            ++p;
        }
        if(p==start||quoted||depth)return Json(nullptr,cJSON_Delete);
        const char *parsed_end=nullptr;
        Json result(cJSON_ParseWithLengthOpts(reinterpret_cast<const char *>(start),p-start,&parsed_end,false),cJSON_Delete);
        if(parsed_end!=reinterpret_cast<const char *>(p))return Json(nullptr,cJSON_Delete);
        return result;
    }
};
bool crl_document(const uint8_t *data,size_t size,bool root_crl,uint32_t target_id,const uint8_t target_fp[32],uint32_t now,
                  Json &metadata,Bytes &entries_tbs,unsigned *count,bool *revoked,uint32_t *revoked_at){
    CrlCursor cursor{data,data+size};if(!cursor.take('{'))return false;
    unsigned seen=0;*count=0;*revoked=false;*revoked_at=0;
    // Worst-case per entry: array tag + uint32 id + 32B bytes + two uint32.
    // Reserve once so growth never holds two large CBOR allocations at once.
    entries_tbs.reserve(256*50+64+76);
    uint32_t previous_id=0;uint8_t previous_fp[32]{};
    for(;;){
        auto key=cursor.value();if(!cJSON_IsString(key.get())||!cursor.take(':'))return false;
        const char *names[]={"type","issuerSn","crlNumber","thisUpdate","nextUpdate","signatureAlgorithm","signature","entries"};
        unsigned field=0;while(field<8&&std::strcmp(key->valuestring,names[field]))++field;
        if(field==8||(seen&(1u<<field)))return false;
        seen|=1u<<field;
        if(field!=7){
            auto v=cursor.value();if(!v||(!cJSON_IsString(v.get())&&!cJSON_IsNumber(v.get())))return false;
            if(!cJSON_AddItemToObject(metadata.get(),names[field],v.get()))return false;
            v.release();
        }else {
            if(!cursor.take('['))return false;
            if(!cursor.take(']'))for(;;){
                if(*count>=256)return false;
                auto entry=cursor.value();if(!cJSON_IsObject(entry.get()))return false;
                unsigned entry_seen=0;
                for(auto *item=entry->child;item;item=item->next){
                    const char *fields[]={root_crl?"sn":"uid","certFingerprint","revokedAt","reason"};unsigned at=0;
                    while(at<4&&std::strcmp(item->string,fields[at]))++at;
                    if(at==4||(entry_seen&(1u<<at)))return false;
                    entry_seen|=1u<<at;
                }
                uint32_t id,at,reason;uint8_t fp[32];
                if(entry_seen!=15||!num(entry.get(),root_crl?"sn":"uid",&id)||!num(entry.get(),"revokedAt",&at)||
                   !num(entry.get(),"reason",&reason)||!decode_field(entry.get(),"certFingerprint",fp,32))return false;
                if(*count&&(id<previous_id||(id==previous_id&&std::memcmp(fp,previous_fp,32)<=0)))return false;
                previous_id=id;std::memcpy(previous_fp,fp,32);
                head(entries_tbs,4,4);integer(entries_tbs,id);binary(entries_tbs,fp,32);integer(entries_tbs,at);integer(entries_tbs,reason);
                if(id==target_id&&!sodium_memcmp(fp,target_fp,32)){*revoked_at=at;*revoked=at<=now;}
                ++*count;
                if(cursor.take(']'))break;
                if(!cursor.take(','))return false;
            }
        }
        if(cursor.take('}'))break;
        if(!cursor.take(','))return false;
    }
    cursor.space();return cursor.p==cursor.end&&seen==255;
}
}
std::string base64url(const uint8_t *p,size_t n){std::string s(sodium_base64_ENCODED_LEN(n,sodium_base64_VARIANT_URLSAFE_NO_PADDING),'\0');sodium_bin2base64(s.data(),s.size(),p,n,sodium_base64_VARIANT_URLSAFE_NO_PADDING);s.resize(std::strlen(s.c_str()));return s;}
bool unbase64(const char *s,uint8_t *out,size_t cap,size_t *n){
    if(!s||!out||!n)return false;
    for(const int variant:{sodium_base64_VARIANT_URLSAFE_NO_PADDING,sodium_base64_VARIANT_ORIGINAL})
        if(sodium_base642bin(out,cap,s,std::strlen(s),nullptr,n,nullptr,variant)==0)return true;
    return false;
}
static bool verify_bundle_impl(const uint8_t *data,size_t size,const char *root_json,const uint8_t pk[32],uint32_t now,Credential *out,std::string *error,uint8_t *intermediate_fingerprint){
    auto fail=[&](const char *s){if(error)*error=s;return false;};
    if(!data||!out||!root_json||size>12288||now<1700000000u)return fail("证书数据无效或设备尚未校时");
    Json root(cJSON_Parse(root_json),cJSON_Delete),inter(nullptr,cJSON_Delete),user(nullptr,cJSON_Delete);
    for(size_t i=0;i<size;++i)if(data[i]=='{'){
        auto obj=object_at(data+i,size-i);const auto *kind=text(obj.get(),"type");
        if((kind&&!std::strcmp(kind,"intermediateCA"))||(!kind&&get(get(obj.get(),"extensions"),"uidRange"))){if(inter)return fail("中间证书重复");inter=std::move(obj);}
        else if((kind&&!std::strcmp(kind,"userCert"))||(!kind&&get(obj.get(),"issuerSn")&&text(get(obj.get(),"subject"),"callsign"))){if(user)return fail("用户证书重复");user=std::move(obj);}
    }
    if(!root||!inter||!user)return fail("未识别到完整的中间证书和用户证书，未更改原身份");
    const auto *ri=get(root.get(),"issuer"),*rs=get(root.get(),"subject"),*re=get(root.get(),"extensions");
    Bytes rb;prefix(rb,15,"rootCA");uint8_t rootpk[32];
    if(!number(rb,root.get(),"sn")||!field(rb,ri,"name")||!field(rb,ri,"email")||!field(rb,rs,"name")||!key(rb,rs,"publicKey",rootpk)||!cJSON_IsTrue(get(re,"isCA")))return fail("内置根证书字段无效");
    rb.push_back(0xf5);
    if(!number(rb,re,"pathLen")||!field(rb,re,"crl")||!field(rb,re,"license")||!field(rb,re,"keyId")||!number(rb,root.get(),"iat")||!number(rb,root.get(),"exp")||!signature(root.get(),rb,rootpk))return fail("内置根证书签名无效");
    const auto *ii=get(inter.get(),"issuer"),*is=get(inter.get(),"subject"),*ie=get(inter.get(),"extensions"),*range=get(ie,"uidRange");
    uint32_t root_sn,issuer_sn,inter_sn,iat,exp,root_iat,root_exp,user_iat,user_exp,uid,range_start,range_end,path;
    uint8_t issuerpk[32],interpk[32],userpk[32];
    if(!num(root.get(),"sn",&root_sn)||!num(ii,"sn",&issuer_sn)||issuer_sn!=root_sn||!text(ii,"name")||std::strcmp(text(ii,"name"),text(rs,"name"))||!decode_field(ii,"publicKey",issuerpk,32)||sodium_memcmp(issuerpk,rootpk,32)||!validity(root.get(),now,&root_iat,&root_exp))return fail("中间证书不属于内置信任根或根已失效");
    Bytes ib;prefix(ib,20,"intermediateCA");
    if(!num(inter.get(),"sn",&inter_sn)||!number(ib,inter.get(),"sn")||!number(ib,ii,"sn")||!field(ib,ii,"name")||!key(ib,ii,"publicKey",issuerpk)||!field(ib,is,"name")||!field(ib,is,"email")||!key(ib,is,"publicKey",interpk)||!cJSON_IsTrue(get(ie,"isCA"))||!num(ie,"pathLen",&path)||path!=0)return fail("中间证书字段无效");
    ib.push_back(0xf5);integer(ib,0);
    if(!field(ib,ie,"keyId")||!field(ib,ie,"crl")||!field(ib,ie,"license")||!num(range,"start",&range_start)||!num(range,"end",&range_end)||range_start>range_end)return fail("中间证书授权范围无效");
    integer(ib,range_start);integer(ib,range_end);
    const auto *countries=get(ie,"issuingCountries");std::vector<std::string> names;
    const int count=cJSON_GetArraySize(countries);if(!cJSON_IsArray(countries)||count<1||count>64)return fail("国家授权范围无效");
    for(int i=0;i<count;++i){const auto *c=cJSON_GetArrayItem(countries,i);if(!cJSON_IsString(c)||std::strlen(c->valuestring)!=2||c->valuestring[0]<'A'||c->valuestring[0]>'Z'||c->valuestring[1]<'A'||c->valuestring[1]>'Z')return fail("国家授权字段无效");names.emplace_back(c->valuestring);}
    std::sort(names.begin(),names.end());head(ib,4,names.size());for(const auto &s:names)string(ib,s.c_str());
    if(!validity(inter.get(),now,&iat,&exp)||iat<root_iat||exp>root_exp||!number(ib,inter.get(),"iat")||!number(ib,inter.get(),"exp")||!signature(inter.get(),ib,rootpk))return fail("中间证书签名或有效期不匹配");
    const auto *us=get(user.get(),"subject");const char *call=text(us,"callsign");
    if(!callsign(call)||!num(user.get(),"issuerSn",&issuer_sn)||issuer_sn!=inter_sn||!num(us,"uid",&uid)||uid<range_start||uid>range_end||!decode_field(us,"publicKey",userpk,32)||sodium_memcmp(userpk,pk,32)||!validity(user.get(),now,&user_iat,&user_exp)||user_iat<iat||user_exp>exp)return fail("用户证书与本机密钥、签发范围或有效期不匹配");
    // Chinese amateur prefixes have an unambiguous country assignment.
    const char *bare=bare_callsign(call);
    if(bare[0]=='B'&&std::find(names.begin(),names.end(),"CN")==names.end())return fail("签发机构未获此呼号的国家授权");
    Bytes ub;prefix(ub,9,"userCert");integer(ub,issuer_sn);string(ub,call);integer(ub,uid);binary(ub,pk,32);integer(ub,user_iat);integer(ub,user_exp);
    if(!signature(user.get(),ub,interpk))return fail("用户证书签名验证失败");
    if(intermediate_fingerprint)crypto_hash_sha256(intermediate_fingerprint,ib.data(),ib.size());
    Credential value;value.user_json=print(user.get());
    crypto_hash_sha256(value.intermediate_fingerprint,ib.data(),ib.size());
    crypto_hash_sha256(value.root_fingerprint,rb.data(),rb.size());value.intermediate_json=print(inter.get());
    if(value.user_json.empty()||value.intermediate_json.empty())return fail("证书序列化失败");
    std::strcpy(value.callsign,call);value.uid=uid;value.expires=user_exp;crypto_hash_sha256(value.fingerprint,ub.data(),ub.size());*out=std::move(value);if(error)error->clear();return true;
}
bool verify_bundle(const uint8_t *data,size_t size,const char *root_json,const uint8_t pk[32],uint32_t now,Credential *out,std::string *error){
    return verify_bundle_impl(data,size,root_json,pk,now,out,error,nullptr);
}
static bool crl_context(const Credential &identity,const char *root_json,uint32_t now,bool root_crl,
                        uint8_t signing_key[32],uint32_t &signer_sn,uint32_t &target_id,uint8_t target_fingerprint[32]){
    // Revalidate the supplied public chain. Do not trust caller metadata such
    // as uid/fingerprint, and never accept a CRL's own embedded signing key.
    Json user(cJSON_Parse(identity.user_json.c_str()),cJSON_Delete);
    uint8_t public_key[32];
    if(!user||!decode_field(get(user.get(),"subject"),"publicKey",public_key,32))return false;
    const auto package="["+identity.intermediate_json+","+identity.user_json+"]";
    Credential verified;std::string error;
    if(!verify_bundle_impl(reinterpret_cast<const uint8_t *>(package.data()),package.size(),root_json,public_key,now,&verified,&error,target_fingerprint))return false;
    Json inter(cJSON_Parse(verified.intermediate_json.c_str()),cJSON_Delete);
    Json issuer_cert(cJSON_Parse(root_crl?root_json:verified.intermediate_json.c_str()),cJSON_Delete);
    target_id=verified.uid;
    if(root_crl){if(!num(inter.get(),"sn",&target_id))return false;}
    else std::memcpy(target_fingerprint,verified.fingerprint,32);
    return num(issuer_cert.get(),"sn",&signer_sn)&&decode_field(get(issuer_cert.get(),"subject"),"publicKey",signing_key,32);
}
static bool verify_crl(const uint8_t *data,size_t size,const Credential &identity,const char *root_json,
                       uint32_t now,uint32_t minimum_number,CrlStatus *status,bool root_crl,Bytes *proof){
    if(status)*status={};
    if(proof)proof->clear();
    if(!status||!data||!size||size>32768||!root_json||now<1700000000u)return false;
    uint8_t signing_key[32],target_fingerprint[32];uint32_t inter_sn,target_id;
    if(!crl_context(identity,root_json,now,root_crl,signing_key,inter_sn,target_id,target_fingerprint))return false;
    Json crl(cJSON_CreateObject(),cJSON_Delete);
    const char *expected_type=root_crl?"rootCRL":"intermediateCRL";

    Bytes tbs;unsigned count=0;bool revoked=false;uint32_t revoked_at=0;
    if(!crl||!crl_document(data,size,root_crl,target_id,target_fingerprint,now,crl,tbs,&count,&revoked,&revoked_at))return false;
    uint32_t issuer,number,this_update,next_update;
    const auto *kind=text(crl.get(),"type"),*algorithm=text(crl.get(),"signatureAlgorithm");
    if(!kind||std::strcmp(kind,expected_type)||!algorithm||std::strcmp(algorithm,"Ed25519")||
       !num(crl.get(),"issuerSn",&issuer)||issuer!=inter_sn||
       !num(crl.get(),"crlNumber",&number)||!num(crl.get(),"thisUpdate",&this_update)||
       !num(crl.get(),"nextUpdate",&next_update)||this_update>now||now>=next_update)return false;
    Bytes header;prefix(header,8,expected_type);integer(header,issuer);integer(header,number);
    integer(header,this_update);integer(header,next_update);head(header,4,count);
    tbs.insert(tbs.begin(),header.begin(),header.end());
    if(!signature(crl.get(),tbs,signing_key)||number<minimum_number)return false;
    if(proof){
        uint8_t sig[64];if(!decode_field(crl.get(),"signature",sig,64))return false;
        const uint32_t n=tbs.size();tbs.insert(tbs.begin(),76,0);
        std::memcpy(tbs.data(),"FCP1",4);tbs[4]=root_crl?0:1;
        for(unsigned i=0;i<4;++i)tbs[8+i]=n>>(8*i);
        std::memcpy(tbs.data()+12,sig,64);*proof=std::move(tbs);
    }
    *status={number,next_update,revoked,this_update,revoked_at};return true;
}
bool verify_user_crl(const uint8_t *data,size_t size,const Credential &identity,const char *root_json,
                     uint32_t now,uint32_t minimum_number,CrlStatus *status,Bytes *proof){
    return verify_crl(data,size,identity,root_json,now,minimum_number,status,false,proof);
}
bool verify_root_crl(const uint8_t *data,size_t size,const Credential &identity,const char *root_json,
                     uint32_t now,uint32_t minimum_number,CrlStatus *status,Bytes *proof){
    return verify_crl(data,size,identity,root_json,now,minimum_number,status,true,proof);
}
bool auth_password(const Credential &c,const uint8_t sk[64],const Relay &r,uint32_t now,std::string *out){
    if(!out||!callsign(c.callsign)||!callsign(r.callsign)||!r.host[0]||!r.port||!r.uid||now<1700000000u||now>=c.expires)return false;
    Bytes b;prefix(b,12,"serverAuthorizerReqHttp");integer(b,r.uid);string(b,r.callsign);integer(b,r.uid);string(b,"user");string(b,r.host);integer(b,r.port);binary(b,r.fingerprint,32);integer(b,now);binary(b,c.fingerprint,32);
    uint8_t sig[64];if(crypto_sign_detached(sig,nullptr,b.data(),b.size(),sk))return false;
    Json root(cJSON_CreateObject(),cJSON_Delete);auto *package=cJSON_AddObjectToObject(root.get(),"certPackage");
    auto *user=cJSON_Parse(c.user_json.c_str()),*inter=cJSON_Parse(c.intermediate_json.c_str());if(!user||!inter){cJSON_Delete(user);cJSON_Delete(inter);return false;}
    cJSON_AddItemToObject(package,"intermediateCert",inter);cJSON_AddItemToObject(package,"userCert",user);
    cJSON_AddStringToObject(root.get(),"targetCallsign",r.callsign);cJSON_AddNumberToObject(root.get(),"targetUID",r.uid);cJSON_AddStringToObject(root.get(),"role","user");cJSON_AddStringToObject(root.get(),"targetUrl",r.host);cJSON_AddNumberToObject(root.get(),"targetPort",r.port);cJSON_AddStringToObject(root.get(),"serverFingerprint",base64url(r.fingerprint,32).c_str());cJSON_AddNumberToObject(root.get(),"timestamp",now);
    cJSON_AddStringToObject(cJSON_AddObjectToObject(root.get(),"proof"),"signature",base64url(sig,64).c_str());const auto json=print(root.get());if(json.empty())return false;*out=base64url(reinterpret_cast<const uint8_t *>(json.data()),json.size());return true;
}
Relay builtin_relay(){
    Relay r{};
    std::strcpy(r.host,kBuiltinRelayHost);
    std::strcpy(r.callsign,kBuiltinRelayCallsign);
    std::strcpy(r.name,kBuiltinRelayName);
    r.uid=0;
    r.port=kBuiltinRelayPort;
    return r;
}
bool is_builtin_relay(const Relay &r){
    return r.uid==0&&r.port==kBuiltinRelayPort&&std::strcmp(r.host,kBuiltinRelayHost)==0;
}
namespace {
bool eq_bare_ci(const char *a,const char *b){
    if(!a||!b)return false;
    auto strip=[](const char *s){
        if((s[0]=='P'||s[0]=='p')&&s[1]=='-')return s+2;
        return bare_callsign(s);
    };
    a=strip(a);b=strip(b);
    if(!a||!b||!*a||!*b)return false;
    while(*a&&*b){
        const char ca=(*a>='a'&&*a<='z')?char(*a-'a'+'A'):*a;
        const char cb=(*b>='a'&&*b<='z')?char(*b-'a'+'A'):*b;
        if(ca!=cb)return false;
        ++a;++b;
    }
    return !*a&&!*b;
}
}
bool is_official_interop_relay(const char *cs){
    return eq_bare_ci(cs,kOfficialInteropCallsign);
}
bool is_own_relay(const char *relay_cs,const char *own_cs){
    return eq_bare_ci(relay_cs,own_cs);
}
void mqtt_username_for_relay(const Credential &c,const Relay &r,char out[20]){
    if(!out)return;
    out[0]=0;
    if(is_builtin_relay(r)){
        const char *bare=bare_callsign(c.callsign);
        if(bare&&bare[0])std::snprintf(out,20,"P-%.12s",bare);
        return;
    }
    std::snprintf(out,20,"%.12s",c.callsign);
}
bool guest_jwt_password(const Credential &c,uint32_t now,std::string *out){
    if(!out||!callsign(c.callsign))return false;
    const char *bare=bare_callsign(c.callsign);
    if(!bare||!bare[0])return false;
    char user[20]{};
    std::snprintf(user,sizeof(user),"P-%.12s",bare);
    char payload[224]{};
    int len=0;
    if(now>=1700000000u){
        const uint64_t exp=uint64_t(now)+86400ull;
        len=std::snprintf(payload,sizeof(payload),"{\"sub\":\"%s\",\"username\":\"%s\",\"client_attrs\":{\"callsign\":\"%s\",\"uid\":\"%u\"},\"exp\":%llu}",
                          user,user,user,static_cast<unsigned>(c.uid),static_cast<unsigned long long>(exp));
    }else{
        len=std::snprintf(payload,sizeof(payload),"{\"sub\":\"%s\",\"username\":\"%s\",\"client_attrs\":{\"callsign\":\"%s\",\"uid\":\"%u\"}}",
                          user,user,user,static_cast<unsigned>(c.uid));
    }
    if(len<=0||static_cast<size_t>(len)>=sizeof(payload))return false;
    static constexpr char kJwtHeader[]="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9";
    static constexpr char kGuestSecret[]="938eb6723056378f06de33994b026f0f99280f3bbd62e5dae974b6e3db944ba7";
    std::string signing_input=std::string(kJwtHeader)+"."+base64url(reinterpret_cast<const uint8_t *>(payload),static_cast<size_t>(len));
    crypto_auth_hmacsha256_state st{};
    uint8_t mac[crypto_auth_hmacsha256_BYTES]{};
    crypto_auth_hmacsha256_init(&st,reinterpret_cast<const uint8_t *>(kGuestSecret),sizeof(kGuestSecret)-1);
    crypto_auth_hmacsha256_update(&st,reinterpret_cast<const uint8_t *>(signing_input.data()),signing_input.size());
    crypto_auth_hmacsha256_final(&st,mac);
    *out=signing_input+"."+base64url(mac,sizeof(mac));
    sodium_memzero(mac,sizeof(mac));
    return true;
}
bool broadcast_frame(const Credential &c,const uint8_t sk[64],const BroadcastConfig &cfg,BroadcastKind kind,uint32_t server,uint32_t now,std::string *out,const char *stamp_style){
    if(!out)return false;
    out->clear();
    if(!sk||!cfg.enabled||!broadcast_config_valid(cfg)||now<1700000000||now>=c.expires||!c.uid||(kind!=BroadcastKind::CQ&&kind!=BroadcastKind::Beacon)||(kind==BroadcastKind::CQ&&!server)||(kind==BroadcastKind::Beacon&&!cfg.frequency[0]))return false;
    std::string login,call;if(!aprs_login(c.callsign,cfg,&login,&call))return false;
    char lat[9],lon[10],frequency[16]{};if(!grid_position(cfg.grid,lat,lon))return false;
    Json cert(cJSON_Parse(c.user_json.c_str()),cJSON_Delete);const auto *subject=get(cert.get(),"subject");uint32_t issuer,uid,iat,exp;uint8_t pk[32],local_pk[32],ca_sig[64];
    const char *cert_call=text(subject,"callsign");
    if(!cert_call||std::strcmp(cert_call,c.callsign)||!num(cert.get(),"issuerSn",&issuer)||!num(subject,"uid",&uid)||uid!=c.uid||!validity(cert.get(),now,&iat,&exp)||exp!=c.expires||!decode_field(subject,"publicKey",pk,32)||!decode_field(cert.get(),"signature",ca_sig,64)||crypto_sign_ed25519_sk_to_pk(local_pk,sk)||sodium_memcmp(local_pk,pk,32))return false;
    auto fields=[&](Bytes &b){integer(b,issuer);string(b,c.callsign);integer(b,uid);binary(b,pk,32);integer(b,iat);integer(b,exp);};
    Bytes cert_tbs;prefix(cert_tbs,9,"userCert");fields(cert_tbs);uint8_t fingerprint[32];crypto_hash_sha256(fingerprint,cert_tbs.data(),cert_tbs.size());if(sodium_memcmp(fingerprint,c.fingerprint,32))return false;
    if(kind==BroadcastKind::Beacon)std::snprintf(frequency,sizeof(frequency),"%.4f",std::strtod(cfg.frequency,nullptr));
    std::string frame=call+(kind==BroadcastKind::Beacon&&cfg.legacy_beacon?">APPASP,TCPIP*:=":">APFMO4,TCPIP*:=")+lat+'F'+lon+'i';
    if(kind==BroadcastKind::Beacon&&cfg.legacy_beacon){
        const char *st="ONLINE";
        if(stamp_style&&stamp_style[0]&&strnlen(stamp_style,8)==4&&stamp_style[0]>='A'&&stamp_style[0]<='Z'&&
           stamp_style[1]>='0'&&stamp_style[1]<='9'&&stamp_style[2]>='0'&&stamp_style[2]<='9'&&stamp_style[3]>='0'&&stamp_style[3]<='9'){
            st=stamp_style;
        }
        frame+="PAT-1,ST:"+std::string(st)+",VER:PassportOS,FREQ:"+std::string(frequency);
        if(cfg.rig[0])frame+=",RIG:"+std::string(cfg.rig);
        if(cfg.antenna[0])frame+=",ANT:"+std::string(cfg.antenna);
    }else {
        Bytes blob;prefix(blob,10,"userCert");fields(blob);binary(blob,ca_sig,64);uint8_t hash[32];crypto_hash_sha256(hash,blob.data(),blob.size());
        const char *type=kind==BroadcastKind::CQ?"CQ":"BEACON";
        const size_t extra=kind==BroadcastKind::Beacon?unsigned(cfg.antenna_height>0)+unsigned(cfg.rig[0]!=0)+unsigned(cfg.antenna[0]!=0):0;
        Bytes tbs;prefix(tbs,10+extra,type);string(tbs,c.callsign);integer(tbs,cfg.ssid);string(tbs,lat);string(tbs,lon);binary(tbs,hash,32);
        frame+=" FMO-V4,"+std::string(type)+",CERT:"+base64url(blob.data(),blob.size());
        if(kind==BroadcastKind::CQ){integer(tbs,server);frame+=",S"+std::to_string(server);}
        else {string(tbs,frequency);frame+=",FREQ:"+std::string(frequency);
            if(cfg.antenna_height){integer(tbs,cfg.antenna_height);frame+=",HEIGHT:"+std::to_string(cfg.antenna_height);}
            if(cfg.rig[0]){string(tbs,cfg.rig);frame+=",RIG:"+std::string(cfg.rig);}
            if(cfg.antenna[0]){string(tbs,cfg.antenna);frame+=",ANT:"+std::string(cfg.antenna);}
        }
        integer(tbs,now/600);uint8_t signature_bytes[64];
        if(crypto_sign_detached(signature_bytes,nullptr,tbs.data(),tbs.size(),sk)||crypto_sign_verify_detached(signature_bytes,tbs.data(),tbs.size(),pk))return false;
        frame+=",SIG:"+base64url(signature_bytes,sizeof(signature_bytes));
    }
    frame+="\r\n";if(frame.size()>512)return false;*out=std::move(frame);return true;
}
namespace {
struct Reader {
 const uint8_t *p,*end;bool ok=true;
 uint64_t take(unsigned major){
  if(p==end){ok=false;return 0;}uint8_t c=*p++;if((c>>5)!=major){ok=false;return 0;}unsigned n=c&31;if(n<24)return n;
  const unsigned bytes=n==24?1:n==25?2:n==26?4:n==27?8:0;if(!bytes||static_cast<size_t>(end-p)<bytes){ok=false;return 0;}
  uint64_t v=0;for(unsigned i=0;i<bytes;++i)v=(v<<8)|*p++;
  if((bytes==1&&v<24)||(bytes==2&&v<256)||(bytes==4&&v<65536)||(bytes==8&&v<=UINT32_MAX))ok=false;
  return v;
 }
 bool literal(const char *s){const auto n=take(3);if(!ok||n!=std::strlen(s)||static_cast<size_t>(end-p)<n){ok=false;return false;}const bool same=!std::memcmp(p,s,n);p+=n;return same;}
 bool bytes(uint8_t *out,size_t n){const auto count=take(2);if(!ok||count!=n||static_cast<size_t>(end-p)<n){ok=false;return false;}std::memcpy(out,p,n);p+=n;return true;}
 bool name(char *out,size_t cap){const auto n=take(3);if(!ok||!n||n>=cap||static_cast<size_t>(end-p)<n){ok=false;return false;}if(std::memchr(p,0,n)){ok=false;return false;}std::memcpy(out,p,n);out[n]=0;p+=n;return true;}
};
bool decimal(const std::string &s,uint32_t *value){if(s.empty()||s.size()>10)return false;uint64_t n=0;for(char c:s){if(c<'0'||c>'9')return false;n=n*10+c-'0';if(n>UINT32_MAX)return false;}*value=n;return true;}
bool verified_aprs_certificate(const char *encoded,const std::string &call,const Credential &identity,const char *root_json,
                               uint32_t now,uint8_t pub[32],uint8_t blob_hash[32],Credential *verified,StationRejection *rejection,const DiscoveryChain *extra=nullptr,uint32_t *unknown_issuer=nullptr){
    uint8_t blob[256],ca_sig[64];size_t size=0;
    if(!unbase64(encoded,blob,sizeof(blob),&size))return false;
    Reader reader{blob,blob+size};char cert_call[13];
    if(reader.take(4)!=10||!reader.literal("FMO")||reader.take(0)!=4||!reader.literal("userCert"))return false;
    const auto issuer=reader.take(0);if(issuer>UINT32_MAX||!reader.name(cert_call,sizeof(cert_call)))return false;
    const bool call_matches=(call==cert_call)||(std::strncmp(cert_call,"P-",2)==0&&call==(cert_call+2));
    if(!call_matches)return false;
    const auto uid=reader.take(0);if(uid>UINT32_MAX||!reader.bytes(pub,32))return false;
    const auto iat=reader.take(0),exp=reader.take(0);
    if(iat>UINT32_MAX||exp>UINT32_MAX||!reader.bytes(ca_sig,64)||!reader.ok||reader.p!=reader.end)return false;
    auto matches_issuer=[issuer](const char *json){
        if(!json||strnlen(json,4097)>4096)return false;
        Json intermediate(cJSON_Parse(json),cJSON_Delete);uint32_t serial;
        return num(intermediate.get(),"sn",&serial)&&serial==issuer;
    };
    const char *intermediate=identity.intermediate_json.c_str();
    if(!matches_issuer(intermediate)){
        if(!extra||!extra->root_json||!matches_issuer(extra->intermediate_json)){
            if(rejection)*rejection=StationRejection::UnknownIssuer;
            if(unknown_issuer)*unknown_issuer=static_cast<uint32_t>(issuer);
            return false;
        }
        intermediate=extra->intermediate_json;
        root_json=extra->root_json;
    }
    if(rejection)*rejection=StationRejection::CertificateInvalid;
    Json user(cJSON_CreateObject(),cJSON_Delete);cJSON_AddStringToObject(user.get(),"type","userCert");cJSON_AddStringToObject(user.get(),"signatureAlgorithm","Ed25519");
    cJSON_AddNumberToObject(user.get(),"issuerSn",issuer);cJSON_AddNumberToObject(user.get(),"iat",iat);cJSON_AddNumberToObject(user.get(),"exp",exp);
    cJSON_AddStringToObject(user.get(),"signature",base64url(ca_sig,64).c_str());auto *subject=cJSON_AddObjectToObject(user.get(),"subject");
    cJSON_AddStringToObject(subject,"callsign",cert_call);cJSON_AddNumberToObject(subject,"uid",uid);cJSON_AddStringToObject(subject,"publicKey",base64url(pub,32).c_str());
    const auto package=std::string("[")+intermediate+","+print(user.get())+"]";std::string error;
    if(!verify_bundle(reinterpret_cast<const uint8_t *>(package.data()),package.size(),root_json,pub,now,verified,&error))return false;
    crypto_hash_sha256(blob_hash,blob,size);return true;
}

}
bool verify_crl_proof(const uint8_t *data,size_t size,bool root_crl,const Credential &identity,const char *root_json,
                      uint32_t now,uint32_t minimum_number,CrlStatus *status,bool allow_stale){
    if(status)*status={};
    if(!status||!data||size<77||size>12940||!root_json||now<1700000000u)return false;
    if(std::memcmp(data,"FCP1",4)||data[4]!=(root_crl?0:1)||data[5]||data[6]||data[7])return false;
    const uint32_t length=uint32_t(data[8])|(uint32_t(data[9])<<8)|(uint32_t(data[10])<<16)|(uint32_t(data[11])<<24);
    if(length!=size-76)return false;
    uint8_t signing_key[32],target_fp[32];uint32_t issuer,target_id;
    if(!crl_context(identity,root_json,now,root_crl,signing_key,issuer,target_id,target_fp))return false;
    if(crypto_sign_verify_detached(data+12,data+76,length,signing_key))return false;
    Reader reader{data+76,data+size};
    if(reader.take(4)!=8||!reader.literal("FMO")||reader.take(0)!=4||!reader.literal(root_crl?"rootCRL":"intermediateCRL")||reader.take(0)!=issuer)return false;
    const auto number=reader.take(0),this_update=reader.take(0),next_update=reader.take(0),count=reader.take(4);
    if(!reader.ok||number>UINT32_MAX||this_update>now||next_update>UINT32_MAX||next_update<=this_update||
       (!allow_stale&&now>=next_update)||number<minimum_number||count>256)return false;
    uint32_t previous_id=0,revoked_at=0;uint8_t previous_fp[32]{};bool revoked=false;
    for(uint64_t i=0;i<count;++i){
        if(reader.take(4)!=4)return false;
        const auto id=reader.take(0);uint8_t fp[32];if(id>UINT32_MAX||!reader.bytes(fp,32))return false;
        const auto at=reader.take(0),reason=reader.take(0);
        if(!reader.ok||at>UINT32_MAX||reason>UINT32_MAX||(i&&(id<previous_id||(id==previous_id&&std::memcmp(fp,previous_fp,32)<=0))))return false;
        previous_id=id;std::memcpy(previous_fp,fp,32);
        if(id==target_id&&!sodium_memcmp(fp,target_fp,32)){revoked_at=at;revoked=at<=now;}
    }
    if(!reader.ok||reader.p!=reader.end)return false;
    *status={static_cast<uint32_t>(number),static_cast<uint32_t>(next_update),revoked,static_cast<uint32_t>(this_update),revoked_at};
    return true;
}
bool peer_announcement(const char *line,size_t size,const Credential &identity,const char *root_json,uint32_t now,PeerAnnouncement *out,const DiscoveryChain *extra_chain){
    // Transport has removed CRLF, which still counts toward the 512-byte limit.
    if(!line||!out||!root_json||!size||size>510||now<1700000000u)return false;
    for(size_t i=0;i<size;++i)if(static_cast<unsigned char>(line[i])<32||line[i]==127)return false;
    const std::string raw(line,size);const auto gt=raw.find('>'),colon=raw.find(':');
    const bool dest_ok=gt!=std::string::npos&&(!raw.compare(gt+1,6,"APFMO4")||!raw.compare(gt+1,6,"APPASP"));
    if(!dest_ok||colon==std::string::npos||colon<gt||raw.find_first_of(",:",gt+1)!=gt+7)return false;
    std::string call=raw.substr(0,gt);uint32_t ssid=0;const auto dash=call.rfind('-');
    if(dash!=std::string::npos){if(!decimal(call.substr(dash+1),&ssid)||ssid>15)return false;call.resize(dash);}
    if(!callsign(call.c_str()))return false;
    const auto payload=raw.substr(colon+1);if(payload.size()<21||payload[0]!='=')return false;
    // Keep the signed raw APRS coordinate fields; no distance/online inference.
    if((payload[8]!='N'&&payload[8]!='S')||(payload[18]!='E'&&payload[18]!='W')||payload[5]!='.'||payload[15]!='.')return false;
    size_t start=20;while(start<payload.size()&&payload[start]==' ')++start;
    std::vector<std::string> tokens;size_t begin=start;
    for(size_t i=start;i<=payload.size();++i)if(i==payload.size()||payload[i]==','){tokens.push_back(payload.substr(begin,i-begin));begin=i+1;if(tokens.size()>8)return false;}
    if(tokens.size()<5||tokens[0]!="FMO-V4"||tokens[2].compare(0,5,"CERT:")||tokens.back().compare(0,4,"SIG:"))return false;
    PeerKind kind;
    if(tokens[1]=="CQ")kind=PeerKind::CQ;
    else if(tokens[1]=="OMCQ")kind=PeerKind::OldFriendCQ;
    else if(tokens[1]=="VOCAL")kind=PeerKind::Vocal;
    else if(tokens[1]=="ONLINE")kind=PeerKind::Online;
    else if(tokens[1]=="BEACON")kind=PeerKind::Beacon;
    else return false;
    const bool beacon=kind==PeerKind::Beacon;
    uint32_t server=0,height=0;std::string frequency,rig,antenna;
    if(!beacon){
        if(tokens.size()!=5||tokens[3].size()<2||tokens[3][0]!='S'||!decimal(tokens[3].substr(1),&server))return false;
        for(unsigned char c:raw)if(c>126)return false;
    }else {
        if(tokens[3].compare(0,5,"FREQ:"))return false;
        const auto wire=tokens[3].substr(5);const auto dot=wire.find('.');
        uint32_t whole,part=0;
        if(dot==std::string::npos||dot<1||dot>5||wire.size()-dot-1<1||wire.size()-dot-1>4||
           !decimal(wire.substr(0,dot),&whole)||!decimal(wire.substr(dot+1),&part))return false;
        for(size_t n=wire.size()-dot-1;n<4;++n)part*=10;
        if(whole>99999||part>9999||(!whole&&!part))return false;
        char normal[24];std::snprintf(normal,sizeof(normal),"%lu.%04lu",static_cast<unsigned long>(whole),static_cast<unsigned long>(part));frequency=normal;
        unsigned previous=0;
        for(size_t i=4;i+1<tokens.size();++i){
            unsigned field=0;
            if(!tokens[i].compare(0,7,"HEIGHT:")){field=1;if(!decimal(tokens[i].substr(7),&height)||!height)return false;}
            else if(!tokens[i].compare(0,4,"RIG:")){field=2;rig=tokens[i].substr(4);if(rig.empty())return false;}
            else if(!tokens[i].compare(0,4,"ANT:")){field=3;antenna=tokens[i].substr(4);if(antenna.empty())return false;}
            else return false;
            if(field<=previous)return false;
            previous=field;
        }
    }
    uint8_t signature_bytes[64],pub[32],hash[32];size_t signature_size=0;Credential peer;
    if(!unbase64(tokens.back().c_str()+4,signature_bytes,64,&signature_size)||signature_size!=64||
       !verified_aprs_certificate(tokens[2].c_str()+5,call,identity,root_json,now,pub,hash,&peer,nullptr,extra_chain))return false;
    for(int delta=-1;delta<=1;++delta){
        const uint32_t window=now/600+delta;
        for(const char *signed_call:{call.c_str(),static_cast<const char *>(peer.callsign)}){
            if(signed_call==peer.callsign&&call==peer.callsign)continue;
            Bytes tbs;prefix(tbs,10+unsigned(height!=0)+unsigned(!rig.empty())+unsigned(!antenna.empty()),tokens[1].c_str());string(tbs,signed_call);integer(tbs,ssid);
            string(tbs,payload.substr(1,8).c_str());string(tbs,payload.substr(10,9).c_str());binary(tbs,hash,32);
            if(beacon){string(tbs,frequency.c_str());if(height)integer(tbs,height);if(!rig.empty())string(tbs,rig.c_str());if(!antenna.empty())string(tbs,antenna.c_str());}
            else integer(tbs,server);
            integer(tbs,window);
            if(crypto_sign_verify_detached(signature_bytes,tbs.data(),tbs.size(),pub))continue;
            PeerAnnouncement result{};result.kind=kind;result.uid=peer.uid;result.server_uid=server;result.ssid=ssid;result.window=window;
            result.valid_until=std::min<uint64_t>(peer.expires,(uint64_t(window)+2)*600);
            std::strcpy(result.callsign,peer.callsign);std::memcpy(result.latitude,payload.data()+1,8);std::memcpy(result.longitude,payload.data()+10,9);
            std::memcpy(result.fingerprint,peer.fingerprint,32);
            if(beacon){
                std::strcpy(result.frequency,frequency.c_str());result.antenna_height=height;
                // Verify complete signed UTF-8 fields, then retain a bounded display
                // prefix; shortening never changes the bytes used for verification.
                auto copy_text=[](const std::string &value,char *target,size_t cap){
                    size_t used=0;
                    for(size_t i=0;i<value.size();){
                        const unsigned char c=value[i];unsigned width=c<0x80?1:c>=0xc2&&c<=0xdf?2:c>=0xe0&&c<=0xef?3:c>=0xf0&&c<=0xf4?4:0;
                        if(!width||i+width>value.size())return false;
                        for(unsigned j=1;j<width;++j)if((static_cast<unsigned char>(value[i+j])&0xc0)!=0x80)return false;
                        if(width>=3){const unsigned char second=value[i+1];if((c==0xe0&&second<0xa0)||(c==0xed&&second>=0xa0)||(c==0xf0&&second<0x90)||(c==0xf4&&second>=0x90))return false;}
                        if(i==used&&used+width<=(value.size()<cap?cap-1:cap-4)){std::memcpy(target+used,value.data()+i,width);used+=width;}
                        i+=width;
                    }
                    if(used<value.size()){std::memcpy(target+used,"...",3);used+=3;}
                    target[used]=0;return true;
                };
                if(!copy_text(rig,result.rig,sizeof(result.rig))||!copy_text(antenna,result.antenna,sizeof(result.antenna)))return false;
            }
            *out=result;return true;
        }
    }
    return false;
}
namespace {
bool event_source(const char *line,size_t size,std::string *call,uint32_t *ssid,std::string *payload){
    if(!line||!size||size>510)return false;
    for(size_t i=0;i<size;++i)if(static_cast<unsigned char>(line[i])<32||line[i]==127)return false;
    const std::string raw(line,size);const auto gt=raw.find('>'),colon=raw.find(':');
    const bool dest_ok=gt!=std::string::npos&&(!raw.compare(gt+1,6,"APFMO4")||!raw.compare(gt+1,6,"APPASP"));
    if(!dest_ok||colon==std::string::npos||colon<gt||raw.find_first_of(",:",gt+1)!=gt+7)return false;
    *call=raw.substr(0,gt);*ssid=0;const auto dash=call->rfind('-');
    if(dash!=std::string::npos){if(!decimal(call->substr(dash+1),ssid)||*ssid>15)return false;call->resize(dash);}
    if(!callsign(call->c_str()))return false;
    *payload=raw.substr(colon+1);return true;
}

}
bool joint_announcement(const char *line,size_t size,const Credential &identity,const char *root_json,uint32_t now,EventProof *out,const DiscoveryChain *extra_chain){
    if(!out||!root_json||now<1700000000u)return false;
    std::string call,payload;uint32_t ssid;
    if(!event_source(line,size,&call,&ssid,&payload)||payload.size()<21||payload[0]!='=')return false;
    if((payload[8]!='N'&&payload[8]!='S')||(payload[18]!='E'&&payload[18]!='W')||payload[5]!='.'||payload[15]!='.')return false;
    size_t start=20;while(start<payload.size()&&payload[start]==' ')++start;
    std::vector<std::string> tokens;size_t begin=start;
    for(size_t i=start;i<=payload.size();++i)if(i==payload.size()||payload[i]==','){tokens.push_back(payload.substr(begin,i-begin));begin=i+1;if(tokens.size()>5)return false;}
    if(tokens.size()!=5||tokens[0]!="FMO-V4"||tokens[1]!="JOINT"||tokens[2].compare(0,5,"CERT:")||tokens[3].compare(0,3,"SH:")||tokens[4].compare(0,4,"SIG:"))return false;
    uint8_t digest[32],signature[64],pub[32],blob_hash[32];size_t n=0;Credential sender;
    if(!unbase64(tokens[3].c_str()+3,digest,32,&n)||n!=32||!unbase64(tokens[4].c_str()+4,signature,64,&n)||n!=64||
       !verified_aprs_certificate(tokens[2].c_str()+5,call,identity,root_json,now,pub,blob_hash,&sender,nullptr,extra_chain))return false;
    for(int delta=-1;delta<=1;++delta){
        const uint32_t window=now/600+delta;Bytes tbs;prefix(tbs,10,"JOINT");string(tbs,call.c_str());integer(tbs,ssid);
        string(tbs,payload.substr(1,8).c_str());string(tbs,payload.substr(10,9).c_str());binary(tbs,blob_hash,32);binary(tbs,digest,32);integer(tbs,window);
        if(crypto_sign_verify_detached(signature,tbs.data(),tbs.size(),pub))continue;
        EventProof result{};std::strcpy(result.callsign,sender.callsign);result.ssid=ssid;result.uid=sender.uid;result.window=window;
        result.valid_until=std::min<uint64_t>(sender.expires,(uint64_t(window)+2)*600);
        std::memcpy(result.fingerprint,sender.fingerprint,32);std::memcpy(result.digest,digest,32);*out=result;return true;
    }
    return false;
}
bool event_status(const char *line,size_t size,EventBody *out){
    if(!out)return false;
    std::string call,payload;uint32_t ssid;
    if(!event_source(line,size,&call,&ssid,&payload)||payload.compare(0,14,">FMO-V4,EVENT,"))return false;
    const size_t a=payload.find(',',14),b=a==std::string::npos?a:payload.find(',',a+1);uint32_t uid;
    if(a==std::string::npos||b==std::string::npos||!decimal(payload.substr(14,a-14),&uid)||!uid)return false;
    const auto topic=payload.substr(a+1,b-a-1),content=payload.substr(b+1);
    if(!valid_utf8(topic,32)||!valid_utf8(content,140))return false;
    EventBody result{};std::strcpy(result.callsign,call.c_str());result.ssid=ssid;result.uid=uid;
    std::strcpy(result.topic,topic.c_str());std::strcpy(result.content,content.c_str());
    crypto_hash_sha256(result.digest,reinterpret_cast<const uint8_t *>(payload.data()+1),payload.size()-1);
    *out=result;return true;
}
bool event_bind(const EventProof &proof,const EventBody &body,uint32_t now,EventNotice *out){
    if(!out||!proof.uid||proof.valid_until<=now||proof.uid!=body.uid||proof.ssid!=body.ssid||std::strcmp(proof.callsign,body.callsign)||sodium_memcmp(proof.digest,body.digest,32))return false;
    // Re-check the accepted window if the device clock moves backwards.
    const uint32_t current=now/600;
    if(uint64_t(proof.window)+1<current||proof.window>uint64_t(current)+1)return false;
    EventNotice result{};result.body=body;result.window=proof.window;result.valid_until=proof.valid_until;
    std::memcpy(result.fingerprint,proof.fingerprint,32);*out=result;return true;
}
bool station_announcement(const char *line,size_t size,const Credential &identity,const char *root_json,uint32_t now,Relay *relay,uint32_t *valid_until,StationStatus *status,StationRejection *rejection,const DiscoveryChain *extra_chain,uint32_t *unknown_issuer){
 if(unknown_issuer)*unknown_issuer=0;
 if(rejection)*rejection=StationRejection::NotStation;
 if(valid_until)*valid_until=0;
 if(status)*status={};
 if(!line||!relay||size>510||!size||now<1700000000u)return false;
 for(size_t i=0;i<size;++i)if(static_cast<unsigned char>(line[i])<32||line[i]==127)return false;
 const std::string raw(line,size);const auto gt=raw.find('>'),colon=raw.find(':');
 const bool dest_ok=gt!=std::string::npos&&(!raw.compare(gt+1,6,"APFMO4")||!raw.compare(gt+1,6,"APPASP"));
 if(!dest_ok||colon==std::string::npos||colon<gt||raw.find_first_of(",:",gt+1)!=gt+7)return false;
 std::string call=raw.substr(0,gt);uint32_t ssid=0;auto dash=call.rfind('-');if(dash!=std::string::npos){if(!decimal(call.substr(dash+1),&ssid)||ssid>15)return false;call.resize(dash);}if(!callsign(call.c_str()))return false;
 const auto payload=raw.substr(colon+1);if(payload.size()<21||payload[0]!='=')return false;
 // Live APRS stations place FMO-V4 directly after the 20-byte POSITION
 // prefix; documentation examples also include a separating space.
 size_t body_start=20;while(body_start<payload.size()&&payload[body_start]==' ')++body_start;
 const auto body=payload.substr(body_start);std::vector<std::string> tokens;size_t start=0;
 for(size_t at=0;at<=body.size();++at)if(at==body.size()||body[at]==','){tokens.push_back(body.substr(start,at-start));start=at+1;if(tokens.size()>10)return false;}
 if(tokens.size()!=10||tokens[0]!="FMO-V4"||tokens[1]!="STATION"||tokens[2].compare(0,5,"CERT:")||tokens[9].compare(0,4,"SIG:"))return false;
 if(rejection)*rejection=StationRejection::Malformed;
 if(tokens[3].size()!=2||tokens[4].size()>=sizeof(relay->name)||tokens[5].empty()||tokens[5].size()>=sizeof(relay->host)||tokens[6].size()<2||tokens[6][0]!='P'||tokens[7].size()<4||tokens[7][0]!='F'||tokens[7].substr(tokens[7].size()-2)!="KM"||tokens[8].empty()||tokens[8][0]!='U')return false;
 uint32_t port,km,online,peak;const auto slash=tokens[8].find('/');
 if(!decimal(tokens[6].substr(1),&port)||!port||port>65535||!decimal(tokens[7].substr(1,tokens[7].size()-3),&km)||slash==std::string::npos||!decimal(tokens[8].substr(1,slash-1),&online)||!decimal(tokens[8].substr(slash+1),&peak))return false;
 uint8_t sig[64],pub[32],hash[32];size_t sig_size=0;Credential station;
 if(!unbase64(tokens[9].c_str()+4,sig,sizeof(sig),&sig_size)||sig_size!=64||
    !verified_aprs_certificate(tokens[2].c_str()+5,call,identity,root_json,now,pub,hash,&station,rejection,extra_chain,unknown_issuer))return false;
 if(rejection)*rejection=StationRejection::SignatureInvalid;
 bool valid=false;uint32_t until=0;
 for(int delta=-1;delta<=1&&!valid;++delta){
  for(const char *signed_call:{call.c_str(),static_cast<const char *>(station.callsign)}){
   if(signed_call==station.callsign&&call==station.callsign)continue;
   Bytes b;prefix(b,16,"STATION");string(b,signed_call);integer(b,ssid);string(b,payload.substr(1,8).c_str());string(b,payload.substr(10,9).c_str());binary(b,hash,32);string(b,tokens[3].c_str());string(b,tokens[4].c_str());string(b,tokens[5].c_str());integer(b,port);integer(b,km);integer(b,online);integer(b,peak);integer(b,now/600+delta);
   valid=crypto_sign_verify_detached(sig,b.data(),b.size(),pub)==0;
   if(valid){until=std::min<uint64_t>(station.expires,(uint64_t(now/600+delta)+2)*600);break;}
  }
 }
 if(!valid)return false;
 if(valid_until)*valid_until=until;
 if(status)*status={online,peak,km,until};
 if(rejection)*rejection=StationRejection::None;
 Relay result{};std::strcpy(result.host,tokens[5].c_str());std::strcpy(result.callsign,station.callsign);std::strcpy(result.name,tokens[4].c_str());result.uid=station.uid;result.port=port;std::memcpy(result.fingerprint,station.fingerprint,32);*relay=result;return true;
}
bool interop_station_announcement(const char *line,size_t size,uint32_t now,Relay *relay,uint32_t *valid_until,StationStatus *status,uint32_t *issuer_out){
 if(valid_until)*valid_until=0;
 if(status)*status={};
 if(issuer_out)*issuer_out=0;
 if(!line||!relay||size>510||!size||now<1700000000u)return false;
 for(size_t i=0;i<size;++i)if(static_cast<unsigned char>(line[i])<32||line[i]==127)return false;
 const std::string raw(line,size);const auto gt=raw.find('>'),colon=raw.find(':');
 const bool dest_ok=gt!=std::string::npos&&(!raw.compare(gt+1,6,"APFMO4")||!raw.compare(gt+1,6,"APPASP"));
 if(!dest_ok||colon==std::string::npos||colon<gt||raw.find_first_of(",:",gt+1)!=gt+7)return false;
 std::string call=raw.substr(0,gt);uint32_t ssid=0;auto dash=call.rfind('-');
 if(dash!=std::string::npos){if(!decimal(call.substr(dash+1),&ssid)||ssid>15)return false;call.resize(dash);}
 if(!callsign(call.c_str()))return false;
 const auto payload=raw.substr(colon+1);if(payload.size()<21||payload[0]!='=')return false;
 size_t body_start=20;while(body_start<payload.size()&&payload[body_start]==' ')++body_start;
 const auto body=payload.substr(body_start);std::vector<std::string> tokens;size_t start=0;
 for(size_t at=0;at<=body.size();++at)if(at==body.size()||body[at]==','){tokens.push_back(body.substr(start,at-start));start=at+1;if(tokens.size()>10)return false;}
 if(tokens.size()!=10||tokens[0]!="FMO-V4"||tokens[1]!="STATION"||tokens[2].compare(0,5,"CERT:")||tokens[9].compare(0,4,"SIG:"))return false;
 if(tokens[3].size()!=2||tokens[4].size()>=sizeof(relay->name)||tokens[5].empty()||tokens[5].size()>=sizeof(relay->host)||tokens[6].size()<2||tokens[6][0]!='P'||tokens[7].size()<4||tokens[7][0]!='F'||tokens[7].substr(tokens[7].size()-2)!="KM"||tokens[8].empty()||tokens[8][0]!='U')return false;
 uint32_t port,km,online,peak;const auto slash=tokens[8].find('/');
 if(!decimal(tokens[6].substr(1),&port)||!port||port>65535||!decimal(tokens[7].substr(1,tokens[7].size()-3),&km)||slash==std::string::npos||!decimal(tokens[8].substr(1,slash-1),&online)||!decimal(tokens[8].substr(slash+1),&peak))return false;
 uint8_t blob[256],ca_sig[64],pub[32],sig[64],hash[32];size_t blob_size=0,sig_size=0;
 if(!unbase64(tokens[9].c_str()+4,sig,sizeof(sig),&sig_size)||sig_size!=64||!unbase64(tokens[2].c_str()+5,blob,sizeof(blob),&blob_size))return false;
 Reader reader{blob,blob+blob_size};char cert_call[13]{};
 if(reader.take(4)!=10||!reader.literal("FMO")||reader.take(0)!=4||!reader.literal("userCert"))return false;
 const auto issuer=reader.take(0);if(!issuer||!reader.name(cert_call,sizeof(cert_call)))return false;
 const bool call_matches=(call==cert_call)||(std::strncmp(cert_call,"P-",2)==0&&call==(cert_call+2));
 if(!call_matches||!callsign(cert_call))return false;
 const auto uid=reader.take(0);if(!uid||uid>UINT32_MAX||!reader.bytes(pub,32))return false;
 const auto iat=reader.take(0),exp=reader.take(0);
 if(iat>UINT32_MAX||exp>UINT32_MAX||!reader.bytes(ca_sig,64)||!reader.ok||reader.p!=reader.end)return false;
 if(now<iat||now>=exp)return false;
 crypto_hash_sha256(hash,blob,blob_size);
 bool valid=false;uint32_t until=0;
 for(int delta=-1;delta<=1&&!valid;++delta){
  for(const char *signed_call:{call.c_str(),static_cast<const char *>(cert_call)}){
   if(signed_call==cert_call&&call==cert_call)continue;
   Bytes b;prefix(b,16,"STATION");string(b,signed_call);integer(b,ssid);string(b,payload.substr(1,8).c_str());string(b,payload.substr(10,9).c_str());binary(b,hash,32);string(b,tokens[3].c_str());string(b,tokens[4].c_str());string(b,tokens[5].c_str());integer(b,port);integer(b,km);integer(b,online);integer(b,peak);integer(b,now/600+delta);
   valid=crypto_sign_verify_detached(sig,b.data(),b.size(),pub)==0;
   if(valid){until=std::min<uint64_t>(exp,(uint64_t(now/600+delta)+2)*600);break;}
  }
 }
 if(!valid)return false;
 Bytes cert_tbs;prefix(cert_tbs,9,"userCert");integer(cert_tbs,issuer);string(cert_tbs,cert_call);integer(cert_tbs,uid);binary(cert_tbs,pub,32);integer(cert_tbs,iat);integer(cert_tbs,exp);
 Relay result{};std::strcpy(result.host,tokens[5].c_str());std::strcpy(result.callsign,cert_call);std::strcpy(result.name,tokens[4].c_str());result.uid=static_cast<uint32_t>(uid);result.port=static_cast<uint16_t>(port);
 crypto_hash_sha256(result.fingerprint,cert_tbs.data(),cert_tbs.size());
 if(valid_until)*valid_until=until;
 if(status)*status={online,peak,km,until};
 if(issuer_out)*issuer_out=issuer<=UINT32_MAX?static_cast<uint32_t>(issuer):0u;
 *relay=result;return true;
}
bool parse_appasp_listening(const char *line,size_t size,char relay_name[48],char relay_callsign[13]){
 if(relay_name)relay_name[0]=0;
 if(relay_callsign)relay_callsign[0]=0;
 if(!line||!size||size>510||!relay_name||!relay_callsign)return false;
 for(size_t i=0;i<size;++i)if(static_cast<unsigned char>(line[i])<32||line[i]==127)return false;
 const std::string raw(line,size);const auto gt=raw.find('>'),colon=raw.find(':');
 if(gt==std::string::npos||colon==std::string::npos||colon<gt)return false;
 if(raw.compare(gt+1,6,"APPASP")!=0||raw.find_first_of(",:",gt+1)!=gt+7)return false;
 const std::string payload=raw.substr(colon+1);
 static constexpr char kPrefix[]=">正在 ";
 static constexpr char kSuffix[]=" 上守听";
 constexpr size_t kPreLen=sizeof(kPrefix)-1,kSufLen=sizeof(kSuffix)-1;
 if(payload.size()<=kPreLen+kSufLen+4)return false;
 if(payload.compare(0,kPreLen,kPrefix)!=0)return false;
 const auto end_pos=payload.find(kSuffix,kPreLen);
 if(end_pos==std::string::npos||end_pos<kPreLen+4||payload[end_pos-1]!=')')return false;
 const auto open_pos=payload.rfind('(',end_pos-1);
 if(open_pos==std::string::npos||open_pos<=kPreLen)return false;
 std::string cs=payload.substr(open_pos+1,end_pos-1-(open_pos+1));
 const auto dash=cs.rfind('-');if(dash!=std::string::npos)cs.resize(dash);
 for(char &ch:cs)if(ch>='a'&&ch<='z')ch=char(ch-'a'+'A');
 if(!callsign(cs.c_str()))return false;
 std::string nm=payload.substr(kPreLen,open_pos-kPreLen);
 if(nm.empty())return false;
 if(nm.size()>=48){
  size_t cut=47;
  while(cut>0&&(static_cast<unsigned char>(nm[cut])&0xc0)==0x80)--cut;
  nm.resize(cut);
 }
 if(nm.empty())return false;
 std::memcpy(relay_name,nm.data(),nm.size());relay_name[nm.size()]=0;
 std::strcpy(relay_callsign,cs.c_str());
 return true;
}

}
