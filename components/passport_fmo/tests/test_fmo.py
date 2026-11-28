"""Real AIRP packet and Ed25519/CBOR compatibility, using independent Python vectors."""
from pathlib import Path
import base64,hashlib,json,os,struct,subprocess,tempfile,zlib
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding,PublicFormat
root=Path(__file__).resolve().parents[3]
def cb(v):
 def head(m,n):
  if n<24:return bytes([m*32+n])
  for lim,k,fmt in [(256,24,'>B'),(65536,25,'>H'),(2**32,26,'>I'),(2**64,27,'>Q')]:
   if n<lim:return bytes([m*32+k])+struct.pack(fmt,n)
 if v is True:return b'\xf5'
 if isinstance(v,int):return head(0,v)
 if isinstance(v,bytes):return head(2,len(v))+v
 if isinstance(v,str):b=v.encode();return head(3,len(b))+b
 if isinstance(v,list):return head(4,len(v))+b''.join(map(cb,v))
 raise TypeError(v)
def b64(b):return base64.urlsafe_b64encode(b).decode().rstrip('=')
def un64(s):return base64.urlsafe_b64decode(s+'='*(-len(s)%4))
def key(n):return Ed25519PrivateKey.from_private_bytes(bytes([n])*32)
def pk(k):return k.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw)
def sign(obj,values,k):obj['signature']=b64(k.sign(cb(values)));return obj
now=1800000000;rk,ik,uk=map(key,[1,2,3]);rpk,ipk,upk=map(pk,[rk,ik,uk])
rt=['FMO',4,'rootCA',1,'Test Root','root@example.test','Test Root',rpk,True,1,'https://fmo.simy.live/ca/crl/root-1.json','','test',now-100,now+10000]
r=sign(dict(sn=1,type='rootCA',issuer=dict(name='Test Root',email='root@example.test'),subject=dict(name='Test Root',publicKey=b64(rpk)),extensions=dict(isCA=True,pathLen=1,crl='https://fmo.simy.live/ca/crl/root-1.json',license='',keyId='test'),iat=now-100,exp=now+10000),rt,rk)
it=['FMO',4,'intermediateCA',2,1,'Test Root',rpk,'Test CA','ca@example.test',ipk,True,0,'test','https://fmo.simy.live/ca/crl/inter-2.json','',100,200,['CN'],now-90,now+9000]
i=sign(dict(sn=2,type='intermediateCA',issuer=dict(sn=1,name='Test Root',publicKey=b64(rpk)),subject=dict(name='Test CA',email='ca@example.test',publicKey=b64(ipk)),extensions=dict(isCA=True,pathLen=0,keyId='test',crl='https://fmo.simy.live/ca/crl/inter-2.json',license='',uidRange=dict(start=100,end=200),issuingCountries=['CN']),iat=now-90,exp=now+9000),it,rk)
ut=['FMO',4,'userCert',2,'BG0TEST',123,upk,now-80,now+8000]
u=sign(dict(type='userCert',issuerSn=2,subject=dict(callsign='BG0TEST',uid=123,publicKey=b64(upk)),iat=now-80,exp=now+8000),ut,ik)
# Independently verify the public trust anchor extracted from the user's firmware.
actual=json.loads((root/'components/passport_fmo/src/passport_root.json').read_text());a=actual;ext=a['extensions'];subject=a['subject'];issuer=a['issuer']
actual_tbs=['FMO',4,'rootCA',a['sn'],issuer['name'],issuer['email'],subject['name'],un64(subject['publicKey']),ext['isCA'],ext['pathLen'],ext['crl'],ext['license'],ext['keyId'],a['iat'],a['exp']]
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
Ed25519PublicKey.from_public_bytes(un64(subject['publicKey'])).verify(un64(a['signature']),cb(actual_tbs))
source=r'''
#include "fmo_crypto.h"
#include "fmo_revocation.h"
#include "fmo_crl_store.h"
#include "fmo_wire.h"
#include "fmo_mqtt.h"
#include "fmo_relay_list.h"
#include "fmo_book.h"
#include "fmo_favorites.h"
#include "fmo_stamp.h"
#include "fmo_navigation.h"
#include "fmo_host_bridge.h"
#include "fmo_peers.h"
#include "fmo_announcements.h"
#include "fmo_announcement_pages.h"
#include "fmo_aprs.h"
#include "fmo_beep.h"
#include <sodium.h>
#include <cassert>
#include <cstring>
#include <fstream>
#include <iterator>
#include <random>
#include <thread>
#include <map>
#include <ctime>
#include <cstdlib>
#include <cstddef>
using namespace fmo;
std::string read(const char *path){std::ifstream f(path,std::ios::binary);return {std::istreambuf_iterator<char>(f),{}};}
int main(int argc,char **argv){
 assert(argc==7&&sodium_init()>=0);auto root=read(argv[1]),bundle=read(argv[2]),seed=read(argv[3]);
 uint8_t pk[32],sk[64];assert(seed.size()==32);assert(!crypto_sign_seed_keypair(pk,sk,reinterpret_cast<const uint8_t *>(seed.data())));
 Credential c;std::string error;
 assert(verify_bundle(reinterpret_cast<const uint8_t *>(bundle.data()),bundle.size(),root.c_str(),pk,1800000000,&c,&error));
 assert(c.uid==123&&!strcmp(c.callsign,"BG0TEST")&&c.expires==1800008000);
 // Track cJSON's live allocation bytes independently of the CBOR buffer.
 // Large signed lists must not allocate one JSON node tree per entry.
 static size_t json_live=0,json_peak=0;
 struct alignas(std::max_align_t) JsonAllocation {size_t size;};
 cJSON_Hooks json_hooks{
  +[](size_t n)->void*{auto *block=static_cast<JsonAllocation *>(std::malloc(sizeof(JsonAllocation)+n));if(!block)return nullptr;block->size=n;json_live+=n;json_peak=std::max(json_peak,json_live);return block+1;},
  +[](void *p){if(!p)return;auto *block=static_cast<JsonAllocation *>(p)-1;assert(json_live>=block->size);json_live-=block->size;std::free(block);}
 };
 cJSON_InitHooks(&json_hooks);
 CrlStatus crl_status;
 for(const char *name:{"revoked","clean","other-key","other-uid","future"}){
  auto raw_crl=read((std::string(argv[2])+".crl."+name).c_str());
  assert(verify_user_crl(reinterpret_cast<const uint8_t *>(raw_crl.data()),raw_crl.size(),c,root.c_str(),1800000000,12,&crl_status));
  assert(crl_status.number==12&&crl_status.next_update==1800001000&&crl_status.revoked==!std::strcmp(name,"revoked"));
 }
 for(const char *name:{"tampered","wrong-signer","wrong-issuer","expired","future-issued","duplicate","unsorted","too-many","bad-type","bad-algorithm","bad-number","bad-fingerprint","nul-key"}){
  auto raw_crl=read((std::string(argv[2])+".crl."+name).c_str());crl_status={99,99,true,99,99};
  assert(!verify_user_crl(reinterpret_cast<const uint8_t *>(raw_crl.data()),raw_crl.size(),c,root.c_str(),1800000000,12,&crl_status));
  assert(!crl_status.number&&!crl_status.next_update&&!crl_status.revoked&&!crl_status.this_update&&!crl_status.revoked_at);
 }
 auto good_crl=read((std::string(argv[2])+".crl.revoked").c_str());
 assert(!verify_user_crl(reinterpret_cast<const uint8_t *>(good_crl.data()),good_crl.size(),c,root.c_str(),1800000000,13,&crl_status));
 assert(!verify_user_crl(reinterpret_cast<const uint8_t *>(good_crl.data()),good_crl.size(),c,root.c_str(),1800001000,12,&crl_status));
 auto forged_metadata=c;forged_metadata.uid=999;memset(forged_metadata.fingerprint,0,32);
 assert(verify_user_crl(reinterpret_cast<const uint8_t *>(good_crl.data()),good_crl.size(),forged_metadata,root.c_str(),1800000000,12,&crl_status)&&crl_status.revoked);
 auto wrong_chain=c;wrong_chain.intermediate_json="{}";
 assert(!verify_user_crl(reinterpret_cast<const uint8_t *>(good_crl.data()),good_crl.size(),wrong_chain,root.c_str(),1800000000,12,&crl_status));
 assert(!verify_user_crl(nullptr,0,c,root.c_str(),1800000000,0,&crl_status));
 std::string huge_crl(32769,' ');assert(!verify_user_crl(reinterpret_cast<const uint8_t *>(huge_crl.data()),huge_crl.size(),c,root.c_str(),1800000000,0,&crl_status));
 puts("FMO Intermediate CRL: independent signed vectors, exact UID/fingerprint, effective time, tampering/issuer/order/bounds and rollback PASS");
 for(const char *name:{"revoked","clean","other-cert","other-sn","future"}){
  auto bytes=read((std::string(argv[2])+".root-crl."+name).c_str());
  assert(verify_root_crl(reinterpret_cast<const uint8_t *>(bytes.data()),bytes.size(),c,root.c_str(),1800000000,5,&crl_status));
  assert(crl_status.number==5&&crl_status.next_update==1800001000&&crl_status.revoked==!std::strcmp(name,"revoked"));
  assert(!verify_user_crl(reinterpret_cast<const uint8_t *>(bytes.data()),bytes.size(),c,root.c_str(),1800000000,0,&crl_status));
 }
 for(const char *name:{"tampered","wrong-signer","wrong-issuer","expired","future-issued","duplicate","unsorted","too-many","bad-type","bad-algorithm"}){
  auto bytes=read((std::string(argv[2])+".root-crl."+name).c_str());crl_status={99,99,true,99,99};
  assert(!verify_root_crl(reinterpret_cast<const uint8_t *>(bytes.data()),bytes.size(),c,root.c_str(),1800000000,5,&crl_status));
  assert(!crl_status.number&&!crl_status.next_update&&!crl_status.revoked&&!crl_status.this_update&&!crl_status.revoked_at);
 }
 auto root_crl_bytes=read((std::string(argv[2])+".root-crl.revoked").c_str());
 assert(!verify_root_crl(reinterpret_cast<const uint8_t *>(root_crl_bytes.data()),root_crl_bytes.size(),c,root.c_str(),1800000000,6,&crl_status));
 assert(!verify_root_crl(reinterpret_cast<const uint8_t *>(good_crl.data()),good_crl.size(),c,root.c_str(),1800000000,0,&crl_status));
 assert(verify_root_crl(reinterpret_cast<const uint8_t *>(root_crl_bytes.data()),root_crl_bytes.size(),forged_metadata,root.c_str(),1800000000,5,&crl_status)&&crl_status.revoked);
 assert(!verify_root_crl(reinterpret_cast<const uint8_t *>(root_crl_bytes.data()),root_crl_bytes.size(),wrong_chain,root.c_str(),1800000000,5,&crl_status));
 puts("FMO Root CRL: independent intermediate TBS hash, root-only signature, serial+fingerprint matching, domain separation, bounds and rollback PASS");
 size_t reference_json_peak=0;
 for(const char *name:{"clean","large165","large256"}){
  auto bytes=read((std::string(argv[2])+".crl."+name).c_str());assert(json_live==0);json_peak=0;
  assert(verify_user_crl(reinterpret_cast<const uint8_t *>(bytes.data()),bytes.size(),c,root.c_str(),1800000000,12,&crl_status));
  assert(json_live==0&&crl_status.revoked==bool(std::strcmp(name,"clean")));
  if(!reference_json_peak)reference_json_peak=json_peak;
  else assert(json_peak<=reference_json_peak+1024);
 }
 assert(!verify_user_crl(reinterpret_cast<const uint8_t *>(good_crl.data()),good_crl.size()-1,c,root.c_str(),1800000000,0,&crl_status));
 auto trailing_crl=good_crl+"{}";assert(!verify_user_crl(reinterpret_cast<const uint8_t *>(trailing_crl.data()),trailing_crl.size(),c,root.c_str(),1800000000,0,&crl_status));
 for(auto bad_crl:{std::string("{}"),std::string("{\"entries\":[],\"entries\":[]}"),std::string("{\"entries\":[{\"uid\":1,\"uid\":2}]}"),std::string("{\"entries\":[[[[]]]]}"),std::string("{\"type\":\"intermediateCRL\",}")})
  assert(!verify_user_crl(reinterpret_cast<const uint8_t *>(bad_crl.data()),bad_crl.size(),c,root.c_str(),1800000000,0,&crl_status));
 assert(json_live==0);cJSON_InitHooks(nullptr);
 std::printf("FMO CRL bounded cursor: signed 165/256 entries, JSON peak independent of entry count (%zu bytes baseline), no JSON leaks, trailing/duplicate/nested/empty rejection PASS\n",reference_json_peak);
 {
  for(bool root_tier:{false,true}){
   const auto bytes=read((std::string(argv[2])+(root_tier?".root-crl.revoked":".crl.revoked")).c_str());
   std::vector<uint8_t> proof;CrlStatus original,restored;
   const bool accepted=root_tier?verify_root_crl(reinterpret_cast<const uint8_t *>(bytes.data()),bytes.size(),c,root.c_str(),1800000000,0,&original,&proof):verify_user_crl(reinterpret_cast<const uint8_t *>(bytes.data()),bytes.size(),c,root.c_str(),1800000000,0,&original,&proof);
   assert(accepted&&proof.size()<300&&verify_crl_proof(proof.data(),proof.size(),root_tier,c,root.c_str(),1800000000,original.number,&restored));
   assert(restored.revoked&&restored.number==original.number&&restored.this_update==original.this_update&&restored.next_update==original.next_update&&restored.revoked_at==original.revoked_at);
   for(size_t at=0;at<proof.size();++at){auto bad=proof;bad[at]^=1;restored={99,99,true,99,99};assert(!verify_crl_proof(bad.data(),bad.size(),root_tier,c,root.c_str(),1800000000,0,&restored)&&!restored.number&&!restored.revoked&&!restored.revoked_at);}
   for(size_t length=0;length<proof.size();++length)assert(!verify_crl_proof(proof.data(),length,root_tier,c,root.c_str(),1800000000,0,&restored));
   assert(!verify_crl_proof(proof.data(),proof.size(),!root_tier,c,root.c_str(),1800000000,0,&restored));
   assert(!verify_crl_proof(proof.data(),proof.size(),root_tier,c,root.c_str(),1800000000,original.number+1,&restored));
   assert(!verify_crl_proof(proof.data(),proof.size(),root_tier,c,root.c_str(),1800001001,0,&restored));
   assert(verify_crl_proof(proof.data(),proof.size(),root_tier,c,root.c_str(),1800001001,0,&restored,true)&&restored.revoked&&restored.next_update<1800001001);
   proof.push_back(0);assert(!verify_crl_proof(proof.data(),proof.size(),root_tier,c,root.c_str(),1800000000,0,&restored));
   const char *empty="{}";assert(!(root_tier?verify_root_crl(reinterpret_cast<const uint8_t *>(empty),2,c,root.c_str(),1800000000,0,&restored,&proof):verify_user_crl(reinterpret_cast<const uint8_t *>(empty),2,c,root.c_str(),1800000000,0,&restored,&proof))&&proof.empty());
  }
  for(const char *name:{"large165","large256"}){
   const auto bytes=read((std::string(argv[2])+".crl."+name).c_str());std::vector<uint8_t> proof;CrlStatus result;
   assert(verify_user_crl(reinterpret_cast<const uint8_t *>(bytes.data()),bytes.size(),c,root.c_str(),1800000000,0,&result,&proof));
   assert(proof.size()<=12940&&verify_crl_proof(proof.data(),proof.size(),false,c,root.c_str(),1800000000,12,&result)&&result.revoked);
   std::ofstream output(std::string(argv[2])+".proof."+name,std::ios::binary);output.write(reinterpret_cast<const char *>(proof.data()),proof.size());
   std::printf("FMO compact signed %s: JSON %zu -> proof %zu bytes\n",name,bytes.size(),proof.size());
  }
  for(const char *name:{"noncanonical","wrong-domain","unsorted","duplicate","trailing","overflow","too-many"}){
   const auto bytes=read((std::string(argv[2])+".proof.bad."+name).c_str());CrlStatus result;
   assert(!verify_crl_proof(reinterpret_cast<const uint8_t *>(bytes.data()),bytes.size(),false,c,root.c_str(),1800000000,0,&result));
  }
  puts("FMO compact CRL proof: independent signatures, complete signed payload, every-byte tamper/truncation, tier/rollback/expiry and signed malformed CBOR rejection PASS");
  const auto hashes=read((std::string(argv[2])+".hashes").c_str());assert(hashes.size()==64);
  assert(!memcmp(hashes.data(),c.root_fingerprint,32)&&!memcmp(hashes.data()+32,c.intermediate_fingerprint,32));
  static_assert(sizeof(RevocationTracker)<=256);RevocationTracker tracker;tracker.bind(c);
  assert(tracker.state(c,1800000000)==RevocationState::Unknown);
  auto user_bytes=read((std::string(argv[2])+".crl.clean").c_str());CrlStatus user_clear,root_clear;
  assert(verify_user_crl(reinterpret_cast<const uint8_t *>(user_bytes.data()),user_bytes.size(),c,root.c_str(),1800000000,0,&user_clear));
  auto root_bytes=read((std::string(argv[2])+".root-crl.clean").c_str());
  assert(verify_root_crl(reinterpret_cast<const uint8_t *>(root_bytes.data()),root_bytes.size(),c,root.c_str(),1800000000,0,&root_clear));
  assert(tracker.accept(CrlLevel::User,c,user_clear,1800000000)&&tracker.state(c,1800000000)==RevocationState::Unknown);
  assert(tracker.accept(CrlLevel::Root,c,root_clear,1800000000)&&tracker.state(c,1800000000)==RevocationState::Current);
  assert(tracker.state(c,1799999980)==RevocationState::Unknown);
  assert(tracker.state(c,1800001000)==RevocationState::Unknown&&tracker.minimum_number(CrlLevel::User)==12);
  auto older=user_clear;older.number=11;older.this_update=1800001000;older.next_update=1800002000;
  assert(!tracker.accept(CrlLevel::User,c,older,1800001000));
  auto contradictory=user_clear;contradictory.revoked=true;contradictory.revoked_at=1799999999;
  assert(!tracker.accept(CrlLevel::User,c,contradictory,1800000000));
  auto future=user_clear;future.number=13;future.revoked_at=1800000005;
  assert(tracker.accept(CrlLevel::User,c,future,1800000000)&&tracker.state(c,1800000000)==RevocationState::Current);
  assert(tracker.state(c,1800000005)==RevocationState::Revoked&&tracker.state(c,1800001001)==RevocationState::Revoked);
  future.revoked=true;assert(tracker.accept(CrlLevel::User,c,future,1800000005));
  auto cleared=user_clear;cleared.number=14;cleared.this_update=1800001001;cleared.next_update=1800002000;
  assert(tracker.accept(CrlLevel::User,c,cleared,1800001001)&&tracker.state(c,1800001001)==RevocationState::Unknown);
  auto fresh_root=root_clear;fresh_root.number=6;fresh_root.this_update=1800001001;fresh_root.next_update=1800002000;
  assert(tracker.accept(CrlLevel::Root,c,fresh_root,1800001001)&&tracker.state(c,1800001001)==RevocationState::Current);
  fresh_root.number=15;fresh_root.revoked=true;fresh_root.revoked_at=1800001001;
  assert(tracker.accept(CrlLevel::Root,c,fresh_root,1800001001)&&tracker.state(c,1800001001)==RevocationState::Revoked);
  RevocationTracker clock_back;clock_back.bind(c);
  assert(clock_back.accept(CrlLevel::Root,c,root_clear,1800000000));
  auto already_effective=user_clear;already_effective.number=13;already_effective.revoked=true;already_effective.revoked_at=1800000005;
  assert(clock_back.accept(CrlLevel::User,c,already_effective,1800000010));
  assert(clock_back.state(c,1800000004)==RevocationState::Current&&clock_back.state(c,1800000005)==RevocationState::Revoked);
  auto renewed=c;renewed.fingerprint[0]^=1;assert(tracker.state(renewed,1800001001)==RevocationState::Unknown);
  tracker.bind(renewed);assert(tracker.minimum_number(CrlLevel::User)==14&&tracker.minimum_number(CrlLevel::Root)==15&&tracker.state(renewed,1800001001)==RevocationState::Revoked);
  renewed.intermediate_fingerprint[0]^=1;tracker.bind(renewed);
  assert(tracker.minimum_number(CrlLevel::Root)==15&&tracker.minimum_number(CrlLevel::User)==0&&tracker.state(renewed,1800001001)==RevocationState::Unknown);
  assert(!tracker.accept(CrlLevel::Root,renewed,fresh_root,1800002000));
  renewed.root_fingerprint[0]^=1;tracker.bind(renewed);
  assert(!tracker.minimum_number(CrlLevel::Root)&&!tracker.minimum_number(CrlLevel::User));
  assert(tracker.state(c,1800001001)==RevocationState::Unknown);
  puts("FMO volatile CRL state: canonical root/intermediate binding, two-level freshness, rollback floors, future effective time, stale revocation and renewal isolation PASS");
 }
 {
  httpd_req_t request;crl_test_root=root;crl_root_bytes="{}";crl_user_bytes=read((std::string(argv[2])+".crl.clean").c_str());
  assert(refresh_crls(&request)==-1&&download_calls==0); // no identity
  fmo::http_identity_ready=true;fmo::http_identity=c;crl_wifi=false;
  assert(refresh_crls(&request)==-1&&download_calls==0);crl_wifi=true;
  mock_clock_error="clock unavailable";assert(refresh_crls(&request)==-1&&download_calls==0);mock_clock_error=nullptr;
  http_mono=100000000;assert(refresh_crls(&request)==0&&download_calls==2);
  auto *result=cJSON_Parse(http_reply.c_str());assert(!strcmp(cJSON_GetObjectItem(result,"state")->valuestring,"unknown")&&!cJSON_IsTrue(cJSON_GetObjectItem(cJSON_GetObjectItem(result,"root"),"updated"))&&cJSON_IsTrue(cJSON_GetObjectItem(cJSON_GetObjectItem(result,"user"),"updated")));cJSON_Delete(result);
  http_mono+=15000000;crl_root_bytes=read((std::string(argv[2])+".root-crl.clean").c_str());assert(refresh_crls(&request)==0&&download_calls==4);
  result=cJSON_Parse(http_reply.c_str());assert(!strcmp(cJSON_GetObjectItem(result,"state")->valuestring,"current"));assert(cJSON_IsTrue(cJSON_GetObjectItem(result,"enforced")));cJSON_Delete(result);
  http_mono+=15000000;crl_root_bytes="{}";crl_user_bytes="{}";assert(refresh_crls(&request)==0&&download_calls==6);
  result=cJSON_Parse(http_reply.c_str());assert(!strcmp(cJSON_GetObjectItem(result,"state")->valuestring,"current")&&!cJSON_IsTrue(cJSON_GetObjectItem(cJSON_GetObjectItem(result,"user"),"updated")));cJSON_Delete(result);
  assert(refresh_crls(&request)==-1&&download_calls==6); // cooldown, no network
  http_mono+=15000000;crl_user_bytes=read((std::string(argv[2])+".crl.revoked13").c_str());assert(refresh_crls(&request)==0&&download_calls==8);
  result=cJSON_Parse(http_reply.c_str());assert(!strcmp(cJSON_GetObjectItem(result,"state")->valuestring,"revoked"));cJSON_Delete(result);
  http_mono+=15000000;crl_user_bytes=read((std::string(argv[2])+".crl.clean").c_str());assert(refresh_crls(&request)==0&&download_calls==10);
  result=cJSON_Parse(http_reply.c_str());assert(!strcmp(cJSON_GetObjectItem(result,"state")->valuestring,"revoked"));cJSON_Delete(result);
  http_mono+=15000000;mock_crl_free=90000;assert(refresh_crls(&request)==-1&&download_calls==10);mock_crl_free=200000;
  assert(provider_crl_url("https://fmo.simy.live/ca/crl/inter-2.json"));
  for(auto *url:{"http://fmo.simy.live/ca/crl/x","https://other.test/ca/crl/x","https://fmo.simy.live/ca/crl/x?key=secret","https://fmo.simy.live/ca/crl/x#fragment","https://fmo.simy.live/ca/crl/../apply.json","https://fmo.simy.live/ca/crl/%2e%2e/apply.json","https://fmo.simy.live/ca/crl/sub/file.json"})assert(!provider_crl_url(url));
  http_mono+=15000000;crl_root_bytes=read((std::string(argv[2])+".root-crl.clean").c_str());crl_user_bytes=read((std::string(argv[2])+".crl.cleared14").c_str());fmo::fail_cache_save=true;
  assert(refresh_crls(&request)==0);result=cJSON_Parse(http_reply.c_str());assert(!strcmp(cJSON_GetObjectItem(result,"state")->valuestring,"current")&&cJSON_IsFalse(cJSON_GetObjectItem(cJSON_GetObjectItem(result,"user"),"saved")));cJSON_Delete(result);fmo::fail_cache_save=false;
  http_mono+=15000000;crl_user_bytes=read((std::string(argv[2])+".crl.revoked15").c_str());assert(refresh_crls(&request)==0);
  result=cJSON_Parse(http_reply.c_str());assert(!strcmp(cJSON_GetObjectItem(result,"state")->valuestring,"revoked")&&cJSON_IsTrue(cJSON_GetObjectItem(cJSON_GetObjectItem(result,"user"),"saved"))&&!strcmp(cJSON_GetObjectItem(result,"persistence")->valuestring,"signed_banks"));cJSON_Delete(result);
  CrlStatus verified_revoked;auto revoked_bytes=read((std::string(argv[2])+".crl.revoked15").c_str());
  assert(verify_user_crl(reinterpret_cast<const uint8_t *>(revoked_bytes.data()),revoked_bytes.size(),c,root.c_str(),1800000000,15,&verified_revoked));
  auto reader=[&](){for(unsigned i=0;i<1000;++i){assert(revocation_state(c,1800000000)==RevocationState::Revoked);assert(revocation_minimum(CrlLevel::User,c)==15);}};
  std::thread reader1(reader),reader2(reader);
  for(unsigned i=0;i<1000;++i)assert(revocation_accept(CrlLevel::User,c,verified_revoked,1800000000));
  reader1.join();reader2.join();
  fmo::http_identity_ready=false;http_mono=0;
  puts("FMO manual CRL HTTP: actual handler + real crypto, independent partial failure, verified cache preservation, revoked/rollback, preconditions/cooldown/memory and provider URL restriction PASS");
 }
 boot_root=root;
 auto previous=c.user_json;uint8_t wrong[32]{};
 assert(!verify_bundle(reinterpret_cast<const uint8_t *>(bundle.data()),bundle.size(),root.c_str(),wrong,1800000000,&c,&error)&&c.user_json==previous);
 for(uint32_t now:{0u,1799999800u,1800010000u})assert(!verify_bundle(reinterpret_cast<const uint8_t *>(bundle.data()),bundle.size(),root.c_str(),pk,now,&c,&error));
 auto changed=bundle;auto pos=changed.find("BG0TEST");assert(pos!=std::string::npos);changed[pos]='A';
 assert(!verify_bundle(reinterpret_cast<const uint8_t *>(changed.data()),changed.size(),root.c_str(),pk,1800000000,&c,&error));
 auto duplicate=bundle+bundle;assert(!verify_bundle(reinterpret_cast<const uint8_t *>(duplicate.data()),duplicate.size(),root.c_str(),pk,1800000000,&c,&error));
 Relay relay{};strcpy(relay.host,"relay.example.test");strcpy(relay.callsign,"BG0SRV");relay.uid=456;relay.port=1883;memset(relay.fingerprint,7,32);
 std::string password;assert(auth_password(c,sk,relay,1800000000,&password));std::ofstream(argv[4])<<password;
 assert(!auth_password(c,sk,relay,c.expires,&password));
 BroadcastConfig bc;std::string frame,login,login_call;
 assert(!broadcast_frame(c,sk,bc,BroadcastKind::CQ,456,1800000000,&frame));
 assert(aprs_login(c.callsign,bc,&login,&login_call)&&login.find(" pass -1 ")!=std::string::npos);
 bc.enabled=true;bc.ssid=1;strcpy(bc.grid,"PM06eb");strcpy(bc.frequency,"438.5");bc.antenna_height=15;strcpy(bc.antenna,"J");
 assert(aprs_login(c.callsign,bc,&login,&login_call)&&login_call=="BG0TEST-1"&&login.find(" pass 4258 ")!=std::string::npos);
 assert(aprs_login_verified("# logresp BG0TEST-1 verified, server TEST",login_call.c_str()));
 assert(!aprs_login_verified("# logresp BG0TEST-1 unverified, server TEST",login_call.c_str()));
 assert(!aprs_login_verified("# logresp OTHER verified, server TEST",login_call.c_str()));
 char lat[9],lon[10];assert(grid_position("PM06eb",lat,lon)&&!strcmp(lat,"3603.75N")&&!strcmp(lon,"12022.50E"));
 assert(grid_position("AA00",lat,lon)&&!strcmp(lat,"8930.00S")&&!strcmp(lon,"17900.00W"));
 assert(grid_position("RR99xx99",lat,lon)&&!strcmp(lat,"8959.88N")&&!strcmp(lon,"17959.75E"));
 assert(!grid_position("SS00",lat,lon)&&!grid_position("PM06e",lat,lon));
 assert(broadcast_frame(c,sk,bc,BroadcastKind::CQ,456,1800000000,&frame)&&frame.size()<=512&&frame.substr(frame.size()-2)=="\r\n");std::ofstream(std::string(argv[4])+".cq",std::ios::binary)<<frame;
 assert(broadcast_frame(c,sk,bc,BroadcastKind::Beacon,456,1800000000,&frame));std::ofstream(std::string(argv[4])+".beacon",std::ios::binary)<<frame;
 bc.legacy_beacon=true;assert(broadcast_frame(c,sk,bc,BroadcastKind::Beacon,456,1800000000,&frame)&&frame.find(">APPASP,TCPIP*:=3603.75NF12022.50EiPAT-1,ST:ONLINE,VER:PassportOS,FREQ:438.5000")!=std::string::npos&&frame.find("CERT:")==std::string::npos);
 bc.legacy_beacon=false;auto saved_bc=bc;bc.enabled=false;assert(!broadcast_frame(c,sk,bc,BroadcastKind::CQ,456,1800000000,&frame)&&frame.empty());bc=saved_bc;
 assert(!broadcast_frame(c,sk,bc,BroadcastKind::CQ,0,1800000000,&frame));assert(!broadcast_frame(c,sk,bc,BroadcastKind::CQ,456,c.expires,&frame));
 auto wrong_identity=c;wrong_identity.fingerprint[0]^=1;assert(!broadcast_frame(wrong_identity,sk,bc,BroadcastKind::CQ,456,1800000000,&frame));
 uint8_t wrong_secret[64]{};assert(!broadcast_frame(c,wrong_secret,bc,BroadcastKind::CQ,456,1800000000,&frame));
 bc.frequency[0]=0;assert(!broadcast_frame(c,sk,bc,BroadcastKind::Beacon,456,1800000000,&frame));bc=saved_bc;
 strcpy(bc.rig,"bad,field");assert(!broadcast_config_valid(bc));bc=saved_bc;
 strcpy(bc.frequency,"nan");assert(!broadcast_config_valid(bc));bc=saved_bc;
 memset(bc.rig,'W',24);bc.rig[24]=0;memset(bc.antenna,'A',24);bc.antenna[24]=0;assert(broadcast_frame(c,sk,bc,BroadcastKind::Beacon,456,1800000000,&frame)&&frame.size()<=512);
 bc=saved_bc;BroadcastGate gate{true,true,true,true,true,true,true,70000000,0,0};
 assert(!broadcast_block_reason(bc,BroadcastKind::CQ,gate));gate.identity_ready=false;assert(broadcast_block_reason(bc,BroadcastKind::CQ,gate));gate.identity_ready=true;
 gate.aprs_verified=false;assert(broadcast_block_reason(bc,BroadcastKind::CQ,gate));gate.aprs_verified=true;
 gate.relay_connected=false;assert(broadcast_block_reason(bc,BroadcastKind::CQ,gate)&&!broadcast_block_reason(bc,BroadcastKind::Beacon,gate));gate.relay_connected=true;
 gate.last_sent_us=gate.now_us-1;assert(broadcast_block_reason(bc,BroadcastKind::CQ,gate));gate.last_sent_us=0;
 gate.last_rx_us=gate.now_us-1000000;assert(broadcast_block_reason(bc,BroadcastKind::CQ,gate));gate.last_rx_us=0;
 bc.enabled=false;assert(broadcast_block_reason(bc,BroadcastKind::CQ,gate));bc=saved_bc;
 send_plan={2,-2,3};send_at=0;written.clear();assert(socket_write(1,"abcdef",6)&&written=="abcdef"&&send_waits==1);
 send_plan={2,-4};send_at=0;written.clear();assert(!socket_write(1,"abcdef",6)&&written=="ab");
 send_plan={-2,-2,-2,-2,-2,-2};send_at=0;send_waits=0;written.clear();assert(!socket_write(1,"abcdef",6)&&written.empty()&&send_waits==5);
 stop_requested=true;assert(!socket_write(1,"abcdef",6));stop_requested=false;
 char receive_data[4]{};recv_plan={-3,-2,3,0,-4};recv_at=0;
 assert(socket_read(1,receive_data,sizeof(receive_data))==-2&&recv_at==1);
 assert(socket_read(1,receive_data,sizeof(receive_data))==-2&&recv_at==2);
 assert(socket_read(1,receive_data,sizeof(receive_data))==3&&!std::strcmp(receive_data,"abc"));
 assert(socket_read(1,receive_data,sizeof(receive_data))==0);
 assert(socket_read(1,receive_data,sizeof(receive_data))==-1&&recv_at==5);
 assert(route_priority_preempts(999,20,1000,10));assert(route_priority_preempts(0,20,2000,10));
 assert(!route_priority_preempts(0,20,2001,10));assert(route_priority_preempts(1000,9,1000,10));
 assert(!route_priority_preempts(1000,11,1000,10));assert(!route_priority_preempts(1001,1,1000,10));
 assert(route_priority_preempts(0xfffffff0u,20,0x10,10));
 assert(crc32(reinterpret_cast<const uint8_t *>("123456789"),9)==0xcbf43926u);
 uint8_t voice[]={0x4b,0x10,0x01},buffer[1400];Packet packet{};packet.vendor=0x1001;packet.uid=123;strcpy(packet.callsign,"BG0TEST");packet.stream_begin=123400;packet.timestamp=123440;packet.server_uid=456;packet.count=1;packet.frames[0]={1,voice,sizeof(voice),1};
 size_t n=write_packet(buffer,sizeof(buffer),packet);assert(n==83);auto golden=read(argv[5]);assert(golden.size()==n&&!memcmp(buffer,golden.data(),n));
 Packet parsed{};assert(parse_packet(buffer,n,&parsed)&&parsed.uid==123&&parsed.frames[0].size==3&&parsed.frames[0].data==buffer+80);
 // RX compatibility: cross-relay/zero server_uid, 0-based frame index, lowercase/padded/dirty-tail callsign, shorter RADPCM.
 {
  uint8_t compat[1400];memcpy(compat,buffer,n);
  // Zero server_uid and dirty bytes after NUL in callsign, plus lowercase and trailing space.
  memset(compat+41,0,4);
  memcpy(compat+10,"bg0ab \0XYZ99",12);
  // 0-based frame index (recompute CRC32 over frame region).
  compat[64]=0;compat[65]=0;
  const uint32_t crc=crc32(compat+64,n-64);
  compat[36]=crc&0xff;compat[37]=(crc>>8)&0xff;compat[38]=(crc>>16)&0xff;compat[39]=(crc>>24)&0xff;
  Packet cp{};assert(parse_packet(compat,n,&cp)&&cp.server_uid==0&&!strcmp(cp.callsign,"BG0AB")&&cp.frames[0].index==0);
 }
 assert(!write_packet(buffer,n-1,packet));
 for(size_t len=0;len<n;++len)assert(!parse_packet(buffer,len,&parsed)&&parsed.count==0);
 for(size_t at:{0u,30u,34u,36u,70u,75u,80u}){buffer[at]^=1;assert(!parse_packet(buffer,n,&parsed)&&parsed.count==0);buffer[at]^=1;}
 std::mt19937 rng(7);for(int k=0;k<10000;++k){size_t size=rng()%sizeof(buffer);for(size_t j=0;j<size;++j)buffer[j]=rng();if(!parse_packet(buffer,size,&parsed))assert(parsed.count==0);}
 RelayList catalog;assert(!fmo::load_relay_cache(&catalog,1800000000));
 assert(catalog.add(relay,1800000600,1800000000));assert(!catalog.add(relay,1800000600,1800000000));
 assert(!catalog.add(relay,1800000000,1800000000));
 auto updated=relay;strcpy(updated.name,"Updated");assert(!catalog.add(updated,1800000500,1800000000));
 assert(catalog.add(updated,1800000700,1800000000)&&catalog.count==1&&!strcmp(catalog.relays[0].name,"Updated"));
 auto saved_selection=relay;
 assert(catalog.refresh_saved_relay(saved_selection,1800000000)==0&&!strcmp(saved_selection.name,"Updated"));
 saved_selection=relay;saved_selection.fingerprint[0]^=1;
 assert(catalog.refresh_saved_relay(saved_selection,1800000000)<0&&!strcmp(saved_selection.name,relay.name));
 saved_selection=relay;strcpy(saved_selection.callsign,"BG0OTHER");
 assert(catalog.refresh_saved_relay(saved_selection,1800000000)<0);
 saved_selection=relay;
 assert(catalog.refresh_saved_relay(saved_selection,1800000700)<0);
 assert(fmo::save_relay_cache(catalog,1800000000));RelayList restored;assert(fmo::load_relay_cache(&restored,1800000000)&&restored.count==1&&restored.relays[0].uid==relay.uid);
 restored={};assert(fmo::load_relay_cache(&restored,1800000800)&&restored.count==0);
 const auto original_cache=cache_bytes;cache_bytes[0]^=1;assert(!fmo::load_relay_cache(&restored,1800000000));cache_bytes=original_cache;
 cache_fail_open=true;assert(!fmo::load_relay_cache(&restored,1800000000)&&!fmo::save_relay_cache(catalog,1800000000));cache_fail_open=false;
 cache_fail_write=true;assert(!fmo::save_relay_cache(catalog,1800000000));cache_fail_write=false;
 cache_fail_commit=true;assert(!fmo::save_relay_cache(catalog,1800000000));cache_fail_commit=false;
 StationStatus snapshot{5,200,500,1800000700};
 assert(catalog.add(updated,1800000700,1800000000,&snapshot));
 assert(!catalog.add(updated,1800000700,1800000000,&snapshot));
 snapshot.online=6;assert(catalog.add(updated,1800000700,1800000000,&snapshot));
 auto stale_snapshot=snapshot;stale_snapshot.valid_until=1800000600;assert(!catalog.add(updated,1800000600,1800000000,&stale_snapshot)&&catalog.status[0].online==6);
 stale_snapshot.valid_until=1800000800;assert(!catalog.add(updated,1800000700,1800000000,&stale_snapshot));
 assert(fmo::save_relay_cache(catalog,1800000000));restored={};assert(fmo::load_relay_cache(&restored,1800000000)&&restored.status[0].online==6&&restored.status[0].peak==200&&restored.status[0].range_km==500);
 const auto good_stats=cache_stats_bytes;
 assert(relay_http_status(nullptr)==0);{Json j(cJSON_Parse(http_reply.c_str()),cJSON_Delete);const auto *rows=cJSON_GetObjectItemCaseSensitive(j.get(),"servers");assert(cJSON_GetArraySize(rows)==1);const auto *row=cJSON_GetArrayItem(rows,0);assert(cJSON_IsTrue(cJSON_GetObjectItemCaseSensitive(row,"stats_known"))&&cJSON_GetObjectItemCaseSensitive(row,"online")->valueint==6&&cJSON_GetObjectItemCaseSensitive(row,"peak")->valueint==200&&cJSON_GetObjectItemCaseSensitive(row,"range_km")->valueint==500);}

 for(size_t byte=0;byte<good_stats.size();++byte){cache_stats_bytes=good_stats;cache_stats_bytes[byte]^=1;restored={};assert(fmo::load_relay_cache(&restored,1800000000)&&restored.count==1&&!restored.status[0].valid_until);}
 for(size_t size:{1u,427u,429u}){cache_stats_bytes=good_stats;cache_stats_bytes.resize(size);restored={};assert(fmo::load_relay_cache(&restored,1800000000)&&!restored.status[0].valid_until);}
 for(size_t byte:{8u,12u,56u}){cache_stats_bytes=good_stats;cache_stats_bytes[byte]^=1;const auto crc=crc32(cache_stats_bytes.data(),cache_stats_bytes.size()-4);for(unsigned n=0;n<4;++n)cache_stats_bytes[cache_stats_bytes.size()-4+n]=crc>>(8*n);restored={};assert(fmo::load_relay_cache(&restored,1800000000)&&!restored.status[0].valid_until);}
 cache_stats_bytes.clear();restored={};assert(fmo::load_relay_cache(&restored,1800000000)&&restored.count==1&&!restored.status[0].valid_until); // Legacy cache is retained.
 cache_stats_bytes=good_stats;
 cache_stats_bytes[0]^=1;relay_http_status(nullptr);{Json j(cJSON_Parse(http_reply.c_str()),cJSON_Delete);const auto *row=cJSON_GetArrayItem(cJSON_GetObjectItemCaseSensitive(j.get(),"servers"),0);assert(cJSON_IsFalse(cJSON_GetObjectItemCaseSensitive(row,"stats_known"))&&!cJSON_GetObjectItemCaseSensitive(row,"online"));}cache_stats_bytes=good_stats;
 page=fmo::Page::Servers;server_list_view(catalog,1800000000);assert(state_label->text.find("6/200")!=std::string::npos&&state_label->text.find("500km")!=std::string::npos);
 normal_view();show_relay(catalog.relays[0],catalog,1800000000);assert(relay_label->text.find("广播 6/200")!=std::string::npos);
 mqtt_connections.update(12,esp_timer_get_time());connected=true;show_relay(catalog.relays[0],catalog,1800000000);assert(relay_label->text.find("最近节点连接 12")!=std::string::npos);
 mqtt_connections.reset();
 auto other_key=catalog.relays[0];other_key.fingerprint[0]^=1;show_relay(other_key,catalog,1800000000);assert(relay_label->text.find("待更新")!=std::string::npos);
 show_relay(catalog.relays[0],catalog,1800000800);assert(relay_label->text.find("待更新")!=std::string::npos);
 char summary[80];station_summary({0,200,500,1800000700},1800000000,summary,sizeof(summary));assert(std::string(summary).find("0/200")!=std::string::npos);
 station_summary({UINT32_MAX,UINT32_MAX,UINT32_MAX,1800000700},1800000000,summary,sizeof(summary));assert(std::string(summary).find("9999+/9999+")!=std::string::npos);
 for(unsigned uid=1000;uid<1007;++uid){auto extra=relay;extra.uid=uid;assert(catalog.add(extra,1800000600,1800000000));}
 char short_text[44];short_name("甲乙丙丁戊己庚辛壬癸子",short_text);assert(std::string(short_text)=="甲乙丙丁戊己庚辛壬癸...");
 const char truncated_utf8[]={char(0xf0),0};short_name(truncated_utf8,short_text);assert(short_text[0]==char(0xf0)&&short_text[1]==0);
 assert(catalog.count==8);auto extra=relay;extra.uid=2000;assert(!catalog.add(extra,1800000600,1800000000));
 catalog.index=7;catalog.move(1);assert(catalog.index==0);catalog.move(-1);assert(catalog.index==7);catalog.move(19);assert(catalog.index==2);
 page=fmo::Page::Servers;server_list_view(catalog);assert(call_label->hidden&&relay_label->height==96&&state_label->text.find("3/8")!=std::string::npos);
 const auto list_text=relay_label->text;show("收听中","another server","BG0OTHER");assert(relay_label->text==list_text); // incoming voice never erases selection
 connected=true;talk_requested=false;key(BSP_BTN_OK,BTN_EVT_LONG,0);assert(!talk_requested); // browsing never starts PTT
 key(BSP_BTN_OK,BTN_EVT_CLICK,0);assert(switch_requested);switch_requested=false;
 key(BSP_BTN_UP,BTN_EVT_CLICK,0);key(BSP_BTN_DOWN,BTN_EVT_CLICK,0);assert(next_requested==1&&previous_requested==1);
 normal_view();assert(page==fmo::Page::Main&&!call_label->hidden&&relay_label->height==40);show("online","selected host","BG0TEST");assert(relay_label->text=="selected host");
 key(BSP_BTN_OK,BTN_EVT_LONG,0);assert(talk_requested);key(BSP_BTN_OK,BTN_EVT_LONG_UP,0);assert(!talk_requested);
 connected=false;key(BSP_BTN_OK,BTN_EVT_LONG,0);assert(!talk_requested);
 key(BSP_BTN_DOWN,BTN_EVT_LONG,0);assert(navigated==-1&&mock_volume==75);
 RelayList long_hosts;for(unsigned n=1;n<=8;++n){auto host=relay;memset(host.host,'a',127);host.host[127]=0;host.name[0]=0;host.uid=n;assert(long_hosts.add(host,1800000600,1800000000));}
 long_hosts.index=7;page=fmo::Page::Servers;server_list_view(long_hosts);assert(relay_label->text.size()<200&&state_label->text.find("8/8")!=std::string::npos);
 normal_view();
 // Expiry releases full catalog slots without moving a surviving selection.
 RelayList expiry=catalog;expiry.index=0;
 assert(expiry.prune(1800000600)&&expiry.count==1&&expiry.index==0&&expiry.relays[0].uid==relay.uid);
 assert(!expiry.prune(1800000600));
 assert(expiry.add(extra,1800001200,1800000600)&&expiry.count==2);
 expiry.index=1;assert(expiry.prune(1800000700)&&expiry.count==1&&expiry.index==0&&expiry.relays[0].uid==extra.uid);
 page=fmo::Page::Servers;assert(expiry.prune(1800001200)&&expiry.count==0&&expiry.index==0);
 server_list_view(expiry);assert(relay_label->text=="暂无有效服务器"&&state_label->text=="等待新的签名广播");
 for(auto reason:{StationRejection::UnknownIssuer,StationRejection::CertificateInvalid,StationRejection::SignatureInvalid}){
  discovery_rejection=reason;server_list_view(expiry);assert(state_label->text==discovery_rejection_message(reason));
 }
 discovery_rejection=StationRejection::UnknownIssuer;discovery_unknown_issuer=1001;server_list_view(expiry);
 assert(state_label->text.find("1001")!=std::string::npos);
 discovery_unknown_issuer=0;discovery_rejection=StationRejection::NotStation;
 auto manual=relay;manual.uid=3000;assert(expiry.add(manual,0,1800001200));
 assert(!expiry.prune(1800002000)&&expiry.count==1); // Explicit manual relay does not expire as a broadcast.
 RelayList moved;for(unsigned uid=1;uid<=3;++uid){auto r=relay;r.uid=uid;const uint32_t until=uid==1?1800000600:1800001200;StationStatus stats{uid,200,500,until};assert(moved.add(r,until,1800000000,&stats));}
 moved.index=2;assert(moved.prune(1800000600)&&moved.index==1&&moved.relays[moved.index].uid==3);
 assert(moved.relays[2].uid==0&&moved.expires[2]==0);
 assert(moved.status[2].valid_until==0&&moved.status[1].online==3);
 normal_view();
 // Exercise actual key -> worker controls -> rendered page transitions.
 fmo::ContactBook heard;heard.count=2;
 heard.contacts[0]={1,456,1800000000,1800000010,2,100,"BG0OLD"};
 heard.contacts[1]={2,456,1800000005,1800000020,3,200,"BG0NEW"};
 fmo::Navigation nav;next_requested=previous_requested=0;menu_requested=back_requested=switch_requested=false;
 connected=true;talk_requested=true;
 key(BSP_BTN_DOWN,BTN_EVT_CLICK,0);assert(page==fmo::Page::Menu&&!talk_requested);
 key(BSP_BTN_OK,BTN_EVT_LONG,0);assert(!talk_requested); // Guard closes before worker draws the menu.
 assert(process_controls(nav,catalog,&heard,true)==fmo::UiAction::None);
 assert(nav.menu_index==0&&relay_label->text.find("> 选择服务器")!=std::string::npos);
 const auto menu_text=relay_label->text;show("live RX","relay","BG0RX");assert(relay_label->text==menu_text);
 key(BSP_BTN_UP,BTN_EVT_CLICK,0);process_controls(nav,catalog,&heard,true);assert(nav.menu_index==16);
 key(BSP_BTN_DOWN,BTN_EVT_CLICK,0);process_controls(nav,catalog,&heard,true);assert(nav.menu_index==0);
 key(BSP_BTN_DOWN,BTN_EVT_CLICK,0);process_controls(nav,catalog,&heard,true);assert(nav.menu_index==1);
 key(BSP_BTN_OK,BTN_EVT_CLICK,0);process_controls(nav,catalog,&heard,true);
 assert(page==fmo::Page::History&&call_label->text=="BG0NEW"&&!call_label->hidden&&relay_label->height==48);
 assert(relay_label->text.find("初次 ")!=std::string::npos&&state_label->text.find("抄收 3 次")!=std::string::npos);
 assert(relay_label->text.find("2027-01-15 16:00")!=std::string::npos);
 mock_timezone=-5*3600;history_view(&heard,0,true);assert(relay_label->text.find("2027-01-15 03:00")!=std::string::npos);mock_timezone=8*3600;history_view(&heard,0,true);
 const auto history_text=relay_label->text;show("new voice","relay","BG0RX");assert(relay_label->text==history_text);
 key(BSP_BTN_OK,BTN_EVT_LONG,0);assert(!talk_requested);
 key(BSP_BTN_UP,BTN_EVT_CLICK,0);process_controls(nav,catalog,&heard,true);assert(call_label->text=="BG0OLD");
 key(BSP_BTN_DOWN,BTN_EVT_CLICK,0);process_controls(nav,catalog,&heard,true);assert(call_label->text=="BG0NEW");
 history_view(nullptr,0,false);assert(call_label->hidden&&relay_label->text=="抄收册暂不可读");
 fmo::ContactBook empty_book;history_view(&empty_book,0,true);assert(relay_label->text=="暂无抄收记录");
 key(BSP_BTN_OK,BTN_EVT_CLICK,0);process_controls(nav,catalog,&heard,true);assert(page==fmo::Page::Menu&&nav.menu_index==1);
 key(BSP_BTN_DOWN,BTN_EVT_CLICK,0);process_controls(nav,catalog,&heard,true);
 key(BSP_BTN_OK,BTN_EVT_CLICK,0);process_controls(nav,catalog,&heard,true);assert(page==fmo::Page::Volume&&call_label->text=="75%");
 key(BSP_BTN_UP,BTN_EVT_CLICK,0);assert(mock_volume==80&&call_label->text=="80%");
 key(BSP_BTN_DOWN,BTN_EVT_CLICK,0);assert(mock_volume==75);
 volume_save_ok=false;key(BSP_BTN_UP,BTN_EVT_CLICK,0);assert(mock_volume==75&&state_label->text=="保存失败，音量未变");volume_save_ok=true;
 mock_volume=100;const auto saves=mock_volume_saves;key(BSP_BTN_UP,BTN_EVT_CLICK,0);assert(mock_volume==100&&mock_volume_saves==saves);
 mock_volume=0;key(BSP_BTN_DOWN,BTN_EVT_CLICK,0);assert(mock_volume==0&&mock_volume_saves==saves);
 key(BSP_BTN_OK,BTN_EVT_LONG,0);assert(!talk_requested);
 key(BSP_BTN_OK,BTN_EVT_CLICK,0);process_controls(nav,catalog,&heard,true);assert(page==fmo::Page::Menu);
 key(BSP_BTN_DOWN,BTN_EVT_CLICK,0);process_controls(nav,catalog,&heard,true);assert(nav.menu_index==3);
 key(BSP_BTN_OK,BTN_EVT_CLICK,0);auto action=process_controls(nav,catalog,&heard,true);assert(action==fmo::UiAction::PhoneSetup);navigate(action);assert(navigated==APP_ID_WIFI);
 key(BSP_BTN_DOWN,BTN_EVT_LONG,0);process_controls(nav,catalog,&heard,true);assert(page==fmo::Page::Main&&!call_label->hidden);
 key(BSP_BTN_UP,BTN_EVT_LONG,0);assert(mock_volume==5);
 key(BSP_BTN_DOWN,BTN_EVT_LONG,0);assert(mock_volume==0); // Main long Down adjusts volume, never exits.
 catalog.index=0;key(BSP_BTN_UP,BTN_EVT_CLICK,0);assert(page==fmo::Page::Servers);
 key(BSP_BTN_OK,BTN_EVT_LONG,0);assert(!talk_requested);
 process_controls(nav,catalog,&heard,true);assert(catalog.index==1);
 key(BSP_BTN_OK,BTN_EVT_CLICK,0);assert(process_controls(nav,catalog,&heard,true)==fmo::UiAction::Connect);
 RelayList empty_discovery;key(BSP_BTN_OK,BTN_EVT_CLICK,0);
 assert(process_controls(nav,empty_discovery,&heard,true)==fmo::UiAction::Discover&&!talk_requested);
 int discovery_fd=42;int64_t discovery_next=30000000,manual_next=0;
 assert(restart_discovery(discovery_fd,discovery_next,manual_next,0)&&discovery_fd==-1&&mock_fd_closed==42&&discovery_next==0&&manual_next==15000000);
 discovery_fd=43;discovery_next=30000000;
 assert(!restart_discovery(discovery_fd,discovery_next,manual_next,14999999)&&discovery_fd==43&&mock_fd_closed==42&&discovery_next==30000000);
 discovery_retry_view(false,false);assert(state_label->text=="请先完成校时与证书配置");
 discovery_retry_view(false);assert(state_label->text=="请稍后再试，间隔15秒");
 assert(restart_discovery(discovery_fd,discovery_next,manual_next,15000000)&&discovery_fd==-1&&mock_fd_closed==43);
 discovery_retry_view(true);assert(state_label->text=="正在重新连接发现服务");
 normal_view();const auto prior_retry_text=state_label->text;discovery_retry_view(true);assert(state_label->text==prior_retry_text);
 normal_view();key(BSP_BTN_DOWN,BTN_EVT_CLICK,0);process_controls(nav,catalog,&heard,true);
 for(int i=0;i<12;++i)key(BSP_BTN_UP,BTN_EVT_CLICK,0);process_controls(nav,catalog,&heard,true);
 key(BSP_BTN_OK,BTN_EVT_CLICK,0);action=process_controls(nav,catalog,&heard,true);assert(action==fmo::UiAction::Exit);navigate(action);assert(navigated==APP_ID_LAUNCHER);
 normal_view();page=fmo::Page::Menu;nav.menu_index=14;switch_requested=true;assert(process_controls(nav,catalog,&heard,true)==fmo::UiAction::ConnectBuiltin);
 normal_view();page=fmo::Page::Menu;nav.menu_index=15;switch_requested=true;assert(process_controls(nav,catalog,&heard,true)==fmo::UiAction::ToggleSentinel);
 normal_view();page=fmo::Page::Menu;nav.menu_index=16;switch_requested=true;action=process_controls(nav,catalog,&heard,true);assert(action==fmo::UiAction::BackgroundListen);navigated=0;navigate(action);assert(navigated==APP_ID_LAUNCHER);
 // Stamp page (menu item 11): preview built-in + custom stamp and save action.
 normal_view();page=fmo::Page::Menu;nav.menu_index=11;switch_requested=true;
 fmo::StampConfig sc{};std::strcpy(sc.style_id,"G003");sc.custom_present=true;uint8_t custom_px[fmo::kStampPixelBytes]{};custom_px[0]=0xFF;
 assert(process_controls(nav,catalog,&heard,true,nullptr,nullptr,nullptr,false,&sc,custom_px,nullptr,"P-BG0TEST")==fmo::UiAction::None);
 assert(page==fmo::Page::Stamp&&nav.stamp_index==2&&call_label->text=="BG0TEST"&&mock_stamp_shown&&mock_stamp_builtin==2);
 key(BSP_BTN_UP,BTN_EVT_CLICK,0);process_controls(nav,catalog,&heard,true,nullptr,nullptr,nullptr,false,&sc,custom_px,nullptr,"P-BG0TEST");assert(nav.stamp_index==1&&mock_stamp_builtin==1);
 for(int i=0;i<11;++i)key(BSP_BTN_DOWN,BTN_EVT_CLICK,0);
 process_controls(nav,catalog,&heard,true,nullptr,nullptr,nullptr,false,&sc,custom_px,nullptr,"P-BG0TEST");assert(nav.stamp_index==12&&mock_stamp_custom);
 key(BSP_BTN_OK,BTN_EVT_CLICK,0);assert(process_controls(nav,catalog,&heard,true,nullptr,nullptr,nullptr,false,&sc,custom_px,nullptr,"P-BG0TEST")==fmo::UiAction::SaveStamp);
 // P- prefix APRS login, PAT-1 stamp broadcast & parsing, and APPASP station discovery.
 {
  std::string p_login,p_call;fmo::BroadcastConfig pcfg{};pcfg.enabled=true;pcfg.ssid=15;std::strcpy(pcfg.grid,"PM06");std::strcpy(pcfg.frequency,"438.5");pcfg.legacy_beacon=true;
  assert(!std::strcmp(fmo::bare_callsign("P-BG0TST"),"BG0TST")&&fmo::aprs_login("P-BG0TST",pcfg,&p_login,&p_call)&&p_call=="BG0TST-15");
  pcfg.ssid=1;assert(!std::strcmp(fmo::bare_callsign("P-BG0TEST"),"BG0TEST")&&fmo::aprs_login("P-BG0TEST",pcfg,&p_login,&p_call)&&p_call=="BG0TEST-1");
  std::string st_frame;assert(fmo::broadcast_frame(c,sk,pcfg,fmo::BroadcastKind::Beacon,456,1800000000,&st_frame,"G007")&&st_frame.find("PAT-1,ST:G007,VER:PassportOS")!=std::string::npos);
  char p_c[13]{},p_s[8]{};assert(fmo::parse_pat1_stamp(st_frame.c_str(),st_frame.size()-2,p_c,p_s)&&!std::strcmp(p_c,"BG0TEST")&&!std::strcmp(p_s,"G007"));
 }
 normal_view();
 page=fmo::Page::Menu;nav.menu_index=6;switch_requested=true;assert(process_controls(nav,catalog,&heard,true)==fmo::UiAction::CQ);
 broadcast_view(false,"PM06","APRS登录未通过验证");key(BSP_BTN_OK,BTN_EVT_LONG,0);assert(!talk_requested&&page==fmo::Page::Broadcast);
 const auto broadcast_text=state_label->text;show("incoming");assert(state_label->text==broadcast_text);
 key(BSP_BTN_OK,BTN_EVT_CLICK,0);process_controls(nav,catalog,&heard,true);assert(page==fmo::Page::Menu);
 nav.menu_index=7;switch_requested=true;assert(process_controls(nav,catalog,&heard,true)==fmo::UiAction::Beacon);normal_view();
 const auto notifications=worker_notified;assert(!prepare_stop()&&stop_requested&&!talk_requested&&worker_notified==notifications+1);running=false;assert(prepare_stop());
 auto announcement=read(argv[6]);Relay found{};
 assert(station_announcement(announcement.data(),announcement.size(),c,root.c_str(),1800000000,&found));
 assert(found.uid==150&&!strcmp(found.host,"relay.example.test")&&!strcmp(found.callsign,"BG0SRV")&&found.port==1883);
 auto compact_announcement=announcement;const auto position=compact_announcement.find(":=")+1;
 compact_announcement[position+9]='F';compact_announcement[position+19]='i';compact_announcement.erase(position+20,1);
 uint32_t valid_until=0;StationStatus parsed_status;assert(station_announcement(compact_announcement.data(),compact_announcement.size(),c,root.c_str(),1800000000,&found,&valid_until,&parsed_status));assert(valid_until==1800001200&&parsed_status.valid_until==valid_until&&parsed_status.online==5&&parsed_status.peak==200&&parsed_status.range_km==500);
 StationRejection reject=StationRejection::Malformed;
 assert(station_announcement(compact_announcement.data(),compact_announcement.size(),c,root.c_str(),1800000000,&found,&valid_until,&parsed_status,&reject)&&reject==StationRejection::None);
 for(const char *suffix:{"unknown-issuer","bad-certificate"}){
  auto packet=read((std::string(argv[6])+"."+suffix).c_str());const auto original_relay=found;
  uint32_t issuer_hint=123;
  assert(!station_announcement(packet.data(),packet.size(),c,root.c_str(),1800000000,&found,&valid_until,&parsed_status,&reject,nullptr,&issuer_hint));
  assert(issuer_hint==(!std::strcmp(suffix,"unknown-issuer")?9999u:0u));
  assert(reject==(!std::strcmp(suffix,"unknown-issuer")?StationRejection::UnknownIssuer:StationRejection::CertificateInvalid));
  assert(!valid_until&&!parsed_status.valid_until&&!std::memcmp(&found,&original_relay,sizeof(found)));
 }
 {
  const auto packet=read((std::string(argv[6])+".unknown-issuer").c_str());
  const auto issuer=read((std::string(argv[6])+".extra-issuer").c_str());
  DiscoveryChain chain{root.c_str(),issuer.c_str()};
  Relay cross{};
  assert(station_announcement(packet.data(),packet.size(),c,root.c_str(),1800000000,&cross,nullptr,nullptr,&reject,&chain)&&cross.uid==150);
  const auto peer_packet=read((std::string(argv[6])+".peer.bad.wrong-issuer").c_str());
  const auto joint_packet=read((std::string(argv[6])+".event.cross-issuer.joint").c_str());
  const auto body_packet=read((std::string(argv[6])+".event.cross-issuer.status").c_str());
  PeerEvents cross_peers;Announcements cross_events;Navigation cross_nav;
  assert(!receive_peer(peer_packet.data(),peer_packet.size(),c,root.c_str(),1800000000,&cross_peers,cross_nav));
  assert(receive_peer(peer_packet.data(),peer_packet.size(),c,root.c_str(),1800000000,&cross_peers,cross_nav,nullptr,&chain));
  assert(!receive_announcement(joint_packet.data(),joint_packet.size(),c,root.c_str(),1800000000,&cross_events,cross_nav,&chain));
  assert(receive_announcement(body_packet.data(),body_packet.size(),c,root.c_str(),1800000000,&cross_events,cross_nav,&chain));
  assert(cross_events.count==1&&cross_events.notices[0].body.uid==150);
  chain.root_json="{}";
  assert(!station_announcement(packet.data(),packet.size(),c,root.c_str(),1800000000,&cross,nullptr,nullptr,&reject,&chain)&&reject==StationRejection::CertificateInvalid);
  chain.root_json=root.c_str();chain.intermediate_json=c.intermediate_json.c_str();
  assert(!station_announcement(packet.data(),packet.size(),c,root.c_str(),1800000000,&cross,nullptr,nullptr,&reject,&chain)&&reject==StationRejection::UnknownIssuer);
 }
 for(const char *type:{"CQ","OMCQ","VOCAL","ONLINE"}){
  auto bytes=read((std::string(argv[6])+".peer."+type).c_str());PeerAnnouncement peer{};
  assert(peer_announcement(bytes.data(),bytes.size(),c,root.c_str(),1800000000,&peer));
  assert(peer.uid==150&&peer.server_uid==456&&peer.ssid==15&&peer.window==3000000&&peer.valid_until==1800001200&&!strcmp(peer.callsign,"BG0SRV")&&!strcmp(peer.latitude,"3037.98N")&&!strcmp(peer.longitude,"11932.20E"));
  assert(peer.kind==(!strcmp(type,"CQ")?PeerKind::CQ:!strcmp(type,"OMCQ")?PeerKind::OldFriendCQ:!strcmp(type,"VOCAL")?PeerKind::Vocal:PeerKind::Online));
  auto compact=bytes;compact.erase(compact.find(" FMO-V4"),1);assert(peer_announcement(compact.data(),compact.size(),c,root.c_str(),1800000000,&peer));
  const auto original=peer;auto changed=bytes;changed.replace(changed.find("S456"),4,"S457");assert(!peer_announcement(changed.data(),changed.size(),c,root.c_str(),1800000000,&peer)&&!memcmp(&peer,&original,sizeof(peer)));
  changed=bytes;changed.replace(changed.find("APFMO4"),6,"APFMO4X");assert(!peer_announcement(changed.data(),changed.size(),c,root.c_str(),1800000000,&peer));
  assert(!peer_announcement(bytes.data(),bytes.size(),c,root.c_str(),1800001800,&peer));
  assert(!peer_announcement(bytes.data(),bytes.size(),c,nullptr,1800000000,&peer)&&!peer_announcement(bytes.data(),bytes.size(),c,root.c_str(),1800000000,nullptr));
 }
 for(const char *bad:{"wrong-issuer","bad-ca","noncanonical-cert","nul-cert-name","expired-cert","wrong-domain","bad-position","extra-token","bad-ssid","overflow-server"}){
  auto bytes=read((std::string(argv[6])+".peer.bad."+bad).c_str());PeerAnnouncement peer{};assert(!peer_announcement(bytes.data(),bytes.size(),c,root.c_str(),1800000000,&peer));
 }
 auto peer_cq=read((std::string(argv[6])+".peer.CQ").c_str());PeerAnnouncement parsed_peer{};
 auto shifted=read((std::string(argv[6])+".peer.window-minus").c_str());assert(peer_announcement(shifted.data(),shifted.size(),c,root.c_str(),1800000000,&parsed_peer)&&parsed_peer.window==2999999&&parsed_peer.valid_until==1800000600);
 shifted=read((std::string(argv[6])+".peer.window-plus").c_str());assert(peer_announcement(shifted.data(),shifted.size(),c,root.c_str(),1800000000,&parsed_peer)&&parsed_peer.window==3000001&&parsed_peer.valid_until==1800001800);
 {
  PeerEvents peers;Navigation peer_nav;RelayList no_servers;
  page=Page::Menu;peer_nav.menu_index=8;switch_requested=true;
  next_requested=previous_requested=0;menu_requested=back_requested=false;
  assert(process_controls(peer_nav,no_servers,nullptr,false,&peers)==UiAction::None&&page==Page::Peers&&call_label->hidden);
  assert(relay_label->text=="暂无有效友台广播");
  assert(!receive_peer(peer_cq.data(),peer_cq.size(),c,root.c_str(),1800000000,nullptr,peer_nav));
  assert(receive_peer(peer_cq.data(),peer_cq.size(),c,root.c_str(),1800000000,&peers,peer_nav));
  assert(peers.count==1&&call_label->text=="BG0SRV"&&relay_label->text.find("CQ 呼叫")!=std::string::npos&&relay_label->text.find("456")!=std::string::npos);
  assert(hint_label->text.find("不代表当前在线")!=std::string::npos);
  assert(!receive_peer(peer_cq.data(),peer_cq.size(),c,root.c_str(),1800000001,&peers,peer_nav)&&peers.count==1);
  assert(!receive_peer("invalid",7,c,root.c_str(),1800000000,&peers,peer_nav));
  const auto online=read((std::string(argv[6])+".peer.ONLINE").c_str());
  assert(receive_peer(online.data(),online.size(),c,root.c_str(),1800000000,&peers,peer_nav)&&peers.count==2&&relay_label->text.find("上线通知")!=std::string::npos);
  key(BSP_BTN_DOWN,BTN_EVT_CLICK,0);process_controls(peer_nav,no_servers,nullptr,false,&peers);
  assert(peer_nav.peer_index==1&&relay_label->text.find("CQ 呼叫")!=std::string::npos);
  key(BSP_BTN_OK,BTN_EVT_LONG,0);assert(!talk_requested);
  const auto peer_text=relay_label->text;show("RX","server","OTHER");assert(relay_label->text==peer_text);
  key(BSP_BTN_OK,BTN_EVT_CLICK,0);process_controls(peer_nav,no_servers,nullptr,false,&peers);assert(page==Page::Menu);
  const auto menu_before=relay_label->text;
  const auto vocal=read((std::string(argv[6])+".peer.VOCAL").c_str());
  assert(receive_peer(vocal.data(),vocal.size(),c,root.c_str(),1800000000,&peers,peer_nav)&&relay_label->text==menu_before);
  const auto untrusted=read((std::string(argv[6])+".peer.bad.wrong-issuer").c_str());
  assert(!receive_peer(untrusted.data(),untrusted.size(),c,root.c_str(),1800000000,&peers,peer_nav)&&peers.count==3);
  assert(!receive_peer(peer_cq.data(),peer_cq.size(),c,root.c_str(),1800001800,&peers,peer_nav));
  assert(peers.prune(1800001200)&&peers.count==0&&!peers.prune(1800001201));
  peers_view(&peers,999);assert(call_label->hidden&&relay_label->text=="暂无有效友台广播");
  peers_view(nullptr,0);assert(relay_label->text=="广播记录内存不足");
  assert(peer_announcement(peer_cq.data(),peer_cq.size(),c,root.c_str(),1800000000,&parsed_peer));
  for(unsigned id=1;id<=10;++id){auto event=parsed_peer;event.uid=id;assert(peers.add(event,1800000000));}
  assert(peers.count==PeerEvents::capacity&&peers.events[0].uid==10&&peers.events[7].uid==3);
  auto replay=peers.events[7];assert(!peers.add(replay,1800000000));
  replay.window++;assert(peers.add(replay,1800000000)&&peers.count==8&&peers.events[0].uid==3&&peers.events[1].uid==10);
  replay.window--;assert(!peers.add(replay,1800000000));replay.fingerprint[0]^=1;
  assert(peers.add(replay,1800000000)&&peers.events[1].uid==3); // renewed key is isolated
  assert(peers.prune(1800001200)&&!peers.count);
  page=Page::Peers;back_requested=true;process_controls(peer_nav,no_servers,nullptr,false,&peers);assert(page==Page::Main);
  puts("FMO peer reception/UI: signed events only, replay/renewal binding, bounded eviction/expiry, menu paging, no PTT or RX/menu takeover, unavailable storage and return navigation PASS");
 }
 peer_cq.resize(511,'x');assert(!peer_announcement(peer_cq.data(),peer_cq.size(),c,root.c_str(),1800000000,&parsed_peer));
 {
  for(unsigned mask=0;mask<8;++mask){
   const auto bytes=read((std::string(argv[6])+".beacon."+std::to_string(mask)).c_str());PeerAnnouncement beacon{};
   assert(peer_announcement(bytes.data(),bytes.size(),c,root.c_str(),1800000000,&beacon));
   assert(beacon.kind==PeerKind::Beacon&&!beacon.server_uid&&!strcmp(beacon.frequency,"438.5000"));
   assert(beacon.antenna_height==(mask&1?15u:0u)&&!strcmp(beacon.rig,mask&2?"FT-5DR":"")&&!strcmp(beacon.antenna,mask&4?"J型天线":""));
  }
  for(const char *timecase:{"past","future"}){
   const auto bytes=read((std::string(argv[6])+".beacon."+timecase).c_str());PeerAnnouncement beacon{};
   assert(peer_announcement(bytes.data(),bytes.size(),c,root.c_str(),1800000000,&beacon));
   assert(beacon.window==(!strcmp(timecase,"past")?2999999u:3000001u));
   assert(!peer_announcement(bytes.data(),bytes.size(),c,root.c_str(),1800002400,&beacon));
  }
  for(const char *bad:{"zeroheight","emptyrig","emptyant","overflowheight","negativeheight","badca","bad-utf8","surrogate","extrafield","badfreq","freqtamper","heighttamper","rigtamper","anttamper","reordered","duplicate"}){
   auto bytes=read((std::string(argv[6])+".beacon."+bad).c_str());PeerAnnouncement beacon{};beacon.uid=777;const auto original=beacon;
   assert(!peer_announcement(bytes.data(),bytes.size(),c,root.c_str(),1800000000,&beacon)&&!memcmp(&beacon,&original,sizeof(beacon)));
  }
  auto bytes=read((std::string(argv[6])+".beacon.longtext").c_str());PeerAnnouncement beacon{};
  assert(peer_announcement(bytes.data(),bytes.size(),c,root.c_str(),1800000000,&beacon)&&!strcmp(beacon.rig,"中文设备名中文...")&&!strcmp(beacon.antenna,"XXXXXXXXXXXXXXXXXXXXX..."));
  bytes=read((std::string(argv[6])+".beacon.shortfreq").c_str());assert(peer_announcement(bytes.data(),bytes.size(),c,root.c_str(),1800000000,&beacon)&&!strcmp(beacon.frequency,"438.5000"));
  bytes=read((std::string(argv[6])+".beacon.7").c_str());
  PeerEvents received;Navigation peer_nav;BroadcastConfig own;strcpy(own.grid,"OM90sp");page=Page::Peers;
  assert(!receive_peer(bytes.data(),bytes.size(),c,root.c_str(),1800000000,&received,peer_nav));
  assert(receive_peer(bytes.data(),bytes.size(),c,root.c_str(),1800000000,&received,peer_nav,&own)&&received.count==1);
  assert(received.events[0].distance_m>1300&&received.events[0].distance_m<1600);
  assert(relay_label->text.find("438.5000MHz")!=std::string::npos&&state_label->text.find("FT-5DR")!=std::string::npos&&state_label->text.find("J型天线")!=std::string::npos&&hint_label->text.find("80km")!=std::string::npos);
  received=PeerEvents{};strcpy(own.grid,"PM06");assert(!receive_peer(bytes.data(),bytes.size(),c,root.c_str(),1800000000,&received,peer_nav,&own)&&!received.count);
  own.grid[0]=0;assert(!receive_peer(bytes.data(),bytes.size(),c,root.c_str(),1800000000,&received,peer_nav,&own));
  uint32_t metres=123456;
  assert(!nearby_beacon(beacon,"",&metres)&&metres==123456&&!nearby_beacon(beacon,"OM90sp",nullptr));
  beacon.kind=PeerKind::CQ;assert(!nearby_beacon(beacon,"OM90sp",&metres));beacon.kind=PeerKind::Beacon;
  for(const char *bad:{"9100.00N","9000.01N","3060.00N","30 7.98N","3037.98X","30a7.98N"}){strcpy(beacon.latitude,bad);assert(!nearby_beacon(beacon,"OM90sp",&metres));}
  strcpy(beacon.latitude,"3037.98N");
  for(const char *bad:{"18100.00E","18000.01E","11960.00E","11932.2 E","11932.20X"}){strcpy(beacon.longitude,bad);assert(!nearby_beacon(beacon,"OM90sp",&metres));}
  strcpy(beacon.latitude,"0001.25N");strcpy(beacon.longitude,"00002.50E");assert(nearby_beacon(beacon,"JJ00aa",&metres)&&metres==0);
  strcpy(beacon.latitude,"0044.41N");assert(nearby_beacon(beacon,"JJ00aa",&metres)&&metres>=79980&&metres<80000);
  strcpy(beacon.latitude,"0044.42N");assert(!nearby_beacon(beacon,"JJ00aa",&metres));
  strcpy(beacon.latitude,"0001.25N");strcpy(beacon.longitude,"18000.00E");assert(nearby_beacon(beacon,"AJ00aa",&metres)&&metres<5000);
  strcpy(beacon.latitude,"9000.00N");strcpy(beacon.longitude,"00000.00E");assert(nearby_beacon(beacon,"AR09ax",&metres)&&metres<2500);
  strcpy(beacon.latitude,"9000.00S");assert(nearby_beacon(beacon,"AA00aa",&metres)&&metres<2500);
  {
   uint32_t far_m=0;assert(aprs_distance_m("OM90sp","3957.36N","11618.62E",&far_m)&&far_m>800000u);
   PeerMetaCache pmc{};PeerMeta pm{};
   const std::string pat="BG1XYZ-1>APPASP,TCPIP*:=3957.36NF11618.62EiPAT-1,ST:G003,VER:0.6.13,FREQ:438.5000,RIG:ID-51,QTH:北京,ANT:J型";
   assert(parse_aprs_peer_meta(pat.data(),pat.size(),1800000000,&pm)&&!strcmp(pm.callsign,"BG1XYZ")&&!strcmp(pm.frequency,"438.5000")&&!strcmp(pm.rig,"ID-51")&&!strcmp(pm.qth,"北京")&&!strcmp(pm.antenna,"J型"));
   pmc.remember(pm);
   const std::string cq="P-BG1XYZ>APFMO4,TCPIP*:=3957.36NF11618.62Ei FMO-V4,CQ,CERT:x,S1032,SIG:y";
   PeerMeta pm2{};assert(parse_aprs_peer_meta(cq.data(),cq.size(),1800000010,&pm2)&&!strcmp(pm2.callsign,"BG1XYZ"));
   pmc.remember(pm2);
   const auto *found=pmc.find("P-BG1XYZ");assert(found&&!strcmp(found->frequency,"438.5000")&&!strcmp(found->rig,"ID-51")&&!strcmp(found->qth,"北京")&&found->seen_utc==1800000010);
   const std::string st="BG0SRV-1>APFMO4,TCPIP*:=3957.36NF11618.62Ei FMO-V4,STATION,CERT:x,CN,TEST,h,P1883,F10KM,U1/1,SIG:y";
   PeerMeta pm3{};assert(!parse_aprs_peer_meta(st.data(),st.size(),1800000020,&pm3));
  }
  normal_view();
  puts("FMO signed BEACON reception: all optional-field combinations, frequency normalization, full UTF-8 signatures before bounded display, tampering/order/bounds rejection, explicit-grid-only 80km filter, poles/dateline and UI metadata PASS");
 }
 puts("FMO peer CQ-family: four independently signed types, complete certificate binding, raw position/server/time, compact wire format, tampering/issuer/CA/NUL/noncanonical/expiry/SSID/size rejection PASS");
 {
  auto fixture=[&](const char *name,const char *part){return read((std::string(argv[6])+".event."+name+"."+part).c_str());};
  const auto joint=fixture("normal","joint"),status=fixture("normal","status");EventProof proof{};EventBody body{};EventNotice notice{};
  assert(joint_announcement(joint.data(),joint.size(),c,root.c_str(),1800000000,&proof));
  assert(proof.uid==150&&proof.ssid==15&&proof.window==3000000&&proof.valid_until==1800001200&&!strcmp(proof.callsign,"BG0SRV"));
  assert(event_status(status.data(),status.size(),&body)&&!strcmp(body.topic,"周末通联活动")&&strstr(body.content,"八点,欢迎")&&strstr(body.content,"<script>"));
  assert(event_bind(proof,body,1800000000,&notice)&&notice.window==proof.window&&!memcmp(notice.fingerprint,proof.fingerprint,32));
  auto compact=joint;compact.erase(compact.find(" FMO-V4"),1);assert(joint_announcement(compact.data(),compact.size(),c,root.c_str(),1800000000,&proof));
  for(const char *name:{"past","future"}){const auto bytes=fixture(name,"joint");EventProof other{};assert(joint_announcement(bytes.data(),bytes.size(),c,root.c_str(),1800000000,&other));assert(!joint_announcement(bytes.data(),bytes.size(),c,root.c_str(),1800002400,&other));}
  for(const char *name:{"bad-ca","bad-position"}){const auto bytes=fixture(name,"joint");EventProof other=proof;assert(!joint_announcement(bytes.data(),bytes.size(),c,root.c_str(),1800000000,&other)&&!memcmp(&other,&proof,sizeof(proof)));}
  for(const char *name:{"digest","domain","coordinate","destination","extra"}){const auto bytes=read((std::string(argv[6])+".event.bad."+name).c_str());EventProof other=proof;assert(!joint_announcement(bytes.data(),bytes.size(),c,root.c_str(),1800000000,&other)&&!memcmp(&other,&proof,sizeof(proof)));}
  assert(!joint_announcement(joint.data(),joint.size(),c,nullptr,1800000000,&proof)&&!joint_announcement(joint.data(),joint.size(),c,root.c_str(),1800000000,nullptr));
  for(const char *name:{"topic-over","body-over","uid-over","uid-zero","utf8"}){const auto bytes=fixture(name,"status");EventBody other=body;assert(!event_status(bytes.data(),bytes.size(),&other)&&!memcmp(&other,&body,sizeof(body)));}
  for(const char *name:{"max-topic","max-body","empty","long"}){const auto bytes=fixture(name,"status");EventBody other{};assert(event_status(bytes.data(),bytes.size(),&other));}
  auto tampered=status;tampered+='X';EventBody wrong{};assert(event_status(tampered.data(),tampered.size(),&wrong)&&!event_bind(proof,wrong,1800000000,&notice));
  for(const char *replacement:{"OTHERX-15","BG0SRV-14"}){auto bytes=status;bytes.replace(0,bytes.find('>'),replacement);assert(event_status(bytes.data(),bytes.size(),&wrong)&&!event_bind(proof,wrong,1800000000,&notice));}
  auto another=fixture("other-uid","status");assert(event_status(another.data(),another.size(),&wrong)&&!event_bind(proof,wrong,1800000000,&notice));
  assert(!event_bind(proof,body,1800001200,&notice)&&!event_bind(proof,body,1799998800,&notice)&&!event_bind(proof,body,1800000000,nullptr));
  const auto original=notice;assert(!event_bind(proof,wrong,1800000000,&notice)&&!memcmp(&notice,&original,sizeof(notice)));
  auto bad_status=status;bad_status.replace(bad_status.find("APFMO4"),6,"APFMO4X");assert(!event_status(bad_status.data(),bad_status.size(),&wrong));
  bad_status=status;bad_status[bad_status.size()-1]='\n';assert(!event_status(bad_status.data(),bad_status.size(),&wrong));
  assert(!event_status(status.data(),status.size(),nullptr));
  auto oversized=status;oversized.resize(511,'X');assert(!event_status(oversized.data(),oversized.size(),&wrong));
  oversized=joint;oversized.resize(511,'X');EventProof oversized_proof{};assert(!joint_announcement(oversized.data(),oversized.size(),c,root.c_str(),1800000000,&oversized_proof));
  Announcements events;
  assert(!events.proof(proof,1800000000)&&!events.count);
  assert(events.body(body,1800000000)&&events.count==1&&!strcmp(events.notices[0].body.content,body.content));
  assert(!events.body(body,1800000001)&&!events.proof(proof,1800000001)&&events.count==1&&events.notices[0].valid_until==1800001200);
  assert(events.prune(1800001200)&&!events.count);
  Announcements reverse;assert(!reverse.body(body,1800000000)&&!reverse.count);assert(reverse.proof(proof,1800000029)&&reverse.count==1);
  Announcements timeout;timeout.body(body,1800000000);timeout.body(body,1800000020);assert(!timeout.proof(proof,1800000030)&&!timeout.count); // replay does not extend waiting
  Announcements mismatched;mismatched.proof(proof,1800000000);mismatched.body(wrong,1800000000);assert(!mismatched.count);
  for(const char *name:{"normal","two","three"}){auto j=fixture(name,"joint"),b=fixture(name,"status");EventProof p{};EventBody v{};assert(joint_announcement(j.data(),j.size(),c,root.c_str(),1800000000,&p)&&event_status(b.data(),b.size(),&v));events.proof(p,1800000000);assert(events.body(v,1800000000));}
  assert(events.count==2&&!strcmp(events.notices[0].body.topic,"第三条")&&!strcmp(events.notices[1].body.topic,"第二条"));
  assert(events.prune(1799998800)&&!events.count); // no display across a backwards clock jump
  Announcements incoming;Navigation event_nav;RelayList servers;page=Page::Menu;event_nav.menu_index=9;next_requested=previous_requested=0;menu_requested=back_requested=false;switch_requested=true;
  assert(process_controls(event_nav,servers,nullptr,false,nullptr,&incoming)==UiAction::None&&page==Page::Announcements&&call_label->hidden&&relay_label->text=="暂无有效活动公告");
  const auto empty_text=relay_label->text;const auto before_navigation=navigated;
  assert(!receive_announcement(status.data(),status.size(),c,root.c_str(),1800000000,&incoming,event_nav)&&relay_label->text==empty_text);
  assert(receive_announcement(joint.data(),joint.size(),c,root.c_str(),1800000000,&incoming,event_nav)&&incoming.count==1&&state_label->text.find("BG0SRV")!=std::string::npos);
  assert(hint_label->text.find("不自动执行")!=std::string::npos&&relay_label->height==96&&navigated==before_navigation&&!talk_requested);
  key(BSP_BTN_OK,BTN_EVT_LONG,0);assert(!talk_requested);
  key(BSP_BTN_OK,BTN_EVT_CLICK,0);process_controls(event_nav,servers,nullptr,false,nullptr,&incoming);assert(page==Page::Menu);
  const auto menu_text=relay_label->text;const auto long_joint=fixture("long","joint"),long_status=fixture("long","status");
  assert(!receive_announcement(long_joint.data(),long_joint.size(),c,root.c_str(),1800000000,&incoming,event_nav));
  assert(receive_announcement(long_status.data(),long_status.size(),c,root.c_str(),1800000000,&incoming,event_nav)&&relay_label->text==menu_text);
  char rendered[kAnnouncementPageBytes];const unsigned pages=announcement_page(incoming.notices[0],0,rendered);assert(pages>=3);
  std::string reconstructed;
  for(unsigned i=0;i<pages;++i){assert(announcement_page(incoming.notices[0],i,rendered)==pages);assert(strlen(rendered)<kAnnouncementPageBytes);for(char *at=rendered;*at;++at)if(*at!='\n')reconstructed+=*at;}
  assert(reconstructed==std::string(incoming.notices[0].body.topic)+incoming.notices[0].body.content);
  page=Page::Announcements;event_nav.event_index=event_nav.event_page=0;announcement_view(&incoming,event_nav);const auto first_page=relay_label->text;
  key(BSP_BTN_DOWN,BTN_EVT_CLICK,0);process_controls(event_nav,servers,nullptr,false,nullptr,&incoming);assert(event_nav.event_page==1&&relay_label->text!=first_page);
  const auto page_text=relay_label->text;show("voice","server","OTHER");assert(relay_label->text==page_text);
  move_announcement(&incoming,event_nav,100);assert(event_nav.event_index<incoming.count);
  move_announcement(&incoming,event_nav,-100);assert(event_nav.event_index<incoming.count);
  announcement_view(nullptr,event_nav);assert(relay_label->text=="公告记录内存不足");
  key(BSP_BTN_DOWN,BTN_EVT_LONG,0);process_controls(event_nav,servers,nullptr,false,nullptr,&incoming);assert(page==Page::Main);
  puts("FMO signed announcements: independent JOINT CBOR/Ed25519 and raw STATUS SHA256, source/SSID/UID binding, UTF-8 limits, tampering/expiry, reverse order/30s timeout, replay/eviction/clock rollback and actual paged UI/no PTT or automatic actions PASS");
 }
 auto changed_status=read((std::string(argv[6])+".updated").c_str());assert(station_announcement(changed_status.data(),changed_status.size(),c,root.c_str(),1800000000,&found,&valid_until,&parsed_status)&&parsed_status.online==6);
 auto fake_status=announcement;fake_status[fake_status.find("U5/200")+1]='6';assert(!station_announcement(fake_status.data(),fake_status.size(),c,root.c_str(),1800000000,&found,&valid_until,&parsed_status)&&valid_until==0&&parsed_status.valid_until==0&&parsed_status.online==0);
 assert(!station_announcement(fake_status.data(),fake_status.size(),c,root.c_str(),1800000000,&found,&valid_until,&parsed_status,&reject)&&reject==StationRejection::SignatureInvalid);
 const char *unrelated="# aprs banner";assert(!station_announcement(unrelated,strlen(unrelated),c,root.c_str(),1800000000,&found,&valid_until,&parsed_status,&reject)&&reject==StationRejection::NotStation);
 auto forged=announcement;forged[forged.find("relay.example")]='x';
 assert(!station_announcement(forged.data(),forged.size(),c,root.c_str(),1800000000,&found));
 assert(!station_announcement(announcement.data(),announcement.size(),c,root.c_str(),1800001800,&found));
 {
  normal_view();connected=true;talk_requested=false;ptt_released=false;
  key(BSP_BTN_OK,BTN_EVT_LONG,0);
  assert(talk_requested&&!ptt_released);
  key(BSP_BTN_OK,BTN_EVT_RELEASE,0);
  assert(!talk_requested&&ptt_released.exchange(false));
  key(BSP_BTN_OK,BTN_EVT_LONG_UP,0);
  assert(!ptt_released);
  key(BSP_BTN_OK,BTN_EVT_LONG,0);
  key(BSP_BTN_DOWN,BTN_EVT_CLICK,0);
  assert(!talk_requested&&!ptt_released);
  AprsInbox inbox;
  const std::string route="BI4TES-15>APFM00,TCPIP*,qAC,RELAY:";
  assert(inbox.receive(route+":BG0TEST  :MSG,你好, hello{A123","BG0TEST-1"));
  assert(!inbox.receive(route+":BG0TEST  :MSG,你好, hello{A123","BG0TEST-1"));
  assert(!inbox.receive(route+":BG0TEST-2:MSG,wrong recipient{2","BG0TEST-1"));
  assert(!inbox.receive(route+":BG0TEST-1:CONTROL,reboot{3","BG0TEST-1"));
  assert(!inbox.receive(route+":BG0TEST-1:MSG,\xc0\x80{4","BG0TEST-1"));
  assert(!inbox.receive(route+":BG0TEST-1:MSG,"+std::string(63,'x')+"{4","BG0TEST-1"));
  assert(inbox.receive(route+":BG0TEST-1:MSG,next{5","BG0TEST-1"));
  Navigation msg_nav;RelayList msg_servers;
  page=Page::Menu;msg_nav.menu_index=12;next_requested=previous_requested=0;menu_requested=back_requested=false;switch_requested=true;
  process_controls(msg_nav,msg_servers,nullptr,false,nullptr,nullptr,nullptr,false,nullptr,nullptr,nullptr,nullptr,&inbox);
  assert(page==Page::Messages&&relay_label->text=="next");
  assert(state_label->text.find("未验签")!=std::string::npos);
  key(BSP_BTN_DOWN,BTN_EVT_CLICK,0);
  process_controls(msg_nav,msg_servers,nullptr,false,nullptr,nullptr,nullptr,false,nullptr,nullptr,nullptr,nullptr,&inbox);
  assert(relay_label->text=="你好, hello");
  normal_view();
 }
 puts("FMO station snapshots: signed updates/tampering, legacy cache, CRC/UID/key/window binding, expiry/compaction and native/web rendering PASS");
 sodium_memzero(sk,sizeof(sk));puts("FMO: bounded packets/CRC/lengths/fuzz, real root, key-bound certificate chains, tampering/expiry/duplicates and SAS proof PASS");
}
'''
app_source=(root/'components/passport_fmo/src/app_fmo.cc').read_text()
def production_function(signature):
 start=app_source.index(signature);opening=app_source.index('{',start);depth=1;end=opening+1
 while depth:
  if app_source[end]=='{':depth+=1
  elif app_source[end]=='}':depth-=1
  end+=1
 return app_source[start:end]
cache_source=(root/'components/passport_fmo/src/fmo_store.cc').read_text()
cache_code=cache_source[cache_source.index('namespace {\nstruct SavedRelays'):cache_source.rfind('\n}')]
cache_prefix=r'''#include <memory>
#include <mutex>
#include <vector>
using nvs_handle_t=int;
constexpr int ESP_OK=0,NVS_READONLY=1,NVS_READWRITE=2;
std::vector<uint8_t> cache_bytes,cache_stats_bytes;bool cache_fail_open=false,cache_fail_write=false,cache_fail_commit=false;
int nvs_open(const char*,int,int *h){*h=1;return cache_fail_open?-1:0;}
int nvs_get_blob(int,const char *key,void *out,size_t *n){const auto &bytes=!strcmp(key,"relay_stats")?cache_stats_bytes:cache_bytes;if(bytes.empty()||*n<bytes.size())return -1;*n=bytes.size();memcpy(out,bytes.data(),*n);return 0;}
int nvs_set_blob(int,const char *key,const void *data,size_t n){if(cache_fail_write)return -1;auto *p=static_cast<const uint8_t *>(data);auto &bytes=!strcmp(key,"relay_stats")?cache_stats_bytes:cache_bytes;bytes.assign(p,p+n);return 0;}
int nvs_commit(int){return cache_fail_commit?-1:0;}void nvs_close(int){}
namespace fmo {std::mutex mutex;const char *kNamespace="fmo_os";
'''+cache_code+'\n}\n'
prefix=r'''#include <atomic>
#include <algorithm>
#include <sys/select.h>
#include <cerrno>
std::atomic<bool> talk_requested{true},stop_requested{false},running{true},ptt_released{false};
std::string written;std::vector<int> send_plan;size_t send_at=0;unsigned send_waits=0;
int test_send(int,const char *data,size_t n,int){int result=send_at<send_plan.size()?send_plan[send_at++]:int(n);if(result<0){errno=result==-2?EAGAIN:result==-3?EINTR:ECONNRESET;return -1;}result=std::min<int>(result,n);written.append(data,result);return result;}
std::vector<int> recv_plan;size_t recv_at=0;
int test_recv(int,char *data,size_t capacity,int){assert(recv_at<recv_plan.size());const int n=recv_plan[recv_at++];if(n<0){errno=n==-2?EAGAIN:n==-3?EINTR:ECONNRESET;return -1;}assert(size_t(n)<=capacity);std::memcpy(data,"abc",n);return n;}
int test_select(int,fd_set*,fd_set*,fd_set*,timeval*){++send_waits;return 1;}

int queue=1,queue_resets=0;void xQueueReset(int){++queue_resets;}
int worker=1,worker_notified=0;void xTaskNotifyGive(int){++worker_notified;}
int mock_mqtt_closed=0,mock_audio_closed=0,mock_fd_closed=-1;char current_speaker[13]{};
namespace fmo {Favorites stored_favorites;bool favorites_save_ok=true;
FavoritesLoad load_favorites(Favorites *out){*out=stored_favorites;return out->count?FavoritesLoad::Ready:FavoritesLoad::Missing;}
bool save_favorites(const Favorites &list){if(!favorites_save_ok)return false;stored_favorites=list;return true;}
StampConfig stored_stamp{};PeerStamps stored_peer_stamps{};
StampLoad load_stamp_config(StampConfig *out){*out=stored_stamp;return StampLoad::Ready;}
bool save_stamp_config(const StampConfig &cfg){stored_stamp=cfg;return true;}
StampLoad load_custom_stamp_image(const StampConfig &,uint8_t *){return StampLoad::Missing;}
StampLoad load_peer_stamps(PeerStamps *out){*out=stored_peer_stamps;return StampLoad::Ready;}
bool save_peer_stamps(const PeerStamps &s){stored_peer_stamps=s;return true;}
bool legacy_identity_available(std::string *,uint32_t *){return false;}
const char *PeerStamps::find(const char *call)const{for(unsigned i=0;i<count;++i)if(!strcmp(entries[i].callsign,call))return entries[i].style_id;return nullptr;}
bool stamp_is_custom_style(const char *s){return s&&!strcmp(s,"CUSTOM");}
int stamp_builtin_index(const char *s){if(!s||s[0]!='G'||strlen(s)!=4)return -1;int n=(s[1]-'0')*100+(s[2]-'0')*10+(s[3]-'0');return (n>=1&&n<=12)?n-1:-1;}
unsigned stamp_fallback_index(const char *s){unsigned h=0;for(;s&&*s;++s)h=h*31+unsigned(*s);return h%kBuiltinStampCount;}
const char *stamp_builtin_id(unsigned i){static const char *ids[]={"G001","G002","G003","G004","G005","G006","G007","G008","G009","G010","G011","G012"};return ids[i%12];}
const char *stamp_builtin_name(unsigned i){static const char *nm[]={"双环圆章","邮戳齿圆","圆角方章","方中带圆","粗边圆章","圆中带方","八角印章","徽章盾牌","六角蜂巢","爱心印章","菱形印章","邮票方章"};return nm[i%12];}
bool parse_pat1_stamp(const char *line,size_t size,char call[13],char style[8]){
 std::string raw(line,size);auto gt=raw.find('>'),co=raw.find(':');if(gt==std::string::npos||co==std::string::npos||raw.compare(gt+1,6,"APPASP"))return false;
 std::string c=raw.substr(0,gt);auto d=c.rfind('-');if(d!=std::string::npos)c.resize(d);
 auto p=raw.find("PAT-1,",co+1);if(p==std::string::npos)return false;auto st=raw.find("ST:",p+6);if(st==std::string::npos)return false;
 auto cm=raw.find(',',st+3);std::string id=raw.substr(st+3,cm==std::string::npos?std::string::npos:cm-st-3);
 if(c.size()<2||c.size()>12||id.size()!=4)return false;strcpy(call,c.c_str());strcpy(style,id.c_str());return true;
}
}
bool mock_stamp_shown=false,mock_stamp_custom=false;unsigned mock_stamp_builtin=0;
void stamp_widget_hide(){mock_stamp_shown=false;mock_stamp_custom=false;}
void stamp_widget_show_builtin(unsigned idx,uint32_t){mock_stamp_shown=true;mock_stamp_custom=false;mock_stamp_builtin=idx;}
void stamp_widget_show(const uint8_t *,uint32_t){mock_stamp_shown=true;mock_stamp_custom=true;}
std::atomic<fmo::MqttConnection> mqtt_connection{fmo::MqttConnection::Connecting};
void ui_apply_mode(fmo::Page,const char * =nullptr){}
void ui_apply_hero_state(bool,bool,bool,bool){}
void ui_apply_hero_meta(const char *,const char *,const char *){}
fmo::NodeConnections mqtt_connections;
int64_t esp_timer_get_time();
void close_mqtt(){++mock_mqtt_closed;mqtt_connections.reset();}
void bsp_audio_deinit(){++mock_audio_closed;}
void home_clock_stop(){}
std::atomic<fmo::Page> page{fmo::Page::Main};
std::atomic<uint32_t> discovery_unknown_issuer{0};
std::atomic<fmo::StationRejection> discovery_rejection{fmo::StationRejection::NotStation};
std::atomic<unsigned> volume_percent{80};std::atomic<bool> volume_saved{true};
std::atomic<bool> menu_requested{false},back_requested{false},favorite_requested{false},connected{false},switch_requested{false};
#include <ctime>
unsigned mock_volume=80,mock_volume_saves=0;bool volume_save_ok=true;
int mock_timezone=8*3600;int time_sync_tz_offset_sec(){return mock_timezone;}
unsigned settings_get_volume(){return mock_volume;}
bool settings_save_volume(unsigned value){++mock_volume_saves;if(!volume_save_ok)return false;mock_volume=value;return true;}
std::atomic<unsigned> next_requested{0},previous_requested{0};
struct Label {std::string text;bool hidden=false;int height=0;};using lv_obj_t=Label;
Label test_screen,test_state,test_relay,test_call,test_hint;
Label *screen=&test_screen,*state_label=&test_state,*relay_label=&test_relay,*call_label=&test_call,*hint_label=&test_hint;
bool ui_lock=true;bool bsp_lvgl_lock(int){return ui_lock;}void bsp_lvgl_unlock(){}
constexpr int LV_OBJ_FLAG_HIDDEN=1;
void ui_pixel_label_set_text(Label *p,const char *s){p->text=s;}
void lv_obj_set_height(Label *p,int height){p->height=height;}
void lv_obj_add_flag(Label *p,int){p->hidden=true;}void lv_obj_remove_flag(Label *p,int){p->hidden=false;}
enum app_btn_event_t {BTN_EVT_CLICK,BTN_EVT_PRESS,BTN_EVT_RELEASE,BTN_EVT_LONG,BTN_EVT_LONG_UP,BTN_EVT_DOUBLE};
constexpr int BSP_BTN_UP=0,BSP_BTN_DOWN=1,BSP_BTN_OK=2,APP_ID_LAUNCHER=0,APP_ID_WIFI=1;
bool mock_worker_navigation=false;
int navigated=-1;void app_registry_switch_to(int id){navigated=id;if(mock_worker_navigation)stop_requested=true;}

int mock_close(int fd){mock_fd_closed=fd;return 0;}
#define close mock_close
'''+production_function('bool restart_discovery(')+'\n'+production_function('void discovery_retry_view(')+'\n'+production_function('void stop_capture(')+'\n'+production_function('void cleanup_session(')+'\n'+production_function('fmo::SessionRevocation reject_revoked_session(')+'\n#undef close\n'+production_function('int decode_radpcm(')+'\n'+production_function('void show(')+'\n'+'\n#define send test_send\n#define select test_select\n'+production_function('bool socket_write(')+'\n#undef send\n#undef select\n#define recv test_recv\n'+production_function('int socket_read(')+'\n#undef recv\n'+production_function('void short_name(')+'\n'+production_function('void station_summary(')+'\n'+production_function('void show_relay(')+'\n'+production_function('const char *discovery_rejection_message(')+'\n'+production_function('void server_list_view(')+'\n'+production_function('void favorites_view(')+'\n'+production_function('__attribute__((noinline)) const char *edit_favorite(')+'\n'+production_function('void normal_view(')+'\n'+app_source[app_source.index('constexpr const char *kMenuItems'):app_source.index('void menu_view(')]+production_function('void menu_view(')+'\n'+production_function('void broadcast_view(')+'\n'+production_function('void stamp_view(')+'\n'+production_function('void beep_view(')+'\n'+production_function('void history_view(')+'\n'+production_function('void peers_view(')+'\n'+production_function('bool receive_peer(')+'\n'+production_function('void announcement_view(')+'\n'+production_function('void message_view(')+'\n'+production_function('void move_announcement(')+'\n'+production_function('__attribute__((noinline)) bool receive_announcement_body(')+'\n'+production_function('bool receive_announcement(')+'\n'+production_function('void volume_view(')+'\n'+production_function('void adjust_volume(')+'\n'+production_function('fmo::UiAction process_controls(')+'\n'+production_function('void navigate(')+'\n'+production_function('void handle_key(')+'\n'+production_function('bool prepare_stop(')+'\n'+production_function('void key(')+'\n'
boot_prefix=app_source[app_source.index('void run(void *){'):app_source.index('    fmo::load_relay_cache(&servers,time(nullptr));',app_source.index('void run(void *){'))]
boot_prefix=boot_prefix.replace('void run(void *){','void run_boot(void *){',1)+'    (void)capturing;(void)next_book_save;(void)next_cache_save;(void)aprs_capable;(void)revocation_epoch;(void)peer_stamps_writable;(void)peer_stamps_dirty;cleanup();running=false;vTaskSuspend(nullptr);return;\n}\n'
boot_prefix='\n#define time boot_time\n#define fmo_root_start boot_root.c_str()\n'+boot_prefix+'\n#undef time\n#undef fmo_root_start\n'
boot_mocks=r'''
#include <functional>
#define ESP_LOGI(...) ((void)0)
#define ESP_LOGW(...) ((void)0)
void play_local_beep(const fmo::BeepConfig &,bool &,bool,int16_t *){}
namespace fmo {
const char *beep_cloud_name(uint8_t id){return id==1?"模拟信令":nullptr;}
BeepLoad load_beep_config(BeepConfig *out){*out={};return BeepLoad::Missing;}
bool save_beep_config(const BeepConfig &){return true;}
}
constexpr int pdTRUE=1;
#define pdMS_TO_TICKS(ms) (ms)
bool mock_clock_valid=false,identity_success=false;int identity_loads=0;fmo::Credential boot_identity;uint8_t *loaded_secret=nullptr;
std::string boot_root;time_t boot_time(time_t*){return 1800000000;}
std::function<void()> wait_step;
void home_clock_start(){}bool home_clock_valid(){return mock_clock_valid;}
int64_t http_mono=0;int64_t esp_timer_get_time(){return http_mono;}
unsigned ulTaskNotifyTake(int clear,unsigned timeout){assert(clear==pdTRUE&&timeout==1000);if(!stop_requested)wait_step();return 0;}
struct Parked {};
void vTaskSuspend(void *){throw Parked{};}
namespace fmo {
Credential http_identity;bool http_identity_ready=false;
std::map<int,std::vector<uint8_t>> mock_saved_crls;bool fail_cache_save=false,fail_cache_load=false;
CrlCacheLoad load_crl_cache(CrlLevel level,const Credential &identity,const char *root,uint32_t now,CrlCacheRecord *out){
 *out={};if(fail_cache_load)return CrlCacheLoad::Unavailable;auto i=mock_saved_crls.find(int(level));if(i==mock_saved_crls.end())return CrlCacheLoad::Missing;
 if(!verify_crl_proof(i->second.data(),i->second.size(),level==CrlLevel::Root,identity,root,now,0,&out->status,true))return CrlCacheLoad::Unavailable;
 out->size=i->second.size();out->data=std::make_unique<uint8_t[]>(out->size);memcpy(out->data.get(),i->second.data(),out->size);return CrlCacheLoad::Ready;
}
bool save_crl_cache(CrlLevel level,const Credential &identity,const char *root,uint32_t now,const uint8_t *proof,size_t size,bool initialize){
 assert(initialize);CrlStatus status;if(fail_cache_save||!verify_crl_proof(proof,size,level==CrlLevel::Root,identity,root,now,0,&status))return false;
 mock_saved_crls[int(level)]={proof,proof+size};return true;
}

bool public_identity(std::string *pub,Credential *out,std::string *){pub->clear();if(!http_identity_ready)return false;*pub="public";*out=http_identity;return true;}
bool load_relay(Relay *){return false;}
bool load_broadcast_config(BroadcastConfig *out){*out={};return true;}
BookLoad load_contact_book(ContactBook *b){b->count=1;b->contacts[0]={3,456,1800000000,1800000010,1,100,"BG0OFF"};return BookLoad::Ready;}
bool save_contact_book(const ContactBook &){return true;}
bool load_identity(Credential *out,uint8_t *secret,std::string *error){assert(mock_clock_valid);++identity_loads;if(identity_success){*out=boot_identity;memset(secret,0x44,64);loaded_secret=secret;return true;}*error="请申请证书";return false;}
}
'''
http=(root/'components/passport_fmo/src/fmo_http.cc').read_text()
http_status=http[http.index('esp_err_t status('):http.index('esp_err_t contact_status(')].replace('esp_err_t status(', 'esp_err_t relay_http_status(',1)
http_prefix=r'''#include "cJSON.h"
using esp_err_t=int;struct httpd_req_t {};
using Json=std::unique_ptr<cJSON,decltype(&cJSON_Delete)>;
std::string http_reply;
bool crl_wifi=true;
struct WifiManager {static WifiManager &GetInstance(){static WifiManager w;return w;}bool HasStationIp(){return crl_wifi;}};
int send(httpd_req_t *,cJSON *j){char *p=cJSON_PrintUnformatted(j);assert(p);http_reply=p;cJSON_free(p);return 0;}
time_t http_time(time_t *){return 1800000000;}
#define time http_time
'''
crl_http_prefix=r'''
std::string crl_test_root,crl_root_bytes,crl_user_bytes,http_error;
int download_calls=0;size_t mock_crl_free=200000,mock_crl_largest=100000;
const char *mock_clock_error=nullptr;
constexpr int MALLOC_CAP_8BIT=1;
size_t heap_caps_get_free_size(int){return mock_crl_free;}size_t heap_caps_get_largest_free_block(int){return mock_crl_largest;}
const char *ensure_ca_clock(){return mock_clock_error;}
int fail(httpd_req_t*,const char *message,const char * =nullptr){http_error=message;return -1;}
const char *download_crl(const char *url,uint8_t *data,size_t capacity,size_t *used){++download_calls;const auto &source=strstr(url,"root-")?crl_root_bytes:crl_user_bytes;assert(source.size()<capacity);*used=source.size();memcpy(data,source.data(),*used);return nullptr;}
#define fmo_root_start crl_test_root.c_str()
'''
def http_function(signature):
 start=http.index(signature);opening=http.index('{',start);depth=1;end=opening+1
 while depth:
  if http[end]=='{':depth+=1
  elif http[end]=='}':depth-=1
  end+=1
 return http[start:end]
crl_http_code='\n'.join(http_function(signature) for signature in ['const char *field(', 'bool provider_crl_url(', 'esp_err_t refresh_crls('])+'\n#undef fmo_root_start\n'
source=source.replace('int main(int argc,char **argv){',cache_prefix+prefix+boot_mocks+boot_prefix+http_prefix+http_status+crl_http_prefix+crl_http_code+'\n#undef time\nint main(int argc,char **argv){')
source=source.replace(' sodium_memzero(sk,sizeof(sk));puts(',r'''
 uint8_t adpcm[328]{};adpcm[6]=64;adpcm[7]=1;memset(adpcm+8,0x77,320);int16_t pcm[640];
 Frame adpcm_frame{2,adpcm,328,1};assert(decode_radpcm(adpcm_frame,pcm)==640);
 assert(pcm[0]==11&&pcm[1]==41&&pcm[2]==104&&pcm[3]==240);
 adpcm[4]=88;memset(adpcm+8,0xff,320);assert(decode_radpcm(adpcm_frame,pcm)==640&&pcm[0]==-32768&&pcm[639]==-32768);
 adpcm[4]=89;assert(decode_radpcm(adpcm_frame,pcm)==-1);
 for(int lifetime=0;lifetime<100;++lifetime){
  c.user_json.assign(1000,'x');c.intermediate_json.assign(1500,'y');std::string uri(300,'u'),pass(4000,'p'),error(200,'e');uint8_t private_bytes[64];memset(private_bytes,9,64);int fd=7;talk_requested=true;
  cleanup_session(c,private_bytes,uri,pass,error,fd,true);
  assert(!talk_requested&&fd==-1&&mock_fd_closed==7&&mock_audio_closed==lifetime+1&&mock_mqtt_closed==lifetime+1);
  for(auto byte:private_bytes)assert(byte==0);
  assert(pass.empty()&&pass.capacity()<32&&uri.capacity()<32&&error.capacity()<32&&c.user_json.capacity()<32&&c.intermediate_json.capacity()<32);
 }
 bool capture_audio=true,capture_active=true,capture_encoding=true,capture_decoder=true;const auto deinit_before=mock_audio_closed;
 stop_capture(capture_audio,capture_active,capture_encoding,capture_decoder);stop_capture(capture_audio,capture_active,capture_encoding,capture_decoder);
 assert(!capture_audio&&!capture_active&&!capture_encoding&&!capture_decoder&&mock_audio_closed==deinit_before+1&&queue_resets==1);
 {
  auto live_identity=fmo::http_identity;uint8_t live_secret[64];memset(live_secret,0x55,64);
  std::string live_uri="mqtt://relay",live_password="signed login",live_error="old";int live_fd=8;
  bool live_audio=true,live_capture=true,live_encoding=true,live_decoder=true;
  auto unrelated=live_identity;unrelated.fingerprint[0]^=1;talk_requested=true;
  assert(revocation_state(unrelated,1800000000)==RevocationState::Unknown);
  const auto live_epoch=revocation_bind(live_identity);
  assert(reject_revoked_session(live_identity,live_secret,live_uri,live_password,live_error,live_fd,live_audio,live_capture,live_encoding,live_decoder,live_epoch,1799999980)==SessionRevocation::Allowed&&live_fd==8&&live_audio&&live_secret[0]==0x55);
  const int old_audio_closes=mock_audio_closed,old_mqtt_closes=mock_mqtt_closed;
  assert(reject_revoked_session(live_identity,live_secret,live_uri,live_password,live_error,live_fd,live_audio,live_capture,live_encoding,live_decoder,live_epoch,1800000000)==SessionRevocation::Revoked);
  assert(!talk_requested&&live_fd==-1&&mock_fd_closed==8&&!live_audio&&!live_capture&&!live_encoding&&!live_decoder);
  assert(mock_audio_closed==old_audio_closes+1&&mock_mqtt_closed==old_mqtt_closes+1&&live_uri.empty()&&live_password.empty());
  for(auto byte:live_secret)assert(!byte);
 }
 // Run the actual worker initialization/failed-identity path with scripted
 // task wakes: menus work before both time sync and certificate readiness.
 mock_worker_navigation=true;mock_clock_valid=false;identity_loads=0;
 stop_requested=false;running=true;next_requested=previous_requested=0;menu_requested=back_requested=switch_requested=false;normal_view();
 unsigned step=0;wait_step=[&](){switch(++step){
  case 1:assert(identity_loads==0);key(BSP_BTN_DOWN,BTN_EVT_CLICK,0);break;
  case 2:assert(page==fmo::Page::Menu);key(BSP_BTN_DOWN,BTN_EVT_CLICK,0);key(BSP_BTN_OK,BTN_EVT_CLICK,0);break;
  case 3:assert(page==fmo::Page::History&&call_label->text=="BG0OFF");mock_clock_valid=true;break;
  case 4:assert(identity_loads==1);key(BSP_BTN_DOWN,BTN_EVT_LONG,0);break;
  case 5:assert(page==fmo::Page::Main&&state_label->text=="请申请证书");key(BSP_BTN_DOWN,BTN_EVT_CLICK,0);break;
  case 6:assert(page==fmo::Page::Menu);for(int i=0;i<3;++i)key(BSP_BTN_DOWN,BTN_EVT_CLICK,0);key(BSP_BTN_OK,BTN_EVT_CLICK,0);break;
  default:assert(false);
 }};
 try{run_boot(nullptr);assert(false);}catch(const Parked&){}
 assert(step==6&&identity_loads==1&&!running&&navigated==APP_ID_WIFI);
 stop_requested=false;running=true;mock_clock_valid=false;identity_loads=0;next_requested=previous_requested=0;menu_requested=back_requested=switch_requested=false;normal_view();step=0;
 wait_step=[&](){switch(++step){
  case 1:key(BSP_BTN_DOWN,BTN_EVT_CLICK,0);break;
  case 2:for(int i=0;i<12;++i)key(BSP_BTN_UP,BTN_EVT_CLICK,0);key(BSP_BTN_OK,BTN_EVT_CLICK,0);break;
  default:assert(false);
 }};
 try{run_boot(nullptr);assert(false);}catch(const Parked&){}
 assert(step==2&&identity_loads==0&&!running&&navigated==APP_ID_LAUNCHER);
stop_requested=false;running=true;mock_clock_valid=true;identity_success=true;boot_identity=fmo::http_identity;identity_loads=0;
 next_requested=previous_requested=0;menu_requested=back_requested=switch_requested=false;normal_view();step=0;
 wait_step=[&](){switch(++step){
  case 1:assert(identity_loads==1&&state_label->text=="本机身份已吊销，请重新申请");for(unsigned i=0;i<64;++i)assert(!loaded_secret[i]);key(BSP_BTN_DOWN,BTN_EVT_CLICK,0);break;
  case 2:assert(page==fmo::Page::Menu);for(unsigned i=0;i<5;++i)key(BSP_BTN_DOWN,BTN_EVT_CLICK,0);key(BSP_BTN_OK,BTN_EVT_CLICK,0);break;
  default:assert(false);
 }};
 try{run_boot(nullptr);assert(false);}catch(const Parked&){}
 assert(step==2&&identity_loads==1&&!running&&navigated==APP_ID_LAUNCHER);identity_success=false;loaded_secret=nullptr;
 {
  auto prior=fmo::http_identity;auto epoch=revocation_bind(prior);auto replacement=prior;replacement.fingerprint[0]^=1;
  revocation_bind(replacement);assert(revocation_session_state(prior,epoch,1800000000)==SessionRevocation::Reconfigured);
  uint8_t secret[64];memset(secret,0x66,64);std::string uri="relay",password="proof",error;int fd=19;bool audio=true,capture=true,encoding=true,decoder=true;
  assert(reject_revoked_session(prior,secret,uri,password,error,fd,audio,capture,encoding,decoder,epoch,1800000000)==SessionRevocation::Reconfigured);
  assert(fd==-1&&!audio&&!capture&&!encoding&&!decoder&&password.empty());for(auto byte:secret)assert(!byte);
 }
 puts("FMO revocation gate: shared concurrent cache, rejected identity at worker startup, secret erasure/menu exit and active MQTT/APRS/audio/PTT teardown with unrelated identity isolation PASS");
 mock_worker_navigation=false;
 auto unknown_frame=read((std::string(argv[6])+".unknown-issuer").c_str());
 Relay interop{};uint32_t interop_until=0,interop_issuer=0;StationStatus interop_status{};
 assert(interop_station_announcement(unknown_frame.data(),unknown_frame.size(),1800000000,&interop,&interop_until,&interop_status,&interop_issuer));
 assert(interop_issuer==9999&&interop.uid==150&&interop.port==1883&&!strcmp(interop.callsign,"BG0SRV")&&!strcmp(interop.host,"relay.example.test")&&interop_status.online==5&&interop_status.peak==200&&interop_until==1800001200);
 auto tampered_interop=unknown_frame;const auto sig_at=tampered_interop.rfind("SIG:")+10;tampered_interop[sig_at]=(tampered_interop[sig_at]=='A'?'B':'A');
 assert(!interop_station_announcement(tampered_interop.data(),tampered_interop.size(),1800000000,&interop));
 auto renamed_interop=unknown_frame;const auto name_at=renamed_interop.find("Test Relay");renamed_interop[name_at]='B';
 assert(!interop_station_announcement(renamed_interop.data(),renamed_interop.size(),1800000000,&interop));
 assert(!interop_station_announcement(unknown_frame.data(),unknown_frame.size(),1800000000+8000,&interop));
 assert(is_official_interop_relay("BI4TES")&&is_official_interop_relay("p-bi4tes")&&!is_official_interop_relay("BG0SRV"));
 assert(is_own_relay("BG0TEST","P-BG0TEST")&&!is_own_relay("BG0SRV","P-BG0TEST"));
 char listen_name[48]{},listen_call[13]{};
 const std::string listen_ok="BG0USR-9>APPASP,TCPIP*:>正在 密云信道(BD1AMC-15) 上守听";
 assert(parse_appasp_listening(listen_ok.data(),listen_ok.size(),listen_name,listen_call)&&!strcmp(listen_name,"密云信道")&&!strcmp(listen_call,"BD1AMC"));
 const std::string listen_bad="BG0USR-9>APFMO4,TCPIP*:>正在 密云信道(BD1AMC) 上守听";
 assert(!parse_appasp_listening(listen_bad.data(),listen_bad.size(),listen_name,listen_call));
 puts("FMO interop discovery (external-CA signature + BI4TES/own + APPASP listening beacon): PASS");
 puts("FMO UI: menu/PTT isolation, history, persistent volume failures/bounds, key wake/stop, phone/exit actions and pre-clock/pre-certificate worker paths PASS");
 sodium_memzero(sk,sizeof(sk));puts(''')
with tempfile.TemporaryDirectory(prefix='passport-fmo-') as d:
 p=Path(d);(p/'test.cc').write_text(source);(p/'root.json').write_text(json.dumps(r));(p/'bundle').write_bytes(b'FMOTEST\0'+json.dumps(i).encode()+b'\0'+json.dumps(u).encode());(p/'seed').write_bytes(bytes([3])*32)
 (p/'bundle.hashes').write_bytes(hashlib.sha256(cb(rt)).digest()+hashlib.sha256(cb(it)).digest())
 # Independent Python signs exact CRL semantic arrays; no production encoder
 # is used to construct expected signatures or certificate fingerprints.
 fingerprint=hashlib.sha256(cb(ut)).digest()
 def crl_entry(uid=123,fp=fingerprint,at=now-1):
  return dict(uid=uid,certFingerprint=b64(fp),revokedAt=at,reason=1)
 def crl(entries,signer=ik,issuer=2,this_update=now-10,next_update=now+1000,number=12):
  values=['FMO',4,'intermediateCRL',issuer,number,this_update,next_update,[[e['uid'],un64(e['certFingerprint']),e['revokedAt'],e['reason']] for e in entries]]
  return sign(dict(type='intermediateCRL',issuerSn=issuer,crlNumber=number,thisUpdate=this_update,nextUpdate=next_update,entries=entries,signatureAlgorithm='Ed25519'),values,signer)
 fixtures={'revoked':crl([crl_entry()]),'clean':crl([]),'other-key':crl([crl_entry(fp=bytes([9])*32)]),'other-uid':crl([crl_entry(uid=124)]),'future':crl([crl_entry(at=now+1)]),
  'wrong-signer':crl([crl_entry()],signer=rk),'wrong-issuer':crl([crl_entry()],issuer=3),'expired':crl([],next_update=now-1),'future-issued':crl([],this_update=now+1),
  'duplicate':crl([crl_entry(),crl_entry()]),'unsorted':crl([crl_entry(uid=124),crl_entry()]),'too-many':crl([crl_entry(uid=uid) for uid in range(257)])}
 import copy
 for name,field,value in [('tampered','crlNumber',13),('bad-type','type','rootCRL'),('bad-algorithm','signatureAlgorithm','other'),('bad-number','crlNumber',12.5)]:
  fixtures[name]=copy.deepcopy(fixtures['revoked']);fixtures[name][field]=value
 fixtures['nul-key']=copy.deepcopy(fixtures['revoked']);fixtures['nul-key']['type\0x']=fixtures['nul-key'].pop('type')
 fixtures['bad-fingerprint']=copy.deepcopy(fixtures['revoked']);fixtures['bad-fingerprint']['entries'][0]['certFingerprint']='bad'
 fixtures['revoked13']=crl([crl_entry()],number=13)
 fixtures['cleared14']=crl([],number=14)
 fixtures['revoked15']=crl([crl_entry()],number=15)
 fixtures['large165']=crl([crl_entry(uid=uid) for uid in range(1,166)])
 fixtures['large256']=crl([crl_entry(uid=uid) for uid in range(1,257)])
 for name,value in fixtures.items():(p/('bundle.crl.'+name)).write_text(json.dumps(value))
 def write_proof(name,body):
  (p/('bundle.proof.bad.'+name)).write_bytes(b'FCP1'+bytes([1,0,0,0])+struct.pack('<I',len(body))+ik.sign(body)+body)
 signed_crl_values=['FMO',4,'intermediateCRL',2,12,now-10,now+1000,[[123,fingerprint,now-1,1]]]
 payload=cb(signed_crl_values);write_proof('noncanonical',payload[:5]+b'\x18\x04'+payload[6:])
 bad=signed_crl_values.copy();bad[2]='rootCRL';write_proof('wrong-domain',cb(bad))
 for name,entries in [('unsorted',[[124,fingerprint,now-1,1],[123,fingerprint,now-1,1]]),('duplicate',[[123,fingerprint,now-1,1]]*2),('overflow',[[2**32,fingerprint,now-1,1]]),('too-many',[[uid,fingerprint,now-1,1] for uid in range(257)])]:
  bad=signed_crl_values.copy();bad[-1]=entries;write_proof(name,cb(bad))
 write_proof('trailing',payload+b'\x00')
 # Root CRL binds to SHA256 of the intermediate's 20-value TBS, not its
 # JSON bytes or user certificate hash. Only the actual root may sign it.
 inter_fp=hashlib.sha256(cb(it)).digest()
 def root_entry(sn=2,fp=inter_fp,at=now-1):
  return dict(sn=sn,certFingerprint=b64(fp),revokedAt=at,reason=2)
 def root_crl(entries,signer=rk,issuer=1,this_update=now-10,next_update=now+1000):
  values=['FMO',4,'rootCRL',issuer,5,this_update,next_update,[[e['sn'],un64(e['certFingerprint']),e['revokedAt'],e['reason']] for e in entries]]
  return sign(dict(type='rootCRL',issuerSn=issuer,crlNumber=5,thisUpdate=this_update,nextUpdate=next_update,entries=entries,signatureAlgorithm='Ed25519'),values,signer)
 root_fixtures={'revoked':root_crl([root_entry()]),'clean':root_crl([]),'other-cert':root_crl([root_entry(fp=hashlib.sha256(json.dumps(i).encode()).digest())]),'other-sn':root_crl([root_entry(sn=3)]),'future':root_crl([root_entry(at=now+1)]),
  'wrong-signer':root_crl([root_entry()],signer=ik),'wrong-issuer':root_crl([root_entry()],issuer=2),'expired':root_crl([],next_update=now-1),'future-issued':root_crl([],this_update=now+1),
  'duplicate':root_crl([root_entry(),root_entry()]),'unsorted':root_crl([root_entry(sn=3),root_entry()]),'too-many':root_crl([root_entry(sn=sn) for sn in range(257)])}
 for name,field,value in [('tampered','crlNumber',6),('bad-type','type','intermediateCRL'),('bad-algorithm','signatureAlgorithm','other')]:
  root_fixtures[name]=copy.deepcopy(root_fixtures['revoked']);root_fixtures[name][field]=value
 for name,value in root_fixtures.items():(p/('bundle.root-crl.'+name)).write_text(json.dumps(value))
 packet=bytearray(83);struct.pack_into('<HII12sII I H I B I',packet,0,1,0x1001,123,b'BG0TEST',123400,123440,83,1,0,0,456);struct.pack_into('<HHIBH',packet,64,1,19,0,1,11);packet[80:]=b'\x4b\x10\x01';struct.pack_into('<I',packet,36,zlib.crc32(packet[64:]));(p/'packet').write_bytes(packet)
 station_key=key(4);station_tbs=['FMO',4,'userCert',2,'BG0SRV',150,pk(station_key),now-70,now+7000]
 station_blob=cb(station_tbs+[ik.sign(cb(station_tbs))])
 station_values=['FMO',4,'STATION','BG0SRV',15,'3037.98N','11932.20E',hashlib.sha256(station_blob).digest(),'CN','Test Relay','relay.example.test',1883,500,5,200,now//600]
 announcement='BG0SRV-15>APFMO4,TCPIP*:=3037.98N/11932.20EI FMO-V4,STATION,CERT:'+b64(station_blob)+',CN,Test Relay,relay.example.test,P1883,F500KM,U5/200,SIG:'+b64(station_key.sign(cb(station_values)))
 (p/'station').write_text(announcement)
 for suffix,issuer,bad_signature in [('unknown-issuer',9999,False),('bad-certificate',2,True)]:
  values=station_tbs.copy();values[3]=issuer;ca_signature=ik.sign(cb(values))
  if bad_signature:ca_signature=bytes([ca_signature[0]^1])+ca_signature[1:]
  blob=cb(values+[ca_signature]);message=station_values.copy();message[7]=hashlib.sha256(blob).digest()
  frame=announcement[:announcement.find('CERT:')+5]+b64(blob)+announcement[announcement.find(',CN,'):announcement.rfind('SIG:')]+'SIG:'+b64(station_key.sign(cb(message)))
  (p/('station.'+suffix)).write_text(frame)
 import copy
 alternate=copy.deepcopy(i);alternate['sn']=9999
 alternate_tbs=it.copy();alternate_tbs[3]=9999
 (p/'station.extra-issuer').write_text(json.dumps(sign(alternate,alternate_tbs,rk)))
 def peer_frame(kind='CQ',blob=station_blob,salt=now//600,latitude='3037.98N',server=456,ssid=15):
  values=['FMO',4,kind,'BG0SRV',ssid,latitude,'11932.20E',hashlib.sha256(blob).digest(),server,salt]
  return 'BG0SRV-'+str(ssid)+'>APFMO4,TCPIP*:='+latitude+'/11932.20EI FMO-V4,'+kind+',CERT:'+b64(blob)+',S'+str(server)+',SIG:'+b64(station_key.sign(cb(values)))
 for kind in ('CQ','OMCQ','VOCAL','ONLINE'):(p/('station.peer.'+kind)).write_text(peer_frame(kind))
 (p/'station.peer.window-minus').write_text(peer_frame(salt=now//600-1));(p/'station.peer.window-plus').write_text(peer_frame(salt=now//600+1))
 peer_bad={}
 fields=station_tbs.copy();fields[3]=9999;cross_blob=cb(fields+[ik.sign(cb(fields))]);peer_bad['wrong-issuer']=peer_frame(blob=cross_blob)
 peer_bad['bad-ca']=peer_frame(blob=station_blob[:-1]+bytes([station_blob[-1]^1]))
 peer_bad['noncanonical-cert']=peer_frame(blob=station_blob[:5]+b'\x18\x04'+station_blob[6:])
 fields=station_tbs.copy();fields[4]='BG0SRV\0extra';peer_bad['nul-cert-name']=peer_frame(blob=cb(fields+[ik.sign(cb(station_tbs))]))
 fields=station_tbs.copy();fields[-1]=now-1;peer_bad['expired-cert']=peer_frame(blob=cb(fields+[ik.sign(cb(fields))]))
 peer_bad['wrong-domain']=peer_frame().replace('FMO-V4,CQ,','FMO-V4,ONLINE,')
 peer_bad['bad-position']=peer_frame(latitude='3037x98N');peer_bad['extra-token']=peer_frame()+',S0'
 peer_bad['bad-ssid']=peer_frame(ssid=16);peer_bad['overflow-server']=peer_frame(server=2**32)
 for name,frame in peer_bad.items():(p/('station.peer.bad.'+name)).write_text(frame)
 def beacon_frame(height=None,rig=None,ant=None,freq='438.5000',latitude='3037.98N',longitude='11932.20E',salt=now//600,blob=station_blob):
  values=['FMO',4,'BEACON','BG0SRV',15,latitude,longitude,hashlib.sha256(blob).digest(),format(float(freq),'.4f')]
  fields=['FMO-V4','BEACON','CERT:'+b64(blob),'FREQ:'+freq]
  if height is not None:values.append(height);fields.append('HEIGHT:'+str(height))
  if rig is not None:values.append(rig);fields.append('RIG:'+rig)
  if ant is not None:values.append(ant);fields.append('ANT:'+ant)
  values.append(salt);fields.append('SIG:'+b64(station_key.sign(cb(values))))
  return 'BG0SRV-15>APFMO4,TCPIP*:='+latitude+'/'+longitude+'I '+','.join(fields)
 for mask in range(8):
  (p/('station.beacon.'+str(mask))).write_text(beacon_frame(15 if mask&1 else None,'FT-5DR' if mask&2 else None,'J型天线' if mask&4 else None))
 for suffix,frame in {
  'shortfreq':beacon_frame(freq='438.5'),
  'longtext':beacon_frame(rig='中文设备名'*3,ant='X'*40),
  'past':beacon_frame(salt=now//600-1),
  'future':beacon_frame(salt=now//600+1),
  'zeroheight':beacon_frame(height=0),
  'emptyrig':beacon_frame(rig=''),
  'emptyant':beacon_frame(ant=''),
  'overflowheight':beacon_frame(height=2**32),
  'negativeheight':beacon_frame(height=1).replace('HEIGHT:1','HEIGHT:-1'),
  'badca':beacon_frame(blob=station_blob[:-1]+bytes([station_blob[-1]^1])),
  'surrogate':beacon_frame(rig='Y').replace('RIG:Y','RIG:BAD'),
  'far':beacon_frame(latitude='3600.00N'),
  'badposition':beacon_frame(latitude='3060.00N'),
  'extrafield':beacon_frame()+',ANT:X',
  'badfreq':beacon_frame().replace('438.5000','438.50000'),
  'freqtamper':beacon_frame().replace('438.5000','145.5000'),
  'heighttamper':beacon_frame(height=15).replace('HEIGHT:15','HEIGHT:16'),
  'rigtamper':beacon_frame(rig='FT-5DR').replace('FT-5DR','FT-3DR'),
  'anttamper':beacon_frame(ant='J型天线').replace('J型天线','别的天线'),
  'reordered':beacon_frame(height=15,rig='FT-5DR').replace('HEIGHT:15,RIG:FT-5DR','RIG:FT-5DR,HEIGHT:15'),
  'duplicate':beacon_frame(height=15).replace('HEIGHT:15','HEIGHT:15,HEIGHT:15'),
 }.items():(p/('station.beacon.'+suffix)).write_text(frame)
 bad_utf8=b'\xc0\xaf'
 utf8_values=['FMO',4,'BEACON','BG0SRV',15,'3037.98N','11932.20E',hashlib.sha256(station_blob).digest(),'438.5000']
 utf8_tbs=b'\x8b'+b''.join(map(cb,utf8_values))+b'\x62'+bad_utf8+cb(now//600)
 utf8_frame=('BG0SRV-15>APFMO4,TCPIP*:=3037.98N/11932.20EI FMO-V4,BEACON,CERT:'+b64(station_blob)+',FREQ:438.5000,RIG:').encode()+bad_utf8+(',SIG:'+b64(station_key.sign(utf8_tbs))).encode()
 (p/'station.beacon.bad-utf8').write_bytes(utf8_frame)
 def event_frames(topic='周末通联活动',content='今晚八点,欢迎参加 <script>self.scene.run</script>',uid=150,salt=now//600,blob=station_blob,latitude='3037.98N'):
  status='FMO-V4,EVENT,'+str(uid)+','+topic+','+content
  digest=hashlib.sha256(status.encode()).digest()
  values=['FMO',4,'JOINT','BG0SRV',15,latitude,'11932.20E',hashlib.sha256(blob).digest(),digest,salt]
  joint='BG0SRV-15>APFMO4,TCPIP*:='+latitude+'/11932.20EI FMO-V4,JOINT,CERT:'+b64(blob)+',SH:'+b64(digest)+',SIG:'+b64(station_key.sign(cb(values)))
  return joint,'BG0SRV-15>APFMO4,TCPIP*:>'+status
 event_cases={'normal':{},'long':{'topic':'题'*32,'content':'🎙'*80},'past':{'salt':now//600-1},'future':{'salt':now//600+1},'topic-over':{'topic':'T'*33},'body-over':{'content':'C'*141},'max-topic':{'topic':'T'*32},'max-body':{'content':'C'*140},'empty':{'topic':'','content':''},'uid-over':{'uid':2**32},'uid-zero':{'uid':0},'other-uid':{'uid':151},'two':{'topic':'第二条','content':'第二份内容'},'three':{'topic':'第三条','content':'第三份内容'},'bad-ca':{'blob':station_blob[:-1]+bytes([station_blob[-1]^1])},'bad-position':{'latitude':'3037x98N'}}
 event_cases['cross-issuer']={'blob':cross_blob}
 for case,kwargs in event_cases.items():
  joint,status=event_frames(**kwargs)
  (p/('station.event.'+case+'.joint')).write_text(joint);(p/('station.event.'+case+'.status')).write_text(status)
 joint,status=event_frames()
 for case,frame in {'digest':joint.replace(',SH:',',SH:A',1),'domain':joint.replace('FMO-V4,JOINT,','FMO-V4,CQ,'),'coordinate':joint.replace('3037.98N','3037.99N'),'destination':joint.replace('APFMO4','APFMO4X'),'extra':joint+',SH:A'}.items():(p/('station.event.bad.'+case)).write_text(frame)
 raw=b'FMO-V4,EVENT,150,T,'+b'\xc0\xaf'
 values=['FMO',4,'JOINT','BG0SRV',15,'3037.98N','11932.20E',hashlib.sha256(station_blob).digest(),hashlib.sha256(raw).digest(),now//600]
 utf8_joint=joint[:joint.find(',SH:')]+',SH:'+b64(hashlib.sha256(raw).digest())+',SIG:'+b64(station_key.sign(cb(values)))
 (p/'station.event.utf8.joint').write_text(utf8_joint);(p/'station.event.utf8.status').write_bytes(b'BG0SRV-15>APFMO4,TCPIP*:>'+raw)
 station_values[-3]=6
 (p/'station.updated').write_text(announcement[:announcement.rfind('SIG:')].replace('U5/200','U6/200')+'SIG:'+b64(station_key.sign(cb(station_values))))
 subprocess.run(['c++','-std=c++17','-pthread','-Wall','-Wextra','-Werror','-Wno-misleading-indentation','-fsanitize=address,undefined','-g','-Imain','-Icomponents/passport_fmo/src','-Itests/vendor/cjson',str(p/'test.cc'),'components/passport_fmo/src/fmo_wire.cc','components/passport_fmo/src/fmo_crypto.cc','components/passport_fmo/src/fmo_revocation_service.cc','components/passport_fmo/src/fmo_aprs.cc','tests/vendor/cjson/cJSON.c','-lsodium','-o',str(p/'test')],cwd=root,check=True)
 subprocess.run([str(p/'test'),str(p/'root.json'),str(p/'bundle'),str(p/'seed'),str(p/'password'),str(p/'packet'),str(p/'station')],cwd=root,check=True)
 for name in ('large165','large256'):
  proof=(p/('bundle.proof.'+name)).read_bytes();assert proof[:8]==b'FCP1\x01\0\0\0' and struct.unpack_from('<I',proof,8)[0]==len(proof)-76
  Ed25519PublicKey.from_public_bytes(ipk).verify(proof[12:76],proof[76:])
  source_crl=fixtures[name];expected=['FMO',4,'intermediateCRL',2,12,now-10,now+1000,[[e['uid'],un64(e['certFingerprint']),e['revokedAt'],e['reason']] for e in source_crl['entries']]]
  assert proof[76:]==cb(expected)
 print('Independent Python compact proof header/complete CBOR/Ed25519 verification: PASS')

 auth=json.loads(un64((p/'password').read_text()));assert auth['certPackage']['userCert']==u
 proof=['FMO',4,'serverAuthorizerReqHttp',456,'BG0SRV',456,'user','relay.example.test',1883,bytes([7])*32,now,hashlib.sha256(cb(ut)).digest()]
 uk.public_key().verify(un64(auth['proof']['signature']),cb(proof))
 print('Independent Python CBOR/Ed25519 verification of generated SAS login proof: PASS')
 for suffix,kind in [('cq','CQ'),('beacon','BEACON')]:
  raw=(p/('password.'+suffix)).read_bytes();assert raw.endswith(b'\r\n') and len(raw)<=512
  frame=raw.decode().strip();assert frame.startswith('BG0TEST-1>APFMO4,TCPIP*:=3603.75NF12022.50Ei ')
  fields=frame.split(' FMO-V4,')[1].split(',');assert fields[0]==kind
  blob=un64(fields[1][5:]);assert blob==cb(ut+[un64(u['signature'])])
  tbs=['FMO',4,kind,'BG0TEST',1,'3603.75N','12022.50E',hashlib.sha256(blob).digest()]
  tbs+=([456] if kind=='CQ' else ['438.5000',15,'AI Passport','J'])
  tbs+=[now//600];uk.public_key().verify(un64(fields[-1][4:]),cb(tbs))
 print('Independent APRS CQ/BEACON CBOR, complete certificate blob and Ed25519 signature verification: PASS')

