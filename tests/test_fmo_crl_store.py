"""Signed CRL banks: real crypto/stdio with injected NVS and filesystem faults."""
from pathlib import Path
import hashlib,json,subprocess,tempfile
root=Path(__file__).resolve().parents[1]
context={'__file__':str(root/'tests/test_fmo.py')}
text=(root/'tests/test_fmo.py').read_text();exec(text[:text.index("source=r'''")],context)
cb,b64,sign=context['cb'],context['b64'],context['sign'];now=context['now'];fp=hashlib.sha256(cb(context['ut'])).digest()
def crl(number,revoked,large=False,root_level=False,future=False):
    entries=([dict(uid=n,certFingerprint=b64(bytes([9])*32),revokedAt=now-1,reason=1) for n in range(256)] if large else [])
    if revoked:entries=[dict(uid=123,certFingerprint=b64(fp),revokedAt=now+50 if future else now-1,reason=1)]
    kind='rootCRL' if root_level else 'intermediateCRL';issuer=1 if root_level else 2
    values=['FMO',4,kind,issuer,number,now-10,now+1000,[[e['uid'],context['un64'](e['certFingerprint']),e['revokedAt'],e['reason']] for e in entries]]
    return sign(dict(type=kind,issuerSn=issuer,crlNumber=number,thisUpdate=now-10,nextUpdate=now+1000,entries=entries,signatureAlgorithm='Ed25519'),values,context['rk'] if root_level else context['ik'])
source=r'''
#include "apps/fmo/fmo_crl_store.h"
#include "apps/fmo/fmo_wire.h"
#include "apps/home/home_storage.h"
#include "nvs.h"
#include <sodium.h>
#include <cassert>
#include <cstdio>
#include <cstring>
#include <map>
#include <set>
#include <string>
#include <vector>
#include <fstream>
#include <thread>
#include <sys/stat.h>
#include <unistd.h>
using namespace fmo;
std::map<std::string,std::vector<uint8_t>> persisted,pending;
bool fail_nvs_read=false,fail_nvs_write_open=false,fail_set=false,fail_commit=false,immediate_set=false;
unsigned nvs_handles=0;
int nvs_open(const char *name,int mode,int *out){assert(!strcmp(name,"fmo_os"));if((mode==NVS_READONLY&&fail_nvs_read)||(mode==NVS_READWRITE&&fail_nvs_write_open))return -1;*out=mode;++nvs_handles;return 0;}
void nvs_close(int){assert(nvs_handles);--nvs_handles;}
int nvs_get_blob(int,const char *key,void *out,size_t *size){if(fail_nvs_read)return -1;auto i=persisted.find(key);if(i==persisted.end())return ESP_ERR_NVS_NOT_FOUND;if(*size<i->second.size())return -1;*size=i->second.size();memcpy(out,i->second.data(),*size);return 0;}
int nvs_set_blob(int,const char *key,const void *data,size_t size){if(fail_set)return -1;const auto *p=static_cast<const uint8_t *>(data);pending[key]={p,p+size};if(immediate_set)persisted[key]=pending[key];return 0;}
int nvs_commit(int){if(fail_commit)return -1;for(auto &entry:pending)persisted[entry.first]=entry.second;pending.clear();return 0;}
std::string directory;bool locked=false,fail_mount=false;unsigned acquire_calls=0;bool requested_init=false;
extern "C" int home_storage_acquire(bool init){assert(!locked);++acquire_calls;requested_init=init;if(fail_mount)return -1;locked=true;return 0;}
extern "C" void home_storage_release(){assert(locked);locked=false;}
std::map<FILE*,std::string> files;std::set<FILE*> writers;
bool fail_write_open=false,fail_read_open=false,fail_read=false,fail_flush=false,fail_sync=false,fail_close=false,tamper_write=false;
long write_budget=-1;unsigned writes=0;
FILE *mock_open(const char *path,const char *mode){assert(locked&&files.empty());if((strchr(mode,'w')&&fail_write_open)||(!strchr(mode,'w')&&fail_read_open))return nullptr;FILE *f=::fopen(path,mode);if(f){files[f]=path;if(strchr(mode,'w'))writers.insert(f);}return f;}
size_t mock_write(const void *data,size_t size,size_t count,FILE *f){assert(size==1);++writes;size_t n=count;if(write_budget>=0){n=std::min(n,size_t(write_budget));write_budget-=n;}return ::fwrite(data,1,n,f);}
size_t mock_read(void *data,size_t size,size_t count,FILE *f){return fail_read?0:::fread(data,size,count,f);}
int mock_flush(FILE *f){const auto rc=::fflush(f);return fail_flush?-1:rc;}
int mock_sync(int fd){return fail_sync?-1:::fsync(fd);}
int mock_close(FILE *f){assert(files.count(f));const auto path=files[f];const bool writing=writers.erase(f);files.erase(f);const int rc=::fclose(f);if(writing&&tamper_write){FILE *g=::fopen(path.c_str(),"r+b");assert(g);assert(!fseek(g,12,SEEK_SET));int c=fgetc(g);assert(!fseek(g,12,SEEK_SET));fputc(c^1,g);::fclose(g);}return writing&&fail_close?-1:rc;}
#define FMO_CRL_BASE directory.c_str()
#define fopen mock_open
#define fread mock_read
#define fwrite mock_write
#define fflush mock_flush
#define fsync mock_sync
#define fclose mock_close
#include "STORE_SOURCE"
#undef fopen
#undef fread
#undef fwrite
#undef fflush
#undef fsync
#undef fclose
std::string read(const std::string &name){std::ifstream f(name,std::ios::binary);return {std::istreambuf_iterator<char>(f),{}};}
void flip(const std::string &name){FILE *f=fopen(name.c_str(),"r+b");assert(f);assert(!fseek(f,12,SEEK_SET));int c=fgetc(f);assert(!fseek(f,12,SEEK_SET));fputc(c^1,f);fclose(f);}
void reset_faults(){fail_nvs_read=fail_nvs_write_open=fail_set=fail_commit=immediate_set=false;fail_mount=fail_write_open=fail_read_open=fail_read=fail_flush=fail_sync=fail_close=tamper_write=false;write_budget=-1;writes=0;pending.clear();assert(!locked&&files.empty());}
std::vector<uint8_t> proof(const std::string &name,const Credential &identity,const std::string &root,bool root_tier=false){auto bytes=read(name);CrlStatus status;std::vector<uint8_t> out;assert(root_tier?verify_root_crl(reinterpret_cast<const uint8_t *>(bytes.data()),bytes.size(),identity,root.c_str(),1800000000,0,&status,&out):verify_user_crl(reinterpret_cast<const uint8_t *>(bytes.data()),bytes.size(),identity,root.c_str(),1800000000,0,&status,&out));return out;}
int main(int argc,char **argv){
 assert(argc==2&&sodium_init()>=0);const std::string base=argv[1];directory=base+"/banks";assert(!mkdir(directory.c_str(),0700));
 const auto root=read(base+"/root.json"),bundle=read(base+"/bundle.json"),pk=read(base+"/pubkey");Credential identity;std::string error;
 assert(pk.size()==32&&verify_bundle(reinterpret_cast<const uint8_t *>(bundle.data()),bundle.size(),root.c_str(),reinterpret_cast<const uint8_t *>(pk.data()),1800000000,&identity,&error));
 const auto old=proof(base+"/crl11.json",identity,root),revoked=proof(base+"/crl12.json",identity,root),large=proof(base+"/crl13.json",identity,root),newer=proof(base+"/crl14.json",identity,root),latest=proof(base+"/crl15.json",identity,root),same_version_other=proof(base+"/crl12other.json",identity,root),root_proof=proof(base+"/root5.json",identity,root,true);
 std::ofstream(directory+"/background-a.jpg")<<"existing background";std::ofstream(directory+"/portrait.bin")<<"legacy resource";
 persisted["seed"]={1,2,3};CrlCacheRecord record;
 assert(load_crl_cache(CrlLevel::User,identity,root.c_str(),1800000000,&record)==CrlCacheLoad::Missing&&acquire_calls==0);
 assert(load_crl_cache(CrlLevel::User,identity,root.c_str(),1800000000,nullptr)==CrlCacheLoad::Unavailable&&acquire_calls==0);
 assert(!save_crl_cache(CrlLevel::Root,identity,root.c_str(),1800000000,revoked.data(),revoked.size())&&acquire_calls==0);
 auto damaged=revoked;damaged[0]^=1;assert(!save_crl_cache(CrlLevel::User,identity,root.c_str(),1800000000,damaged.data(),damaged.size())&&acquire_calls==0);
 fail_mount=true;assert(!save_crl_cache(CrlLevel::User,identity,root.c_str(),1800000000,revoked.data(),revoked.size())&&!locked);reset_faults();
 assert(save_crl_cache(CrlLevel::User,identity,root.c_str(),1800000000,revoked.data(),revoked.size(),true)&&requested_init);
 assert(persisted["crl_user"].size()==96&&persisted["seed"]==std::vector<uint8_t>({1,2,3}));
 assert(load_crl_cache(CrlLevel::User,identity,root.c_str(),1800000000,&record)==CrlCacheLoad::Ready&&record.status.number==12&&record.status.revoked&&!requested_init);
 assert(load_crl_cache(CrlLevel::User,identity,root.c_str(),1800001001,&record)==CrlCacheLoad::Ready&&record.status.revoked&&record.status.next_update<1800001001);
 fail_mount=true;assert(load_crl_cache(CrlLevel::User,identity,root.c_str(),1800000000,&record)==CrlCacheLoad::Unavailable&&!record.data&&!record.size);reset_faults();
 assert(!save_crl_cache(CrlLevel::User,identity,root.c_str(),1800001001,revoked.data(),revoked.size())); // stale proofs recover, but are never newly published as fresh
 const auto old_metadata=persisted["crl_user"];
 assert(!save_crl_cache(CrlLevel::User,identity,root.c_str(),1800000000,old.data(),old.size()));
 assert(!save_crl_cache(CrlLevel::User,identity,root.c_str(),1800000000,same_version_other.data(),same_version_other.size()));
 for(unsigned failure=0;failure<11;++failure){
  reset_faults();switch(failure){case 0:fail_write_open=true;break;case 1:write_budget=600;break;case 2:fail_flush=true;break;case 3:fail_sync=true;break;case 4:fail_close=true;break;case 5:tamper_write=true;break;case 6:fail_read=true;break;case 7:fail_nvs_write_open=true;break;case 8:fail_set=true;break;case 9:fail_commit=true;break;case 10:fail_read_open=true;break;}
  assert(!save_crl_cache(CrlLevel::User,identity,root.c_str(),1800000000,large.data(),large.size()));assert(persisted["crl_user"]==old_metadata);reset_faults();
  assert(load_crl_cache(CrlLevel::User,identity,root.c_str(),1800000000,&record)==CrlCacheLoad::Ready&&record.status.number==12&&record.status.revoked);
 }
 fail_nvs_read=true;assert(!save_crl_cache(CrlLevel::User,identity,root.c_str(),1800000000,large.data(),large.size())&&writes==0);assert(load_crl_cache(CrlLevel::User,identity,root.c_str(),1800000000,&record)==CrlCacheLoad::Unavailable);reset_faults();
 immediate_set=true;fail_commit=true;assert(!save_crl_cache(CrlLevel::User,identity,root.c_str(),1800000000,large.data(),large.size()));reset_faults();
 assert(load_crl_cache(CrlLevel::User,identity,root.c_str(),1800000000,&record)==CrlCacheLoad::Ready&&record.status.number==13&&!record.status.revoked);
 assert(!read(directory+"/fmo-crl-user-a.fcp").empty()&&!read(directory+"/fmo-crl-user-b.fcp").empty());
 assert(save_crl_cache(CrlLevel::User,identity,root.c_str(),1800000000,newer.data(),newer.size()));
 auto metadata=persisted["crl_user"];auto active=directory+(metadata[5]?"/fmo-crl-user-b.fcp":"/fmo-crl-user-a.fcp");flip(active);
 assert(load_crl_cache(CrlLevel::User,identity,root.c_str(),1800000000,&record)==CrlCacheLoad::Unavailable); // never fall back from14 to13
 assert(save_crl_cache(CrlLevel::User,identity,root.c_str(),1800000000,newer.data(),newer.size()));
 assert(save_crl_cache(CrlLevel::User,identity,root.c_str(),1800000000,newer.data(),newer.size())); // identical authenticated backup
 metadata=persisted["crl_user"];active=directory+(metadata[5]?"/fmo-crl-user-b.fcp":"/fmo-crl-user-a.fcp");flip(active);
 assert(load_crl_cache(CrlLevel::User,identity,root.c_str(),1800000000,&record)==CrlCacheLoad::Ready&&record.status.number==14&&record.status.revoked);
 reset_faults();fail_read_open=true;assert(!save_crl_cache(CrlLevel::User,identity,root.c_str(),1800000000,latest.data(),latest.size())&&writes==0);reset_faults();
 assert(load_crl_cache(CrlLevel::User,identity,root.c_str(),1800000000,&record)==CrlCacheLoad::Ready&&record.status.number==14);
 reset_faults();write_budget=5;assert(!save_crl_cache(CrlLevel::User,identity,root.c_str(),1800000000,latest.data(),latest.size()));reset_faults();
 assert(load_crl_cache(CrlLevel::User,identity,root.c_str(),1800000000,&record)==CrlCacheLoad::Ready&&record.status.number==14&&record.status.revoked); // preserve sole valid fallback across failed replacement
 {std::ofstream restore(active,std::ios::binary);restore.write(reinterpret_cast<const char *>(newer.data()),newer.size());}flip(active);
 metadata=persisted["crl_user"];auto forged_metadata=metadata;const auto corrupted_file=read(active);crypto_hash_sha256(forged_metadata.data()+44,reinterpret_cast<const uint8_t *>(corrupted_file.data()),corrupted_file.size());
 uint32_t forged_crc=crc32(forged_metadata.data(),92);for(unsigned i=0;i<4;++i)forged_metadata[92+i]=forged_crc>>(8*i);persisted["crl_user"]=forged_metadata;
 assert(load_crl_cache(CrlLevel::User,identity,root.c_str(),1800000000,&record)==CrlCacheLoad::Unavailable&&!record.data&&!record.status.revoked);persisted["crl_user"]=metadata;
 auto other=identity;other.intermediate_fingerprint[0]^=1;assert(load_crl_cache(CrlLevel::User,other,root.c_str(),1800000000,&record)==CrlCacheLoad::Missing);
 metadata=persisted["crl_user"];
 for(size_t i=0;i<metadata.size();++i){persisted["crl_user"]=metadata;persisted["crl_user"][i]^=1;assert(load_crl_cache(CrlLevel::User,identity,root.c_str(),1800000000,&record)==CrlCacheLoad::Unavailable);assert(!save_crl_cache(CrlLevel::User,identity,root.c_str(),1800000000,newer.data(),newer.size()));}
 persisted["crl_user"]=metadata;persisted["crl_user"][76]=1;auto &bad=persisted["crl_user"];uint32_t sum=crc32(bad.data(),92);for(unsigned i=0;i<4;++i)bad[92+i]=sum>>(8*i);assert(load_crl_cache(CrlLevel::User,identity,root.c_str(),1800000000,&record)==CrlCacheLoad::Unavailable);persisted["crl_user"]=metadata;
 assert(save_crl_cache(CrlLevel::Root,identity,root.c_str(),1800000000,root_proof.data(),root_proof.size()));assert(load_crl_cache(CrlLevel::Root,identity,root.c_str(),1800000000,&record)==CrlCacheLoad::Ready&&!record.status.revoked);
 std::thread writer([&](){assert(save_crl_cache(CrlLevel::User,identity,root.c_str(),1800000000,latest.data(),latest.size()));});
 std::thread older_writer([&](){save_crl_cache(CrlLevel::User,identity,root.c_str(),1800000000,newer.data(),newer.size());});writer.join();older_writer.join();
 assert(load_crl_cache(CrlLevel::User,identity,root.c_str(),1800000000,&record)==CrlCacheLoad::Ready&&record.status.number==15&&!record.status.revoked);
 auto recovered=revocation_restore(identity,root.c_str(),1800000000);
 assert(recovered.root==CrlRestoreResult::Restored&&recovered.user==CrlRestoreResult::Restored&&revocation_state(identity,1800000000)==RevocationState::Current&&!requested_init);
 auto unrelated_identity=identity;unrelated_identity.root_fingerprint[0]^=1;revocation_bind(unrelated_identity);
 recovered=revocation_restore(identity,root.c_str(),1800001001);
 assert(recovered.user==CrlRestoreResult::Restored&&revocation_minimum(CrlLevel::User,identity)==15&&revocation_state(identity,1800001001)==RevocationState::Unknown);
 const auto future=proof(base+"/crl16.json",identity,root);
 assert(save_crl_cache(CrlLevel::User,identity,root.c_str(),1800000000,future.data(),future.size()));revocation_bind(unrelated_identity);
 recovered=revocation_restore(identity,root.c_str(),1800000051);
 assert(recovered.root==CrlRestoreResult::Restored&&recovered.user==CrlRestoreResult::Restored&&revocation_state(identity,1800000051)==RevocationState::Revoked&&revocation_session_state(identity,recovered.epoch,1800000051)==SessionRevocation::Revoked);
 auto saved_metadata=persisted["crl_user"];persisted["crl_user"][0]^=1;recovered=revocation_restore(identity,root.c_str(),1800000051);
 assert(recovered.user==CrlRestoreResult::Unavailable&&revocation_state(identity,1800000051)==RevocationState::Revoked);persisted["crl_user"]=saved_metadata;
 assert(read(directory+"/background-a.jpg")=="existing background"&&read(directory+"/portrait.bin")=="legacy resource"&&!locked&&files.empty()&&!nvs_handles);
 puts("FMO CRL banks: actual signed proofs/NVS metadata, partial write/flush/sync/close/readback/set/commit failures, publish-before-commit, no rollback fallback, exact backup recovery, scope/CRC/reserved checks, concurrent versions and user-file preservation PASS");
}
'''
source=source.replace('0:::fread','0: ::fread').replace('-1:::fsync','-1: ::fsync')
with tempfile.TemporaryDirectory(prefix='fmo-crl-store-') as d:
    p=Path(d);(p/'root.json').write_text(json.dumps(context['r']));(p/'bundle.json').write_text(json.dumps([context['i'],context['u']]));(p/'pubkey').write_bytes(context['upk'])
    for number in (11,12,13,14,15):(p/f'crl{number}.json').write_text(json.dumps(crl(number,number in (12,14),large=number==13)))
    (p/'crl16.json').write_text(json.dumps(crl(16,True,future=True)))
    (p/'crl12other.json').write_text(json.dumps(crl(12,False)));(p/'root5.json').write_text(json.dumps(crl(5,False,root_level=True)))
    (p/'esp_err.h').write_text('#pragma once\ntypedef int esp_err_t;\n#define ESP_OK 0\n#define ESP_FAIL -1\n')
    (p/'nvs.h').write_text('#pragma once\n#include <stddef.h>\n#include "esp_err.h"\ntypedef int nvs_handle_t;\n#define NVS_READONLY 0\n#define NVS_READWRITE 1\n#define ESP_ERR_NVS_NOT_FOUND 0x1102\nint nvs_open(const char*,int,int*);\nvoid nvs_close(int);\nint nvs_get_blob(int,const char*,void*,size_t*);\nint nvs_set_blob(int,const char*,const void*,size_t);\nint nvs_commit(int);\n')
    (p/'test.cc').write_text(source.replace('STORE_SOURCE',str(root/'main/apps/fmo/fmo_crl_store.cc')))
    subprocess.run(['c++','-std=c++17','-pthread','-Wall','-Wextra','-Werror','-Wno-misleading-indentation','-fsanitize=address,undefined','-g','-I'+d,'-Imain','-Itests/vendor/cjson',str(p/'test.cc'),'main/apps/fmo/fmo_crypto.cc','main/apps/fmo/fmo_wire.cc','main/apps/fmo/fmo_revocation_service.cc','main/apps/fmo/fmo_aprs.cc','tests/vendor/cjson/cJSON.c','-lsodium','-o',str(p/'test')],cwd=root,check=True)
    subprocess.run([str(p/'test'),d],cwd=root,check=True)
