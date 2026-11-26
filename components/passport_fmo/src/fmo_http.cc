#include "fmo_http.h"
#include "fmo_store.h"
#include "esp_http_client.h"
#include "esp_crt_bundle.h"
#include "esp_timer.h"
#include "wifi_manager.h"
#include <cJSON.h>
#include <atomic>
#include <algorithm>
#include <memory>
#include <string>
#include <vector>
#include <cstring>
#include <ctime>
#include "fmo_book.h"
#include "fmo_stamp.h"
#include "fmo_beep.h"
#include "fmo_aprs.h"
#include "fmo_revocation.h"
#include "fmo_crl_store.h"
#include "esp_heap_caps.h"
#include <new>
#include "fmo_host_bridge.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
extern const char fmo_root_start[] asm("_binary_passport_root_json_start");
namespace {
std::atomic<bool> busy{false};
struct Busy { Busy(){busy=true;} ~Busy(){busy=false;} };
using Json=std::unique_ptr<cJSON,decltype(&cJSON_Delete)>;
esp_err_t send(httpd_req_t *r,cJSON *o,int status=200){char *text=cJSON_PrintUnformatted(o);httpd_resp_set_type(r,"application/json");httpd_resp_set_hdr(r,"Cache-Control","no-store");if(status!=200)httpd_resp_set_status(r,"400 Bad Request");auto e=httpd_resp_sendstr(r,text?text:"{\"error\":\"oom\"}");cJSON_free(text);return e;}
esp_err_t fail(httpd_req_t *r,const char *text,const char *code=nullptr){Json j(cJSON_CreateObject(),cJSON_Delete);cJSON_AddStringToObject(j.get(),"error",text);if(code)cJSON_AddStringToObject(j.get(),"code",code);return send(r,j.get(),400);}
esp_err_t ca_fail(httpd_req_t *r,const char *text,const char *code=nullptr){
    // ESP-IDF otherwise purges unread request data after a successful handler
    // return. An aborted/slow photo must not extend our upstream deadline.
    httpd_resp_set_hdr(r,"Connection","close");
    const auto result=fail(r,text,code);
    return result==ESP_OK?ESP_FAIL:result;
}
const char *field(const cJSON *j,const char *key){const auto *s=cJSON_GetObjectItemCaseSensitive(j,key);return cJSON_IsString(s)?s->valuestring:nullptr;}
const char *ensure_ca_clock(){
    if(fmo_clock_valid())return nullptr;
    const bool owned=!fmo_clock_running();
    if(owned)fmo_clock_start();
    struct Release {bool owned;~Release(){if(owned)fmo_clock_stop();}} release{owned};
    const int64_t deadline=esp_timer_get_time()+10000000;
    for(;;){
        if(!WifiManager::GetInstance().HasStationIp())return "校时期间网络断开，请重新连接Wi-Fi";
        if(fmo_clock_valid())return nullptr;
        if(esp_timer_get_time()>=deadline)return "设备时间尚未校准，请重连Wi-Fi让手机校时，或检查网络NTP服务后重试";
        vTaskDelay(pdMS_TO_TICKS(100));
    }
}
const char *download_crl(const char *url,uint8_t *data,size_t capacity,size_t *used){
    *used=0;
    const int64_t deadline=esp_timer_get_time()+20000000;
    esp_http_client_config_t config{};config.url=url;config.method=HTTP_METHOD_GET;
    config.crt_bundle_attach=esp_crt_bundle_attach;config.disable_auto_redirect=true;
    config.timeout_ms=5000;config.buffer_size=512;config.buffer_size_tx=512;
    auto client=esp_http_client_init(&config);if(!client)return "下载连接内存不足";
    struct Close {esp_http_client_handle_t c;~Close(){esp_http_client_cleanup(c);}} close{client};
    if(esp_http_client_open(client,0)!=ESP_OK)return "无法连接吊销服务";
    if(esp_timer_get_time()>=deadline)return "吊销查询超时";
    const auto length=esp_http_client_fetch_headers(client);
    if(length<0||esp_http_client_get_status_code(client)!=200)return "吊销服务暂不可用";
    if(length>32768)return "吊销列表超过32KB上限";
    while(*used<capacity){
        if(!WifiManager::GetInstance().HasStationIp())return "吊销查询期间网络断开";
        if(esp_timer_get_time()>=deadline)return "吊销查询超时";
        const int n=esp_http_client_read(client,reinterpret_cast<char *>(data+*used),std::min<size_t>(512,capacity-*used));
        if(n<0)return "吊销列表读取失败";
        if(!n)return esp_http_client_is_complete_data_received(client)?nullptr:"吊销列表接收不完整";
        *used+=n;
        if(*used>32768)return "吊销列表超过32KB上限";
    }
    return "吊销列表超过32KB上限";
}
bool provider_crl_url(const char *url){
    constexpr char prefix[]="https://fmo.simy.live/ca/crl/";
    if(!url||std::strlen(url)>=256||std::strncmp(url,prefix,sizeof(prefix)-1))return false;
    const char *name=url+sizeof(prefix)-1;const size_t length=std::strlen(name);
    if(length<6||std::strcmp(name+length-5,".json")||std::strstr(name,".."))return false;
    for(const char *p=name;*p;++p){
        const auto c=static_cast<unsigned char>(*p);
        if(!((c>='a'&&c<='z')||(c>='A'&&c<='Z')||(c>='0'&&c<='9')||c=='-'||c=='_'||c=='.'))return false;
    }
    return true;
}
esp_err_t refresh_crls(httpd_req_t *r){
    if(!WifiManager::GetInstance().HasStationIp())return fail(r,"设备尚未连接可上网的Wi-Fi，请先连接路由器后再检查吊销列表","wifi_required");
    if(const char *error=ensure_ca_clock())return fail(r,error);
    std::string pub,error;fmo::Credential identity;
    if(!fmo::public_identity(&pub,&identity,&error))return fail(r,"请先取得有效的本机证书");
    static int64_t next_request=0;
    const int64_t now_us=esp_timer_get_time();
    if(now_us<next_request)return fail(r,"吊销查询请间隔15秒");
    next_request=now_us+15000000;
    if(heap_caps_get_free_size(MALLOC_CAP_8BIT)<98304||heap_caps_get_largest_free_block(MALLOC_CAP_8BIT)<32769)return fail(r,"空闲内存不足，请退出音频应用后重试");
    const auto restored=fmo::revocation_restore(identity,fmo_root_start,time(nullptr));
    Json root(cJSON_Parse(fmo_root_start),cJSON_Delete),inter(cJSON_Parse(identity.intermediate_json.c_str()),cJSON_Delete);
    Json report(cJSON_CreateObject(),cJSON_Delete);
    if(!root||!inter||!report)return fail(r,"吊销查询内存不足");
    for(unsigned level=0;level<2;++level){
        const auto kind=level?fmo::CrlLevel::User:fmo::CrlLevel::Root;
        const auto *cert=level?inter.get():root.get();
        const char *url=field(cJSON_GetObjectItemCaseSensitive(cert,"extensions"),"crl");
        const char *issue=nullptr;bool updated=false,saved=false;size_t used=0;
        std::unique_ptr<uint8_t[]> bytes;std::vector<uint8_t> proof;
        if(!provider_crl_url(url))issue="证书未提供支持的公开吊销地址";
        else {
            bytes.reset(new(std::nothrow) uint8_t[32769]);
            issue=bytes?download_crl(url,bytes.get(),32769,&used):"吊销查询内存不足";
        }
        // TLS is already closed before signature verification allocates CBOR.
        if(!issue&&(heap_caps_get_free_size(MALLOC_CAP_8BIT)<32768||heap_caps_get_largest_free_block(MALLOC_CAP_8BIT)<24576))issue="验签空闲内存不足";
        if(!issue){
            fmo::CrlStatus result;const uint32_t now=time(nullptr);
            const bool verified=level?fmo::verify_user_crl(bytes.get(),used,identity,fmo_root_start,now,fmo::revocation_minimum(kind,identity),&result,&proof):
                fmo::verify_root_crl(bytes.get(),used,identity,fmo_root_start,now,fmo::revocation_minimum(kind,identity),&result,&proof);
            if(!verified)issue="列表签名、格式、有效期或版本未通过验证";
            else if(!(updated=fmo::revocation_accept(kind,identity,result,now)))issue="列表版本与已有验证结果冲突";
            // Release the 32KB download buffer before file readback/crypto.
            bytes.reset();
            if(updated){
                saved=fmo::save_crl_cache(kind,identity,fmo_root_start,time(nullptr),proof.data(),proof.size(),true);
                if(!saved)issue="本次已验证，缓存保存未确认，重启后请再次检查";
            }
        }
        auto *item=cJSON_AddObjectToObject(report.get(),level?"user":"root");
        cJSON_AddBoolToObject(item,"updated",updated);cJSON_AddBoolToObject(item,"saved",saved);
        const auto cache=level?restored.user:restored.root;
        cJSON_AddStringToObject(item,"cache",cache==fmo::CrlRestoreResult::Restored?"restored":cache==fmo::CrlRestoreResult::Missing?"missing":"unavailable");
        cJSON_AddStringToObject(item,"message",issue?issue:"本次列表已验证");
    }
    const auto state=fmo::revocation_state(identity,time(nullptr));
    cJSON_AddStringToObject(report.get(),"state",state==fmo::RevocationState::Revoked?"revoked":state==fmo::RevocationState::Current?"current":"unknown");
    cJSON_AddStringToObject(report.get(),"persistence","signed_banks");cJSON_AddBoolToObject(report.get(),"enforced",true);
    return send(r,report.get());
}
const char *forward_photo(httpd_req_t *r,esp_http_client_handle_t client,int64_t deadline){
    char chunk[512];size_t sent=0;
    while(sent<static_cast<size_t>(r->content_len)){
        if(esp_timer_get_time()>deadline)return "申请上传超时，请重试";
        const int count=httpd_req_recv(r,chunk,std::min(sizeof(chunk),static_cast<size_t>(r->content_len)-sent));
        if(count<=0)return "申请上传中断";
        int written=0;
        while(written<count){
            // A slow upstream may consume only a few bytes per write. Check
            // every partial write, rather than once per 512-byte phone chunk.
            if(esp_timer_get_time()>deadline)return "申请上传超时，请重试";
            const int n=esp_http_client_write(client,chunk+written,count-written);
            if(n<=0)return "签发服务连接中断";
            written+=n;
        }
        sent+=count;
    }
    return nullptr;
}
esp_err_t status(httpd_req_t *r){
    std::string pub,error;fmo::Credential credential;const bool ready=fmo::public_identity(&pub,&credential,&error);
    Json j(cJSON_CreateObject(),cJSON_Delete);cJSON_AddStringToObject(j.get(),"pubkey",pub.c_str());cJSON_AddBoolToObject(j.get(),"ready",ready);cJSON_AddStringToObject(j.get(),"message",error.c_str());
    cJSON_AddBoolToObject(j.get(),"clock_valid",fmo_clock_valid());
    cJSON_AddBoolToObject(j.get(),"sta_connected",WifiManager::GetInstance().HasStationIp());
    if(ready){cJSON_AddStringToObject(j.get(),"callsign",credential.callsign);cJSON_AddNumberToObject(j.get(),"uid",credential.uid);cJSON_AddNumberToObject(j.get(),"expires",credential.expires);}
    {
        std::string legacy_call;uint32_t legacy_uid=0;
        const bool legacy_ok=!ready&&fmo::legacy_identity_available(&legacy_call,&legacy_uid);
        auto *lc=cJSON_AddObjectToObject(j.get(),"legacy_cred");
        cJSON_AddBoolToObject(lc,"available",legacy_ok);
        if(legacy_ok){cJSON_AddStringToObject(lc,"callsign",legacy_call.c_str());cJSON_AddNumberToObject(lc,"uid",legacy_uid);}
    }
    {
        fmo::StampConfig sc{};const auto sl=fmo::load_stamp_config(&sc);
        char hex[8];std::snprintf(hex,sizeof(hex),"#%06lX",static_cast<unsigned long>(sc.color_rgb&0xFFFFFFu));
        auto *st=cJSON_AddObjectToObject(j.get(),"stamp");
        cJSON_AddBoolToObject(st,"available",sl!=fmo::StampLoad::Unavailable);
        cJSON_AddStringToObject(st,"style_id",sc.style_id);
        cJSON_AddStringToObject(st,"color",hex);
        cJSON_AddStringToObject(st,"label",sc.label);
        cJSON_AddBoolToObject(st,"custom_present",sc.custom_present);
    }
    {
        fmo::BeepConfig bc{};const auto bl=fmo::load_beep_config(&bc);
        auto *bp=cJSON_AddObjectToObject(j.get(),"beep");
        cJSON_AddBoolToObject(bp,"available",bl!=fmo::BeepLoad::Unavailable);
        cJSON_AddBoolToObject(bp,"enabled",bc.enabled);
        cJSON_AddBoolToObject(bp,"use_custom",bc.use_custom);
        cJSON_AddBoolToObject(bp,"custom_present",bc.custom_present);
        cJSON_AddNumberToObject(bp,"custom_id",bc.custom_id);
        cJSON_AddNumberToObject(bp,"custom_samples",bc.custom_samples);
    }
    fmo::Relay relay{};const bool has_saved_relay=fmo::load_relay(&relay);
    if(has_saved_relay){auto *v=cJSON_AddObjectToObject(j.get(),"relay");cJSON_AddStringToObject(v,"host",relay.host);cJSON_AddStringToObject(v,"callsign",relay.callsign);cJSON_AddNumberToObject(v,"uid",relay.uid);cJSON_AddNumberToObject(v,"port",relay.port);cJSON_AddStringToObject(v,"fingerprint",fmo::base64url(relay.fingerprint,32).c_str());}
    {
        auto *br=cJSON_AddObjectToObject(j.get(),"builtin_relay");
        cJSON_AddStringToObject(br,"name",fmo::kBuiltinRelayName);
        cJSON_AddStringToObject(br,"host",fmo::kBuiltinRelayHost);
        cJSON_AddNumberToObject(br,"port",fmo::kBuiltinRelayPort);
        cJSON_AddBoolToObject(br,"active",!has_saved_relay);
    }
    const uint32_t now=time(nullptr);fmo::RelayList list;fmo::load_relay_cache(&list,now);auto *servers=cJSON_AddArrayToObject(j.get(),"servers");
    for(unsigned i=0;i<list.count;++i){const auto &r=list.relays[i];const auto &snapshot=list.status[i];auto *v=cJSON_CreateObject();cJSON_AddItemToArray(servers,v);cJSON_AddStringToObject(v,"name",r.name[0]?r.name:r.host);cJSON_AddStringToObject(v,"host",r.host);cJSON_AddStringToObject(v,"callsign",r.callsign);cJSON_AddNumberToObject(v,"uid",r.uid);cJSON_AddNumberToObject(v,"port",r.port);cJSON_AddNumberToObject(v,"valid_until",list.expires[i]);
        const bool known=snapshot.valid_until>now;cJSON_AddBoolToObject(v,"stats_known",known);
        if(known){cJSON_AddNumberToObject(v,"online",snapshot.online);cJSON_AddNumberToObject(v,"peak",snapshot.peak);cJSON_AddNumberToObject(v,"range_km",snapshot.range_km);}
    }
    fmo::BroadcastConfig config;const bool available=fmo::load_broadcast_config(&config);auto *v=cJSON_AddObjectToObject(j.get(),"aprs");
    cJSON_AddBoolToObject(v,"available",available);cJSON_AddBoolToObject(v,"enabled",available&&config.enabled);cJSON_AddBoolToObject(v,"legacy_beacon",config.legacy_beacon);
    cJSON_AddNumberToObject(v,"ssid",config.ssid);cJSON_AddNumberToObject(v,"antenna_height",config.antenna_height);
    cJSON_AddStringToObject(v,"grid",config.grid);cJSON_AddStringToObject(v,"frequency",config.frequency);cJSON_AddStringToObject(v,"rig",config.rig);cJSON_AddStringToObject(v,"antenna",config.antenna);
    return send(r,j.get());
}
esp_err_t contact_status(httpd_req_t *r,unsigned page){
    Json j(cJSON_CreateObject(),cJSON_Delete);
    auto book=std::make_unique<fmo::ContactBook>();const auto loaded=fmo::load_contact_book(book.get());
    auto psty=std::make_unique<fmo::PeerStamps>();const bool has_psty=psty&&fmo::load_peer_stamps(psty.get())==fmo::StampLoad::Ready;
    cJSON_AddBoolToObject(j.get(),"contacts_available",loaded!=fmo::BookLoad::Unavailable);
    cJSON_AddNumberToObject(j.get(),"contacts_capacity",fmo::ContactBook::capacity);
    cJSON_AddNumberToObject(j.get(),"total",loaded==fmo::BookLoad::Ready?book->count:0);
    auto *contacts=cJSON_AddArrayToObject(j.get(),"contacts");
    if(loaded==fmo::BookLoad::Ready)for(unsigned i=page*8;i<book->count&&i<(page+1)*8;++i){const auto &c=book->contacts[i];auto *v=cJSON_CreateObject();cJSON_AddItemToArray(contacts,v);
        cJSON_AddStringToObject(v,"callsign",c.callsign);cJSON_AddNumberToObject(v,"uid",c.uid);cJSON_AddNumberToObject(v,"relay_uid",c.relay_uid);
        cJSON_AddNumberToObject(v,"first_seen",c.first_seen);cJSON_AddNumberToObject(v,"last_seen",c.last_seen);cJSON_AddNumberToObject(v,"receptions",c.receptions);
        const char *sty=has_psty?psty->find(c.callsign):nullptr;
        cJSON_AddStringToObject(v,"stamp_style",sty?sty:fmo::stamp_builtin_id(fmo::stamp_fallback_index(c.callsign)));
    }
    return send(r,j.get());
}
esp_err_t restore_contacts(httpd_req_t *r,const cJSON *request){
    const auto *version=cJSON_GetObjectItemCaseSensitive(request,"v");
    const auto *entries=cJSON_GetObjectItemCaseSensitive(request,"contacts");
    if(!cJSON_IsNumber(version)||version->valuedouble!=1||!cJSON_IsArray(entries)||
       cJSON_GetArraySize(entries)>static_cast<int>(fmo::ContactBook::capacity))return fail(r,"抄收备份格式无效");
    std::unique_ptr<fmo::ContactBook> book(new(std::nothrow) fmo::ContactBook);
    if(!book||fmo::load_contact_book(book.get())==fmo::BookLoad::Unavailable)return fail(r,"现有抄收册暂不可读");
    std::unique_ptr<fmo::PeerStamps> styles(new(std::nothrow) fmo::PeerStamps);
    const bool styles_available=styles&&fmo::load_peer_stamps(styles.get())!=fmo::StampLoad::Unavailable;
    auto number=[](const cJSON *entry,const char *key,uint32_t &out){
        const auto *value=cJSON_GetObjectItemCaseSensitive(entry,key);
        if(!cJSON_IsNumber(value)||!(value->valuedouble>=0&&value->valuedouble<=UINT32_MAX))return false;
        out=static_cast<uint32_t>(value->valuedouble);
        return out==value->valuedouble;
    };
    unsigned added=0,skipped=0,styles_added=0,styles_skipped=0;
    const cJSON *entry;
    cJSON_ArrayForEach(entry,entries){
        fmo::Contact c;
        const char *call=field(entry,"callsign");
        if(!call||strnlen(call,13)<2||strnlen(call,13)>12||
           !number(entry,"uid",c.uid)||!c.uid||!number(entry,"relay_uid",c.relay_uid)||!c.relay_uid||
           !number(entry,"first_seen",c.first_seen)||c.first_seen<1700000000||
           !number(entry,"last_seen",c.last_seen)||c.last_seen<c.first_seen||
           !number(entry,"receptions",c.receptions)||!c.receptions)return fail(r,"抄收记录字段无效");
        for(const char *p=call;*p;++p)
            if(!((*p>='A'&&*p<='Z')||(*p>='0'&&*p<='9')||*p=='/'||*p=='-'))return fail(r,"抄收记录呼号无效");
        const auto *style_field=cJSON_GetObjectItemCaseSensitive(entry,"stamp_style");
        const char *style=field(entry,"stamp_style");
        if(style_field&&!fmo::stamp_style_valid(style))return fail(r,"印章样式编号无效");
        // Older exports carry the UTC receipt time, but no replay cursor.
        c.last_stream=c.last_seen*1000u;
        std::strcpy(c.callsign,call);
        unsigned slot=0;
        while(slot<book->count&&(book->contacts[slot].uid!=c.uid||std::strcmp(book->contacts[slot].callsign,c.callsign)))++slot;
        const bool retained=slot<book->count||book->count<fmo::ContactBook::capacity;
        if(slot<book->count||!retained)++skipped;
        else {book->contacts[book->count++]=c;++added;}
        if(style){
            if(retained&&styles_available&&styles->count<fmo::PeerStamps::capacity&&
               !styles->find(call)&&styles->remember(call,style))++styles_added;
            else ++styles_skipped;
        }
    }
    Json result(cJSON_CreateObject(),cJSON_Delete);
    if(!result)return fail(r,"抄收备份导入内存不足");
    if(added&&!fmo::save_contact_book(*book))return fail(r,"抄收备份保存失败");
    const bool styles_saved=!styles_added||fmo::save_peer_stamps(*styles);
    if(!styles_saved){styles_skipped+=styles_added;styles_added=0;}
    cJSON_AddNumberToObject(result.get(),"added",added);
    cJSON_AddNumberToObject(result.get(),"skipped",skipped);
    cJSON_AddNumberToObject(result.get(),"styles_added",styles_added);
    cJSON_AddNumberToObject(result.get(),"styles_skipped",styles_skipped);
    cJSON_AddBoolToObject(result.get(),"styles_saved",styles_saved);
    return send(r,result.get());
}
}
bool fmo_http_busy(){return busy.load();}
esp_err_t fmo_http_settings(httpd_req_t *r){
    if(r->method==HTTP_GET){
        char query[256]{},page[4]{};
        if(httpd_req_get_url_query_str(r,query,sizeof(query))==ESP_OK&&httpd_query_key_value(query,"book",page,sizeof(page))==ESP_OK){
            if(page[0]<'0'||page[0]>'7'||page[1])return fail(r,"抄收册页码无效");
            return contact_status(r,page[0]-'0');
        }
        return status(r);
    }
    Busy scope;
    if(r->content_len<=0||r->content_len>18000)return fail(r,"FMO配置数据过大");
    std::vector<char> body(r->content_len+1,0);size_t at=0;
    while(at<static_cast<size_t>(r->content_len)){int n=httpd_req_recv(r,body.data()+at,r->content_len-at);if(n<=0)return fail(r,"FMO配置接收中断");at+=n;}
    // Bound parser recursion before accepting a phone request.
    unsigned depth=0;bool quoted=false,escaped=false;
    for(size_t i=0;i<at;++i){char c=body[i];if(quoted){if(escaped)escaped=false;else if(c=='\\')escaped=true;else if(c=='"')quoted=false;}else if(c=='"')quoted=true;else if(c=='{'||c=='['){if(++depth>16)return fail(r,"FMO配置嵌套过深");}else if(c=='}'||c==']'){if(!depth)return fail(r,"FMO配置格式无效");--depth;}}
    Json j(cJSON_Parse(body.data()),cJSON_Delete);const char *action=field(j.get(),"action");std::string error;
    if(!action)return fail(r,"FMO操作无效");
    if(!std::strcmp(action,"restore_contacts"))return restore_contacts(r,j.get());
    if(!std::strcmp(action,"check_crl"))return refresh_crls(r);
    if(!std::strcmp(action,"aprs")){
        fmo::BroadcastConfig c;const auto *enabled=cJSON_GetObjectItemCaseSensitive(j.get(),"enabled"),*legacy=cJSON_GetObjectItemCaseSensitive(j.get(),"legacy_beacon"),*ssid=cJSON_GetObjectItemCaseSensitive(j.get(),"ssid"),*height=cJSON_GetObjectItemCaseSensitive(j.get(),"antenna_height");
        const char *grid=field(j.get(),"grid"),*freq=field(j.get(),"frequency"),*rig=field(j.get(),"rig"),*ant=field(j.get(),"antenna");
        if(!cJSON_IsBool(enabled)||!cJSON_IsBool(legacy)||!cJSON_IsNumber(ssid)||ssid->valuedouble<0||ssid->valuedouble>15||ssid->valuedouble!=ssid->valueint||!cJSON_IsNumber(height)||height->valuedouble<0||height->valuedouble>999||height->valuedouble!=height->valueint||!grid||std::strlen(grid)>8||!freq||std::strlen(freq)>15||!rig||std::strlen(rig)>24||!ant||std::strlen(ant)>24)return fail(r,"APRS参数无效");
        c.enabled=cJSON_IsTrue(enabled);c.legacy_beacon=cJSON_IsTrue(legacy);c.ssid=ssid->valueint;c.antenna_height=height->valueint;
        std::strcpy(c.grid,grid);std::strcpy(c.frequency,freq);std::strcpy(c.rig,rig);std::strcpy(c.antenna,ant);
        if(!fmo::broadcast_config_valid(c))return fail(r,"请检查4/6/8位网格、100至1300MHz频率及无逗号的设备/天线信息");
        if(!fmo::save_broadcast_config(c))return fail(r,"APRS设置保存失败，原设置未确认更改");
    }else if(!std::strcmp(action,"init")){if(!fmo::create_identity(&error))return fail(r,error.c_str());}
    else if(!std::strcmp(action,"import_legacy")){
        if(!fmo::import_legacy_identity(&error))return fail(r,error.c_str());
    }else if(!std::strcmp(action,"stamp")){
        const char *style_id=field(j.get(),"style_id"),*color=field(j.get(),"color"),*label=field(j.get(),"label");
        if(!style_id||!fmo::stamp_style_valid(style_id)||!color||std::strlen(color)!=7||color[0]!='#'||!label||!fmo::stamp_label_valid(label))return fail(r,"印章样式、颜色或铭文参数无效");
        uint32_t rgb=0;
        for(unsigned i=1;i<7;++i){
            const char c=color[i];
            unsigned v=(c>='0'&&c<='9')?c-'0':(c>='A'&&c<='F')?10+c-'A':(c>='a'&&c<='f')?10+c-'a':16;
            if(v>=16)return fail(r,"印章颜色格式应为 #RRGGBB");
            rgb=(rgb<<4)|v;
        }
        fmo::StampConfig cfg{};
        if(fmo::load_stamp_config(&cfg)==fmo::StampLoad::Unavailable)return fail(r,"印章配置暂不可读，未覆盖原配置");
        if(fmo::stamp_is_custom_style(style_id)&&!cfg.custom_present)return fail(r,"尚未上传定制印章图案，请先上传图片");
        std::strcpy(cfg.style_id,style_id);cfg.color_rgb=rgb;std::strcpy(cfg.label,label);
        if(!fmo::save_stamp_config(cfg))return fail(r,"印章配置保存失败，请重试");
    }else if(!std::strcmp(action,"import")){
        const char *cert=field(j.get(),"certificate");if(!cert||std::strlen(cert)>16384)return fail(r,"证书数据无效");
        std::vector<uint8_t> bytes(12288);size_t n;
        if(!fmo::unbase64(cert,bytes.data(),bytes.size(),&n))return fail(r,"证书编码无效");
        if(!fmo::import_certificate(bytes.data(),n,&error))return fail(r,error.c_str());
    }else if(!std::strcmp(action,"beep")){
        const auto *en=cJSON_GetObjectItemCaseSensitive(j.get(),"enabled"),*uc=cJSON_GetObjectItemCaseSensitive(j.get(),"use_custom");
        if(!cJSON_IsBool(en)||(uc&&!cJSON_IsBool(uc)))return fail(r,"结束信令音参数无效");
        fmo::BeepConfig cfg{};
        if(fmo::load_beep_config(&cfg)==fmo::BeepLoad::Unavailable)return fail(r,"信令音配置暂不可读，未覆盖原配置");
        cfg.enabled=cJSON_IsTrue(en);
        if(uc){
            const bool want_custom=cJSON_IsTrue(uc);
            if(want_custom&&!cfg.custom_present)return fail(r,"尚未下载自定义信令音，请先下载");
            cfg.use_custom=want_custom;
        }
        if(!fmo::save_beep_config(cfg))return fail(r,"信令音配置保存失败，请重试");
    }else if(!std::strcmp(action,"select_builtin_relay")){
        if(!fmo::clear_relay(&error))return fail(r,error.c_str());
    }else if(!std::strcmp(action,"select_relay")){
        const auto *uid=cJSON_GetObjectItemCaseSensitive(j.get(),"uid");
        if(!cJSON_IsNumber(uid)||uid->valuedouble<1||uid->valuedouble>UINT32_MAX||uid->valuedouble!=static_cast<uint32_t>(uid->valuedouble))return fail(r,"服务器选择无效");
        fmo::RelayList list;fmo::load_relay_cache(&list,time(nullptr));const int index=list.find(uid->valuedouble);
        if(index<0)return fail(r,"服务器信息已过期，请回到设备FMO重新获取");
        if(!fmo::save_relay(list.relays[index],&error))return fail(r,error.c_str());
    }else if(!std::strcmp(action,"relay")){
        fmo::Relay relay{};const char *host=field(j.get(),"host"),*call=field(j.get(),"callsign"),*fp=field(j.get(),"fingerprint");
        const auto *uid=cJSON_GetObjectItemCaseSensitive(j.get(),"uid"),*port=cJSON_GetObjectItemCaseSensitive(j.get(),"port");size_t n;
        if(!host||!call||!fp||std::strlen(host)>=sizeof(relay.host)||std::strlen(call)>12||!cJSON_IsNumber(uid)||uid->valuedouble<1||uid->valuedouble>UINT32_MAX||uid->valuedouble!=static_cast<uint32_t>(uid->valuedouble)||!cJSON_IsNumber(port)||port->valuedouble<1||port->valuedouble>65535||port->valuedouble!=port->valueint||!fmo::unbase64(fp,relay.fingerprint,32,&n)||n!=32)return fail(r,"中继参数无效");
        std::strcpy(relay.host,host);std::strcpy(relay.callsign,call);relay.uid=uid->valuedouble;relay.port=port->valueint;
        if(!fmo::save_relay(relay,&error))return fail(r,error.c_str());
    }else return fail(r,"不支持的FMO操作");
    return status(r);
}
esp_err_t fmo_http_ca(httpd_req_t *r){
    Busy scope;
    // Includes the optional 10-second clock bootstrap. Individual network
    // calls time out after 12 seconds, within the phone's 90-second budget.
    const int64_t deadline=esp_timer_get_time()+70000000;
    if(!WifiManager::GetInstance().HasStationIp())return ca_fail(r,"设备尚未连接可上网的Wi-Fi，请先连接路由器后再申请证书","wifi_required");
    const bool apply=r->method==HTTP_POST;
    if(apply&&(r->content_len<=0||r->content_len>196608))return ca_fail(r,"申请图片或数据过大，请重新压缩");
    if(const char *clock_error=ensure_ca_clock())return ca_fail(r,clock_error);
    // Read validity/fingerprint only after time is ready, including a clock
    // update that raced with this request's arrival.
    std::string pub,error;fmo::Credential credential;fmo::public_identity(&pub,&credential,&error);
    if(pub.empty())return ca_fail(r,"请先初始化FMO身份");
    std::string url="https://fmo.simy.live/ca/";
    url+=apply?"apply":"status?pk="+pub;
    if(!apply&&credential.uid)url+="&fp="+fmo::base64url(credential.fingerprint,32);
    esp_http_client_config_t config{};config.url=url.c_str();config.method=apply?HTTP_METHOD_POST:HTTP_METHOD_GET;config.crt_bundle_attach=esp_crt_bundle_attach;config.timeout_ms=12000;config.buffer_size=512;config.buffer_size_tx=512;config.disable_auto_redirect=true;
    auto client=esp_http_client_init(&config);if(!client)return ca_fail(r,"签发连接内存不足，请稍后再试");
    struct Close {esp_http_client_handle_t c;~Close(){esp_http_client_cleanup(c);}} close{client};
    esp_http_client_set_header(client,"Content-Type","application/json");
    if(esp_http_client_open(client,apply?r->content_len:0)!=ESP_OK)return ca_fail(r,"无法连接签发服务，请检查网络和设备时间");
    if(apply)if(const char *upload_error=forward_photo(r,client,deadline))return ca_fail(r,upload_error);
    if(esp_timer_get_time()>deadline)return ca_fail(r,"签发请求超时，请重试");
    if(esp_http_client_fetch_headers(client)<0)return ca_fail(r,"签发服务没有返回有效响应");
    std::vector<char> response(17000,0);size_t used=0;
    for(;;){if(esp_timer_get_time()>deadline)return ca_fail(r,"签发服务响应超时");int n=esp_http_client_read(client,response.data()+used,response.size()-1-used);if(n<0)return ca_fail(r,"签发服务响应中断");if(!n)break;used+=n;if(used==response.size()-1)return ca_fail(r,"证书服务响应过大，未导入");}
    if(!esp_http_client_is_complete_data_received(client))return ca_fail(r,"签发服务响应不完整");
    const int code=esp_http_client_get_status_code(client);
    // Forward JSON as data. Never execute remote text or follow redirects to another service.
    if(code<200||code>=300)return ca_fail(r,"签发服务拒绝或暂不可用，请稍后查询申请状态");
    httpd_resp_set_type(r,"application/json");httpd_resp_set_hdr(r,"Cache-Control","no-store");return httpd_resp_send(r,response.data(),used);
}
esp_err_t fmo_http_stamp(httpd_req_t *r){
    if(r->method==HTTP_GET){
        fmo::StampConfig cfg{};const auto loaded=fmo::load_stamp_config(&cfg);
        char query[96]{},raw_flag[8]{};
        if(httpd_req_get_url_query_str(r,query,sizeof(query))==ESP_OK&&httpd_query_key_value(query,"raw",raw_flag,sizeof(raw_flag))==ESP_OK&&!std::strcmp(raw_flag,"1")){
            if(loaded!=fmo::StampLoad::Ready||!cfg.custom_present)return fail(r,"尚未保存定制印章图案");
            std::unique_ptr<uint8_t[]> pixels(new(std::nothrow) uint8_t[fmo::kStampPixelBytes]);
            if(!pixels)return fail(r,"读取印章内存不足");
            if(fmo::load_custom_stamp_image(cfg,pixels.get())!=fmo::StampLoad::Ready)return fail(r,"定制印章文件不可读");
            httpd_resp_set_type(r,"application/octet-stream");httpd_resp_set_hdr(r,"Cache-Control","no-store");
            return httpd_resp_send(r,reinterpret_cast<const char *>(pixels.get()),fmo::kStampPixelBytes);
        }
        Json j(cJSON_CreateObject(),cJSON_Delete);
        char hex[8];std::snprintf(hex,sizeof(hex),"#%06lX",static_cast<unsigned long>(cfg.color_rgb&0xFFFFFFu));
        cJSON_AddBoolToObject(j.get(),"available",loaded!=fmo::StampLoad::Unavailable);
        cJSON_AddStringToObject(j.get(),"style_id",cfg.style_id);
        cJSON_AddStringToObject(j.get(),"color",hex);
        cJSON_AddStringToObject(j.get(),"label",cfg.label);
        cJSON_AddBoolToObject(j.get(),"custom_present",cfg.custom_present);
        cJSON_AddNumberToObject(j.get(),"width",fmo::kStampWidth);
        cJSON_AddNumberToObject(j.get(),"height",fmo::kStampHeight);
        cJSON_AddNumberToObject(j.get(),"bytes",fmo::kStampPixelBytes);
        return send(r,j.get());
    }
    Busy scope;
    if(r->method==HTTP_DELETE){
        fmo::StampConfig cfg{};
        if(!fmo::clear_custom_stamp_image(&cfg))return fail(r,"清除定制印章失败，原数据未确认改动");
        return status(r);
    }
    if(r->content_len!=static_cast<int>(fmo::kStampPixelBytes))return fail(r,"定制印章点阵长度无效（应为 96×96 4位灰度 4608 字节）");
    std::unique_ptr<uint8_t[]> pixels(new(std::nothrow) uint8_t[fmo::kStampPixelBytes]);
    if(!pixels)return fail(r,"印章上传内存不足");
    size_t received=0;
    const int64_t deadline=esp_timer_get_time()+60000000;
    while(received<fmo::kStampPixelBytes){
        if(esp_timer_get_time()>deadline)return fail(r,"定制印章上传超时，请重试");
        const int n=httpd_req_recv(r,reinterpret_cast<char *>(pixels.get()+received),std::min<size_t>(512,fmo::kStampPixelBytes-received));
        if(n<=0)return fail(r,"定制印章上传中断，请重试");
        received+=n;
    }
    if(!fmo::stamp_pixels_nonempty(pixels.get()))return fail(r,"印章图案几乎为空白，请调整去底阈值或更换高对比度图案");
    fmo::StampConfig cfg{};
    if(fmo::load_stamp_config(&cfg)==fmo::StampLoad::Unavailable)return fail(r,"印章配置不可读，未覆盖原数据");
    if(!fmo::save_custom_stamp_image(pixels.get(),&cfg,true))return fail(r,"定制印章保存未确认，请检查存储后重试");
    return status(r);
}
esp_err_t fmo_http_beep(httpd_req_t *r){
    if(r->method==HTTP_GET){
        fmo::BeepConfig cfg{};const auto loaded=fmo::load_beep_config(&cfg);
        Json j(cJSON_CreateObject(),cJSON_Delete);
        cJSON_AddBoolToObject(j.get(),"available",loaded!=fmo::BeepLoad::Unavailable);
        cJSON_AddBoolToObject(j.get(),"enabled",cfg.enabled);
        cJSON_AddBoolToObject(j.get(),"use_custom",cfg.use_custom);
        cJSON_AddBoolToObject(j.get(),"custom_present",cfg.custom_present);
        cJSON_AddNumberToObject(j.get(),"custom_id",cfg.custom_id);
        cJSON_AddNumberToObject(j.get(),"custom_samples",cfg.custom_samples);
        cJSON_AddNumberToObject(j.get(),"max_bytes",fmo::kBeepMaxFileBytes);
        return send(r,j.get());
    }
    Busy scope;
    if(r->method==HTTP_DELETE){
        fmo::BeepConfig cfg{};
        if(!fmo::clear_custom_beep(&cfg))return fail(r,"清除自定义信令音失败，原数据未确认改动");
        return status(r);
    }
    if(r->content_len<=0||static_cast<size_t>(r->content_len)>fmo::kBeepMaxFileBytes){
        return fail(r,"信令音文件过大或为空（上限 3 秒 / 48 KB）");
    }
    // Small JSON command: {"download_id": N} to fetch https://fmo.simy.live/fw/beep/<N>.bin directly on device.
    char ctype[64]{};
    const bool is_json=(httpd_req_get_hdr_value_str(r,"Content-Type",ctype,sizeof(ctype))==ESP_OK&&std::strstr(ctype,"application/json")!=nullptr);
    if(is_json&&r->content_len<=256){
        char body[257]{};size_t at=0;
        while(at<static_cast<size_t>(r->content_len)){
            const int n=httpd_req_recv(r,body+at,r->content_len-at);
            if(n<=0)return fail(r,"信令音请求接收中断");
            at+=n;
        }
        Json j(cJSON_Parse(body),cJSON_Delete);
        const auto *did=cJSON_GetObjectItemCaseSensitive(j.get(),"download_id");
        if(!cJSON_IsNumber(did)||did->valuedouble<1||did->valuedouble>255||did->valuedouble!=did->valueint){
            return fail(r,"云端信令音编号无效");
        }
        if(!WifiManager::GetInstance().HasStationIp()){
            return fail(r,"设备尚未连接可上网的Wi-Fi，请先连接路由器后再下载云端信令音","wifi_required");
        }
        if(heap_caps_get_free_size(MALLOC_CAP_8BIT)<98304){
            return fail(r,"空闲内存不足，请稍后重试");
        }
        char url[96];
        std::snprintf(url,sizeof(url),"https://fmo.simy.live/fw/beep/%u.bin",static_cast<unsigned>(did->valueint));
        esp_http_client_config_t config{};
        config.url=url;config.method=HTTP_METHOD_GET;
        config.crt_bundle_attach=esp_crt_bundle_attach;config.disable_auto_redirect=true;
        config.timeout_ms=10000;config.buffer_size=512;config.buffer_size_tx=512;
        auto client=esp_http_client_init(&config);
        if(!client)return fail(r,"信令音下载连接内存不足");
        struct Close {esp_http_client_handle_t c;~Close(){if(c)esp_http_client_cleanup(c);}} close{client};
        const int64_t deadline=esp_timer_get_time()+25000000;
        if(esp_http_client_open(client,0)!=ESP_OK)return fail(r,"无法连接信令音服务器");
        const auto length=esp_http_client_fetch_headers(client);
        if(length<=0||esp_http_client_get_status_code(client)!=200)return fail(r,"云端信令音不存在或暂不可用");
        if(static_cast<size_t>(length)>fmo::kBeepMaxFileBytes)return fail(r,"云端信令音超过3秒上限");
        std::unique_ptr<uint8_t[]> data(new(std::nothrow) uint8_t[static_cast<size_t>(length)]);
        if(!data)return fail(r,"信令音下载内存不足");
        size_t got=0;
        while(got<static_cast<size_t>(length)){
            if(!WifiManager::GetInstance().HasStationIp())return fail(r,"下载期间网络断开");
            if(esp_timer_get_time()>deadline)return fail(r,"信令音下载超时，请重试");
            const int n=esp_http_client_read(client,reinterpret_cast<char *>(data.get()+got),std::min<size_t>(512,static_cast<size_t>(length)-got));
            if(n<=0)return fail(r,"信令音下载中断");
            got+=n;
        }
        if(!esp_http_client_is_complete_data_received(client))return fail(r,"信令音下载不完整");
        esp_http_client_cleanup(client);
        close.c=nullptr;
        uint8_t file_id=0;
        if(!fmo::beep_parse_fbep(data.get(),got,&file_id,nullptr,nullptr)||file_id!=did->valueint)
            return fail(r,"云端信令音编号或文件校验不一致");
        fmo::BeepConfig cfg{};
        if(!fmo::save_custom_beep_fbep(data.get(),got,&cfg,true))return fail(r,"信令音校验或写入失败，请重试");
        return status(r);
    }
    // Raw FBEP binary upload directly from phone browser.
    const size_t total=static_cast<size_t>(r->content_len);
    std::unique_ptr<uint8_t[]> data(new(std::nothrow) uint8_t[total]);
    if(!data)return fail(r,"信令音上传内存不足");
    size_t received=0;
    const int64_t deadline=esp_timer_get_time()+60000000;
    while(received<total){
        if(esp_timer_get_time()>deadline)return fail(r,"信令音上传超时，请重试");
        const int n=httpd_req_recv(r,reinterpret_cast<char *>(data.get()+received),std::min<size_t>(512,total-received));
        if(n<=0)return fail(r,"信令音上传中断，请重试");
        received+=n;
    }
    fmo::BeepConfig cfg{};
    if(!fmo::save_custom_beep_fbep(data.get(),received,&cfg,true)){
        return fail(r,"信令音格式(FBEP)校验失败或写入未确认");
    }
    return status(r);
}

#ifdef ESP_PLATFORM
extern const char fmo_setup_page_start[] asm("_binary_fmo_setup_html_gz_start");
extern const char fmo_setup_page_end[] asm("_binary_fmo_setup_html_gz_end");

namespace {
esp_err_t send_unauthorized(httpd_req_t *req) {
    httpd_resp_set_type(req, "application/json");
    httpd_resp_set_hdr(req, "Cache-Control", "no-store, max-age=0");
    httpd_resp_set_status(req, "401 Unauthorized");
    return httpd_resp_sendstr(req, "{\"error\":\"unauthorized\"}");
}
esp_err_t handler_fmo_page(httpd_req_t *req) {
    httpd_resp_set_type(req, "text/html; charset=utf-8");
    httpd_resp_set_hdr(req, "Content-Encoding", "gzip");
    httpd_resp_set_hdr(req, "Cache-Control", "no-store, max-age=0");
    return httpd_resp_send(req, fmo_setup_page_start, fmo_setup_page_end - fmo_setup_page_start);
}
esp_err_t auth_fmo_settings(httpd_req_t *req) {
    return fmo_http_token_ok(req) ? fmo_http_settings(req) : send_unauthorized(req);
}
esp_err_t auth_fmo_ca(httpd_req_t *req) {
    return fmo_http_token_ok(req) ? fmo_http_ca(req) : send_unauthorized(req);
}
esp_err_t auth_fmo_stamp(httpd_req_t *req) {
    return fmo_http_token_ok(req) ? fmo_http_stamp(req) : send_unauthorized(req);
}
esp_err_t auth_fmo_beep(httpd_req_t *req) {
    return fmo_http_token_ok(req) ? fmo_http_beep(req) : send_unauthorized(req);
}
} // namespace

bool fmo_http_register(httpd_handle_t server) {
    if (!server) return false;
    const httpd_uri_t routes[] = {
        {"/fmo", HTTP_GET, handler_fmo_page, nullptr},
        {"/api/fmo", HTTP_GET, auth_fmo_settings, nullptr},
        {"/api/fmo", HTTP_POST, auth_fmo_settings, nullptr},
        {"/api/fmo/ca", HTTP_GET, auth_fmo_ca, nullptr},
        {"/api/fmo/ca", HTTP_POST, auth_fmo_ca, nullptr},
        {"/api/fmo/stamp", HTTP_GET, auth_fmo_stamp, nullptr},
        {"/api/fmo/stamp", HTTP_POST, auth_fmo_stamp, nullptr},
        {"/api/fmo/stamp", HTTP_DELETE, auth_fmo_stamp, nullptr},
        {"/api/fmo/beep", HTTP_GET, auth_fmo_beep, nullptr},
        {"/api/fmo/beep", HTTP_POST, auth_fmo_beep, nullptr},
        {"/api/fmo/beep", HTTP_DELETE, auth_fmo_beep, nullptr},
    };
    for (const auto &r : routes) {
        if (httpd_register_uri_handler(server, &r) != ESP_OK) return false;
    }
    return true;
}
#endif
