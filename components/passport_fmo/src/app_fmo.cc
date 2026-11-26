#ifdef ESP_PLATFORM
#include "passport_fmo.h"
#else
#include "app_fmo.h"
#endif
#include "fmo_host_bridge.h"
#include "fmo_http.h"
#include "fmo_sentinel.h"
#include "fmo_crypto.h"
#include "fmo_revocation.h"
#include "fmo_store.h"
#include "fmo_wire.h"
#include "fmo_mqtt.h"
#include "fmo_book.h"
#include "fmo_favorites.h"
#include "fmo_stamp.h"
#include "fmo_beep.h"
#include "fmo_navigation.h"
#include "fmo_peers.h"
#include "fmo_announcements.h"
#include "fmo_announcement_pages.h"
#include "fmo_aprs.h"
#include "src/misc/cache/instance/lv_image_cache.h"
#include "bsp_audio.h"
#include "bsp_audio_workspace.h"
#include "bsp_battery.h"
#include "bsp_button.h"
#include "bsp_display.h"
#include "wifi_manager.h"
#include "mqtt_client.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/queue.h"
#include "lwip/sockets.h"
#include "lwip/netdb.h"
#include "lwip/tcp.h"
#include <sodium.h>
#include <atomic>
#include <algorithm>
#include <cstring>
#include <cstdio>
#include <ctime>
#include <memory>
#include <new>
#include <sys/time.h>
#include <fcntl.h>
#include <errno.h>

extern "C" int opus_encode(OpusEncoder *,const int16_t *,int,unsigned char *,int32_t);
extern "C" int opus_encoder_ctl(OpusEncoder *,int,...);
extern const char fmo_root_start[] asm("_binary_passport_root_json_start");
#ifdef PASSPORT_FMO_EXTRA_DISCOVERY_CHAIN
extern const char fmo_discovery_root[] asm("_binary_fmo_discovery_root_json_start");
extern const char fmo_discovery_intermediate[] asm("_binary_fmo_discovery_intermediate_json_start");
#endif
namespace {
#ifdef PASSPORT_FMO_EXTRA_DISCOVERY_CHAIN
constexpr fmo::DiscoveryChain extra_discovery_chain{fmo_discovery_root,fmo_discovery_intermediate};
constexpr auto *discovery_chain=&extra_discovery_chain;
#else
constexpr const fmo::DiscoveryChain *discovery_chain=nullptr;
#endif
// Opus SILK encoding (silk_NSQ_c) needs ~19 KiB of stack on ESP32-C3 (matching
// xiaozhi_audio's 22 KiB worker stack). Give the FMO task the full realtime
// audio workspace and place the small RX queue/assembly storage on the heap.
constexpr size_t kStackBytes=audio_workspace::kRealtimeBytes;
struct Raw {uint16_t size;uint8_t data[fmo::kPacketMax];};
constexpr unsigned kQueueCount=6;
static_assert(kStackBytes<=audio_workspace::kRealtimeBytes);
StaticTask_t task_buffer;
StaticQueue_t queue_buffer;
TaskHandle_t worker;
QueueHandle_t queue;
uint8_t *rx_storage;
std::atomic<bool> stop_requested{false},running{false},talk_requested{false},connected{false},switch_requested{false};
std::atomic<bool> ptt_released{false};
std::atomic<unsigned> next_requested{0},previous_requested{0};
std::atomic<fmo::Page> page{fmo::Page::Main};
std::atomic<uint32_t> discovery_unknown_issuer{0};
std::atomic<fmo::StationRejection> discovery_rejection{fmo::StationRejection::NotStation};
std::atomic<bool> menu_requested{false},back_requested{false},favorite_requested{false};
std::atomic<unsigned> volume_percent{80};
std::atomic<bool> volume_saved{true};
std::atomic<unsigned> observed_fmo_count{0};
lv_obj_t *screen,*state_label,*relay_label,*call_label,*hint_label,*stamp_image;
lv_obj_t *top_clock,*hero_card,*hero_dot,*hero_rule,*hero_foot_l,*hero_foot_r;
lv_obj_t *sub_header,*sub_title,*panel_card,*panel_rule,*panel_meta;
lv_image_dsc_t stamp_dsc{};
uint8_t *stamp_image_buf;
esp_mqtt_client_handle_t mqtt;
uint8_t *assembly;
fmo::MqttInbox mqtt_inbox;
std::atomic<fmo::MqttConnection> mqtt_connection{fmo::MqttConnection::Connecting};
fmo::NodeConnections mqtt_connections;
char current_speaker[13]{};

void ui_refresh_topbar(){
    if(!top_clock)return;
    char clock_buf[16]{};fmo_clock_format_time(clock_buf,sizeof(clock_buf));
    const int soc=bsp_battery_soc();
    char text[32]{};
    if(soc>=0)std::snprintf(text,sizeof(text),"%s  %d%%",clock_buf,soc);
    else std::snprintf(text,sizeof(text),"%s",clock_buf);
    fmo_pixel_label_set_text(top_clock,text);
}
void ui_apply_hero_state(bool is_online,bool is_tx,bool is_rx,bool is_error){
    if(!screen||!hero_card||page!=fmo::Page::Main)return;
    uint32_t bg=0x1b232cu,border=0x2e3b47u,ink=0xe7ecf1u,sub_ink=0xb7c4d0u,rule=0x33414fu,dot=0xffb37au;
    if(is_tx){bg=0xd93829u;border=0xf06558u;ink=0xffffffu;sub_ink=0xffe5e2u;rule=0xf08074u;dot=0xffe066u;}
    else if(is_rx){bg=0x197a54u;border=0x2ea073u;ink=0xffffffu;sub_ink=0xd9f7eau;rule=0x4da885u;dot=0x7ef0c2u;}
    else if(is_online){bg=0xff7a1au;border=0xff9647u;ink=0x14181cu;sub_ink=0x2c1b0cu;rule=0x8a5520u;dot=0x168f63u;}
    else if(is_error){dot=0xff6b60u;}
    lv_obj_set_style_bg_color(hero_card,lv_color_hex(bg),0);
    lv_obj_set_style_border_color(hero_card,lv_color_hex(border),0);
    if(hero_dot)lv_obj_set_style_bg_color(hero_dot,lv_color_hex(dot),0);
    if(hero_rule)lv_obj_set_style_bg_color(hero_rule,lv_color_hex(rule),0);
    if(relay_label)lv_obj_set_style_text_color(relay_label,lv_color_hex(ink),0);
    if(call_label)lv_obj_set_style_text_color(call_label,lv_color_hex(ink),0);
    if(hero_foot_l)lv_obj_set_style_text_color(hero_foot_l,lv_color_hex(sub_ink),0);
    if(hero_foot_r)lv_obj_set_style_text_color(hero_foot_r,lv_color_hex(sub_ink),0);
}
void ui_apply_mode(fmo::Page p,const char *heading=nullptr){
    if(!screen||!hero_card||!panel_card)return;
    ui_refresh_topbar();
    const bool is_main=(p==fmo::Page::Main);
    auto set_vis=[](lv_obj_t *o,bool show){
        if(!o)return;
        if(show)lv_obj_remove_flag(o,LV_OBJ_FLAG_HIDDEN);
        else lv_obj_add_flag(o,LV_OBJ_FLAG_HIDDEN);
    };
    set_vis(hero_card,is_main);
    set_vis(hero_dot,is_main);
    set_vis(hero_rule,is_main);
    set_vis(hero_foot_l,is_main);
    set_vis(hero_foot_r,is_main);
    set_vis(sub_header,!is_main);
    if(!is_main&&sub_title&&heading)fmo_pixel_label_set_text(sub_title,heading);
    if(is_main){
        lv_obj_set_pos(panel_card,12,170);lv_obj_set_size(panel_card,216,94);
        set_vis(panel_rule,true);lv_obj_set_pos(panel_rule,24,224);lv_obj_set_size(panel_rule,192,1);
        set_vis(panel_meta,true);lv_obj_set_pos(panel_meta,20,232);lv_obj_set_size(panel_meta,200,22);
        lv_obj_set_pos(relay_label,34,36);lv_obj_set_width(relay_label,182);lv_obj_set_style_text_align(relay_label,LV_TEXT_ALIGN_LEFT,0);
        lv_obj_set_pos(call_label,16,84);lv_obj_set_width(call_label,208);lv_obj_set_style_text_align(call_label,LV_TEXT_ALIGN_CENTER,0);
        lv_obj_set_pos(state_label,20,176);lv_obj_set_width(state_label,200);lv_obj_set_height(state_label,44);lv_obj_set_style_text_color(state_label,lv_color_hex(0xe7ecf1),0);
        lv_obj_set_pos(hint_label,10,272);lv_obj_set_width(hint_label,220);lv_obj_set_height(hint_label,44);
        ui_apply_hero_state(connected.load(),talk_requested.load(),false,mqtt_connection.load()==fmo::MqttConnection::AuthenticationRejected||mqtt_connection.load()==fmo::MqttConnection::BrokerRejected||mqtt_connection.load()==fmo::MqttConnection::TransportFailed);
        return;
    }
    lv_obj_set_pos(panel_card,12,68);lv_obj_set_size(panel_card,216,196);
    const bool list_page=(p==fmo::Page::Servers||p==fmo::Page::Menu||p==fmo::Page::Favorites||p==fmo::Page::Beep||p==fmo::Page::Announcements||p==fmo::Page::Messages);
    if(list_page){
        set_vis(panel_rule,true);lv_obj_set_pos(panel_rule,22,180);lv_obj_set_size(panel_rule,196,1);
        set_vis(panel_meta,p==fmo::Page::Servers);lv_obj_set_pos(panel_meta,20,238);lv_obj_set_size(panel_meta,200,20);
        lv_obj_set_pos(relay_label,22,78);lv_obj_set_width(relay_label,196);lv_obj_set_style_text_align(relay_label,LV_TEXT_ALIGN_LEFT,0);lv_obj_set_style_text_color(relay_label,lv_color_hex(0xe7ecf1),0);
        lv_obj_set_pos(state_label,20,188);lv_obj_set_width(state_label,200);lv_obj_set_height(state_label,46);lv_obj_set_style_text_color(state_label,lv_color_hex(0xffb37a),0);
        if(p==fmo::Page::Servers&&panel_meta){
            char m[48]{};const unsigned obs=observed_fmo_count.load();
            if(obs)std::snprintf(m,sizeof(m),"另发现只读 FMO 中继 %u 台",obs);
            else std::snprintf(m,sizeof(m),"含官方互通与 PASS 中继");
            fmo_pixel_label_set_text(panel_meta,m);
        }
    }else{
        set_vis(panel_rule,false);set_vis(panel_meta,false);
        lv_obj_set_pos(relay_label,20,82);lv_obj_set_width(relay_label,200);lv_obj_set_style_text_align(relay_label,LV_TEXT_ALIGN_CENTER,0);lv_obj_set_style_text_color(relay_label,lv_color_hex(0xffb37a),0);
        lv_obj_set_pos(call_label,20,132);lv_obj_set_width(call_label,200);lv_obj_set_style_text_align(call_label,LV_TEXT_ALIGN_CENTER,0);lv_obj_set_style_text_color(call_label,lv_color_hex(0xffffff),0);
        lv_obj_set_pos(state_label,20,182);lv_obj_set_width(state_label,200);lv_obj_set_height(state_label,52);lv_obj_set_style_text_color(state_label,lv_color_hex(0xd6dfe8),0);
    }
    lv_obj_set_pos(hint_label,10,272);lv_obj_set_width(hint_label,220);lv_obj_set_height(hint_label,44);
}
void ui_apply_hero_meta(const char *foot_left,const char *foot_right,const char *meta_line){
    if(!screen||page!=fmo::Page::Main)return;
    if(!bsp_lvgl_lock(100))return;
    ui_refresh_topbar();
    if(hero_foot_l&&foot_left)fmo_pixel_label_set_text(hero_foot_l,foot_left);
    if(hero_foot_r&&foot_right)fmo_pixel_label_set_text(hero_foot_r,foot_right);
    if(panel_meta&&meta_line)fmo_pixel_label_set_text(panel_meta,meta_line);
    bsp_lvgl_unlock();
}

void stamp_widget_hide(){
    if(!screen)return;
    if(stamp_image)lv_obj_add_flag(stamp_image,LV_OBJ_FLAG_HIDDEN);
}
void stamp_widget_show_builtin(unsigned style_index,uint32_t color_rgb){
    if(!screen||!stamp_image||!stamp_image_buf)return;
    fmo::stamp_build_palette(color_rgb,stamp_image_buf);
    fmo::stamp_render_builtin(style_index,stamp_image_buf+fmo::kStampPaletteBytes);
    lv_image_cache_drop(&stamp_dsc);
    lv_image_set_src(stamp_image,&stamp_dsc);
    lv_obj_set_pos(stamp_image,(240-fmo::kStampWidth)/2,74);
    lv_obj_remove_flag(stamp_image,LV_OBJ_FLAG_HIDDEN);
    lv_obj_invalidate(stamp_image);
    lv_obj_set_pos(call_label,20,174);lv_obj_set_width(call_label,200);lv_obj_set_style_text_align(call_label,LV_TEXT_ALIGN_CENTER,0);lv_obj_set_style_text_color(call_label,lv_color_hex(0xff7a1a),0);
    lv_obj_set_pos(relay_label,20,198);lv_obj_set_width(relay_label,200);lv_obj_set_style_text_align(relay_label,LV_TEXT_ALIGN_CENTER,0);lv_obj_set_style_text_color(relay_label,lv_color_hex(0xd6dfe8),0);
    lv_obj_set_pos(state_label,20,238);lv_obj_set_width(state_label,200);lv_obj_set_height(state_label,24);lv_obj_set_style_text_color(state_label,lv_color_hex(0x8b98a5),0);
    lv_obj_set_pos(hint_label,10,272);
}
void stamp_widget_show(const uint8_t *pixels,uint32_t color_rgb){
    if(!screen||!stamp_image||!stamp_image_buf||!pixels)return;
    fmo::stamp_build_palette(color_rgb,stamp_image_buf);
    std::memcpy(stamp_image_buf+fmo::kStampPaletteBytes,pixels,fmo::kStampPixelBytes);
    lv_image_cache_drop(&stamp_dsc);
    lv_image_set_src(stamp_image,&stamp_dsc);
    lv_obj_set_pos(stamp_image,(240-fmo::kStampWidth)/2,74);
    lv_obj_remove_flag(stamp_image,LV_OBJ_FLAG_HIDDEN);
    lv_obj_invalidate(stamp_image);
    lv_obj_set_pos(call_label,20,174);lv_obj_set_width(call_label,200);lv_obj_set_style_text_align(call_label,LV_TEXT_ALIGN_CENTER,0);lv_obj_set_style_text_color(call_label,lv_color_hex(0xff7a1a),0);
    lv_obj_set_pos(relay_label,20,198);lv_obj_set_width(relay_label,200);lv_obj_set_style_text_align(relay_label,LV_TEXT_ALIGN_CENTER,0);lv_obj_set_style_text_color(relay_label,lv_color_hex(0xd6dfe8),0);
    lv_obj_set_pos(state_label,20,238);lv_obj_set_width(state_label,200);lv_obj_set_height(state_label,24);lv_obj_set_style_text_color(state_label,lv_color_hex(0x8b98a5),0);
    lv_obj_set_pos(hint_label,10,272);
}

void show(const char *state,const char *relay=nullptr,const char *call=nullptr){
    if(page!=fmo::Page::Main)return;
    if(!bsp_lvgl_lock(100))return;
    if(screen){
        fmo_pixel_label_set_text(state_label,state);
        if(relay)fmo_pixel_label_set_text(relay_label,relay);
        if(call)fmo_pixel_label_set_text(call_label,call);
        const bool tx=(state&&std::strncmp(state,"正在发送",12)==0)||talk_requested.load();
        const bool rx=(state&&std::strncmp(state,"正在收听",12)==0);
        const auto mc=mqtt_connection.load();
        const bool err=(mc==fmo::MqttConnection::AuthenticationRejected||mc==fmo::MqttConnection::BrokerRejected||mc==fmo::MqttConnection::TransportFailed||mc==fmo::MqttConnection::LocalSetupFailed);
        ui_apply_hero_state(connected.load(),tx,rx,err);
    }
    bsp_lvgl_unlock();
}
void short_name(const char *source,char *out){
    unsigned units=0;size_t used=0;
    while(*source&&units<20){
        const unsigned char lead=*source;unsigned bytes=lead<0x80?1:(lead&0xe0)==0xc0?2:(lead&0xf0)==0xe0?3:(lead&0xf8)==0xf0?4:1;
        for(unsigned i=1;i<bytes;++i)if(!source[i]||(static_cast<unsigned char>(source[i])&0xc0)!=0x80){bytes=1;break;}
        const unsigned w=(bytes>1)?2u:1u;
        if(units+w>20)break;
        if(lead<0x20){out[used++]=' ';++source;}else {std::memcpy(out+used,source,bytes);used+=bytes;source+=bytes;}
        units+=w;
    }
    if(*source){std::memcpy(out+used,"...",3);used+=3;}out[used]=0;
}
void station_summary(const fmo::StationStatus &status,uint32_t now,char *out,size_t capacity){
    if(!status.valid_until||status.valid_until<=now){std::snprintf(out,capacity,"广播在线数待更新");return;}
    char online[8],peak[8],range[8];
    auto number=[](char *text,uint32_t n){if(n>9999)std::strcpy(text,"9999+");else std::snprintf(text,8,"%lu",static_cast<unsigned long>(n));};
    number(online,status.online);number(peak,status.peak);number(range,status.range_km);
    std::snprintf(out,capacity,"广播 %s/%s · %skm",online,peak,range);
}
void show_relay(const fmo::Relay &relay,const fmo::RelayList &list,uint32_t now){
    if(page!=fmo::Page::Main||!bsp_lvgl_lock(100))return;
    if(screen){char name[44],summary[80],caption[144];short_name(relay.name[0]?relay.name:relay.host,name);
        if(fmo::is_builtin_relay(relay)){
            std::snprintf(summary,sizeof(summary),"内置兜底中继");
        }else{
            const int slot=list.find(relay.uid);const bool matches=slot>=0&&relay.port==list.relays[slot].port&&!std::strcmp(relay.host,list.relays[slot].host)&&!std::memcmp(relay.fingerprint,list.relays[slot].fingerprint,32);
            station_summary(matches?list.status[slot]:fmo::StationStatus{},now,summary,sizeof(summary));
        }
        uint32_t count=0;
        if(connected&&mqtt_connections.read(esp_timer_get_time(),&count)){
            if(count>9999)std::snprintf(summary,sizeof(summary),"最近节点连接 9999+");
            else std::snprintf(summary,sizeof(summary),"最近节点连接 %lu",static_cast<unsigned long>(count));
        }
        std::snprintf(caption,sizeof(caption),"%s\n%s",name,summary);fmo_pixel_label_set_text(relay_label,caption);
    }bsp_lvgl_unlock();
}
const char *discovery_rejection_message(fmo::StationRejection reason){
    switch(reason){
    case fmo::StationRejection::UnknownIssuer:return "未验证广播：缺少签发链";
    case fmo::StationRejection::CertificateInvalid:return "广播证书未通过验证";
    case fmo::StationRejection::SignatureInvalid:return "广播签名未通过验证";
    default:return "等待新的签名广播";
    }
}
void server_list_view(const fmo::RelayList &list,uint32_t now=static_cast<uint32_t>(time(nullptr)),const fmo::Favorites *favorites=nullptr){
    if(!bsp_lvgl_lock(100))return;
    if(screen){
        stamp_widget_hide();
        ui_apply_mode(fmo::Page::Servers,"中继列表");
        lv_obj_add_flag(call_label,LV_OBJ_FLAG_HIDDEN);
        lv_obj_set_height(relay_label,96);
        if(!list.count){
            fmo_pixel_label_set_text(relay_label,"暂无有效服务器");
            const auto rejection=discovery_rejection.load();
            const uint32_t issuer=discovery_unknown_issuer.load();
            if(rejection==fmo::StationRejection::UnknownIssuer&&issuer){
                char detail[96];
                std::snprintf(detail,sizeof(detail),"缺少中间证书\n广播声明编号 %lu",static_cast<unsigned long>(issuer));
                fmo_pixel_label_set_text(state_label,detail);
            }else fmo_pixel_label_set_text(state_label,discovery_rejection_message(rejection));
            fmo_pixel_label_set_text(hint_label,"确定重连发现服务\n长按下键返回通联");
            bsp_lvgl_unlock();return;
        }
        char rows[256]{},position[128],summary[80];size_t used=0;
        const unsigned first=list.count<=3?0:std::min<unsigned>(list.index?list.index-1:0,list.count-3);
        for(unsigned i=first;i<list.count&&i<first+3;++i){const auto &r=list.relays[i];char name[44];short_name(r.name[0]?r.name:r.host,name);used+=std::snprintf(rows+used,sizeof(rows)-used,"%c %s%s",i==list.index?'>':' ',name,i+1<list.count&&i+1<first+3?"\n":"");}
        station_summary(list.status[list.index],now,summary,sizeof(summary));
        std::snprintf(position,sizeof(position),"%u/%u %s%s\n%s",unsigned(list.index+1),unsigned(list.count),list.relays[list.index].callsign,favorites&&favorites->find(list.relays[list.index])>=0?" *":"",summary);
        fmo_pixel_label_set_text(relay_label,rows);fmo_pixel_label_set_text(state_label,position);
        fmo_pixel_label_set_text(hint_label,"上下选台 · 确定连接\n长按上收藏 · 长按下返回");
    }bsp_lvgl_unlock();
}
void favorites_view(const fmo::Favorites *favorites,const fmo::RelayList &servers,unsigned index,bool writable){
    if(!bsp_lvgl_lock(100))return;
    if(screen){
        stamp_widget_hide();
        ui_apply_mode(fmo::Page::Favorites,"收藏中继");
        lv_obj_add_flag(call_label,LV_OBJ_FLAG_HIDDEN);lv_obj_set_height(relay_label,96);
        if(!favorites||!writable){fmo_pixel_label_set_text(relay_label,"收藏记录不可读");fmo_pixel_label_set_text(state_label,"原记录未被覆盖");}
        else if(!favorites->count){fmo_pixel_label_set_text(relay_label,"暂无收藏服务器");fmo_pixel_label_set_text(state_label,"在选台页长按上键收藏");}
        else {
            index%=favorites->count;const auto now=static_cast<uint32_t>(time(nullptr));char rows[256]{},caption[96];size_t used=0;
            const unsigned first=favorites->count<=3?0:std::min<unsigned>(index?index-1:0,favorites->count-3);
            for(unsigned i=first;i<favorites->count&&i<first+3;++i){char name[44];const int slot=favorites->resolve(i,servers,now);
                short_name(slot<0?favorites->entries[i].callsign:servers.relays[slot].name[0]?servers.relays[slot].name:servers.relays[slot].callsign,name);
                used+=std::snprintf(rows+used,sizeof(rows)-used,"%c %s%s%s",i==index?'>':' ',name,slot<0?" (待更新)":"",i+1<favorites->count&&i+1<first+3?"\n":"");
            }
            std::snprintf(caption,sizeof(caption),"%u/%u %s\n%s",index+1,favorites->count,favorites->entries[index].callsign,favorites->resolve(index,servers,now)>=0?"有效广播 · 确定连接":"等待新的签名广播");
            fmo_pixel_label_set_text(relay_label,rows);fmo_pixel_label_set_text(state_label,caption);
        }
        fmo_pixel_label_set_text(hint_label,"上下选择 · 确定连接\n长按上取消 · 长按下返回");
    }bsp_lvgl_unlock();
}
__attribute__((noinline)) const char *edit_favorite(fmo::Favorites *favorites,bool writable,const fmo::RelayList &servers,unsigned index,bool removing){
    if(!favorites||!writable)return "收藏记录不可写，未覆盖";
    fmo::Favorites candidate=*favorites;bool erased=removing;
    if(removing){if(!candidate.erase(index))return "没有可取消的收藏";}
    else {
        if(index>=servers.count||!servers.expires[index]||servers.expires[index]<=uint64_t(time(nullptr)))return "请选择有效签名服务器";
        const auto &relay=servers.relays[index];const int existing=candidate.find(relay);erased=existing>=0;
        if(existing>=0)candidate.erase(existing);
        else if(!candidate.add(relay))return "收藏已满，最多8台";
    }
    if(!fmo::save_favorites(candidate))return "收藏保存未确认，请重试";
    *favorites=candidate;return erased?"已取消收藏":"已收藏服务器";
}
void normal_view(){
    page=fmo::Page::Main;
    if(!bsp_lvgl_lock(100))return;
    if(screen){stamp_widget_hide();ui_apply_mode(fmo::Page::Main);lv_obj_set_height(relay_label,40);lv_obj_remove_flag(call_label,LV_OBJ_FLAG_HIDDEN);fmo_pixel_label_set_text(hint_label,"上键选台 · 下键菜单\n长按确定讲话 · 调音量");}
    bsp_lvgl_unlock();
}
constexpr const char *kMenuItems[]={"选择服务器","抄收记录","播放音量","手机配置","返回通联","退出FMO","发送APRS CQ","发送友台信标","友台广播","活动公告","收藏服务器","我的印章","短消息","结束信令音","连接内置中继","后台守听插播","转后台守听"};
constexpr unsigned kMenuSize=sizeof(kMenuItems)/sizeof(*kMenuItems);

void menu_view(unsigned index){
    index%=kMenuSize;
    if(!bsp_lvgl_lock(100))return;
    if(screen){
        stamp_widget_hide();
        ui_apply_mode(fmo::Page::Menu,"快捷菜单");
        lv_obj_add_flag(call_label,LV_OBJ_FLAG_HIDDEN);
        lv_obj_set_height(relay_label,96);
        char rows[160]{};size_t used=0;const unsigned first=std::min(index?index-1:0,kMenuSize-3);
        for(unsigned i=first;i<first+3;++i)used+=std::snprintf(rows+used,sizeof(rows)-used,"%c %s%s",i==index?'>':' ',kMenuItems[i],i<first+2?"\n":"");
        fmo_pixel_label_set_text(relay_label,rows);fmo_pixel_label_set_text(state_label,"快捷菜单");
        fmo_pixel_label_set_text(hint_label,"上下键选择 · 确定打开\n长按下键返回通联");
    }bsp_lvgl_unlock();
}
void broadcast_view(bool beacon,const char *grid,const char *state){
    page=fmo::Page::Broadcast;
    if(!bsp_lvgl_lock(100))return;
    if(screen){stamp_widget_hide();ui_apply_mode(fmo::Page::Broadcast,beacon?"友台信标":"APRS CQ");lv_obj_set_height(relay_label,40);lv_obj_remove_flag(call_label,LV_OBJ_FLAG_HIDDEN);
        fmo_pixel_label_set_text(relay_label,beacon?"友台信标":"APRS CQ");fmo_pixel_label_set_text(call_label,grid&&*grid?grid:"未设置网格");fmo_pixel_label_set_text(state_label,state);
        fmo_pixel_label_set_text(hint_label,"确定返回菜单\n长按下键返回通联");
    }bsp_lvgl_unlock();
}
void stamp_view(const fmo::StampConfig &cfg,unsigned preview_index,const uint8_t *custom_pixels,const char *callsign,const char *status_text=nullptr){
    const unsigned total=fmo::kBuiltinStampCount+(cfg.custom_present&&custom_pixels?1u:0u);
    preview_index%=total;
    const bool is_custom=preview_index==fmo::kBuiltinStampCount;
    if(!bsp_lvgl_lock(100))return;
    if(screen){
        ui_apply_mode(fmo::Page::Stamp,"我的印章");
        if(is_custom)stamp_widget_show(custom_pixels,cfg.color_rgb);
        else stamp_widget_show_builtin(preview_index,cfg.color_rgb);
        lv_obj_remove_flag(call_label,LV_OBJ_FLAG_HIDDEN);
        lv_obj_set_height(relay_label,40);
        const char *shown_call=(callsign&&*callsign)?fmo::bare_callsign(callsign):"FMO STAMP";
        fmo_pixel_label_set_text(call_label,shown_call);
        char info[80],state[80];
        if(is_custom)std::snprintf(info,sizeof(info),"定制图案 · CUSTOM\n%s",cfg.label[0]?cfg.label:"AI PASSPORT");
        else std::snprintf(info,sizeof(info),"%s · %s\n%s",fmo::stamp_builtin_id(preview_index),fmo::stamp_builtin_name(preview_index),cfg.label[0]?cfg.label:"AI PASSPORT");
        if(status_text&&*status_text)std::snprintf(state,sizeof(state),"%s",status_text);
        else std::snprintf(state,sizeof(state),"%u/%u · %s",preview_index+1,total,is_custom?(fmo::stamp_is_custom_style(cfg.style_id)?"当前已启用":"确定启用定制章"):(!std::strcmp(cfg.style_id,fmo::stamp_builtin_id(preview_index))?"当前已启用":"确定保存样式"));
        fmo_pixel_label_set_text(relay_label,info);
        fmo_pixel_label_set_text(state_label,state);
        fmo_pixel_label_set_text(hint_label,"上下切印章 · 确定保存\n长按下键返回通联");
    }bsp_lvgl_unlock();
}
void beep_view(const fmo::BeepConfig &cfg,unsigned mode_index,const char *status_text=nullptr){
    const unsigned total=cfg.custom_present?3u:2u;
    mode_index%=total;
    if(!bsp_lvgl_lock(100))return;
    if(screen){
        stamp_widget_hide();
        ui_apply_mode(fmo::Page::Beep,"结束信令音");
        lv_obj_add_flag(call_label,LV_OBJ_FLAG_HIDDEN);
        lv_obj_set_height(relay_label,96);
        char rows[160]{};
        if(cfg.custom_present){
            const char *cname=fmo::beep_cloud_name(cfg.custom_id);
            char clabel[32]{};
            if(cname)std::snprintf(clabel,sizeof(clabel),"%s (#%u)",cname,static_cast<unsigned>(cfg.custom_id));
            else std::snprintf(clabel,sizeof(clabel),"自定义音 #%u",static_cast<unsigned>(cfg.custom_id));
            std::snprintf(rows,sizeof(rows),"%c 内置双音\n%c 关闭信令音\n%c %s",
                          mode_index==0?'>':' ',mode_index==1?'>':' ',mode_index==2?'>':' ',clabel);
        }else{
            std::snprintf(rows,sizeof(rows),"%c 内置双音\n%c 关闭信令音",
                          mode_index==0?'>':' ',mode_index==1?'>':' ');
        }
        char state[80]{};
        if(status_text&&*status_text){
            std::snprintf(state,sizeof(state),"%s",status_text);
        }else if(!cfg.enabled){
            std::snprintf(state,sizeof(state),"当前：已关闭");
        }else if(cfg.use_custom&&cfg.custom_present){
            const char *cname=fmo::beep_cloud_name(cfg.custom_id);
            if(cname)std::snprintf(state,sizeof(state),"当前：%s (#%u)",cname,static_cast<unsigned>(cfg.custom_id));
            else std::snprintf(state,sizeof(state),"当前：自定义音 #%u",static_cast<unsigned>(cfg.custom_id));
        }else{
            std::snprintf(state,sizeof(state),"当前：内置双音");
        }
        fmo_pixel_label_set_text(relay_label,rows);
        fmo_pixel_label_set_text(state_label,state);
        fmo_pixel_label_set_text(hint_label,"上下选择 · 确定保存试听\n长按下键返回通联");
    }bsp_lvgl_unlock();
}
void history_view(const fmo::ContactBook *book,unsigned index,bool available,const fmo::PeerStamps *peer_stamps=nullptr){
    if(!bsp_lvgl_lock(100))return;
    if(screen){
        ui_apply_mode(fmo::Page::History,"护照章册");
        lv_obj_set_height(relay_label,48);
        fmo_pixel_label_set_text(hint_label,"上下键翻阅 · 确定回菜单\n长按下键返回通联");
        if(!available||!book||!book->count){
            stamp_widget_hide();
            lv_obj_add_flag(call_label,LV_OBJ_FLAG_HIDDEN);
            fmo_pixel_label_set_text(relay_label,available?"暂无抄收记录":"抄收册暂不可读");
            fmo_pixel_label_set_text(state_label,available?"成功播放友台语音后记录":"原记录未被覆盖");
        }else {
            unsigned order[fmo::ContactBook::capacity];
            for(unsigned i=0;i<book->count;++i)order[i]=i;
            std::sort(order,order+book->count,[&](unsigned a,unsigned b){return book->contacts[a].last_seen>book->contacts[b].last_seen;});
            index%=book->count;const auto &c=book->contacts[order[index]];
            const char *learned=peer_stamps?peer_stamps->find(c.callsign):nullptr;
            const int bidx=learned?fmo::stamp_builtin_index(learned):-1;
            const unsigned style_idx=bidx>=0?unsigned(bidx):fmo::stamp_fallback_index(c.callsign);
            stamp_widget_show_builtin(style_idx,fmo::kDefaultStampColor);
            const int offset=fmo_tz_offset_sec();
            char first[24]{},last[24]{},dates[100],count[80];tm date{};time_t utc=static_cast<time_t>(c.first_seen)+offset;
            gmtime_r(&utc,&date);std::strftime(first,sizeof(first),"%Y-%m-%d %H:%M",&date);utc=static_cast<time_t>(c.last_seen)+offset;
            gmtime_r(&utc,&date);std::strftime(last,sizeof(last),"%Y-%m-%d %H:%M",&date);
            std::snprintf(dates,sizeof(dates),"初次 %s\n最近 %s",first,last);
            std::snprintf(count,sizeof(count),"%u/%u 位 · 抄收 %lu 次",index+1,book->count,static_cast<unsigned long>(c.receptions));
            lv_obj_remove_flag(call_label,LV_OBJ_FLAG_HIDDEN);fmo_pixel_label_set_text(call_label,c.callsign);
            fmo_pixel_label_set_text(relay_label,dates);fmo_pixel_label_set_text(state_label,count);
        }
    }bsp_lvgl_unlock();
}
void peers_view(const fmo::PeerEvents *peers,unsigned index){
    if(!bsp_lvgl_lock(100))return;
    if(screen){
        stamp_widget_hide();
        ui_apply_mode(fmo::Page::Peers,"友台广播");
        lv_obj_set_height(relay_label,48);
        fmo_pixel_label_set_text(hint_label,"广播记录，不代表当前在线\n上下翻阅 · 确定回菜单\n长按下键返回通联");
        if(!peers||!peers->count){
            lv_obj_add_flag(call_label,LV_OBJ_FLAG_HIDDEN);
            fmo_pixel_label_set_text(relay_label,peers?"暂无有效友台广播":"广播记录内存不足");
            fmo_pixel_label_set_text(state_label,"仅显示验签通过的通知\n附近信标需先设置网格");
        }else {
            index%=peers->count;const auto &event=peers->events[index];
            const char *kind=event.kind==fmo::PeerKind::CQ?"CQ 呼叫":event.kind==fmo::PeerKind::OldFriendCQ?"老友呼叫":event.kind==fmo::PeerKind::Vocal?"语音活动通知":"上线通知";
            char details[112],position[80];
            std::snprintf(details,sizeof(details),"%s\n服务器 UID %lu",kind,static_cast<unsigned long>(event.server_uid));
            std::snprintf(position,sizeof(position),"%u/%u · 签名广播\n%s %s",index+1,peers->count,event.latitude,event.longitude);
            lv_obj_remove_flag(call_label,LV_OBJ_FLAG_HIDDEN);fmo_pixel_label_set_text(call_label,event.callsign);
            if(event.kind==fmo::PeerKind::Beacon){
                char rig[44],antenna[44],height[24];short_name(event.rig,rig);short_name(event.antenna,antenna);
                if(!event.antenna_height)std::strcpy(height,"高度未提供");
                else if(event.antenna_height>9999)std::strcpy(height,"9999+m");
                else std::snprintf(height,sizeof(height),"%lum",static_cast<unsigned long>(event.antenna_height));
                std::snprintf(details,sizeof(details),"%u/%u %sMHz\n信标 · %lu.%lukm · %s",index+1,peers->count,event.frequency,static_cast<unsigned long>(event.distance_m/1000),static_cast<unsigned long>(event.distance_m%1000/100),height);
                // Each equipment field has a separate bounded line.
                fmo_pixel_label_set_text(relay_label,details);
                char equipment[112];std::snprintf(equipment,sizeof(equipment),"设备 %s\n天线 %s",*rig?rig:"未提供",*antenna?antenna:"未提供");
                fmo_pixel_label_set_text(state_label,equipment);
                fmo_pixel_label_set_text(hint_label,"80km内签名信标，非在线名单\n上下翻阅 · 确定回菜单\n长按下键返回通联");
            }else {fmo_pixel_label_set_text(relay_label,details);fmo_pixel_label_set_text(state_label,position);}
        }
    }bsp_lvgl_unlock();
}
bool receive_peer(const char *line,size_t bytes,const fmo::Credential &identity,const char *root,uint32_t now,fmo::PeerEvents *peers,fmo::Navigation &nav,const fmo::BroadcastConfig *config=nullptr,const fmo::DiscoveryChain *chain=nullptr){
    if(!peers)return false;
    fmo::PeerAnnouncement event{};
    if(!fmo::peer_announcement(line,bytes,identity,root,now,&event,chain))return false;
    if(event.kind==fmo::PeerKind::Beacon&&(!config||!fmo::nearby_beacon(event,config->grid,&event.distance_m)))return false;
    if(!peers->add(event,now))return false;
    if(page==fmo::Page::Peers){nav.peer_index=0;peers_view(peers,0);}
    return true;
}
void announcement_view(const fmo::Announcements *announcements,const fmo::Navigation &nav){
    if(!bsp_lvgl_lock(100))return;
    if(screen){
        stamp_widget_hide();
        ui_apply_mode(fmo::Page::Announcements,"活动公告");
        lv_obj_add_flag(call_label,LV_OBJ_FLAG_HIDDEN);lv_obj_set_height(relay_label,96);
        if(!announcements||!announcements->count){
            fmo_pixel_label_set_text(relay_label,announcements?"暂无有效活动公告":"公告记录内存不足");
            fmo_pixel_label_set_text(state_label,"仅显示签名与正文摘要匹配的公告");
        }else {
            const unsigned index=nav.event_index%announcements->count;const auto &notice=announcements->notices[index];
            char body[fmo::kAnnouncementPageBytes],state[80];const unsigned pages=fmo::announcement_page(notice,0,body),selected=nav.event_page%pages;
            if(selected)fmo::announcement_page(notice,selected,body);
            std::snprintf(state,sizeof(state),"%u/%u · 页%u/%u\n%s",index+1,announcements->count,selected+1,pages,notice.body.callsign);
            fmo_pixel_label_set_text(relay_label,body);fmo_pixel_label_set_text(state_label,state);
        }
        fmo_pixel_label_set_text(hint_label,"上下翻页 · 确定回菜单\n长按下键返回通联\n文字公告，不自动执行");
    }bsp_lvgl_unlock();
}
void message_view(const fmo::AprsInbox *inbox,unsigned index){
    if(!bsp_lvgl_lock(100))return;
    if(screen){
        stamp_widget_hide();
        ui_apply_mode(fmo::Page::Messages,"短消息");
        lv_obj_add_flag(call_label,LV_OBJ_FLAG_HIDDEN);
        lv_obj_set_height(relay_label,96);
        if(inbox&&inbox->count){
            const auto &message=inbox->messages[index%inbox->count];
            char state[64];
            std::snprintf(state,sizeof(state),"%u/%u · %s\n来源未验签",index%inbox->count+1,inbox->count,message.sender);
            fmo_pixel_label_set_text(relay_label,message.body);
            fmo_pixel_label_set_text(state_label,state);
        }else{
            fmo_pixel_label_set_text(relay_label,inbox?"暂无短消息":"短消息内存不足");
            fmo_pixel_label_set_text(state_label,"来源未验签");
        }
        fmo_pixel_label_set_text(hint_label,"上下键翻阅 · 确定回菜单\n仅保留本次会话");
    }
    bsp_lvgl_unlock();
}

void move_announcement(const fmo::Announcements *announcements,fmo::Navigation &nav,int delta){
    if(!announcements||!announcements->count){announcement_view(announcements,nav);return;}
    unsigned sizes[fmo::Announcements::capacity],total=0,current=0;char text[fmo::kAnnouncementPageBytes];
    const unsigned index=nav.event_index%announcements->count;
    for(unsigned i=0;i<announcements->count;++i){sizes[i]=fmo::announcement_page(announcements->notices[i],0,text);if(i<index)current+=sizes[i];total+=sizes[i];}
    current+=nav.event_page%sizes[index];current=(int(current)+delta%int(total)+int(total))%int(total);
    nav.event_index=0;while(current>=sizes[nav.event_index])current-=sizes[nav.event_index++];nav.event_page=current;
    announcement_view(announcements,nav);
}
// The STATUS parser needs a bounded 744-byte body. Keep that storage outside
// the task's long-lived frame and outside the certificate-verification path.
__attribute__((noinline)) bool receive_announcement_body(const char *line,size_t bytes,uint32_t now,fmo::Announcements *announcements){
    fmo::EventBody body{};
    return fmo::event_status(line,bytes,&body)&&announcements->body(body,now);
}
bool receive_announcement(const char *line,size_t bytes,const fmo::Credential &identity,const char *root,uint32_t now,fmo::Announcements *announcements,fmo::Navigation &nav,const fmo::DiscoveryChain *chain=nullptr){
    if(!announcements)return false;
    fmo::EventProof proof{};bool changed=false;
    if(fmo::joint_announcement(line,bytes,identity,root,now,&proof,chain))changed=announcements->proof(proof,now);
    else changed=receive_announcement_body(line,bytes,now,announcements);
    if(changed&&page==fmo::Page::Announcements){nav.event_index=nav.event_page=0;announcement_view(announcements,nav);}
    return changed;
}
void volume_view(unsigned percent,bool saved=true){
    if(!bsp_lvgl_lock(100))return;
    if(screen){char value[16];std::snprintf(value,sizeof(value),"%u%%",percent);
        stamp_widget_hide();
        ui_apply_mode(fmo::Page::Volume,"播放音量");
        lv_obj_set_height(relay_label,40);
        lv_obj_remove_flag(call_label,LV_OBJ_FLAG_HIDDEN);fmo_pixel_label_set_text(call_label,value);
        fmo_pixel_label_set_text(relay_label,"播放音量");fmo_pixel_label_set_text(state_label,saved?"上键加 · 下键减":"保存失败，音量未变");
        fmo_pixel_label_set_text(hint_label,"每次调整5% · 确定回菜单\n长按下键返回通联");
    }bsp_lvgl_unlock();
}
// Called by the input task, using the same persistent master volume as OS Settings.
void adjust_volume(int delta){
    const unsigned before=fmo_get_volume(),target=std::clamp<int>(int(before)+delta,0,100);
    const bool saved=before==target||fmo_save_volume(target);
    volume_percent=saved?target:before;volume_saved=saved;
    if(page==fmo::Page::Volume)volume_view(saved?target:before,saved);
    else {char hint[64];std::snprintf(hint,sizeof(hint),saved?"音量 %u%%":"音量保存失败，保持 %u%%",saved?target:before);show(hint);}
}
fmo::UiAction process_controls(fmo::Navigation &nav,fmo::RelayList &servers,const fmo::ContactBook *book,bool available,fmo::PeerEvents *peers=nullptr,fmo::Announcements *announcements=nullptr,fmo::Favorites *favorites=nullptr,bool favorites_writable=false,const fmo::StampConfig *stamp_cfg=nullptr,const uint8_t *custom_stamp=nullptr,const fmo::PeerStamps *peer_stamps=nullptr,const char *self_callsign=nullptr,const fmo::AprsInbox *inbox=nullptr,const fmo::BeepConfig *beep_cfg=nullptr){
    if(back_requested.exchange(false)){talk_requested=false;switch_requested=false;menu_requested=false;normal_view();}
    if(menu_requested.exchange(false)){talk_requested=false;page=fmo::Page::Menu;nav.menu_index=0;menu_view(nav.menu_index);}
    const unsigned next=next_requested.load(),previous=previous_requested.load();
    if(next!=nav.seen_next||previous!=nav.seen_previous){
        const int delta=int(std::min<unsigned>(next-nav.seen_next,64))-int(std::min<unsigned>(previous-nav.seen_previous,64));nav.seen_next=next;nav.seen_previous=previous;
        talk_requested=false;
        if(page==fmo::Page::Menu){nav.menu_index=(int(nav.menu_index)+delta%int(kMenuSize)+int(kMenuSize))%int(kMenuSize);menu_view(nav.menu_index);}
        else if(page==fmo::Page::History){if(book&&book->count)nav.history_index=(int(nav.history_index)+delta%int(book->count)+int(book->count))%int(book->count);history_view(book,nav.history_index,available,peer_stamps);}
        else if(page==fmo::Page::Favorites){if(favorites&&favorites->count)nav.favorite_index=(int(nav.favorite_index)+delta%int(favorites->count)+int(favorites->count))%int(favorites->count);favorites_view(favorites,servers,nav.favorite_index,favorites_writable);}
        else if(page==fmo::Page::Announcements){move_announcement(announcements,nav,delta);}
        else if(page==fmo::Page::Messages){
            if(inbox&&inbox->count){
                const int count=inbox->count;
                nav.message_index=(int(nav.message_index)+delta%count+count)%count;
            }
            message_view(inbox,nav.message_index);
        }
        else if(page==fmo::Page::Peers){if(peers&&peers->count)nav.peer_index=(int(nav.peer_index)+delta%int(peers->count)+int(peers->count))%int(peers->count);peers_view(peers,nav.peer_index);}
        else if(page==fmo::Page::Stamp){
            const fmo::StampConfig fallback{};const auto &sc=stamp_cfg?*stamp_cfg:fallback;
            const unsigned total=fmo::kBuiltinStampCount+(sc.custom_present&&custom_stamp?1u:0u);
            nav.stamp_index=(int(nav.stamp_index)+delta%int(total)+int(total))%int(total);
            stamp_view(sc,nav.stamp_index,custom_stamp,self_callsign);
        }
        else if(page==fmo::Page::Beep){
            const fmo::BeepConfig fallback{};const auto &bc=beep_cfg?*beep_cfg:fallback;
            const unsigned total=bc.custom_present?3u:2u;
            nav.beep_index=(int(nav.beep_index)+delta%int(total)+int(total))%int(total);
            beep_view(bc,nav.beep_index);
        }
        else if(page==fmo::Page::Servers){servers.move(delta);server_list_view(servers,time(nullptr),favorites);}
    }
    if(favorite_requested.exchange(false)&&(page==fmo::Page::Servers||page==fmo::Page::Favorites)){
        talk_requested=false;switch_requested=false;const bool removing=page==fmo::Page::Favorites;
        const char *message=edit_favorite(favorites,favorites_writable,servers,removing?nav.favorite_index:servers.index,removing);
        if(removing){if(favorites&&favorites->count)nav.favorite_index=std::min(nav.favorite_index,favorites->count-1);favorites_view(favorites,servers,nav.favorite_index,favorites_writable);}
        else server_list_view(servers,time(nullptr),favorites);
        if(bsp_lvgl_lock(100)){if(screen)fmo_pixel_label_set_text(state_label,message);bsp_lvgl_unlock();}
    }
    if(!switch_requested.exchange(false))return fmo::UiAction::None;
    if(page==fmo::Page::Menu){
        switch(nav.menu_index){
        case 0:page=fmo::Page::Servers;server_list_view(servers,time(nullptr),favorites);break;
        case 1:page=fmo::Page::History;nav.history_index=0;history_view(book,0,available,peer_stamps);break;
        case 2:page=fmo::Page::Volume;volume_view(volume_percent.load(),volume_saved.load());break;
        case 3:return fmo::UiAction::PhoneSetup;
        case 4:normal_view();break;
        case 5:return fmo::UiAction::Exit;
        case 6:return fmo::UiAction::CQ;
        case 7:return fmo::UiAction::Beacon;
        case 8:page=fmo::Page::Peers;nav.peer_index=0;peers_view(peers,0);break;
        case 9:page=fmo::Page::Announcements;nav.event_index=nav.event_page=0;announcement_view(announcements,nav);break;
        case 10:page=fmo::Page::Favorites;nav.favorite_index=0;favorites_view(favorites,servers,0,favorites_writable);break;
        case 11:{
            page=fmo::Page::Stamp;
            const fmo::StampConfig fallback{};const auto &sc=stamp_cfg?*stamp_cfg:fallback;
            if(fmo::stamp_is_custom_style(sc.style_id)&&sc.custom_present&&custom_stamp)nav.stamp_index=fmo::kBuiltinStampCount;
            else {const int bi=fmo::stamp_builtin_index(sc.style_id);nav.stamp_index=bi>=0?unsigned(bi):0u;}
            stamp_view(sc,nav.stamp_index,custom_stamp,self_callsign);
            break;
        }
        case 12:page=fmo::Page::Messages;nav.message_index=0;message_view(inbox,0);break;
        case 13:{
            page=fmo::Page::Beep;
            const fmo::BeepConfig fallback{};const auto &bc=beep_cfg?*beep_cfg:fallback;
            nav.beep_index=!bc.enabled?1u:(bc.use_custom&&bc.custom_present?2u:0u);
            beep_view(bc,nav.beep_index);
            break;
        }
        case 14:return fmo::UiAction::ConnectBuiltin;
        case 15:return fmo::UiAction::ToggleSentinel;
        case 16:return fmo::UiAction::BackgroundListen;
        }
    }else if(page==fmo::Page::Stamp){return fmo::UiAction::SaveStamp;}
    else if(page==fmo::Page::Beep){return fmo::UiAction::SaveBeep;}
    else if(page==fmo::Page::History||page==fmo::Page::Volume||page==fmo::Page::Broadcast||page==fmo::Page::Peers||page==fmo::Page::Announcements||page==fmo::Page::Messages){page=fmo::Page::Menu;menu_view(nav.menu_index);}
    else if(page==fmo::Page::Favorites){
        const int slot=favorites&&favorites_writable?favorites->resolve(nav.favorite_index,servers,time(nullptr)):-1;
        if(slot>=0){servers.index=slot;return fmo::UiAction::Connect;}
        favorites_view(favorites,servers,nav.favorite_index,favorites_writable);
    }
    else if(page==fmo::Page::Servers)return servers.count?fmo::UiAction::Connect:fmo::UiAction::Discover;
    return fmo::UiAction::None;
}
void navigate(fmo::UiAction action){
    if(action==fmo::UiAction::PhoneSetup||action==fmo::UiAction::Exit||action==fmo::UiAction::BackgroundListen){
        talk_requested=false;
        // running remains true: registry cooperatively defers teardown until
        // this worker has stopped networking, saved its book and parked.
        if(action==fmo::UiAction::PhoneSetup)fmo_switch_to_wifi_setup();else fmo_switch_to_launcher();
    }
}
const char *mqtt_connection_message(fmo::MqttConnection state){
    switch(state){
    case fmo::MqttConnection::Online:return "在线 · 长按确定讲话";
    case fmo::MqttConnection::AuthenticationRejected:return "服务器拒绝认证";
    case fmo::MqttConnection::BrokerRejected:return "服务器拒绝连接";
    case fmo::MqttConnection::TransportFailed:return "连接服务器失败";
    case fmo::MqttConnection::Disconnected:return "已断线 · 等待重连";
    case fmo::MqttConnection::LocalSetupFailed:return "无法启动服务器连接";
    default:return "正在连接服务器";
    }
}
void event(void *,esp_event_base_t,int32_t id,void *data){
    auto *e=static_cast<esp_mqtt_event_handle_t>(data);
    if(id==MQTT_EVENT_CONNECTED){
        mqtt_inbox.reset();mqtt_connections.reset();mqtt_connection=fmo::MqttConnection::Online;connected=true;
        esp_mqtt_client_subscribe(e->client,"FMO/RAW",0);
        esp_mqtt_client_subscribe(e->client,"$SYS/brokers/+/stats/connections/count",0);
    }else if(id==MQTT_EVENT_DISCONNECTED||id==MQTT_EVENT_ERROR){
        using State=fmo::MqttConnection;
        if(id==MQTT_EVENT_ERROR){
            const auto *error=e->error_handle;
            if(error&&error->error_type==MQTT_ERROR_TYPE_CONNECTION_REFUSED){
                // MQTT 3.1.1 CONNACK codes 4 and 5 mean bad credentials or not authorized.
                const int code=error->connect_return_code;
                mqtt_connection=(code==4||code==5)?State::AuthenticationRejected:State::BrokerRejected;
            }else {
                mqtt_connection=State::TransportFailed;
            }
        }else{
            auto state=mqtt_connection.load();
            if(state==State::Online||state==State::Connecting)mqtt_connection=State::Disconnected;
        }
        connected=false;talk_requested=false;mqtt_inbox.reset();mqtt_connections.reset();
    }else if(id==MQTT_EVENT_DATA){
        if(stop_requested||!queue||!assembly)return;
        const auto kind=mqtt_inbox.feed(e->topic,e->topic_len,e->data,e->data_len,e->current_data_offset,e->total_data_len,assembly,fmo::kPacketMax);
        if(kind==fmo::MqttKind::Voice){Raw raw{};raw.size=e->total_data_len;std::memcpy(raw.data,assembly,raw.size);xQueueSend(queue,&raw,0);}
        else if(kind==fmo::MqttKind::NodeConnections){uint32_t count;if(fmo::node_connection_count(assembly,e->total_data_len,&count))mqtt_connections.update(count,esp_timer_get_time());}
    }
}
void close_mqtt(){
    connected=false;talk_requested=false;
    if(mqtt){esp_mqtt_client_stop(mqtt);esp_mqtt_client_destroy(mqtt);mqtt=nullptr;}
    mqtt_inbox.reset();mqtt_connections.reset();mqtt_connection=fmo::MqttConnection::Connecting;if(queue)xQueueReset(queue);
}
bool start_mqtt(const fmo::Credential &identity,const uint8_t *secret,const fmo::Relay &relay,std::string *uri,std::string *password){
    mqtt_connection=fmo::MqttConnection::LocalSetupFailed;
    const bool builtin=fmo::is_builtin_relay(relay);
    const bool auth_ok=builtin?fmo::guest_jwt_password(identity,time(nullptr),password):fmo::auth_password(identity,secret,relay,time(nullptr),password);
    if(!auth_ok)return false;
    *uri="mqtt://"+std::string(relay.host)+":"+std::to_string(relay.port);
    // Match the reference firmware's stable per-callsign session identity.
    // esp_mqtt_client_init copies this string synchronously in IDF 5.5.3.
    char client_id[32],username[20];
    std::snprintf(client_id,sizeof(client_id),"PASSPORT-%.12s",fmo::bare_callsign(identity.callsign));
    fmo::mqtt_username_for_relay(identity,relay,username);
    esp_mqtt_client_config_t config{};config.broker.address.uri=uri->c_str();config.credentials.client_id=client_id;config.credentials.username=username;config.credentials.authentication.password=password->c_str();config.session.keepalive=30;config.session.protocol_ver=MQTT_PROTOCOL_V_3_1_1;config.network.disable_auto_reconnect=true;config.network.timeout_ms=1500;config.task.stack_size=6144;config.buffer.size=2048;config.buffer.out_size=8192;
    mqtt=esp_mqtt_client_init(&config);if(!mqtt)return false;
    mqtt_connection=fmo::MqttConnection::Connecting;
    if(esp_mqtt_client_register_event(mqtt,static_cast<esp_mqtt_event_id_t>(ESP_EVENT_ANY_ID),event,nullptr)!=ESP_OK||esp_mqtt_client_start(mqtt)!=ESP_OK){esp_mqtt_client_destroy(mqtt);mqtt=nullptr;mqtt_connection=fmo::MqttConnection::LocalSetupFailed;return false;}
    return true;
}
bool socket_write(int fd,const char *data,size_t size){
    size_t at=0;unsigned waits=0;
    while(at<size&&!stop_requested){
        const int n=send(fd,data+at,size-at,0);if(n>0){at+=n;continue;}
        if(n<0&&errno==EINTR){if(++waits<=5)continue;return false;}
        if(n>=0||(errno!=EAGAIN&&errno!=EWOULDBLOCK)||++waits>5)return false;
        fd_set writable;FD_ZERO(&writable);FD_SET(fd,&writable);timeval timeout{0,20000};if(select(fd+1,nullptr,&writable,nullptr,&timeout)<0&&errno!=EINTR)return false;
    }return at==size;
}
// A signal interruption is transient, just like a nonblocking socket with
// no data. Defer to the next worker iteration so stop/PTT remain responsive.
// -2 means retry later; zero is orderly EOF; -1 is a fatal socket error.
int socket_read(int fd,char *data,size_t capacity){
    const int n=recv(fd,data,capacity,0);
    if(n<0&&(errno==EINTR||errno==EAGAIN||errno==EWOULDBLOCK))return -2;
    return n;
}
// Restart only the discovery socket, preserving MQTT/audio and trusted cache.
// A monotonic cooldown prevents repeated button presses from flooding logins.
bool restart_discovery(int &fd,int64_t &next_attempt,int64_t &next_manual,int64_t now){
    if(now<next_manual)return false;
    if(fd>=0)close(fd);
    fd=-1;next_attempt=0;next_manual=now+15000000;
    return true;
}
void discovery_retry_view(bool restarted,bool ready=true){
    if(page!=fmo::Page::Servers||!bsp_lvgl_lock(100))return;
    if(screen)fmo_pixel_label_set_text(state_label,!ready?"请先完成校时与证书配置":restarted?"正在重新连接发现服务":"请稍后再试，间隔15秒");
    bsp_lvgl_unlock();
}
int open_aprs(const char *host){
    addrinfo hints{},*info=nullptr;hints.ai_family=AF_INET;hints.ai_socktype=SOCK_STREAM;
    if(getaddrinfo(host,"14580",&hints,&info))return -1;
    int fd=-1;
    for(auto *p=info;p&&!stop_requested;p=p->ai_next){
        fd=socket(p->ai_family,p->ai_socktype,p->ai_protocol);if(fd<0)continue;
        fcntl(fd,F_SETFL,fcntl(fd,F_GETFL,0)|O_NONBLOCK);
        const int rc=connect(fd,p->ai_addr,p->ai_addrlen);bool ready=rc==0;const bool pending=rc<0&&errno==EINPROGRESS;
        for(unsigned n=0;!ready&&pending&&n<30&&!stop_requested;++n){fd_set write;FD_ZERO(&write);FD_SET(fd,&write);timeval timeout{0,100000};const int result=select(fd+1,nullptr,&write,nullptr,&timeout);if(result>0){int error=0;socklen_t bytes=sizeof(error);ready=getsockopt(fd,SOL_SOCKET,SO_ERROR,&error,&bytes)==0&&!error;break;}if(result<0)break;}
        if(ready){int enabled=1;setsockopt(fd,IPPROTO_TCP,TCP_NODELAY,&enabled,sizeof(enabled));break;}
        close(fd);fd=-1;
    }
    freeaddrinfo(info);return fd;
}
int decode_radpcm(const fmo::Frame &frame,int16_t *pcm){
    static constexpr int steps[]={7,8,9,10,11,12,13,14,16,17,19,21,23,25,28,31,34,37,41,45,50,55,60,66,73,80,88,97,107,118,130,143,157,173,190,209,230,253,279,307,337,371,408,449,494,544,598,658,724,796,876,963,1060,1166,1282,1411,1552,1707,1878,2066,2272,2499,2749,3024,3327,3660,4026,4428,4871,5358,5894,6484,7132,7845,8630,9493,10442,11487,12635,13899,15289,16818,18500,20350,22385,24623,27086,29794,32767};
    static constexpr int indices[]={-1,-1,-1,-1,2,4,6,8};
    if(frame.size!=328||frame.data[4]>88)return -1;
    int predictor=static_cast<int16_t>(frame.data[2]|uint16_t(frame.data[3])<<8),index=frame.data[4];
    for(unsigned i=0;i<640;++i){const unsigned nibble=(frame.data[8+i/2]>>(i%2?0:4))&15;int step=steps[index],diff=step>>3;if(nibble&1)diff+=step>>2;if(nibble&2)diff+=step>>1;if(nibble&4)diff+=step;predictor=std::clamp(predictor+((nibble&8)?-diff:diff),-32768,32767);index=std::clamp(index+indices[nibble&7],0,88);pcm[i]=predictor;}
    return 640;
}
void stop_capture(bool &audio,bool &capturing,bool &encoding,bool &decoder_ready){
    if(!capturing)return;
    bsp_audio_deinit();audio=capturing=encoding=decoder_ready=false;
    if(queue)xQueueReset(queue);
}
void cleanup_session(fmo::Credential &identity,uint8_t *secret,std::string &uri,std::string &password,std::string &error,int &aprs,bool audio){
    talk_requested=false;
    close_mqtt();
    if(aprs>=0){close(aprs);aprs=-1;}
    if(audio)bsp_audio_deinit();
    fmo_clock_stop();
    sodium_memzero(secret,64);
    if(!password.empty())sodium_memzero(password.data(),password.size());
    // vTaskDelete does not unwind C++ locals. Release every owning string
    // before parking the task, rather than merely clearing its length.
    std::string{}.swap(password);
    std::string{}.swap(uri);
    std::string{}.swap(error);
    std::string{}.swap(identity.user_json);
    std::string{}.swap(identity.intermediate_json);
}
fmo::SessionRevocation reject_revoked_session(fmo::Credential &identity,uint8_t *secret,std::string &uri,std::string &password,std::string &error,
                            int &aprs,bool &audio,bool &capturing,bool &encoding,bool &decoder_ready,uint32_t epoch,uint32_t now){
    const auto result=fmo::revocation_session_state(identity,epoch,now);
    if(result==fmo::SessionRevocation::Allowed)return result;
    cleanup_session(identity,secret,uri,password,error,aprs,audio);
    audio=capturing=encoding=decoder_ready=false;current_speaker[0]=0;
    if(queue)xQueueReset(queue);
    return result;
}
__attribute__((noinline)) void play_local_beep(const fmo::BeepConfig &cfg,bool &audio,bool capturing,int16_t *pcm){
    if(!cfg.enabled||capturing||stop_requested)return;
    bool temp_audio=false;
    if(!audio){
        if(bsp_audio_init_playback()!=ESP_OK)return;
        if(bsp_audio_set_format(8000,16,1)!=ESP_OK){bsp_audio_deinit();return;}
        bsp_audio_set_volume(100);
        temp_audio=true;
    }
    fmo::BeepStream stream;
    stream.open(cfg);
    const uint32_t total=stream.total_samples();
    for(uint32_t off=0;off<total&&!stop_requested&&!talk_requested;off+=fmo::kBeepFrameSamples){
        const uint32_t n=std::min<uint32_t>(fmo::kBeepFrameSamples,total-off);
        stream.read_samples(off,pcm,n);
        if(bsp_audio_write(pcm,n*sizeof(int16_t))!=ESP_OK)break;
    }
    stream.close();
    if(temp_audio)bsp_audio_deinit();
}
__attribute__((noinline)) void finish_ptt_with_beep(const fmo::BeepConfig &cfg,const fmo::Credential &identity,
                                                    const fmo::Relay &selected,OpusEncoder *encoder,
                                                    uint32_t stream_begin,int64_t tx_start,uint16_t &tx_index,
                                                    bool &audio,bool &capturing,bool &encoding,bool &decoder_ready,
                                                    int16_t *pcm,uint8_t *encoded,uint8_t *outgoing,fmo::Packet &packet){
    // Release capture immediately so no post-release microphone samples are retained.
    if(capturing){bsp_audio_deinit();audio=capturing=false;}
    fmo::BeepStream stream;
    stream.open(cfg);
    const uint32_t total=stream.total_samples();
    ESP_LOGI("fmo","Roger beep (%s, %lu samples) TX+play",stream.is_custom()?"custom":"builtin",static_cast<unsigned long>(total));
    if(connected&&mqtt&&encoder){
        for(uint32_t off=0;off<total&&!stop_requested&&connected&&!talk_requested;off+=fmo::kBeepFrameSamples){
            if(esp_timer_get_time()-tx_start>=60000000)break;
            stream.read_samples(off,pcm,fmo::kBeepFrameSamples);
            const int bytes=opus_encode(encoder,pcm,static_cast<int>(fmo::kBeepFrameSamples),encoded,1275);
            if(bytes<=0)break;
            packet={};
            packet.vendor=0x1001;packet.uid=identity.uid;std::strcpy(packet.callsign,identity.callsign);
            packet.server_uid=selected.uid;packet.stream_begin=stream_begin;
            packet.timestamp=stream_begin+static_cast<uint32_t>((esp_timer_get_time()-tx_start)/1000);
            packet.count=1;packet.frames[0]={1,encoded,static_cast<size_t>(bytes),tx_index++};
            if(!tx_index)tx_index=1;
            const auto n=fmo::write_packet(outgoing,1400,packet);
            if(!n||esp_mqtt_client_publish(mqtt,"FMO/RAW",reinterpret_cast<const char *>(outgoing),n,0,0)<0)break;
            vTaskDelay(pdMS_TO_TICKS(15));
        }
    }
    encoding=false;decoder_ready=false;
    if(!stop_requested&&!talk_requested){
        audio=bsp_audio_init_playback()==ESP_OK;
        if(audio)audio=bsp_audio_set_format(8000,16,1)==ESP_OK;
        if(!audio){bsp_audio_deinit();}
        else{
            bsp_audio_set_volume(100);
            for(uint32_t off=0;off<total&&!stop_requested&&!talk_requested;off+=fmo::kBeepFrameSamples){
                const uint32_t n=std::min<uint32_t>(fmo::kBeepFrameSamples,total-off);
                stream.read_samples(off,pcm,n);
                if(bsp_audio_write(pcm,n*sizeof(int16_t))!=ESP_OK)break;
            }
        }
    }
    stream.close();
}
void run(void *){
    struct WorkerScratch {
        fmo::Credential identity{};
        fmo::RelayList servers{};
        fmo::Relay selected{};
        fmo::Relay discovered{};
        fmo::StationStatus snapshot{};
        fmo::StampConfig stamp_cfg{};
        fmo::BeepConfig beep_cfg{};
        fmo::BroadcastConfig broadcast{};
        fmo::Packet packet{};
        int16_t pcm[640]{};
        uint8_t encoded[1275]{};
        uint8_t outgoing[1400]{};
        char line[513]{};
        char chunk[256]{};
        alignas(4) uint8_t raw_storage[4+fmo::kPacketMax]{};
        struct ObservedRelay { fmo::Relay relay{}; uint32_t valid_until=0; fmo::StationStatus status{}; };
        ObservedRelay observed[12]{};
        unsigned observed_count=0;
        char peer_pass_calls[16][13]{};
        unsigned peer_pass_count=0;
        char listen_name[48]{};
        char listen_call[13]{};
    };
    uint8_t secret[64]{};std::string error,uri,password;int aprs=-1;bool audio=false,capturing=false;
    std::unique_ptr<WorkerScratch> scratch(new(std::nothrow) WorkerScratch);
    if(!scratch){show("FMO内存不足");running=false;vTaskSuspend(nullptr);return;}
    auto &identity=scratch->identity;auto &servers=scratch->servers;auto *pcm=scratch->pcm;
    auto &stamp_cfg=scratch->stamp_cfg;auto &beep_cfg=scratch->beep_cfg;auto &broadcast=scratch->broadcast;
    bool cache_dirty=false;int64_t next_cache_save=0;
    // Heap-owned to preserve the worker's bounded audio stack. vTaskDelete
    // skips destructors, so cleanup explicitly releases all buffers before park.
    std::unique_ptr<fmo::ContactBook> book(new(std::nothrow) fmo::ContactBook);
    std::unique_ptr<fmo::PeerEvents> peers(new(std::nothrow) fmo::PeerEvents);
    std::unique_ptr<fmo::AprsInbox> inbox(new(std::nothrow) fmo::AprsInbox);
    std::unique_ptr<fmo::Announcements> announcements(new(std::nothrow) fmo::Announcements);
    std::unique_ptr<fmo::Favorites> favorites(new(std::nothrow) fmo::Favorites);
    std::unique_ptr<fmo::PeerStamps> peer_stamps(new(std::nothrow) fmo::PeerStamps);
    const bool stamp_writable=fmo::load_stamp_config(&stamp_cfg)!=fmo::StampLoad::Unavailable;
    const bool beep_writable=fmo::load_beep_config(&beep_cfg)!=fmo::BeepLoad::Unavailable;
    std::unique_ptr<uint8_t[]> custom_stamp;
    if(stamp_writable&&stamp_cfg.custom_present){
        custom_stamp.reset(new(std::nothrow) uint8_t[fmo::kStampPixelBytes]);
        if(custom_stamp&&fmo::load_custom_stamp_image(stamp_cfg,custom_stamp.get())!=fmo::StampLoad::Ready)custom_stamp.reset();
    }
    const bool peer_stamps_writable=peer_stamps&&fmo::load_peer_stamps(peer_stamps.get())!=fmo::StampLoad::Unavailable;
    bool peer_stamps_dirty=false;
    const bool favorites_writable=favorites&&fmo::load_favorites(favorites.get())!=fmo::FavoritesLoad::Unavailable;
    bool book_dirty=false;const bool book_writable=book&&fmo::load_contact_book(book.get())!=fmo::BookLoad::Unavailable;
    int64_t next_book_save=esp_timer_get_time()+60000000;
    const bool broadcast_config_ok=fmo::load_broadcast_config(&broadcast);bool broadcast_ready=false;
    std::string aprs_login_text,aprs_login_call;
    auto cleanup=[&](){std::string{}.swap(aprs_login_text);std::string{}.swap(aprs_login_call);cleanup_session(identity,secret,uri,password,error,aprs,audio);if(cache_dirty&&scratch)fmo::save_relay_cache(scratch->servers,time(nullptr));if(book_dirty)fmo::save_contact_book(*book);if(peer_stamps_dirty&&peer_stamps)fmo::save_peer_stamps(*peer_stamps);book.reset();peers.reset();announcements.reset();inbox.reset();favorites.reset();peer_stamps.reset();custom_stamp.reset();scratch.reset();};
    fmo::Navigation nav;
    auto service_controls=[&](){if(announcements&&announcements->prune(time(nullptr))&&page==fmo::Page::Announcements)announcement_view(announcements.get(),nav);
        const auto action=process_controls(nav,servers,book.get(),book_writable,peers.get(),announcements.get(),favorites.get(),favorites_writable,&stamp_cfg,custom_stamp.get(),peer_stamps.get(),identity.callsign,inbox.get(),&beep_cfg);
        if(action==fmo::UiAction::BackgroundListen)fmo::set_sentinel_enabled(true);
        navigate(action);
        if(action==fmo::UiAction::BackgroundListen)return fmo::UiAction::None;
        if(action==fmo::UiAction::SaveStamp){
            const char *msg="印章配置不可写，未覆盖";
            if(stamp_writable){
                fmo::StampConfig next=stamp_cfg;
                const bool pick_custom=nav.stamp_index==fmo::kBuiltinStampCount&&stamp_cfg.custom_present&&custom_stamp;
                std::strcpy(next.style_id,pick_custom?"CUSTOM":fmo::stamp_builtin_id(nav.stamp_index));
                if(fmo::save_stamp_config(next)){stamp_cfg=next;msg="印章样式已保存";}
                else msg="印章保存失败，请重试";
            }
            stamp_view(stamp_cfg,nav.stamp_index,custom_stamp.get(),identity.callsign,msg);
            return fmo::UiAction::None;
        }
        if(action==fmo::UiAction::SaveBeep){
            const char *msg="信令音配置不可写，未覆盖";
            if(beep_writable){
                fmo::BeepConfig next=beep_cfg;
                const unsigned total=beep_cfg.custom_present?3u:2u;
                const unsigned mode=nav.beep_index%total;
                next.enabled=(mode!=1u);
                next.use_custom=(mode==2u&&beep_cfg.custom_present);
                if(fmo::save_beep_config(next)){
                    beep_cfg=next;
                    msg=!next.enabled?"结束信令音已关闭":(next.use_custom?"已启用自定义信令音":"已启用内置双音");
                    if(next.enabled)play_local_beep(beep_cfg,audio,capturing,pcm);
                }else msg="信令音保存失败，请重试";
            }
            beep_view(beep_cfg,nav.beep_index,msg);
            return fmo::UiAction::None;
        }
        if(action==fmo::UiAction::ToggleSentinel){
            const bool next=!fmo::sentinel_enabled();
            const bool ok=fmo::set_sentinel_enabled(next);
            const char *msg=ok?(next?"后台守听插播：已开启\n听歌时自动插播通联":"后台守听插播：已关闭"):"保存失败，请重试";
            if(bsp_lvgl_lock(100)){if(screen)fmo_pixel_label_set_text(state_label,msg);bsp_lvgl_unlock();}
            return fmo::UiAction::None;
        }
        if(action==fmo::UiAction::Discover&&!broadcast_ready){discovery_retry_view(false,false);return fmo::UiAction::None;}
        if(action==fmo::UiAction::CQ||action==fmo::UiAction::Beacon){broadcast_view(action==fmo::UiAction::Beacon,broadcast.grid,broadcast_ready?"正在检查广播条件":"请先完成校时与证书配置");if(!broadcast_ready)return fmo::UiAction::None;}
        return action;};
    // Setup and local history remain usable during time sync, while offline,
    // and before a certificate has been issued.
    auto wait_for_exit=[&](const char *state,const char *relay){while(!stop_requested){const auto act=service_controls();if(act==fmo::UiAction::Connect)normal_view();show(state,relay,identity.callsign);ulTaskNotifyTake(pdTRUE,pdMS_TO_TICKS(1000));}};
    fmo_clock_start();
    while(!fmo_clock_valid()&&!stop_requested){service_controls();show("正在校准设备时间");ulTaskNotifyTake(pdTRUE,pdMS_TO_TICKS(1000));}
    if(stop_requested){cleanup();running=false;vTaskSuspend(nullptr);return;}
    if(!fmo::load_identity(&identity,secret,&error)){ESP_LOGW("fmo","Identity not ready: %s",error.c_str());wait_for_exit(error.c_str(),"手机设置 → FMO 身份与证书");cleanup();running=false;vTaskSuspend(nullptr);return;}
    ESP_LOGI("fmo","Session ready uid=%lu beep=%s",static_cast<unsigned long>(identity.uid),beep_cfg.enabled?(beep_cfg.use_custom?"custom":"builtin"):"off");
    const auto restored=fmo::revocation_restore(identity,fmo_root_start,time(nullptr));
    const uint32_t revocation_epoch=restored.epoch;
    const auto initial_revocation=fmo::revocation_session_state(identity,revocation_epoch,time(nullptr));
    if(initial_revocation!=fmo::SessionRevocation::Allowed){
        sodium_memzero(secret,sizeof(secret));
        wait_for_exit(initial_revocation==fmo::SessionRevocation::Revoked?"本机身份已吊销，请重新申请":"身份已更新，请重新打开FMO","手机设置 → FMO 身份与证书");
        cleanup();running=false;vTaskSuspend(nullptr);return;
    }
    const bool aprs_tx_capable=broadcast_config_ok&&broadcast.enabled&&fmo::aprs_login(identity.callsign,broadcast,&aprs_login_text,&aprs_login_call);
    const bool aprs_capable=aprs_tx_capable||fmo::aprs_login(identity.callsign,fmo::BroadcastConfig{},&aprs_login_text,&aprs_login_call);
    fmo::load_relay_cache(&servers,time(nullptr));
    auto &relays=servers.relays;auto &count=servers.count;auto &index=servers.index;
    auto &selected=scratch->selected;selected={};bool has_selected=fmo::load_relay(&selected);
    if(has_selected){
        const int refreshed=servers.refresh_saved_relay(selected,time(nullptr));
        if(refreshed>=0)index=refreshed;
        else if(servers.find(selected.uid)<0){
            if(count==fmo::RelayList::capacity)--count;
            if(servers.add(selected,0,time(nullptr)))index=count-1;
        }
        show("准备连接",selected.name[0]?selected.name:selected.host,identity.callsign);
    }
    else if(count){selected=relays[0];has_selected=true;fmo::save_relay(selected,&error);show("使用已验证服务器缓存",selected.name[0]?selected.name:selected.host,identity.callsign);}
    else {
        selected=fmo::builtin_relay();
        has_selected=true;
        ESP_LOGI("fmo","No saved/cached PASS relay; falling back to built-in relay %s:%u",selected.host,static_cast<unsigned>(selected.port));
        show("使用内置兜底中继",selected.name,identity.callsign);
    }
    const int decoder_bytes=opus_decoder_get_size(1),encoder_bytes=opus_encoder_get_size(1);
    if(decoder_bytes<=0||encoder_bytes<=0||static_cast<size_t>(std::max(decoder_bytes,encoder_bytes))>audio_workspace::kAuxBytes){wait_for_exit("语音编解码内存不足","可使用菜单查看记录或配网");cleanup();running=false;vTaskSuspend(nullptr);return;}
    auto *decoder=reinterpret_cast<OpusDecoder *>(audio_workspace::aux());auto *encoder=reinterpret_cast<OpusEncoder *>(audio_workspace::aux());
    bool encoding=false,decoder_ready=false,ptt_preempted=false;uint32_t stream_begin=0,last_uid=0,last_stream=0;int64_t last_rx=0,tx_start=0,next_connect=0,next_aprs=0,last_ui=0;unsigned aprs_server=0;int64_t next_manual_discovery=0;
    bool aprs_login_sent=false,aprs_ack=false,aprs_verified=false;int64_t aprs_opened=0,aprs_last_data=0,last_broadcast[2]={-60000000,-60000000};
    uint32_t favorite_on_connect_until=0;
    auto last_logged_mqtt=fmo::MqttConnection::Connecting;
    broadcast_ready=true;
    uint16_t tx_index=1;auto *line=scratch->line;size_t line_bytes=0;bool oversized_line=false;
    auto *encoded=scratch->encoded;auto *outgoing=scratch->outgoing;auto &packet=scratch->packet;
    auto &raw=*reinterpret_cast<Raw *>(scratch->raw_storage);
    static_assert(sizeof(scratch->raw_storage)>=sizeof(Raw));
    auto has_peer_pass=[&](const char *cs)->bool{
        for(unsigned i=0;i<scratch->peer_pass_count;++i)if(fmo::is_own_relay(cs,scratch->peer_pass_calls[i]))return true;
        return false;
    };
    auto promote_interop_relay=[&](const fmo::Relay &r,uint32_t until,const fmo::StationStatus &st,const char *kind,uint32_t now_s)->bool{
        if(!servers.add(r,until,now_s,&st))return false;
        discovery_rejection=fmo::StationRejection::None;
        ESP_LOGI("fmo","Discovered %s interop relay %s (%s:%u uid=%lu)",kind,r.name,r.host,static_cast<unsigned>(r.port),static_cast<unsigned long>(r.uid));
        cache_dirty=true;
        if(favorites_writable&&favorites)fmo::remember_connected_relay(favorites.get(),r,until,now_s);
        if(!has_selected){selected=r;has_selected=true;index=servers.find(r.uid);fmo::save_relay(selected,&error);next_connect=0;}
        if(page==fmo::Page::Favorites)favorites_view(favorites.get(),servers,nav.favorite_index,favorites_writable);
        if(page==fmo::Page::Servers)server_list_view(servers,now_s,favorites.get());
        return true;
    };
    auto remember_observed=[&](const fmo::Relay &r,uint32_t until,const fmo::StationStatus &st,uint32_t now_s){
        unsigned kept=0;
        for(unsigned i=0;i<scratch->observed_count;++i){
            if(scratch->observed[i].valid_until<=now_s)continue;
            if(kept!=i)scratch->observed[kept]=scratch->observed[i];
            ++kept;
        }
        scratch->observed_count=kept;
        for(unsigned i=0;i<scratch->observed_count;++i){
            if(scratch->observed[i].relay.uid==r.uid){
                scratch->observed[i]={r,until,st};
                observed_fmo_count=scratch->observed_count;
                return;
            }
        }
        const unsigned slot=(scratch->observed_count<12)?scratch->observed_count++:0u;
        scratch->observed[slot]={r,until,st};
        observed_fmo_count=scratch->observed_count;
    };
    auto remember_peer_pass=[&](const char *cs,uint32_t now_s){
        if(!cs||!*cs)return;
        if(!has_peer_pass(cs)){
            const unsigned slot=(scratch->peer_pass_count<16)?scratch->peer_pass_count++:0u;
            std::snprintf(scratch->peer_pass_calls[slot],sizeof(scratch->peer_pass_calls[slot]),"%.12s",cs);
            ESP_LOGI("fmo","Learned APPASP PASS relay hint: %s",scratch->peer_pass_calls[slot]);
        }
        for(unsigned i=0;i<scratch->observed_count;++i){
            const auto &obs=scratch->observed[i];
            if(obs.valid_until>now_s&&fmo::is_own_relay(obs.relay.callsign,cs)){
                promote_interop_relay(obs.relay,obs.valid_until,obs.status,"appasp",now_s);
            }
        }
    };
    while(!stop_requested){
        const int64_t now=esp_timer_get_time();
        // Free expired slots before processing broadcasts, including when full.
        // The active MQTT relay is kept separately; pruning never drops a call.
        if(servers.prune(time(nullptr))){cache_dirty=true;if(page==fmo::Page::Favorites)favorites_view(favorites.get(),servers,nav.favorite_index,favorites_writable);if(page==fmo::Page::Servers)server_list_view(servers,time(nullptr),favorites.get());if(has_selected)show_relay(selected,servers,time(nullptr));}
        if(peers&&peers->prune(time(nullptr))&&page==fmo::Page::Peers)peers_view(peers.get(),nav.peer_index);
        const auto action=service_controls();
        if(stop_requested)break;
        const auto revocation=reject_revoked_session(identity,secret,uri,password,error,aprs,audio,capturing,encoding,decoder_ready,revocation_epoch,time(nullptr));
        if(revocation!=fmo::SessionRevocation::Allowed){
            broadcast_ready=false;
            wait_for_exit(revocation==fmo::SessionRevocation::Revoked?"本机身份已吊销，通联已停止":"身份已更新，请重新打开FMO","手机设置 → FMO 身份与证书");break;
        }
        if(static_cast<uint64_t>(time(nullptr))>=identity.expires){close_mqtt();if(aprs>=0){close(aprs);aprs=-1;}if(audio)bsp_audio_deinit();audio=capturing=false;sodium_memzero(secret,sizeof(secret));broadcast_ready=false;wait_for_exit("设备证书已过期，请重新申请","手机设置 → FMO 身份与证书");break;}
        // Only a physical PTT release may append a tone. Menu navigation,
        // capture failure, route preemption and timeout simply stop capture.
        if(!talk_requested){
            const bool released=ptt_released.exchange(false);
            if(released&&encoding&&tx_index!=1&&!ptt_preempted&&page==fmo::Page::Main&&
               connected&&WifiManager::GetInstance().IsConnected()&&beep_cfg.enabled&&now-tx_start<60000000){
                finish_ptt_with_beep(beep_cfg,identity,selected,encoder,stream_begin,tx_start,tx_index,audio,capturing,encoding,decoder_ready,pcm,encoded,outgoing,packet);
            }else{
                stop_capture(audio,capturing,encoding,decoder_ready);
            }
            ptt_preempted=false;
        }
        if(action==fmo::UiAction::Discover)discovery_retry_view(restart_discovery(aprs,next_aprs,next_manual_discovery,now));
        if(action==fmo::UiAction::ConnectBuiltin){
            favorite_on_connect_until=0;
            talk_requested=false;close_mqtt();
            selected=fmo::builtin_relay();has_selected=true;
            fmo::clear_relay(&error);next_connect=0;
            ESP_LOGI("fmo","Switched to built-in fallback relay %s:%u",selected.host,static_cast<unsigned>(selected.port));
            normal_view();show("正在连接内置中继",selected.name,identity.callsign);show_relay(selected,servers,time(nullptr));
        }
        if(action==fmo::UiAction::Connect&&count){
            favorite_on_connect_until=0;
            if(servers.expires[index]&&servers.expires[index]<=uint64_t(time(nullptr))){normal_view();show("服务器信息过期，等待更新");}
            else {
                talk_requested=false;close_mqtt();
                selected=relays[index];has_selected=true;
                if(favorites_writable&&favorites->find(selected)<0)favorite_on_connect_until=servers.expires[index];
                fmo::save_relay(selected,&error);next_connect=0;
                normal_view();show_relay(selected,servers,time(nullptr));
            }
        }
        if(favorite_on_connect_until&&connected&&!talk_requested&&now-last_rx>=2000000){
            const uint32_t signed_until=favorite_on_connect_until;
            favorite_on_connect_until=0;
            if(fmo::remember_connected_relay(favorites.get(),selected,signed_until,time(nullptr))){
                if(page==fmo::Page::Favorites)favorites_view(favorites.get(),servers,nav.favorite_index,favorites_writable);
                if(page==fmo::Page::Servers)server_list_view(servers,time(nullptr),favorites.get());
            }
        }
        if(action==fmo::UiAction::CQ||action==fmo::UiAction::Beacon){
            const bool beacon=action==fmo::UiAction::Beacon;const unsigned slot=beacon?1:0;const char *message=nullptr;
            const fmo::BroadcastGate gate{broadcast_ready,broadcast_config_ok,aprs_tx_capable,WifiManager::GetInstance().IsConnected(),aprs>=0,aprs_verified,has_selected&&connected&&!fmo::is_builtin_relay(selected),now,last_rx,last_broadcast[slot]};
            message=fmo::broadcast_block_reason(broadcast,beacon?fmo::BroadcastKind::Beacon:fmo::BroadcastKind::CQ,gate);
            if(!message){
                std::string frame;
                const char *st=(beacon&&broadcast.legacy_beacon&&!fmo::stamp_is_custom_style(stamp_cfg.style_id))?stamp_cfg.style_id:nullptr;
                if(!fmo::broadcast_frame(identity,secret,broadcast,beacon?fmo::BroadcastKind::Beacon:fmo::BroadcastKind::CQ,selected.uid,time(nullptr),&frame,st))message="报文生成失败，请缩短配置字段";
                else if(socket_write(aprs,frame.data(),frame.size())){last_broadcast[slot]=now;message="已写入APRS连接\n未确认远端接收";}
                else {close(aprs);aprs=-1;aprs_verified=false;message="发送未确认，请重连后重试";}
            }
            broadcast_view(beacon,broadcast.grid,message);
        }
        if(!WifiManager::GetInstance().IsConnected()){talk_requested=false;close_mqtt();if(aprs>=0){close(aprs);aprs=-1;}if(audio)bsp_audio_deinit();audio=capturing=encoding=decoder_ready=false;last_uid=last_stream=0;current_speaker[0]=0;show("网络未连接");ulTaskNotifyTake(pdTRUE,pdMS_TO_TICKS(1000));continue;}
        if(aprs>=0&&((!aprs_ack&&now-aprs_opened>15000000)||now-aprs_last_data>90000000)){ESP_LOGW("fmo","APRS socket timeout (ack=%d), reconnecting",aprs_ack?1:0);close(aprs);aprs=-1;aprs_verified=false;}
        if(aprs_capable&&now>=next_aprs&&aprs<0&&!talk_requested&&now-last_rx>=1500000){const char *aprs_host=(aprs_server++%2)?"rotate.aprs2.net":"china.aprs2.net";aprs=open_aprs(aprs_host);ESP_LOGI("fmo","APRS connect %s -> fd=%d",aprs_host,aprs);next_aprs=now+30000000;aprs_opened=aprs_last_data=esp_timer_get_time();aprs_login_sent=aprs_ack=aprs_verified=false;line_bytes=0;oversized_line=false;}
        if(aprs>=0&&!talk_requested&&now-last_rx>=500000){auto *chunk=scratch->chunk;const int n=socket_read(aprs,chunk,sizeof(scratch->chunk));
            if(n==0||n==-1){ESP_LOGW("fmo","APRS closed (n=%d)",n);close(aprs);aprs=-1;}
            else if(n>0){aprs_last_data=now;for(int k=0;k<n;++k){char ch=chunk[k];if(ch=='\n'){
                if(line_bytes&&!oversized_line){if(line[line_bytes-1]=='\r')--line_bytes;line[line_bytes]=0;
                    if(line[0]=='#'){
                        if(!aprs_login_sent){if(socket_write(aprs,aprs_login_text.data(),aprs_login_text.size()))aprs_login_sent=true;else {close(aprs);aprs=-1;break;}}
                        else {const std::string prefix="# logresp "+aprs_login_call+" ";if(!std::strncmp(line,prefix.c_str(),prefix.size())){aprs_ack=true;aprs_verified=aprs_tx_capable&&fmo::aprs_login_verified(line,aprs_login_call.c_str());ESP_LOGI("fmo","APRS logresp ack (verified=%d)",aprs_verified?1:0);}}
                    }else if(aprs_ack&&inbox&&inbox->receive(std::string_view(line,line_bytes),aprs_login_call)){
                        if(page==fmo::Page::Messages){
                            nav.message_index=0;
                            message_view(inbox.get(),0);
                        }
                    }else if(fmo::parse_appasp_listening(line,line_bytes,scratch->listen_name,scratch->listen_call)){
                        remember_peer_pass(scratch->listen_call,static_cast<uint32_t>(time(nullptr)));
                    }else if(!connected||now-last_rx>=1000000){auto &discovered=scratch->discovered;discovered={};uint32_t until=0;auto &snapshot=scratch->snapshot;snapshot={};fmo::StationRejection rejection;uint32_t unknown_issuer=0;const uint32_t now_s=static_cast<uint32_t>(time(nullptr));
                        if(fmo::station_announcement(line,line_bytes,identity,fmo_root_start,now_s,&discovered,&until,&snapshot,&rejection,discovery_chain,&unknown_issuer)&&servers.add(discovered,until,now_s,&snapshot)){
                            discovery_rejection=fmo::StationRejection::None;
                            ESP_LOGI("fmo","Discovered verified relay %s (%s:%u uid=%lu)",discovered.name,discovered.host,static_cast<unsigned>(discovered.port),static_cast<unsigned long>(discovered.uid));
                            if(page==fmo::Page::Favorites)favorites_view(favorites.get(),servers,nav.favorite_index,favorites_writable);
                            cache_dirty=true;
                            if(!has_selected){selected=discovered;has_selected=true;index=servers.find(discovered.uid);fmo::save_relay(selected,&error);next_connect=0;}
                            if(page==fmo::Page::Servers)server_list_view(servers,now_s,favorites.get());
                        }else if(rejection==fmo::StationRejection::UnknownIssuer&&fmo::interop_station_announcement(line,line_bytes,now_s,&discovered,&until,&snapshot,&unknown_issuer)){
                            if(fmo::is_official_interop_relay(discovered.callsign)){
                                promote_interop_relay(discovered,until,snapshot,"official",now_s);
                            }else if(fmo::is_own_relay(discovered.callsign,identity.callsign)){
                                promote_interop_relay(discovered,until,snapshot,"own",now_s);
                            }else if(has_peer_pass(discovered.callsign)){
                                promote_interop_relay(discovered,until,snapshot,"appasp",now_s);
                            }else{
                                remember_observed(discovered,until,snapshot,now_s);
                                if(!count){
                                    discovery_unknown_issuer=unknown_issuer;
                                    discovery_rejection=rejection;
                                    if(page==fmo::Page::Servers)server_list_view(servers,now_s,favorites.get());
                                }
                            }
                        }else if(rejection==fmo::StationRejection::NotStation){
                            if(!receive_peer(line,line_bytes,identity,fmo_root_start,now_s,peers.get(),nav,broadcast_config_ok?&broadcast:nullptr,discovery_chain)&&
                               !receive_announcement(line,line_bytes,identity,fmo_root_start,now_s,announcements.get(),nav,discovery_chain)&&
                               peer_stamps_writable&&peer_stamps){
                                char peer_call[13]{},peer_sty[8]{};
                                if(fmo::parse_pat1_stamp(line,line_bytes,peer_call,peer_sty)&&peer_stamps->remember(peer_call,peer_sty))peer_stamps_dirty=true;
                            }
                        }else if(!count&&(rejection==fmo::StationRejection::UnknownIssuer||rejection==fmo::StationRejection::CertificateInvalid||rejection==fmo::StationRejection::SignatureInvalid)){
                            if(discovery_rejection.load()!=rejection||discovery_unknown_issuer.load()!=unknown_issuer){
                                ESP_LOGW("fmo","Station beacon rejected: reason=%d issuerSn=%lu",static_cast<int>(rejection),static_cast<unsigned long>(unknown_issuer));
                            }
                            discovery_unknown_issuer=unknown_issuer;
                            discovery_rejection=rejection;
                            if(page==fmo::Page::Servers)server_list_view(servers,now_s,favorites.get());
                        }
                    }
                }line_bytes=0;oversized_line=false;
            }else if(line_bytes<512&&!oversized_line)line[line_bytes++]=ch;else oversized_line=true;}}
        }
        if(cache_dirty&&!talk_requested&&!encoding&&now-last_rx>=2000000&&now>=next_cache_save){if(fmo::save_relay_cache(servers,time(nullptr)))cache_dirty=false;next_cache_save=now+60000000;}
        if((book_dirty||peer_stamps_dirty)&&!talk_requested&&!encoding&&now-last_rx>=2000000&&now>=next_book_save){
            if(book_dirty&&fmo::save_contact_book(*book))book_dirty=false;
            if(peer_stamps_dirty&&peer_stamps&&fmo::save_peer_stamps(*peer_stamps))peer_stamps_dirty=false;
            next_book_save=now+60000000;
        }
        const auto cur_mqtt=mqtt_connection.load();
        if(cur_mqtt!=last_logged_mqtt){
            ESP_LOGI("fmo","MQTT state -> %d (%s)",static_cast<int>(cur_mqtt),mqtt_connection_message(cur_mqtt));
            last_logged_mqtt=cur_mqtt;
        }
        if(has_selected&&!connected&&now>=next_connect){
            close_mqtt();
            show(fmo::is_builtin_relay(selected)?"正在连接内置中继":"正在认证中继");
            show_relay(selected,servers,time(nullptr));
            ESP_LOGI("fmo","MQTT connect %s:%u (auth=%s)",selected.host,static_cast<unsigned>(selected.port),fmo::is_builtin_relay(selected)?"guest-jwt":"sas4");
            const bool started=start_mqtt(identity,secret,selected,&uri,&password);
            if(!started)ESP_LOGW("fmo","MQTT start failed");
            next_connect=now+30000000;decoder_ready=false;
        }
        if(connected&&!audio){audio=bsp_audio_init_playback()==ESP_OK;capturing=false;if(audio)audio=bsp_audio_set_format(8000,16,1)==ESP_OK;if(!audio){bsp_audio_deinit();talk_requested=false;show("音频设备不可用");vTaskDelay(pdMS_TO_TICKS(500));continue;}bsp_audio_set_volume(100);}
        if(talk_requested&&connected&&audio){
            if(!encoding){if(last_uid&&now-last_rx<1000000){talk_requested=false;show("频道忙，请松开确定键");continue;}
                if(opus_encoder_init(encoder,8000,1,2048)!=0){talk_requested=false;show("语音编码初始化失败");continue;}
                // Play v0.6.11 PTT start chirp (1200 Hz, 45 ms) while speaker is still open.
                if(beep_cfg.enabled&&audio&&!capturing){fmo::beep_render_ptt_start(pcm,fmo::kBeepPttStartSamples);bsp_audio_write(pcm,fmo::kBeepPttStartSamples*sizeof(int16_t));}
                // Start capture only after PTT: no pre-press microphone samples are retained.
                bsp_audio_deinit();audio=bsp_audio_init_capture()==ESP_OK;capturing=true;
                if(audio)audio=bsp_audio_set_format(8000,16,1)==ESP_OK;
                if(!audio){bsp_audio_deinit();talk_requested=false;show("麦克风初始化失败");continue;}
                opus_encoder_ctl(encoder,4010,4);opus_encoder_ctl(encoder,4024,3001);opus_encoder_ctl(encoder,4002,-1000);opus_encoder_ctl(encoder,4006,1);opus_encoder_ctl(encoder,4020,1);
                timeval utc{};gettimeofday(&utc,nullptr);
                encoding=true;ptt_preempted=false;decoder_ready=false;tx_start=now;stream_begin=static_cast<uint32_t>(uint64_t(utc.tv_sec)*1000+utc.tv_usec/1000);tx_index=1;show("正在发送 · 松开停止",nullptr,identity.callsign);
            }
            // Keep receiving routing headers during PTT so an earlier stream can
            // interrupt our transmission. Never mix its PCM with capture.
            for(unsigned drained=0;drained<kQueueCount&&xQueueReceive(queue,&raw,0)==pdTRUE;++drained){
                auto &other=packet;other={};
                if(fmo::parse_packet(raw.data,raw.size,&other)&&(fmo::is_builtin_relay(selected)||other.server_uid==selected.uid)&&other.uid!=identity.uid&&fmo::route_priority_preempts(other.stream_begin,other.uid,stream_begin,identity.uid)){
                    talk_requested=false;ptt_preempted=true;last_uid=other.uid;last_stream=other.stream_begin;last_rx=now;std::strcpy(current_speaker,other.callsign);show("频道忙，发送已停止",nullptr,current_speaker);break;
                }
            }
            if(!talk_requested)continue;
            if(now-tx_start>=60000000){talk_requested=false;show("已到一分钟，发送已停止");continue;}
            if(bsp_audio_read(pcm,320*sizeof(int16_t))!=ESP_OK){talk_requested=false;ptt_preempted=true;show("麦克风读取失败");continue;}
            if(!talk_requested||stop_requested)continue;
            const int bytes=opus_encode(encoder,pcm,320,encoded,sizeof(scratch->encoded));if(bytes<=0){talk_requested=false;ptt_preempted=true;continue;}
            if(tx_index==1)ESP_LOGI("fmo","PTT first Opus frame=%d B stack_hwm=%u B",bytes,static_cast<unsigned>(uxTaskGetStackHighWaterMark(nullptr)));
            if(tx_index%25==1){const unsigned sec=static_cast<unsigned>((now-tx_start)/1000000);char timer_buf[24]{};std::snprintf(timer_buf,sizeof(timer_buf),"发射 %u:%02u",sec/60,sec%60);ui_apply_hero_meta(nullptr,timer_buf,nullptr);}
            packet={};packet.vendor=0x1001;packet.uid=identity.uid;std::strcpy(packet.callsign,identity.callsign);packet.server_uid=selected.uid;packet.stream_begin=stream_begin;packet.timestamp=stream_begin+static_cast<uint32_t>((esp_timer_get_time()-tx_start)/1000);packet.count=1;packet.frames[0]={1,encoded,static_cast<size_t>(bytes),tx_index++};if(!tx_index)tx_index=1;
            const auto n=fmo::write_packet(outgoing,sizeof(scratch->outgoing),packet);if(!n||esp_mqtt_client_publish(mqtt,"FMO/RAW",reinterpret_cast<const char *>(outgoing),n,0,0)<0){talk_requested=false;ptt_preempted=true;show("发送失败，等待重连");}
        }else{
            if(encoding){encoding=false;decoder_ready=false;xQueueReset(queue);}
            if(capturing){bsp_audio_deinit();audio=bsp_audio_init_playback()==ESP_OK;capturing=false;if(audio)audio=bsp_audio_set_format(8000,16,1)==ESP_OK;if(!audio)bsp_audio_deinit();else bsp_audio_set_volume(100);}
            if(audio&&connected&&xQueueReceive(queue,&raw,pdMS_TO_TICKS(10))==pdTRUE){
                for(unsigned burst=0;burst<4&&!stop_requested&&!talk_requested;++burst){
                    if(burst>0&&xQueueReceive(queue,&raw,0)!=pdTRUE)break;
                    const int64_t rx_now=esp_timer_get_time();
                    packet={};
                    if(fmo::parse_packet(raw.data,raw.size,&packet)&&(fmo::is_builtin_relay(selected)||packet.server_uid==selected.uid)&&packet.uid!=identity.uid){
                        // Half duplex and deterministic route arbitration; stale later streams do not preempt.
                        if(last_uid&&packet.uid!=last_uid&&rx_now-last_rx<1500000&&!fmo::route_priority_preempts(packet.stream_begin,packet.uid,last_stream,last_uid))continue;
                        const bool stream_changed=(last_uid!=packet.uid||last_stream!=packet.stream_begin||rx_now-last_rx>=1000000||std::strcmp(current_speaker,packet.callsign)!=0);
                        if(last_uid!=packet.uid||last_stream!=packet.stream_begin)decoder_ready=false;
                        last_uid=packet.uid;last_stream=packet.stream_begin;last_rx=rx_now;
                        if(stream_changed){
                            std::strcpy(current_speaker,packet.callsign);
                            show("正在收听",nullptr,current_speaker);
                            char vol_buf[24]{};std::snprintf(vol_buf,sizeof(vol_buf),"音量 %u%%",volume_percent.load());
                            ui_apply_hero_meta(nullptr,vol_buf,nullptr);
                        }
                        bool played=false;
                        for(size_t i=0;i<packet.count&&!stop_requested&&!talk_requested;++i){const auto &f=packet.frames[i];int samples=-1;
                            if(f.codec==1){if(!decoder_ready){decoder_ready=opus_decoder_init(decoder,8000,1)==0;}if(decoder_ready)samples=opus_decode(decoder,f.data,f.size,pcm,640,0);}
                            else {samples=decode_radpcm(f,pcm);decoder_ready=false;}
                            if(samples>0&&samples<=640&&bsp_audio_write(pcm,samples*sizeof(int16_t))==ESP_OK)played=true;
                        }
                        const uint32_t book_relay_uid=fmo::is_builtin_relay(selected)?fmo::kBuiltinRelayBookUid:selected.uid;
                        if(played&&book_writable&&book->heard(packet.uid,packet.callsign,book_relay_uid,packet.stream_begin,time(nullptr)))book_dirty=true;
                    }
                }
            }else vTaskDelay(pdMS_TO_TICKS(5));
            if(now-last_ui>=1000000&&now-last_rx>=1000000){
                show(has_selected?mqtt_connection_message(mqtt_connection.load()):aprs>=0?"等待服务器签名广播":"服务器发现服务连接中",nullptr,current_speaker[0]?current_speaker:identity.callsign);
                if(has_selected)show_relay(selected,servers,time(nullptr));
                const char *foot_l=!has_selected?"等待选台":(fmo::is_builtin_relay(selected)?"内置兜底":(fmo::is_official_interop_relay(selected.callsign)?"官方互通":(fmo::is_own_relay(selected.callsign,identity.callsign)?"我的中继":"PASS中继")));
                char foot_r[24]{},meta[48]{};
                std::snprintf(foot_r,sizeof(foot_r),"音量 %u%%",volume_percent.load());
                const unsigned obs=observed_fmo_count.load();
                if(aprs_ack)std::snprintf(meta,sizeof(meta),"APRS在线 可连%u 观察%u",unsigned(servers.count+1),obs);
                else std::snprintf(meta,sizeof(meta),"APRS%s · 信令音%s",aprs>=0?"连接中":"离线",beep_cfg.enabled?"开":"关");
                ui_apply_hero_meta(foot_l,foot_r,meta);
                last_ui=now;
            }
        }
    }
    cleanup();running=false;vTaskSuspend(nullptr);
}
lv_obj_t *label(int y,const lv_font_t *font){auto *l=fmo_pixel_label(screen,"",font,0xdddddd);lv_obj_set_pos(l,12,y);lv_obj_set_width(l,216);lv_obj_set_style_text_align(l,LV_TEXT_ALIGN_CENTER,0);lv_label_set_long_mode(l,LV_LABEL_LONG_DOT);return l;}
void start(){
    fmo_sentinel_stop_sync();
    discovery_unknown_issuer=0;
    discovery_rejection=fmo::StationRejection::NotStation;
    observed_fmo_count=0;
    stop_requested=false;talk_requested=false;ptt_released=false;connected=false;switch_requested=false;page=fmo::Page::Main;menu_requested=false;back_requested=false;favorite_requested=false;next_requested=previous_requested=0;current_speaker[0]=0;
    volume_percent=fmo_get_volume();volume_saved=true;
    stamp_image_buf=new(std::nothrow) uint8_t[fmo::kStampImageBytes]();
    stamp_dsc={};
    if(stamp_image_buf){
        stamp_dsc.header.magic=LV_IMAGE_HEADER_MAGIC;
        stamp_dsc.header.cf=LV_COLOR_FORMAT_I4;
        stamp_dsc.header.w=fmo::kStampWidth;
        stamp_dsc.header.h=fmo::kStampHeight;
        stamp_dsc.header.stride=fmo::kStampWidth/2;
        stamp_dsc.data_size=fmo::kStampImageBytes;
        stamp_dsc.data=stamp_image_buf;
    }
    bsp_lvgl_lock(-1);
    screen=lv_obj_create(nullptr);lv_obj_set_style_bg_color(screen,lv_color_hex(0x0b0f13),0);lv_obj_remove_flag(screen,LV_OBJ_FLAG_SCROLLABLE);
    auto make_box=[](lv_obj_t *parent,int x,int y,int w,int h,int r,uint32_t bg,int bw,uint32_t bc){
        auto *o=lv_obj_create(parent);lv_obj_set_pos(o,x,y);lv_obj_set_size(o,w,h);
        lv_obj_set_style_radius(o,r,0);lv_obj_set_style_bg_color(o,lv_color_hex(bg),0);lv_obj_set_style_bg_opa(o,LV_OPA_COVER,0);
        lv_obj_set_style_border_width(o,bw,0);lv_obj_set_style_border_color(o,lv_color_hex(bc),0);
        lv_obj_set_style_pad_all(o,0,0);lv_obj_remove_flag(o,LV_OBJ_FLAG_SCROLLABLE);return o;
    };
    auto *brand=fmo_pixel_label(screen,"FMO",fmo_font_16(),0xff7a1a);lv_obj_set_pos(brand,12,6);
    auto *subbrand=fmo_pixel_label(screen,"PASSPORT",fmo_font_16(),0x7b8896);lv_obj_set_pos(subbrand,48,6);
    top_clock=fmo_pixel_label(screen,"--:--",fmo_font_16(),0xa8b5c2);lv_obj_set_pos(top_clock,132,6);lv_obj_set_width(top_clock,96);lv_obj_set_style_text_align(top_clock,LV_TEXT_ALIGN_RIGHT,0);
    hero_card=make_box(screen,12,30,216,132,12,0x1b232c,1,0x2e3b47);
    hero_dot=make_box(screen,22,42,8,8,4,0xffb37a,0,0);
    hero_rule=make_box(screen,24,126,192,1,0,0x33414f,0,0);
    hero_foot_l=fmo_pixel_label(screen,"准备中",fmo_font_16(),0xb7c4d0);lv_obj_set_pos(hero_foot_l,24,134);lv_obj_set_width(hero_foot_l,116);lv_label_set_long_mode(hero_foot_l,LV_LABEL_LONG_DOT);
    hero_foot_r=fmo_pixel_label(screen,"音量 80%",fmo_font_16(),0xb7c4d0);lv_obj_set_pos(hero_foot_r,140,134);lv_obj_set_width(hero_foot_r,76);lv_obj_set_style_text_align(hero_foot_r,LV_TEXT_ALIGN_RIGHT,0);
    sub_header=make_box(screen,12,30,216,32,8,0x182029,1,0x26313c);
    make_box(sub_header,0,4,4,24,2,0xff7a1a,0,0);
    sub_title=fmo_pixel_label(sub_header,"FMO",fmo_font_16(),0xe7ecf1);lv_obj_set_pos(sub_title,12,6);lv_obj_set_width(sub_title,196);lv_label_set_long_mode(sub_title,LV_LABEL_LONG_DOT);
    lv_obj_add_flag(sub_header,LV_OBJ_FLAG_HIDDEN);
    panel_card=make_box(screen,12,170,216,94,10,0x141a21,1,0x24303c);
    panel_rule=make_box(screen,24,224,192,1,0,0x222d38,0,0);
    panel_meta=fmo_pixel_label(screen,"APRS 连接中",fmo_font_16(),0x8b98a5);lv_obj_set_pos(panel_meta,20,232);lv_obj_set_width(panel_meta,200);lv_obj_set_style_text_align(panel_meta,LV_TEXT_ALIGN_CENTER,0);lv_label_set_long_mode(panel_meta,LV_LABEL_LONG_DOT);
    stamp_image=lv_image_create(screen);lv_obj_set_pos(stamp_image,(240-fmo::kStampWidth)/2,74);lv_obj_add_flag(stamp_image,LV_OBJ_FLAG_HIDDEN);
    relay_label=label(36,fmo_font_16());call_label=label(84,fmo_font_20());state_label=label(176,fmo_font_16());hint_label=label(272,fmo_font_16());
    lv_obj_set_height(relay_label,40);lv_obj_set_height(call_label,36);lv_obj_set_height(state_label,44);lv_obj_set_height(hint_label,44);
    lv_obj_set_style_text_color(hint_label,lv_color_hex(0x7b8896),0);
    lv_label_set_text(hint_label,"上键选台 · 下键菜单\n长按确定讲话 · 调音量");
    ui_apply_mode(fmo::Page::Main);
    lv_screen_load(screen);bsp_lvgl_unlock();
    if(!audio_workspace::acquire(audio_workspace::Owner::Plugin)){show("音频资源正在使用");return;}
    constexpr size_t kRxStorageBytes=kQueueCount*sizeof(Raw)+fmo::kPacketMax;
    rx_storage=new(std::nothrow) uint8_t[kRxStorageBytes]();
    if(!rx_storage){audio_workspace::release(audio_workspace::Owner::Plugin);show("FMO音频内存不足");return;}
    queue=xQueueCreateStatic(kQueueCount,sizeof(Raw),rx_storage,&queue_buffer);assembly=rx_storage+kQueueCount*sizeof(Raw);
    if(!queue){assembly=nullptr;delete[] rx_storage;rx_storage=nullptr;audio_workspace::release(audio_workspace::Owner::Plugin);show("FMO音频队列启动失败");return;}
    running=true;worker=xTaskCreateStatic(run,"fmo",kStackBytes,nullptr,5,reinterpret_cast<StackType_t *>(audio_workspace::storage),&task_buffer);
    if(!worker){running=false;vQueueDelete(queue);queue=nullptr;assembly=nullptr;delete[] rx_storage;rx_storage=nullptr;audio_workspace::release(audio_workspace::Owner::Plugin);show("FMO任务启动失败");}
}
bool prepare_stop(){stop_requested=true;talk_requested=false;if(worker)xTaskNotifyGive(worker);return !running.load();}
void stop(){
    if(!prepare_stop())return;
    if(worker){vTaskDelete(worker);worker=nullptr;}if(queue){vQueueDelete(queue);queue=nullptr;}assembly=nullptr;
    if(rx_storage){sodium_memzero(rx_storage,kQueueCount*sizeof(Raw)+fmo::kPacketMax);delete[] rx_storage;rx_storage=nullptr;}
    if(audio_workspace::owner.load()==audio_workspace::Owner::Plugin){sodium_memzero(audio_workspace::storage,audio_workspace::kBytes);audio_workspace::release(audio_workspace::Owner::Plugin);}
    bsp_lvgl_lock(-1);
    if(stamp_image_buf)lv_image_cache_drop(&stamp_dsc);
    if(screen)lv_obj_delete(screen);
    screen=state_label=relay_label=call_label=hint_label=stamp_image=nullptr;
    top_clock=hero_card=hero_dot=hero_rule=hero_foot_l=hero_foot_r=nullptr;
    sub_header=sub_title=panel_card=panel_rule=panel_meta=nullptr;
    bsp_lvgl_unlock();
    delete[] stamp_image_buf;stamp_image_buf=nullptr;stamp_dsc={};
}
void handle_key(uint8_t button,app_btn_event_t e,uint16_t){
    if(button==BSP_BTN_UP&&e==BTN_EVT_LONG){if(page==fmo::Page::Main)adjust_volume(5);else if(page==fmo::Page::Servers||page==fmo::Page::Favorites)favorite_requested=true;return;}
    if(button==BSP_BTN_DOWN&&e==BTN_EVT_LONG){
        talk_requested=false;
        if(page==fmo::Page::Main)adjust_volume(-5);else back_requested=true;
        return;
    }
    if((button==BSP_BTN_UP||button==BSP_BTN_DOWN)&&e==BTN_EVT_CLICK){
        if(page==fmo::Page::Volume){adjust_volume(button==BSP_BTN_UP?5:-5);return;}
        talk_requested=false;
        if(page==fmo::Page::Main){
            if(button==BSP_BTN_DOWN){page=fmo::Page::Menu;menu_requested=true;return;}
            page=fmo::Page::Servers;++next_requested;return;
        }
        if(button==BSP_BTN_UP)++previous_requested;else ++next_requested;
        return;
    }
    if(button==BSP_BTN_OK){
        if(e==BTN_EVT_LONG){if(page!=fmo::Page::Main)return;if(connected){ptt_released=false;talk_requested=true;}else show("请先连接中继");}
        else if(e==BTN_EVT_RELEASE||e==BTN_EVT_LONG_UP){
            if(talk_requested)ptt_released=true;
            talk_requested=false;
        }
        else if(e==BTN_EVT_CLICK)switch_requested=true;
    }
}
void key(uint8_t button,app_btn_event_t e,uint16_t mv){
    handle_key(button,e,mv);
    // Wake after publishing the request. Offline/setup pages can block between
    // keys instead of polling, and stop requests use the same wake path.
    if(worker)xTaskNotifyGive(worker);
}
}
#ifdef ESP_PLATFORM
namespace {
constexpr const char *kFmoIconRows[PASSPORT_PLUGIN_ICON_ROWS] = {
    ".................",
    "...........#.....",
    "...........#.....",
    "...........#.....",
    "...........#.....",
    "....#########....",
    "....#.......#....",
    "....#.......#....",
    "....#.#####.#....",
    "....#.......#....",
    "....#.#####.#....",
    "....#.......#....",
    "....#...#...#....",
    "....#...#...#....",
    "....#.......#....",
    "....#########....",
    ".................",
};

const passport_plugin_t kFmoPlugin = {
    .id = "fmo",
    .name = "FMO",
    .en_name = "FMO",
    .desc = "通联 · 守听",
    .tag = "Wi-Fi",
    .theme_color = 0xFF7A1A,
    .icon_rows = kFmoIconRows,
    .caps = PASSPORT_PLUGIN_CAP_HEAVY_HEAP | PASSPORT_PLUGIN_CAP_BALANCED_WIFI | PASSPORT_PLUGIN_CAP_OWNS_LONG_OK,
    .heap_largest = 16 * 1024,
    .heap_free = 64 * 1024,
    .mcp_alias = "fmo",
    .web_path = "/fmo",
    .web_title = "FMO 互通通联配置",
    .web_subtitle = "证书 · 中继 · 印章 · 尾音",
    .init = nullptr,
    .start = start,
    .stop = stop,
    .on_key = key,
    .prepare_stop = prepare_stop,
    .on_back = nullptr,
    .register_http = fmo_http_register,
    .http_busy = fmo_http_busy,
    .on_system_state = fmo_sentinel_on_system_state,
};
} // namespace

extern "C" int passport_fmo_plugin_register(int base_app_id) {
    return passport_plugin_register(&kFmoPlugin, base_app_id);
}
#else
const passport_app_t g_fmo_app={.id=APP_ID_FMO,.name="FMO",.en_name="FMO",.desc="通联 · 守听",.tag="Wi-Fi",.theme_color=0xff9b40,.init=nullptr,.start=start,.stop=stop,.on_key=key,.prepare_stop=prepare_stop};
#endif
