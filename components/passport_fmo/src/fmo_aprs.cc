#include "fmo_aprs.h"
#include "fmo_utf8.h"
#include <cstring>
#include <cstdio>
#include <cmath>
#include <cstdlib>
namespace fmo {
namespace {
unsigned upper(unsigned char c){return c>='a'&&c<='z'?c-'a'+'A':c;}
bool grid_ok(const char *grid){
    const auto n=strnlen(grid,9);if(n!=4&&n!=6&&n!=8)return false;
    for(unsigned i=0;i<n;++i){const auto c=upper(grid[i]);if(i<2){if(c<'A'||c>'R')return false;}else if(i<4||i>=6){if(c<'0'||c>'9')return false;}else if(c<'A'||c>'X')return false;}
    return true;
}
bool text_ok(const char *s,size_t cap){
    if(strnlen(s,cap)>=cap)return false;
    for(const auto *p=reinterpret_cast<const unsigned char *>(s);*p;++p)if(*p<32||*p==127||*p==',')return false;
    return true;
}
// Grid centres are exact multiples of 1/480 degree. Integer conversion avoids
// half-centiminute rounding differences at southern/western grid boundaries.
void position(int ticks,bool latitude,char *out){
    const unsigned total=(static_cast<unsigned>(ticks<0?-ticks:ticks)*25+1)/2,degree=total/6000,minute=total%6000;
    std::snprintf(out,latitude?9:10,latitude?"%02u%02u.%02u%c":"%03u%02u.%02u%c",degree,minute/100,minute%100,latitude?(ticks<0?'S':'N'):(ticks<0?'W':'E'));
}
}
bool broadcast_config_valid(const BroadcastConfig &c){
    if(c.ssid>15||c.antenna_height>999||!text_ok(c.grid,sizeof(c.grid))||!text_ok(c.frequency,sizeof(c.frequency))||!text_ok(c.rig,sizeof(c.rig))||!text_ok(c.antenna,sizeof(c.antenna)))return false;
    if((c.enabled||c.grid[0])&&!grid_ok(c.grid))return false;
    if(c.frequency[0]){
        bool dot=false;unsigned digits=0,decimal=0;
        for(const char *p=c.frequency;*p;++p){if(*p=='.'&&!dot&&digits){dot=true;continue;}if(*p<'0'||*p>'9')return false;++digits;if(dot&&++decimal>4)return false;}
        const double n=std::strtod(c.frequency,nullptr);if(!digits||(dot&&!decimal)||!std::isfinite(n)||n<100||n>1300)return false;
    }return true;
}
bool grid_position(const char *grid,char lat[9],char lon[10]){
    if(!grid||!lat||!lon||!grid_ok(grid))return false;
    const auto n=std::strlen(grid);int x=-180*480+(int(upper(grid[0]))-'A')*20*480+(grid[2]-'0')*960,y=-90*480+(int(upper(grid[1]))-'A')*10*480+(grid[3]-'0')*480,dx=960,dy=480;
    if(n>=6){dx/=24;dy/=24;x+=(int(upper(grid[4]))-'A')*dx;y+=(int(upper(grid[5]))-'A')*dy;}
    if(n==8){dx/=10;dy/=10;x+=(grid[6]-'0')*dx;y+=(grid[7]-'0')*dy;}
    position(x+dx/2,false,lon);position(y+dy/2,true,lat);return true;
}
bool nearby_beacon(const PeerAnnouncement &event,const char *grid,uint32_t *distance_m){
    if(event.kind!=PeerKind::Beacon||!distance_m)return false;
    char own_lat[9],own_lon[10];if(!grid_position(grid,own_lat,own_lon))return false;
    auto coordinate=[](const char *text,bool latitude,double *value){
        const unsigned length=latitude?8:9,degrees=latitude?2:3;
        if(strnlen(text,length+1)!=length||text[degrees+2]!='.')return false;
        const char hemisphere=text[length-1];
        if(latitude?(hemisphere!='N'&&hemisphere!='S'):(hemisphere!='E'&&hemisphere!='W'))return false;
        unsigned degree=0,minutes=0;
        for(unsigned i=0;i<length-1;++i){
            if(i==degrees+2)continue;
            if(text[i]<'0'||text[i]>'9')return false;
            if(i<degrees)degree=degree*10+text[i]-'0';else minutes=minutes*10+text[i]-'0';
        }
        const unsigned maximum=latitude?90:180;
        if(degree>maximum||minutes>=6000||(degree==maximum&&minutes))return false;
        *value=(degree+minutes/6000.0)*((hemisphere=='S'||hemisphere=='W')?-1:1);return true;
    };
    double a,b,c,d;
    if(!coordinate(own_lat,true,&a)||!coordinate(own_lon,false,&b)||!coordinate(event.latitude,true,&c)||!coordinate(event.longitude,false,&d))return false;
    constexpr double radians=3.14159265358979323846/180;
    const double lat=std::sin((a-c)*radians/2),lon=std::sin((b-d)*radians/2);
    double hav=lat*lat+std::cos(a*radians)*std::cos(c*radians)*lon*lon;
    hav=hav<0?0:hav>1?1:hav;
    const double km=6371.0088*2*std::atan2(std::sqrt(hav),std::sqrt(1-hav));
    if(km>80.0)return false;
    *distance_m=static_cast<uint32_t>(std::round(km*1000));return true;
}
const char *bare_callsign(const char *call){
    if(!call)return "";
    if(call[0]=='P'&&call[1]=='-'&&strnlen(call,13)>=5)return call+2;
    return call;
}
bool aprs_login(const char *call,const BroadcastConfig &c,std::string *login,std::string *login_call){
    if(!login||!login_call)return false;
    login->clear();login_call->clear();if(!call||!broadcast_config_valid(c))return false;
    call=bare_callsign(call);
    const size_t n=strnlen(call,10);if(n<3||n>9)return false;
    unsigned parity[2]{};
    for(unsigned i=0;i<n;++i){const unsigned char ch=call[i];if(!((ch>='A'&&ch<='Z')||(ch>='0'&&ch<='9')))return false;parity[i%2]^=ch;}
    std::string name=call;if(c.enabled&&c.ssid)name+='-'+std::to_string(c.ssid);if(name.size()>9)return false;
    // APRS-IS uses the callsign's alternating-byte XOR checksum, not an
    // account password. A validated FMO identity and explicit opt-in gate TX.
    const int code=c.enabled?((0x73e2^(parity[0]<<8)^parity[1])&0x7fff):-1;
    *login_call=name;
    *login="user "+name+" pass "+std::to_string(code)+" vers PassportOS 0.9 filter u/APFMO4/APPASP g/"+name;
    if(name!=call)*login+="/"+std::string(call);
    *login+="\r\n";
    return true;
}
bool AprsInbox::receive(std::string_view line,std::string_view login){
    const auto gt=line.find('>');
    if(login.empty()||gt<3||gt>9||line.substr(gt+1,6)!="APFM00")return false;
    const auto header_end=gt+7;
    if(line.size()<=header_end||(line[header_end]!=','&&line[header_end]!=':'))return false;
    const auto colon=line.find(':',header_end);
    if(colon==line.npos)return false;
    const auto packet=line.substr(colon+1);
    if(packet.size()<17||packet.front()!=':'||packet[10]!=':'||packet.substr(11,4)!="MSG,")return false;
    auto target=packet.substr(1,9);
    const auto last=target.find_last_not_of(' ');
    if(last==target.npos)return false;
    target=target.substr(0,last+1);
    if(target!=login&&target!=login.substr(0,login.find('-')))return false;
    const auto payload=packet.substr(11);
    const auto separator=payload.rfind('{');
    if(payload.size()>67||separator==payload.npos||separator<=4)return false;
    const auto id=payload.substr(separator+1);
    const auto body=payload.substr(4,separator-4);
    if(id.empty()||id.size()>5||!valid_utf8(body,67))return false;
    const auto letter_or_digit=[](unsigned char c){
        c=upper(c);
        return (c>='A'&&c<='Z')||(c>='0'&&c<='9');
    };
    for(unsigned char c:id)if(!letter_or_digit(c))return false;
    for(unsigned char c:body)if(c<32||c==127)return false;
    const auto sender=line.substr(0,gt);
    for(unsigned char c:sender)if(!letter_or_digit(c)&&c!='-')return false;
    for(unsigned i=0;i<count;++i)
        if(sender==messages[i].sender&&id==messages[i].index&&body==messages[i].body)return false;
    AprsMessage message{};
    std::memcpy(message.sender,sender.data(),sender.size());
    std::memcpy(message.index,id.data(),id.size());
    std::memcpy(message.body,body.data(),body.size());
    if(count<capacity)++count;
    std::memmove(messages+1,messages,(count-1)*sizeof(*messages));
    messages[0]=message;
    return true;
}
bool aprs_login_verified(const char *line,const char *call){
    if(!line||!call||!*call||strnlen(line,513)>512)return false;
    const std::string expected="# logresp "+std::string(call)+" verified,";
    return !std::strncmp(line,expected.c_str(),expected.size());
}
const char *broadcast_block_reason(const BroadcastConfig &c,BroadcastKind kind,const BroadcastGate &g){
    if(!g.identity_ready)return "请先完成校时与证书配置";
    if(!g.config_available)return "广播配置不可读，请重新设置";
    if(!c.enabled)return "请在手机设置开启按键广播";
    if(!g.tx_capable)return "呼号与SSID不适配APRS";
    if(!g.network_connected||!g.aprs_connected)return "APRS尚未连接，请稍后重试";
    if(!g.aprs_verified)return "APRS登录未通过验证";
    if(kind==BroadcastKind::CQ&&!g.relay_connected)return "发送CQ前请先连接中继";
    if(kind==BroadcastKind::Beacon&&!c.frequency[0])return "请先设置电台频率";
    if(g.now_us-g.last_rx_us<1500000)return "频道正在收听，请稍后发送";
    if(g.now_us-g.last_sent_us<60000000)return "每类广播请间隔一分钟";
    return nullptr;
}
}
