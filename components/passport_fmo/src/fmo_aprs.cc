#include "fmo_aprs.h"
#include "fmo_utf8.h"
#include "fmo_qth_table.inc"
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
namespace {
bool parse_aprs_coord(const char *text,bool latitude,double *value){
    if(!text||!value)return false;
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
}
bool aprs_distance_km_raw(const char *grid,const char *lat_s,const char *lon_s,double *km_out,uint16_t *bearing_out=nullptr){
    if(!grid||!lat_s||!lon_s||!km_out)return false;
    char own_lat[9],own_lon[10];if(!grid_position(grid,own_lat,own_lon))return false;
    double a,b,c,d;
    if(!parse_aprs_coord(own_lat,true,&a)||!parse_aprs_coord(own_lon,false,&b)||!parse_aprs_coord(lat_s,true,&c)||!parse_aprs_coord(lon_s,false,&d))return false;
    constexpr double radians=3.14159265358979323846/180;
    const double lat=std::sin((a-c)*radians/2),lon=std::sin((b-d)*radians/2);
    double hav=lat*lat+std::cos(a*radians)*std::cos(c*radians)*lon*lon;
    hav=hav<0?0:hav>1?1:hav;
    *km_out=6371.0088*2*std::atan2(std::sqrt(hav),std::sqrt(1-hav));
    if(!std::isfinite(*km_out))return false;
    if(bearing_out){
        const double phi1=a*radians,phi2=c*radians,dlam=(d-b)*radians;
        const double y=std::sin(dlam)*std::cos(phi2);
        const double x=std::cos(phi1)*std::sin(phi2)-std::sin(phi1)*std::cos(phi2)*std::cos(dlam);
        double deg=std::atan2(y,x)*(180.0/3.14159265358979323846);
        if(!std::isfinite(deg))deg=0.0;
        if(deg<0.0)deg+=360.0;
        *bearing_out=static_cast<uint16_t>(static_cast<unsigned>(std::round(deg))%360u);
    }
    return true;
}
uint32_t aprs_crc32(const uint8_t *p,size_t n){
    uint32_t c=0xffffffffu;
    while(n--){
        c^=*p++;
        for(unsigned i=0;i<8;++i)c=(c>>1)^(0xedb88320u&(0u-(c&1u)));
    }
    return ~c;
}
void copy_clean_utf8(const char *src,size_t len,char *dst,size_t cap){
    if(!dst||!cap)return;
    dst[0]=0;
    if(!src||!len)return;
    // Strip leading/trailing whitespace and control chars, then keep valid UTF-8 prefix.
    while(len&&(static_cast<unsigned char>(*src)<=32||*src==127)){++src;--len;}
    while(len&&(static_cast<unsigned char>(src[len-1])<=32||src[len-1]==127))--len;
    size_t out=0;
    for(size_t i=0;i<len&&out+1<cap;){
        const unsigned char c=static_cast<unsigned char>(src[i]);
        if(c<32||c==127){++i;continue;}
        size_t bytes=c<0x80?1:(c&0xe0)==0xc0?2:(c&0xf0)==0xe0?3:(c&0xf8)==0xf0?4:1;
        if(i+bytes>len){break;}
        bool ok=true;
        for(size_t k=1;k<bytes;++k)if((static_cast<unsigned char>(src[i+k])&0xc0)!=0x80){ok=false;break;}
        if(!ok){++i;continue;}
        if(out+bytes>=cap)break;
        std::memcpy(dst+out,src+i,bytes);out+=bytes;i+=bytes;
    }
    dst[out]=0;
}
bool same_bare_call(const char *a,const char *b){
    a=bare_callsign(a);b=bare_callsign(b);
    if(!a||!b||!*a||!*b)return false;
    while(*a&&*b){
        if(*a=='-'||*b=='-')break;
        if(upper(static_cast<unsigned char>(*a))!=upper(static_cast<unsigned char>(*b)))return false;
        ++a;++b;
    }
    const bool a_end=(!*a||*a=='-'),b_end=(!*b||*b=='-');
    return a_end&&b_end;
}
}
bool aprs_distance_m(const char *grid,const char *lat,const char *lon,uint32_t *distance_m){
    return aprs_distance_bearing(grid,lat,lon,distance_m,nullptr);
}
bool aprs_distance_bearing(const char *grid,const char *lat,const char *lon,uint32_t *distance_m,uint16_t *bearing_deg){
    if(!distance_m)return false;
    double km=0;
    if(!aprs_distance_km_raw(grid,lat,lon,&km,bearing_deg))return false;
    *distance_m=static_cast<uint32_t>(std::round(km*1000.0));
    return true;
}
bool aprs_coords_to_grid(const char *lat_s,const char *lon_s,char grid_out[7]){
    if(!lat_s||!lon_s||!grid_out)return false;
    double lat_d=0,lon_d=0;
    if(!parse_aprs_coord(lat_s,true,&lat_d)||!parse_aprs_coord(lon_s,false,&lon_d))return false;
    double lon=lon_d+180.0,lat=lat_d+90.0;
    if(lon>=360.0)lon=359.999999;else if(lon<0.0)lon=0.0;
    if(lat>=180.0)lat=179.999999;else if(lat<0.0)lat=0.0;
    const int f_lon=static_cast<int>(lon/20.0);lon-=f_lon*20.0;
    const int f_lat=static_cast<int>(lat/10.0);lat-=f_lat*10.0;
    const int s_lon=static_cast<int>(lon/2.0);lon-=s_lon*2.0;
    const int s_lat=static_cast<int>(lat/1.0);lat-=s_lat*1.0;
    int sub_lon=static_cast<int>(lon*12.0);if(sub_lon>23)sub_lon=23;else if(sub_lon<0)sub_lon=0;
    int sub_lat=static_cast<int>(lat*24.0);if(sub_lat>23)sub_lat=23;else if(sub_lat<0)sub_lat=0;
    grid_out[0]=static_cast<char>('A'+f_lon);
    grid_out[1]=static_cast<char>('A'+f_lat);
    grid_out[2]=static_cast<char>('0'+s_lon);
    grid_out[3]=static_cast<char>('0'+s_lat);
    grid_out[4]=static_cast<char>('a'+sub_lon);
    grid_out[5]=static_cast<char>('a'+sub_lat);
    grid_out[6]=0;
    return true;
}
bool aprs_coords_to_qth(const char *lat_s,const char *lon_s,char *out,size_t cap){
    if(!lat_s||!lon_s||!out||cap<4)return false;
    out[0]=0;
    double lat_d=0,lon_d=0;
    if(!parse_aprs_coord(lat_s,true,&lat_d)||!parse_aprs_coord(lon_s,false,&lon_d))return false;
    // Quick bounding box around China + HK/Macau/Taiwan to skip overseas coordinates immediately.
    if(lat_d<10.0||lat_d>55.5||lon_d<72.0||lon_d>137.0)return false;
    constexpr double radians=3.14159265358979323846/180.0;
    const double cos_lat=std::cos(lat_d*radians);
    constexpr size_t count=sizeof(qth_data::kCities)/sizeof(qth_data::kCities[0]);
    double best_d2=1e18;
    size_t best_idx=count;
    for(size_t i=0;i<count;++i){
        const auto &e=qth_data::kCities[i];
        const double dy=(lat_d-double(e.lat_e2)*0.01)*111.0;
        const double dx=(lon_d-double(e.lon_e2)*0.01)*111.0*cos_lat;
        const double d2=dx*dx+dy*dy;
        if(d2<best_d2){best_d2=d2;best_idx=i;}
    }
    // Accept up to 280 km (covers vast western prefectures while rejecting neighboring countries).
    if(best_idx>=count||best_d2>280.0*280.0)return false;
    const auto &hit=qth_data::kCities[best_idx];
    const char *prov=qth_data::kProvinces[hit.prov];
    const char *city=reinterpret_cast<const char *>(qth_data::kCityNames+hit.name_off);
    if(!std::strcmp(prov,city))std::snprintf(out,cap,"%s",city);
    else std::snprintf(out,cap,"%s%s",prov,city);
    return out[0]!=0;
}
bool grid_to_qth(const char *grid,char *out,size_t cap){
    char lat[9]{},lon[10]{};
    if(!grid_position(grid,lat,lon))return false;
    return aprs_coords_to_qth(lat,lon,out,cap);
}
bool nearby_beacon(const PeerAnnouncement &event,const char *grid,uint32_t *distance_m){
    if(event.kind!=PeerKind::Beacon||!distance_m)return false;
    double km=0;
    if(!aprs_distance_km_raw(grid,event.latitude,event.longitude,&km)||km>80.0)return false;
    *distance_m=static_cast<uint32_t>(std::round(km*1000));return true;
}
void PeerMetaCache::remember(const PeerMeta &meta){
    if(!meta.callsign[0])return;
    unsigned slot=count;
    for(unsigned i=0;i<count;++i){
        if(same_bare_call(entries[i].callsign,meta.callsign)){slot=i;break;}
    }
    PeerMeta merged=meta;
    if(slot<count){
        const auto &prev=entries[slot];
        if(!merged.latitude[0]&&prev.latitude[0])std::strcpy(merged.latitude,prev.latitude);
        if(!merged.longitude[0]&&prev.longitude[0])std::strcpy(merged.longitude,prev.longitude);
        if(!merged.frequency[0]&&prev.frequency[0])std::strcpy(merged.frequency,prev.frequency);
        if(!merged.rig[0]&&prev.rig[0])std::strcpy(merged.rig,prev.rig);
        if(!merged.antenna[0]&&prev.antenna[0])std::strcpy(merged.antenna,prev.antenna);
        if((!merged.qth[0]||!std::strcmp(merged.qth,"Hello FMO"))&&prev.qth[0]&&std::strcmp(prev.qth,"Hello FMO")!=0)std::strcpy(merged.qth,prev.qth);
        else if(!merged.qth[0]&&prev.qth[0])std::strcpy(merged.qth,prev.qth);
        if(!merged.relay_name[0]&&prev.relay_name[0])std::strcpy(merged.relay_name,prev.relay_name);
    }else if(count<capacity){
        ++count;
    }else{
        slot=capacity-1;
        // Prefer evicting an older status-only entry (without coords/freq/qth) before a richer peer entry.
        const bool incoming_rich=(merged.latitude[0]||merged.frequency[0]||merged.qth[0]);
        if(incoming_rich){
            for(unsigned i=capacity;i>0;--i){
                const auto &e=entries[i-1];
                if(!e.latitude[0]&&!e.frequency[0]&&!e.qth[0]){slot=i-1;break;}
            }
        }
    }
    for(unsigned i=slot;i>0;--i)entries[i]=entries[i-1];
    entries[0]=merged;
}
const PeerMeta *PeerMetaCache::find(const char *call) const {
    if(!call||!*call)return nullptr;
    for(unsigned i=0;i<count;++i){
        if(same_bare_call(entries[i].callsign,call))return &entries[i];
    }
    return nullptr;
}
size_t serialize_peer_meta_cache(const PeerMetaCache &cache,uint8_t *out,size_t cap){
    const unsigned n=cache.count>PeerMetaCache::capacity?PeerMetaCache::capacity:cache.count;
    const size_t payload=n*sizeof(PeerMeta);
    const size_t total=12+payload;
    if(!out||cap<total)return 0;
    std::memcpy(out,"FPM1",4);
    out[4]=static_cast<uint8_t>(n&0xffu);out[5]=static_cast<uint8_t>((n>>8)&0xffu);
    const uint16_t esz=static_cast<uint16_t>(sizeof(PeerMeta));
    out[6]=static_cast<uint8_t>(esz&0xffu);out[7]=static_cast<uint8_t>((esz>>8)&0xffu);
    if(payload)std::memcpy(out+12,cache.entries,payload);
    const uint32_t crc=aprs_crc32(out+12,payload);
    out[8]=static_cast<uint8_t>(crc&0xffu);out[9]=static_cast<uint8_t>((crc>>8)&0xffu);
    out[10]=static_cast<uint8_t>((crc>>16)&0xffu);out[11]=static_cast<uint8_t>((crc>>24)&0xffu);
    return total;
}
bool deserialize_peer_meta_cache(const uint8_t *data,size_t size,PeerMetaCache *out){
    if(!data||!out||size<12||std::memcmp(data,"FPM1",4)!=0)return false;
    const uint16_t n=uint16_t(data[4])|(uint16_t(data[5])<<8);
    const uint16_t esz=uint16_t(data[6])|(uint16_t(data[7])<<8);
    const uint32_t hdr_crc=uint32_t(data[8])|(uint32_t(data[9])<<8)|(uint32_t(data[10])<<16)|(uint32_t(data[11])<<24);
    if(n>PeerMetaCache::capacity||esz!=sizeof(PeerMeta))return false;
    const size_t payload=size_t(n)*sizeof(PeerMeta);
    if(size!=12+payload)return false;
    if(aprs_crc32(data+12,payload)!=hdr_crc)return false;
    *out={};
    out->count=n;
    if(payload)std::memcpy(out->entries,data+12,payload);
    for(unsigned i=0;i<n;++i){
        auto &e=out->entries[i];
        e.callsign[sizeof(e.callsign)-1]=0;
        e.latitude[sizeof(e.latitude)-1]=0;
        e.longitude[sizeof(e.longitude)-1]=0;
        e.frequency[sizeof(e.frequency)-1]=0;
        e.rig[sizeof(e.rig)-1]=0;
        e.antenna[sizeof(e.antenna)-1]=0;
        e.qth[sizeof(e.qth)-1]=0;
        e.relay_name[sizeof(e.relay_name)-1]=0;
    }
    return true;
}
bool parse_aprs_peer_meta(const char *line,size_t size,uint32_t now,PeerMeta *out){
    if(!line||!size||size>512||!out)return false;
    *out={};
    std::string_view sv(line,size);
    const auto gt=sv.find('>');
    if(gt<3||gt>15)return false;
    const auto dest_end=sv.find_first_of(",:",gt+1);
    if(dest_end==sv.npos||dest_end<gt+6)return false;
    const auto dest=sv.substr(gt+1,dest_end-gt-1);
    const bool dest_ok=(dest.substr(0,5)=="APFMO"||dest.substr(0,5)=="APPAS");
    if(!dest_ok)return false;
    const auto colon=sv.find(':',dest_end);
    if(colon==sv.npos||colon+2>=sv.size())return false;
    auto src=sv.substr(0,gt);
    if(src.size()>=5&&(src[0]=='P'||src[0]=='p')&&src[1]=='-')src=src.substr(2);
    const auto dash=src.rfind('-');
    if(dash!=src.npos)src=src.substr(0,dash);
    if(src.size()<3||src.size()>=sizeof(out->callsign))return false;
    for(size_t i=0;i<src.size();++i){
        const unsigned char c=upper(static_cast<unsigned char>(src[i]));
        if(!((c>='A'&&c<='Z')||(c>='0'&&c<='9')||c=='/'||c=='-'))return false;
        out->callsign[i]=static_cast<char>(c);
    }
    out->callsign[src.size()]=0;
    const auto payload=sv.substr(colon+1);
    // Case 1: Status frame ">正在 <relay_name>(<relay_call>) 上守听" (APFMO2 / APPASP)
    if(payload[0]=='>'){
        static constexpr std::string_view kPre=">正在 ";
        static constexpr std::string_view kSuf=" 上守听";
        if(payload.size()<=kPre.size()+kSuf.size()+3||payload.substr(0,kPre.size())!=kPre)return false;
        const auto end_pos=payload.find(kSuf,kPre.size());
        if(end_pos==payload.npos||end_pos<=kPre.size()+2)return false;
        std::string_view inner=payload.substr(kPre.size(),end_pos-kPre.size());
        if(!inner.empty()&&inner.back()==')'){
            const auto open_pos=inner.rfind('(');
            if(open_pos!=inner.npos&&open_pos>0)inner=inner.substr(0,open_pos);
        }
        copy_clean_utf8(inner.data(),inner.size(),out->relay_name,sizeof(out->relay_name));
        if(!out->relay_name[0])return false;
        out->seen_utc=now;
        return true;
    }
    // Case 2: Position frame "=/!ddmm.mmN<sym>dddmm.mmE<sym>..." or "/|@<7-byte-ts>ddmm.mmN..."
    size_t pos_off=0;
    if(payload[0]=='='||payload[0]=='!')pos_off=1;
    else if(payload[0]=='/'||payload[0]=='@')pos_off=8;
    else return false;
    if(payload.size()<pos_off+19)return false;
    if((payload[pos_off+7]!='N'&&payload[pos_off+7]!='S')||(payload[pos_off+17]!='E'&&payload[pos_off+17]!='W')||payload[pos_off+4]!='.'||payload[pos_off+14]!='.')return false;
    std::memcpy(out->latitude,payload.data()+pos_off,8);out->latitude[8]=0;
    std::memcpy(out->longitude,payload.data()+pos_off+9,9);out->longitude[9]=0;
    size_t pos=pos_off+19;
    while(pos<payload.size()&&payload[pos]==' ')++pos;
    const auto body=payload.substr(pos);
    // Skip relay station & event announcements; those are not user QSO metadata.
    if(body.substr(0,14)=="FMO-V4,STATION"||body.substr(0,12)=="FMO-V4,JOINT")return false;
    const bool structured=(body.substr(0,6)=="PAT-1,"||body.substr(0,7)=="FMO-V4,"||body.substr(0,7)=="ONLINE,");
    bool any_kv=false;
    size_t start=0;
    while(start<=body.size()){
        const auto comma=body.find(',',start);
        const auto tok=comma==body.npos?body.substr(start):body.substr(start,comma-start);
        if(tok.substr(0,5)=="FREQ:"){
            char fbuf[10]{};
            copy_clean_utf8(tok.data()+5,tok.size()-5,fbuf,sizeof(fbuf));
            bool ok=fbuf[0]!=0,dot=false;
            for(const char *p=fbuf;*p;++p){if(*p=='.'&&!dot){dot=true;continue;}if(*p<'0'||*p>'9'){ok=false;break;}}
            if(ok){const double mhz=std::strtod(fbuf,nullptr);if(std::isfinite(mhz)&&mhz>=28.0&&mhz<=1300.0){std::strcpy(out->frequency,fbuf);any_kv=true;}}
        }else if(tok.substr(0,4)=="RIG:"){
            copy_clean_utf8(tok.data()+4,tok.size()-4,out->rig,sizeof(out->rig));any_kv=true;
        }else if(tok.substr(0,4)=="ANT:"){
            copy_clean_utf8(tok.data()+4,tok.size()-4,out->antenna,sizeof(out->antenna));any_kv=true;
        }else if(tok.substr(0,4)=="QTH:"){
            copy_clean_utf8(tok.data()+4,tok.size()-4,out->qth,sizeof(out->qth));any_kv=true;
        }
        if(comma==body.npos)break;
        start=comma+1;
    }
    // APFMO2 / legacy free-text comment after position (e.g. QTH / greeting)
    if(!structured&&!any_kv&&!body.empty()&&body.substr(0,5)!="CERT:"&&body.substr(0,4)!="SIG:"){
        copy_clean_utf8(body.data(),body.size(),out->qth,sizeof(out->qth));
    }
    out->seen_utc=now;
    return true;
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
    *login="user "+name+" pass "+std::to_string(code)+" vers PassportOS 0.9 filter u/APFMO2/APFMO4/APPASP g/"+name;
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
