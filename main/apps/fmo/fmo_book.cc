#include "fmo_book.h"
#include "fmo_wire.h"
#include "nvs.h"
#include <cstring>
#include <mutex>
#include <vector>
#include <algorithm>
#include <limits>
namespace fmo {
namespace {
std::mutex book_mutex;
constexpr size_t kHeader=12,kRecord=40;
constexpr uint32_t kMagic=0x31424d46; // FMB1; explicit little-endian storage.
uint32_t get32(const uint8_t *p){return uint32_t(p[0])|uint32_t(p[1])<<8|uint32_t(p[2])<<16|uint32_t(p[3])<<24;}
void put32(uint8_t *p,uint32_t n){for(unsigned i=0;i<4;++i)p[i]=n>>(8*i);}
bool valid_call(const char *call){
    if(!call)return false;
    const size_t n=strnlen(call,13);if(n<2||n>12)return false;
    for(size_t i=0;i<n;++i)if(!((call[i]>='A'&&call[i]<='Z')||(call[i]>='0'&&call[i]<='9')||call[i]=='/'||call[i]=='-'))return false;
    return true;
}
bool valid(const Contact &c){return c.uid&&c.relay_uid&&c.receptions&&c.first_seen>=1700000000&&c.last_seen>=c.first_seen&&!c.callsign[12]&&valid_call(c.callsign);}
}
bool ContactBook::heard(uint32_t uid,const char *call,uint32_t relay,uint32_t stream,uint32_t utc){
    if(!uid||!relay||utc<1700000000||!valid_call(call)||count>capacity)return false;
    unsigned slot=0;for(;slot<count;++slot)if(contacts[slot].uid==uid&&!std::strcmp(contacts[slot].callsign,call))break;
    if(slot==count){
        // Preserve collected entries when full; never silently evict a stamp.
        if(count==capacity)return false;
        auto &c=contacts[count++];c={};c.uid=uid;std::strcpy(c.callsign,call);c.first_seen=utc;
    }else {
        const auto &c=contacts[slot];const uint32_t delta=stream-c.last_stream;
        if(utc<c.last_seen||!delta)return false;
        // Suppress retransmitted/older streams, including across a reboot.
        // AIRP UTC milliseconds wrap every 49.7 days; an absence exceeding
        // 24 days makes that ordering ambiguous, so accept the next stream.
        if(delta>=0x80000000u&&utc-c.last_seen<=24u*86400)return false;
    }
    auto &c=contacts[slot];c.last_seen=utc;c.relay_uid=relay;c.last_stream=stream;
    if(c.receptions<std::numeric_limits<uint32_t>::max())++c.receptions;
    return true;
}
BookLoad load_contact_book(ContactBook *book){
    if(!book)return BookLoad::Unavailable;
    std::lock_guard<std::mutex> guard(book_mutex);nvs_handle_t h;
    auto e=nvs_open("fmo_os",NVS_READONLY,&h);
    if(e==ESP_ERR_NVS_NOT_FOUND){*book={};return BookLoad::Missing;}
    if(e!=ESP_OK)return BookLoad::Unavailable;
    size_t n=0;e=nvs_get_blob(h,"heard_v1",nullptr,&n);
    if(e==ESP_ERR_NVS_NOT_FOUND){nvs_close(h);*book={};return BookLoad::Missing;}
    if(e!=ESP_OK||n<kHeader||n>kHeader+ContactBook::capacity*kRecord){nvs_close(h);return BookLoad::Unavailable;}
    std::vector<uint8_t> bytes(n);const size_t expected=n;e=nvs_get_blob(h,"heard_v1",bytes.data(),&n);nvs_close(h);
    if(e!=ESP_OK||n!=expected||get32(bytes.data())!=kMagic)return BookLoad::Unavailable;
    const unsigned count=get32(bytes.data()+4);
    if(count>ContactBook::capacity||n!=kHeader+count*kRecord||get32(bytes.data()+8)!=crc32(bytes.data()+kHeader,n-kHeader))return BookLoad::Unavailable;
    // Validate everything before replacing the caller's state.
    for(unsigned i=0;i<count;++i){const auto *p=bytes.data()+kHeader+i*kRecord;Contact c{};
        c.uid=get32(p);c.relay_uid=get32(p+4);c.first_seen=get32(p+8);c.last_seen=get32(p+12);c.receptions=get32(p+16);c.last_stream=get32(p+20);std::memcpy(c.callsign,p+24,13);
        if(!valid(c)||p[37]||p[38]||p[39])return BookLoad::Unavailable;
        for(unsigned j=0;j<i;++j){const auto *previous=bytes.data()+kHeader+j*kRecord;if(get32(previous)==c.uid&&!std::strcmp(reinterpret_cast<const char *>(previous+24),c.callsign))return BookLoad::Unavailable;}
    }
    *book={};book->count=count;
    for(unsigned i=0;i<count;++i){const auto *p=bytes.data()+kHeader+i*kRecord;auto &c=book->contacts[i];
        c.uid=get32(p);c.relay_uid=get32(p+4);c.first_seen=get32(p+8);c.last_seen=get32(p+12);c.receptions=get32(p+16);c.last_stream=get32(p+20);std::memcpy(c.callsign,p+24,13);
    }return BookLoad::Ready;
}
bool save_contact_book(const ContactBook &book){
    if(book.count>ContactBook::capacity)return false;
    std::vector<uint8_t> bytes(kHeader+book.count*kRecord,0);put32(bytes.data(),kMagic);put32(bytes.data()+4,book.count);
    for(unsigned i=0;i<book.count;++i){const auto &c=book.contacts[i];if(!valid(c))return false;auto *p=bytes.data()+kHeader+i*kRecord;
        for(unsigned j=0;j<i;++j)if(book.contacts[j].uid==c.uid&&!std::strcmp(book.contacts[j].callsign,c.callsign))return false;
        put32(p,c.uid);put32(p+4,c.relay_uid);put32(p+8,c.first_seen);put32(p+12,c.last_seen);put32(p+16,c.receptions);put32(p+20,c.last_stream);std::memcpy(p+24,c.callsign,std::strlen(c.callsign));
    }
    put32(bytes.data()+8,crc32(bytes.data()+kHeader,bytes.size()-kHeader));
    std::lock_guard<std::mutex> guard(book_mutex);nvs_handle_t h;if(nvs_open("fmo_os",NVS_READWRITE,&h)!=ESP_OK)return false;
    auto e=nvs_set_blob(h,"heard_v1",bytes.data(),bytes.size());if(e==ESP_OK)e=nvs_commit(h);nvs_close(h);return e==ESP_OK;
}
}
