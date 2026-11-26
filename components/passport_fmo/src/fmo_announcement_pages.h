#pragma once
#include "fmo_crypto.h"
#include <cstdio>
#include <cstring>
namespace fmo {
constexpr unsigned kAnnouncementPageBytes=224;
// Four 26-column rows fit the existing 216x96 label. Wide UTF-8 glyphs use
// two columns; text is already validated by event_status before publication.
inline unsigned announcement_page(const EventNotice &notice,unsigned wanted,char out[kAnnouncementPageBytes]){
    char text[692];std::snprintf(text,sizeof(text),"%s\n%s",notice.body.topic,notice.body.content);
    unsigned page=0,row=0,column=0,used=0;out[0]=0;
    auto newline=[&](){
        column=0;
        if(++row==4){++page;row=0;}
        else if(page==wanted)out[used++]='\n';
    };
    for(size_t i=0;text[i];){
        const unsigned char lead=text[i];
        if(lead=='\n'){newline();++i;continue;}
        const unsigned bytes=lead<0x80?1:(lead&0xe0)==0xc0?2:(lead&0xf0)==0xe0?3:4;
        const unsigned columns=bytes==1?1:2;
        if(column+columns>26)newline();
        if(page==wanted&&used+bytes<kAnnouncementPageBytes){std::memcpy(out+used,text+i,bytes);used+=bytes;}
        column+=columns;i+=bytes;
    }
    out[used]=0;return page+1;
}
}
