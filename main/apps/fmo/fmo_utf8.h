#pragma once
#include <string_view>

namespace fmo {
inline bool valid_utf8(std::string_view text,unsigned maximum){
    unsigned count=0;
    for(size_t i=0;i<text.size();){
        const unsigned char c=text[i];const unsigned width=c<0x80?1:c>=0xc2&&c<=0xdf?2:c>=0xe0&&c<=0xef?3:c>=0xf0&&c<=0xf4?4:0;
        if(!width||i+width>text.size()||++count>maximum)return false;
        for(unsigned j=1;j<width;++j)if((static_cast<unsigned char>(text[i+j])&0xc0)!=0x80)return false;
        if(width>=3){const unsigned char second=text[i+1];if((c==0xe0&&second<0xa0)||(c==0xed&&second>=0xa0)||(c==0xf0&&second<0x90)||(c==0xf4&&second>=0x90))return false;}
        i+=width;
    }
    return true;
}
}
