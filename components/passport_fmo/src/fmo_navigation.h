#pragma once
namespace fmo {
enum class Page { Main, Servers, Menu, History, Volume, Broadcast, Peers, Announcements, Favorites, Stamp, Messages, Beep, WebConfig };
enum class UiAction { None, Connect, PhoneSetup, Exit, CQ, Beacon, Discover, SaveStamp, SaveBeep, ConnectBuiltin, ToggleSentinel, BackgroundListen, OpenGlobalSetup };
struct Navigation {
    unsigned seen_next=0,seen_previous=0,menu_index=0,history_index=0,peer_index=0,event_index=0,event_page=0,favorite_index=0,stamp_index=0,message_index=0,beep_index=0;
};
}
