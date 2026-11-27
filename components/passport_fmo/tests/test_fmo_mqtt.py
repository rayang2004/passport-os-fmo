"""Actual MQTT callback routing and bounded fragment assembly; no broker needed."""
from pathlib import Path
import subprocess,tempfile
root=Path(__file__).resolve().parents[3]
s=(root/'components/passport_fmo/src/app_fmo.cc').read_text()
def function(signature):
 start=s.index(signature);opening=s.index('{',start);depth=1;i=opening+1
 while depth:
  if s[i]=='{':depth+=1
  elif s[i]=='}':depth-=1
  i+=1
 return s[start:i]
source=r'''
#include "fmo_mqtt.h"
#include "fmo_wire.h"
#include "fmo_crypto.h"
#include "fmo_aprs.h"
#include <ctime>
#include <cstdio>
#include <cassert>
#include <string>
#include <vector>
#include <random>
struct Raw {uint16_t size;uint8_t data[fmo::kPacketMax];};
using esp_event_base_t=const char *;
enum {MQTT_ERROR_TYPE_CONNECTION_REFUSED=1};
struct MqttError {int error_type=0,connect_return_code=0;};
struct Event {MqttError *error_handle=nullptr;int client=1;const char *topic=nullptr,*data=nullptr;int topic_len=0,data_len=0,current_data_offset=0,total_data_len=0;};
using esp_mqtt_event_handle_t=Event *;
enum {MQTT_EVENT_CONNECTED=1,MQTT_EVENT_DISCONNECTED,MQTT_EVENT_ERROR,MQTT_EVENT_DATA};
std::atomic<bool> connected{false},stop_requested{false},talk_requested{false};
std::atomic<fmo::MqttConnection> mqtt_connection{fmo::MqttConnection::Connecting};
fmo::MqttInbox mqtt_inbox;fmo::NodeConnections mqtt_connections;
uint8_t storage[fmo::kPacketMax];uint8_t *assembly=storage;int queue=1,mqtt=1,worker=1;
std::vector<Raw> received;std::vector<std::string> subscriptions;unsigned stopped=0,destroyed=0,worker_wakes=0;
int esp_mqtt_client_subscribe(int,const char *topic,int){subscriptions.emplace_back(topic);return 0;}
void esp_mqtt_client_stop(int){++stopped;}void esp_mqtt_client_destroy(int){++destroyed;}
void xQueueSend(int,const Raw *raw,int){received.push_back(*raw);}void xQueueReset(int){received.clear();}
void xTaskNotifyGive(int){++worker_wakes;}
int64_t mono=100000000;int64_t esp_timer_get_time(){return mono;}

struct esp_mqtt_client_config_t {
 struct {struct {const char *uri=nullptr;} address;} broker;
 struct {const char *client_id=nullptr,*username=nullptr;struct {const char *password=nullptr;} authentication;} credentials;
 struct {int keepalive=0,protocol_ver=0;} session;
 struct {bool disable_auto_reconnect=false;int timeout_ms=0;} network;
 struct {int stack_size=0;} task;
 struct {int size=0,out_size=0;} buffer;
};
constexpr int MQTT_PROTOCOL_V_3_1_1=4,ESP_EVENT_ANY_ID=-1,ESP_OK=0;
using esp_mqtt_event_id_t=int;
bool auth_ok=true,init_ok=true,register_ok=true,start_ok=true;
unsigned auth_calls=0,init_calls=0;
std::string captured_id,captured_user,captured_password,captured_uri;
namespace fmo {
bool auth_password(const Credential &,const uint8_t *,const Relay &,uint32_t,std::string *password){++auth_calls;if(!auth_ok)return false;*password="signed-proof-fixture";return true;}
bool guest_jwt_password(const Credential &,uint32_t,std::string *password){++auth_calls;if(!auth_ok)return false;*password="guest-jwt-fixture";return true;}
Relay builtin_relay(){Relay r{};strcpy(r.host,kBuiltinRelayHost);strcpy(r.callsign,kBuiltinRelayCallsign);strcpy(r.name,kBuiltinRelayName);r.uid=0;r.port=kBuiltinRelayPort;return r;}
bool is_builtin_relay(const Relay &r){return r.uid==0&&r.port==kBuiltinRelayPort&&!strcmp(r.host,kBuiltinRelayHost);}
void mqtt_username_for_relay(const Credential &c,const Relay &r,char out[20]){if(is_builtin_relay(r))snprintf(out,20,"P-%.12s",bare_callsign(c.callsign));else snprintf(out,20,"%.12s",c.callsign);}
}
int esp_mqtt_client_init(const esp_mqtt_client_config_t *c){
 ++init_calls;if(!init_ok)return 0;
 assert(c->credentials.client_id);captured_id=c->credentials.client_id;captured_user=c->credentials.username;captured_password=c->credentials.authentication.password;captured_uri=c->broker.address.uri;
 assert(c->session.keepalive==30&&c->session.protocol_ver==MQTT_PROTOCOL_V_3_1_1&&c->network.disable_auto_reconnect&&c->network.timeout_ms==1500&&c->task.stack_size==6144&&c->buffer.size==2048&&c->buffer.out_size==8192);return 1;
}
int esp_mqtt_client_register_event(int,int,void (*)(void *,esp_event_base_t,int32_t,void *),void *){return register_ok?0:-1;}
int esp_mqtt_client_start(int){return start_ok?0:-1;}
'''+function('void event(void *')+'\n'+function('void close_mqtt(')+'\n'+function('bool start_mqtt(')+r'''
int main(){
 Event e;
 using State=fmo::MqttConnection;
 MqttError error{MQTT_ERROR_TYPE_CONNECTION_REFUSED,5};e.error_handle=&error;
 event(nullptr,nullptr,MQTT_EVENT_ERROR,&e);assert(mqtt_connection==State::AuthenticationRejected);
 event(nullptr,nullptr,MQTT_EVENT_DISCONNECTED,&e);assert(mqtt_connection==State::AuthenticationRejected);
 error.connect_return_code=3;event(nullptr,nullptr,MQTT_EVENT_ERROR,&e);assert(mqtt_connection==State::BrokerRejected);
 e.error_handle=nullptr;event(nullptr,nullptr,MQTT_EVENT_ERROR,&e);assert(mqtt_connection==State::TransportFailed);
 event(nullptr,nullptr,MQTT_EVENT_CONNECTED,&e);assert(mqtt_connection==State::Online);assert(connected&&subscriptions.size()==2&&subscriptions[0]=="FMO/RAW"&&subscriptions[1]=="$SYS/brokers/+/stats/connections/count");
 auto feed=[&](const char *topic,const char *data,int n,int offset,int total){e.topic=topic;e.topic_len=topic?strlen(topic):0;e.data=data;e.data_len=n;e.current_data_offset=offset;e.total_data_len=total;event(nullptr,nullptr,MQTT_EVENT_DATA,&e);};
 uint32_t count=777;assert(!mqtt_connections.read(mono,&count));
 const unsigned wakes_before=worker_wakes;
 feed("FMO/RAW","ab",2,0,4);assert(received.empty()&&worker_wakes==wakes_before);feed(nullptr,"cd",2,2,4);assert(received.size()==1&&worker_wakes==wakes_before+1&&received[0].size==4&&!memcmp(received[0].data,"abcd",4));
 const char *topic="$SYS/brokers/emqx@127.0.0.1/stats/connections/count";
 feed(topic,"1",1,0,3);assert(!mqtt_connections.read(mono,&count));feed(nullptr,"23",2,1,3);assert(mqtt_connections.read(mono,&count)&&count==123&&received.size()==1);
 for(const char *bad:{"-1","+1","1.0"," 1","1 ","{}","4294967296","12345678901"}){feed(topic,bad,strlen(bad),0,strlen(bad));assert(mqtt_connections.read(mono,&count)&&count==123&&received.size()==1);}
 feed(topic,"4294967295",10,0,10);assert(mqtt_connections.read(mono,&count)&&count==UINT32_MAX);
 feed(topic,"0",1,0,1);assert(mqtt_connections.read(mono,&count)&&count==0);
 assert(mqtt_connections.read(mono+120000000,&count)&&!mqtt_connections.read(mono+121000000,&count)&&!mqtt_connections.read(mono-1000000,&count));
 for(const char *bad:{"FMO/PROFILE","FMO/RAW/X","$SYS/brokers//stats/connections/count","$SYS/brokers/x/y/stats/connections/count","$SYS/brokers/+/stats/connections/count","$SYS/brokers/x/stats/connections/countX","$SYS/brokers/x/stats/sessions/count"}){feed(bad,"ABCD",4,0,4);assert(received.size()==1);}
 feed(topic,"1",1,0,2);feed("$SYS/brokers/other/stats/connections/count","2",1,1,2);assert(mqtt_connections.read(mono,&count)&&count==0);
 feed("FMO/RAW","ab",2,0,4);feed(topic,"8",1,0,1);feed(nullptr,"cd",2,2,4);assert(received.size()==1&&mqtt_connections.read(mono,&count)&&count==8);
 feed("FMO/RAW","1234",4,0,4);assert(received.size()==2);
 feed("FMO/RAW","x",1,0,1401);feed("FMO/RAW","x",1,-1,1);feed("FMO/RAW","xx",2,0,1);assert(received.size()==2);
 feed("FMO/RAW","x",1,0,2);feed(nullptr,"y",1,1,3);assert(received.size()==2);
 e.data=nullptr;e.data_len=1;e.topic="FMO/RAW";e.topic_len=7;e.total_data_len=1;e.current_data_offset=0;event(nullptr,nullptr,MQTT_EVENT_DATA,&e);assert(received.size()==2);
 stop_requested=true;feed("FMO/RAW","zz",2,0,2);assert(received.size()==2);stop_requested=false;
 event(nullptr,nullptr,MQTT_EVENT_DISCONNECTED,&e);assert(!connected&&!mqtt_connections.read(mono,&count));
 event(nullptr,nullptr,MQTT_EVENT_CONNECTED,&e);assert(!mqtt_connections.read(mono,&count));feed(topic,"9",1,0,1);assert(mqtt_connections.read(mono,&count)&&count==9);
 mqtt=1;close_mqtt();assert(!connected&&!talk_requested&&stopped==1&&destroyed==1&&received.empty()&&!mqtt_connections.read(mono,&count)&&mqtt_inbox.kind==fmo::MqttKind::None);
 fmo::Credential identity;strcpy(identity.callsign,"BG0TEST");fmo::Relay relay;strcpy(relay.host,"relay.example.test");relay.port=1883;uint8_t secret[64]{};std::string uri,password;
 assert(start_mqtt(identity,secret,relay,&uri,&password));assert(captured_id=="PASSPORT-BG0TEST"&&captured_user=="BG0TEST"&&captured_password=="signed-proof-fixture"&&captured_uri=="mqtt://relay.example.test:1883");close_mqtt();
 strcpy(identity.callsign,"BG0TEST/P123");assert(start_mqtt(identity,secret,relay,&uri,&password)&&captured_id=="PASSPORT-BG0TEST/P123");close_mqtt();
 strcpy(identity.callsign,"P-BG0TEST");assert(start_mqtt(identity,secret,relay,&uri,&password)&&captured_id=="PASSPORT-BG0TEST"&&captured_user=="P-BG0TEST");close_mqtt();
 const auto builtin=fmo::builtin_relay();
 strcpy(identity.callsign,"BG0TEST");assert(start_mqtt(identity,secret,builtin,&uri,&password)&&captured_id=="PASSPORT-BG0TEST"&&captured_user=="P-BG0TEST"&&captured_password=="guest-jwt-fixture"&&captured_uri=="mqtt://fmo.simy.asia:1883");close_mqtt();
 strcpy(identity.callsign,"P-BG0TEST");assert(start_mqtt(identity,secret,builtin,&uri,&password)&&captured_id=="PASSPORT-BG0TEST"&&captured_user=="P-BG0TEST"&&captured_password=="guest-jwt-fixture");close_mqtt();
 const auto inits=init_calls;auth_ok=false;assert(!start_mqtt(identity,secret,relay,&uri,&password)&&init_calls==inits);auth_ok=true;
 init_ok=false;assert(!start_mqtt(identity,secret,relay,&uri,&password)&&!mqtt);init_ok=true;
 auto destructions=destroyed;register_ok=false;assert(!start_mqtt(identity,secret,relay,&uri,&password)&&!mqtt&&destroyed==destructions+1);register_ok=true;
 destructions=destroyed;start_ok=false;assert(!start_mqtt(identity,secret,relay,&uri,&password)&&!mqtt&&destroyed==destructions+1);start_ok=true;
 puts("FMO MQTT identity: actual startup config, PASSPORT-callsign ID, distinct username and signed credential, SDK-copied strings, longest callsign and init/register/start/auth failure cleanup PASS");
 // Fuzz fragment metadata, lengths and routes under ASan/UBSan. No allocations
 // or queueing are performed by the production assembler itself.
 fmo::MqttInbox inbox;uint8_t buffer[32];std::mt19937 rng(43);char data[32]{};
 for(unsigned i=0;i<20000;++i){const char *name=i%3==0?topic:i%3==1?"FMO/RAW":"OTHER";inbox.feed(name,strlen(name),data,int(rng()%35)-1,int(rng()%35)-1,int(rng()%35)-1,buffer,sizeof(buffer));}
 inbox.reset();assert(inbox.feed("FMO/RAW",7,"a",1,0,2,buffer,sizeof(buffer))==fmo::MqttKind::None);assert(inbox.feed(nullptr,0,"b",1,1,2,buffer,1)==fmo::MqttKind::None);
 mqtt_connections.update(1,-1);assert(!mqtt_connections.read(0,&count));
 puts("FMO MQTT: actual callback subscriptions, topic/fragment isolation, strict node counters, no telemetry in voice queue, expiry/clock/connection reset and malformed/fuzz bounds PASS");
}
'''
# Host handles are integers; the SDK uses nullable pointer handles.
source=source.replace('mqtt=nullptr','mqtt=0')
with tempfile.TemporaryDirectory(prefix='passport-fmo-mqtt-') as td:
 p=Path(td);(p/'test.cc').write_text(source)
 subprocess.run(['c++','-std=c++17','-Wall','-Wextra','-Werror','-fsanitize=address,undefined','-g','-Imain','-Icomponents/passport_fmo/src',str(p/'test.cc'),'components/passport_fmo/src/fmo_aprs.cc','-o',str(p/'test')],cwd=root,check=True)
 subprocess.run([str(p/'test')],cwd=root,check=True)
