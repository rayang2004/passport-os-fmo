// Execute the real captive page with a strict DOM and offline HTTP doubles.
const fs=require('node:fs'),vm=require('node:vm'),assert=require('node:assert/strict');
const html=fs.readFileSync('main/apps/home/phone_setup.html','utf8');
const script=html.match(/<script>\r?\n([\s\S]*?)<\/script>/)[1];
const cityCatalog=JSON.parse(fs.readFileSync('main/apps/home/cities.json','utf8'));
const ids=[...html.matchAll(/\bid="([^"]+)"/g)].map(m=>m[1]);assert.equal(new Set(ids).size,ids.length);
for(const retired of ['portraitSection','cardSection','museSection','/api/avatar','/api/share','/api/cards','portraitPixels'])assert.ok(!html.includes(retired),retired);
assert.ok(!/<(?:script|img|link)\b[^>]*(?:src|href)=["']https?:|url\(["']?https?:/i.test(html));
{const line=script.split('\n').find(l=>l.includes('pt=('));const w={};vm.runInNewContext(line,{window:w,document:{cookie:'pt=314159'}});assert.equal(w.__T,'314159')}
const elements=new Map(),requests=[],timers=new Map();let nextTimer=1;
let fmoCrl={state:'unknown',root:{updated:false,saved:false,cache:'missing',message:'根列表不可用'},user:{updated:true,saved:true,cache:'missing',message:'已验证'},persistence:'signed_banks',enforced:true},failFmoCrl=false,fmoCrlGate=null;
let fmoPub='',fmoReady=false,fmoRemote={state:'none'},failFmoImport=false,fmoRelay=null,fmoServers=[];
let fmoBook=[],fmoBookFault='',fmoClockValid=true,failFmoClock=false,fmoStaConnected=true,fmoLegacyAvail=false;
let fmoStamp={available:true,style_id:'G001',color:'#FF7A1A',label:'AI PASSPORT',custom_present:false,width:96,height:96,bytes:4608};
let fmoBeep={available:true,enabled:true,use_custom:false,custom_present:false,custom_id:0,custom_samples:0};
let fmoAprs={available:true,enabled:false,legacy_beacon:false,ssid:15,grid:'',frequency:'',antenna_height:0,rig:'AI Passport',antenna:''},failAprsSave=false;
let blobBytes=6000,imageMode='ok',qualityAttempts=[],backgroundPresent=false,failBackground=false,failProfile=false;
class Element {
 constructor(){this.value='';this.textContent='';this.style={};this.dataset={};this.options=[];this.classList={toggle(){}};this.type='password';this.files=[];this.hidden=false;this.checked=false;}
 add(o){this.options.push(o)}replaceChildren(...o){this.options=o;this.value=''}
 append(...o){this.options.push(...o)}
 setAttribute(k,v){this[k]=v}removeAttribute(k){delete this[k]}click(){}focus(){}select(){}setSelectionRange(){}
 get selectedOptions(){return this.options.filter(o=>o.value===this.value)}
 getContext(){return {drawImage(){},fillRect(){},translate(){},rotate(){}}}
 toBlob(cb,type,quality){qualityAttempts.push(quality);cb(new Blob([new Uint8Array(typeof blobBytes==='function'?blobBytes(quality):blobBytes)],{type}))}
}
const get=id=>{assert.ok(ids.includes(id),'unknown DOM id '+id);if(!elements.has(id))elements.set(id,new Element());return elements.get(id)};
class Image {constructor(){this.naturalWidth=640;this.naturalHeight=480}set src(v){this._src=v;if(imageMode!=='stall')setImmediate(()=>imageMode==='error'?this.onerror?.():this.onload?.())}}
let state='idle',saved=false,denyFinish=false,emptyScan=true,failScan=false,connectError='',failCities=false,cityGate=null;
let savedProfile={city:'自定义城市',lat:'22.3',lon:'113.6'};
const phoneWindow={__T:314159,scrollTo(){},addEventListener(){},isSecureContext:false,crypto:require('node:crypto').webcrypto,location:{origin:'http://192.168.4.1'}};
const phoneNavigator={};
class TestURL extends URL {static createObjectURL(){return 'blob:fixture'}static revokeObjectURL(){}}
let beepCloudMode='ok',failBeepWrite=false;
const context=vm.createContext({document:{getElementById:get,createElement:()=>new Element()},window:phoneWindow,navigator:phoneNavigator,Option:class{constructor(text,value){this.text=text;this.value=value;this.dataset={}}},Image,FileReader:class{readAsDataURL(){this.result="data:image/jpeg;base64,dGVzdA==";setImmediate(()=>this.onload())}},TextEncoder,Uint8Array,Blob,AbortController,URL:TestURL,URLSearchParams,setTimeout(fn,ms){const id=nextTimer++;timers.set(id,{fn,ms});return id},clearTimeout:id=>timers.delete(id),fetch:async(url,options)=>{
 requests.push({url,options});let result={},ok=true;
 if(url==='https://fmo.simy.live/fw/beep/list.json')return {ok:true,json:async()=>({
  '6':{n:'模拟信令',s:'all'},'2x':'坏编号','1':{n:'指定呼号',s:'call',c:['OTHER']},
  '4':{n:'缺少名单',s:'call'},'5':{n:'未知范围',s:'other'}
 })};
 if(url==='https://fmo.simy.live/fw/beep/6.bin'){
  if(beepCloudMode==='offline')throw Error('offline');
  const payload=new Uint8Array(656);
  payload.set([70,66,69,80,1,beepCloudMode==='wrong-id'?2:6]);
  return {ok:true,blob:async()=>new Blob([payload])};
 }
 const route=url.split('?')[0];assert.ok(['/api/cities','/api/profile','/api/setup','/api/networks','/api/connect','/api/time','/api/finish','/api/background','/api/fmo','/api/fmo/ca','/api/fmo/stamp','/api/fmo/beep'].includes(route),route);
 if(route==='/api/cities'){if(cityGate)await cityGate;if(failCities)throw Error('offline');result=cityCatalog}
 if(route==='/api/profile'){if(!options.method)result=savedProfile;else if(failProfile){ok=false;result={error:'invalid'}}}
 if(route==='/api/setup')result={state,sta_connected:state==='connected',sta_ssid:state==='connected'?'Test Wi-Fi':'',saved_network:saved,saved_networks:saved?['Absent Wi-Fi','Test Wi-Fi']:[],ssid:'Test Wi-Fi'};
 if(route==='/api/networks'){if(failScan)throw Error('offline');result=emptyScan?[]:[{ssid:'Test Wi-Fi',rssi:-45,secure:true}]}
 if(route==='/api/connect'){if(connectError){ok=false;result={error:connectError}}else if(!fmoStaConnected){fmoStaConnected=true;state='connected'}}
 if(route==='/api/time'){result={ok:true,applied:true}}
 if(route==='/api/finish'&&denyFinish){ok=false;result={error:'network_required'}}
 if(route==='/api/background'){
  if(!options.method)result={present:backgroundPresent,available:true,max_bytes:24576};
  else if(failBackground){ok=false;result={error:'background_store'}}
  else if(options.method==='DELETE')backgroundPresent=false;
  else {assert.equal(options.body.type,'image/jpeg');assert.ok(options.body.size<=24576);backgroundPresent=true}
 }
 if(route==='/api/fmo'){
  if(options.method==='POST'){const body=JSON.parse(options.body);if(body.action==='init'){fmoPub||='A'.repeat(43)}else if(body.action==='import_legacy'){fmoPub='L'.repeat(43);fmoReady=true;fmoLegacyAvail=false}else if(body.action==='stamp'){fmoStamp={...fmoStamp,style_id:body.style_id,color:body.color,label:body.label}}else if(body.action==='beep'){fmoBeep={...fmoBeep,enabled:body.enabled,use_custom:body.use_custom??fmoBeep.use_custom}}else if(body.action==='select_builtin_relay'){fmoRelay=null}else if(body.action==='import'){assert.equal(body.certificate,'Y2VydA==');if(failFmoImport){ok=false;result={error:'证书签名验证失败'}}else fmoReady=true}else if(body.action==='check_crl'){if(fmoCrlGate)await fmoCrlGate;if(failFmoCrl){ok=false;result={error:'吊销查询网络断开'}}else result=fmoCrl}else if(body.action==='relay')fmoRelay=body;else if(body.action==='select_relay'){const found=fmoServers.find(s=>s.uid===body.uid);if(!found){ok=false;result={error:'服务器信息已过期'}}else fmoRelay=found}else if(body.action==='aprs'){if(failAprsSave){ok=false;result={error:'APRS保存失败'}}else fmoAprs={...body,available:true}}else assert.fail('unknown FMO action')}
  if(ok&&!(options.method==='POST'&&JSON.parse(options.body).action==='check_crl'))result={pubkey:fmoPub,ready:fmoReady,callsign:fmoReady?'BG0TEST':'',uid:fmoReady?123:0,sta_connected:fmoStaConnected,legacy_cred:fmoLegacyAvail&&!fmoReady?{available:true,callsign:'P-BG0OLD',uid:9610010}:{available:false},stamp:fmoStamp,beep:fmoBeep,builtin_relay:{name:'PASSPORT内置中继台',host:'fmo.simy.asia',port:1883,active:!fmoRelay},relay:fmoRelay,servers:fmoServers,aprs:fmoAprs,clock_valid:fmoClockValid};
  if(url.includes('book=')){
   const page=Number(new URL(url,'http://device/').searchParams.get('book'));
   result={contacts_available:fmoBookFault!=='unavailable',contacts_capacity:64,total:fmoBook.length,contacts:fmoBook.slice(page*8,(page+1)*8)};
   if(fmoBookFault==='missing'&&page===1)result.contacts=[];
  }
 }
 if(route==='/api/fmo/stamp'){
  if(url.includes('raw=1'))return {ok:true,arrayBuffer:async()=>new Uint8Array(4608).fill(0x5a).buffer};
  if(!options.method)result=fmoStamp;
  else if(options.method==='DELETE'){fmoStamp={...fmoStamp,custom_present:false,style_id:'G001'};result={stamp:fmoStamp}}
  else {assert.equal(options.body.type,'application/octet-stream');assert.equal(options.body.size,4608);fmoStamp={...fmoStamp,custom_present:true,style_id:'CUSTOM'};result={stamp:fmoStamp}}
 }
 if(route==='/api/fmo/beep'){
  if(!options.method)result=fmoBeep;
  else if(options.method==='DELETE'){fmoBeep={...fmoBeep,custom_present:false,use_custom:false,custom_id:0};result={beep:fmoBeep}}
  else if(failBeepWrite){ok=false;result={error:'设备写入失败'}}
  else {fmoBeep={...fmoBeep,enabled:true,use_custom:true,custom_present:true,custom_id:6};result={beep:fmoBeep}}
 }
 if(route==='/api/fmo/ca'){
  if(!fmoStaConnected){ok=false;result={error:'设备尚未连接可上网的Wi-Fi',code:'wifi_required'}}
  else if(failFmoClock){ok=false;result={error:'设备时间尚未校准，请重连Wi-Fi让手机校时后重试'}}
  else if(options.method==='POST'){const body=JSON.parse(options.body);assert.equal(body.pubkey,fmoPub);assert.equal(body.callsign,'BG0TEST');assert.match(body.photo_b64,/^data:image\/jpeg;base64,/);result={ok:true};fmoRemote={state:'pending'}}
  else result=fmoRemote;
 }
 return {ok,json:async()=>result};
}});
vm.runInContext(script,context);const flush=()=>new Promise(resolve=>setImmediate(resolve));
const posts=()=>requests.filter(r=>r.options.method==='POST');
(async()=>{
 await flush();await flush();await flush();let profile;
 let copiedText='';
 context.document.execCommand=cmd=>{assert.equal(cmd,'copy');copiedText=get('voiceTutorialLink').value;return true};
 await get('copyVoiceTutorial').onclick();assert.equal(copiedText,'https://github.com/manchunx7-bit/passport-os');assert.equal(get('voiceTutorialLink').hidden,true);
 context.document.execCommand=()=>false;
 await get('copyVoiceTutorial').onclick();assert.equal(get('voiceTutorialLink').hidden,false);assert.match(get('voiceCopyStatus').textContent,/长按/);
 phoneWindow.isSecureContext=true;phoneNavigator.clipboard={writeText:async text=>{copiedText=text}};
 await get('copyVoiceTutorial').onclick();assert.equal(get('voiceTutorialLink').hidden,true);
 phoneNavigator.clipboard.writeText=async()=>{throw Error('denied')};
 await get('copyVoiceTutorial').onclick();assert.equal(get('voiceTutorialLink').hidden,false);
 phoneWindow.isSecureContext=false;

 assert.match(get('scanStatus').textContent,/等待扫描结果/);
 const retry=[...timers.entries()].find(([,t])=>t.ms===1500);assert.ok(retry,'empty first result must schedule a retry');
 emptyScan=false;timers.delete(retry[0]);await retry[1].fn();assert.match(get('scanStatus').textContent,/已找到 1/);
 get('network').value='Test Wi-Fi';failScan=true;await context.scan();assert.equal(get('network').value,'Test Wi-Fi','failed refresh preserves selection');
 failScan=false;await context.scan();
 await get('save').onclick();assert.equal(posts().length,0,'first boot cannot complete without Wi-Fi');
 get('network').value='Test Wi-Fi';get('password').value='short';await get('connect').onclick();assert.equal(posts().length,0);

 assert.match(get('scanStatus').textContent,/已找到 1/);
 get('manualToggle').onclick();get('ssid').value='Test Wi-Fi';get('password').value='  secret with spaces  ';
 await get('connect').onclick();let req=posts().at(-1);assert.equal(req.url,'/api/connect?t=314159');assert.equal(JSON.parse(req.options.body).password,'  secret with spaces  ');
 state='failed';await context.poll();assert.equal(get('connect').disabled,false);assert.match(get('networkStatus').textContent,/检查密码/);
 state='connected';await context.poll();assert.equal(get('step2').hidden,false);assert.equal(get('password').value,'');
 get('city').value='';await get('save').onclick();assert.equal(get('step3').hidden,false);
 const payload=JSON.parse(posts().filter(r=>r.url.startsWith('/api/profile')).at(-1).options.body);
 assert.deepEqual(Object.keys(payload).sort(),['city','country_code','lat','lon','radio_city','region'].sort());
 saved=true;await context.load();get('savedNetwork').value='Test Wi-Fi';await get('reuse').onclick();
 const body=JSON.parse(posts().at(-1).options.body);assert.equal(body.saved,true);assert.equal(body.ssid,'Test Wi-Fi');assert.ok(Number.isInteger(body.epoch));
 connectError='saved_not_found';await get('reuse').onclick();assert.match(get('networkStatus').textContent,/已保存网络/);connectError='';
 state='connected';await context.poll();
 // Nationwide search and stable ids distinguish repeated county names.
 assert.ok(cityCatalog.length>=3000);assert.equal(new Set(cityCatalog.map(c=>c[4])).size,34);
 get('province').value='广东';get('province').onchange();
 get('citySearch').value='珠海';get('citySearch').oninput();
 const zhuhai=cityCatalog.find(c=>c[1]==='珠海'&&c[4]==='广东');
 assert.ok(get('city').options.some(o=>o.value===zhuhai[0]));
 get('city').value=zhuhai[0];get('city').onchange();assert.equal(get('customCityFields').hidden,true);
 await get('save').onclick();profile=JSON.parse(posts().filter(r=>r.url.startsWith('/api/profile')).at(-1).options.body);
 assert.deepEqual({city:profile.city,region:profile.region,radio_city:profile.radio_city,country_code:profile.country_code,lat:profile.lat,lon:profile.lon},
     {city:'珠海',region:'广东',radio_city:'珠海',country_code:'CN',lat:'22.2707',lon:'113.5767'});
 get('citySearch').value='不存在的地点';get('citySearch').oninput();
 assert.match(get('cityStatus').textContent,/没有找到/);assert.equal(get('city').value,zhuhai[0],'search does not erase the saved choice');
 const chaoyang=cityCatalog.filter(c=>c[1]==='朝阳');assert.ok(chaoyang.length>1);
 assert.equal(new Set(chaoyang.map(c=>c[0])).size,chaoyang.length);
 get('city').value='__custom';get('city').onchange();get('customCity').value='测试新区';get('customLat').value='91';get('customLon').value='113.6';
 let beforeInvalid=posts().length;await get('save').onclick();assert.equal(posts().length,beforeInvalid);assert.match(get('saveStatus').textContent,/有效/);
 get('customLat').value='';get('customLon').value='';await get('save').onclick();
 profile=JSON.parse(posts().filter(r=>r.url.startsWith('/api/profile')).at(-1).options.body);assert.equal(profile.city,'测试新区');assert.equal(profile.lat,'');
 get('city').value='';get('city').onchange();await get('save').onclick();
 profile=JSON.parse(posts().filter(r=>r.url.startsWith('/api/profile')).at(-1).options.body);assert.equal(profile.city,'');assert.equal(profile.region,'');
 // Cold directory failure must not turn a saved catalogue city into a custom one.
 const savedCity={city:'珠海',region:'广东',radio_city:'珠海',country_code:'CN',lat:'22.2707',lon:'113.5767'};
 savedProfile={...savedProfile,...savedCity};
 vm.runInContext('cities=[]',context);failCities=true;await context.load();
 assert.match(get('cityStatus').textContent,/目录未能读取/);
 assert.equal(get('city').value,'__saved');assert.match(get('city').selectedOptions[0].text,/珠海/);
 assert.equal(get('customCityFields').hidden,true);assert.equal(get('retryCities').hidden,false);
 assert.deepEqual(JSON.parse(JSON.stringify(context.selectedCityProfile())),savedCity);
 get('province').value='北京';get('province').onchange();get('citySearch').value='无匹配';get('citySearch').oninput();
 assert.equal(get('city').value,'__saved','filters preserve the saved fallback');
 for(let i=0;i<2;i++)await get('retryCities').onclick();
 assert.equal(get('city').options.filter(o=>o.value==='__saved').length,1,'failed retries do not duplicate saved options');
 assert.equal(get('retryCities').disabled,false);
 await get('save').onclick();profile=JSON.parse(posts().filter(r=>r.url.startsWith('/api/profile')).at(-1).options.body);
 for(const key of Object.keys(savedCity))assert.equal(profile[key],savedCity[key],'offline save preserves '+key);
 failCities=false;await get('retryCities').onclick();
 assert.equal(get('city').value,zhuhai[0]);assert.equal(get('customCityFields').hidden,true);assert.equal(get('retryCities').hidden,true);
 assert.match(get('cityStatus').textContent,new RegExp(String(cityCatalog.length)));
 failCities=true;await context.load();get('city').value='__custom';get('city').onchange();
 get('customCity').value='手动新区';get('customLat').value='22.4';get('customLon').value='113.7';
 failCities=false;await get('retryCities').onclick();
 assert.equal(get('city').value,'__custom');assert.equal(get('customCity').value,'手动新区');assert.equal(get('customLat').value,'22.4');
 failCities=true;vm.runInContext('cities=[]',context);await context.loadCities();context.restoreCity({});
 assert.equal(get('city').value,'');assert.equal(get('customCityFields').hidden,true,'first boot does not fabricate a saved city');
 context.restoreCity(savedCity);failCities=false;let releaseCity;
 cityGate=new Promise(resolve=>releaseCity=resolve);const pendingCityRetry=get('retryCities').onclick();
 get('city').value='__custom';get('city').onchange();get('customCity').value='重试期间修改';
 releaseCity();await pendingCityRetry;cityGate=null;
 assert.equal(get('city').value,'__custom');assert.equal(get('customCity').value,'重试期间修改','in-flight retry does not overwrite deliberate edits');
 failCities=false;await context.load();
 context.restoreCity({city:'珠海',region:'广东',lat:'22.5',lon:'113.8'});
 assert.equal(get('city').value,'__custom');assert.equal(get('customLat').value,'22.5','custom coordinates for an existing name remain custom');
 // Phone coordinates reach weather unchanged; nearest place is only a label for radio.
 const target=cityCatalog.find(c=>c[1]==='香洲'&&c[4]==='广东');assert.ok(target);
 const lat=target[2]+.001,lon=target[3]+.001;
 let callbacks=null;phoneWindow.isSecureContext=true;
 phoneNavigator.geolocation={getCurrentPosition(ok,fail,options){callbacks={ok,fail};assert.equal(options.timeout,20000);assert.equal(options.enableHighAccuracy,true)}};
 get('locate').onclick();assert.equal(get('locate').disabled,true);callbacks.ok({coords:{latitude:lat,longitude:lon,accuracy:12}});
 assert.equal(get('city').value,target[0]);assert.match(get('locationStatus').textContent,/附近地点/);
 profile=context.selectedCityProfile();assert.equal(profile.lat,lat.toFixed(6));assert.equal(profile.lon,lon.toFixed(6));assert.equal(profile.radio_city,'珠海');
 await get('save').onclick();profile=JSON.parse(posts().filter(r=>r.url.startsWith('/api/profile')).at(-1).options.body);assert.equal(profile.lat,lat.toFixed(6));
 // Restoring a nearby location must never snap actual phone coordinates to the city centre.
 context.restoreCity({...profile});assert.equal(context.selectedCityProfile().lat,lat.toFixed(6));
 get('locate').onclick();callbacks.fail({code:1});assert.match(get('locationStatus').textContent,/权限/);assert.equal(context.selectedCityProfile().lat,lat.toFixed(6));
 get('locate').onclick();const stale=callbacks;get('city').value=zhuhai[0];get('city').onchange();stale.ok({coords:{latitude:lat,longitude:lon,accuracy:12}});assert.equal(get('city').value,zhuhai[0]);
 get('locate').onclick();callbacks.fail({code:3});assert.match(get('locationStatus').textContent,/超时/);assert.equal(get('locate').disabled,false);
 assert.throws(()=>context.applyPhonePosition(91,lon,2),/无效/);assert.throws(()=>context.applyPhonePosition(lat,lon,60000),/范围太大/);assert.throws(()=>context.applyPhonePosition(0,0,2),/没有目录地点/);
 phoneWindow.isSecureContext=false;get('locate').onclick();assert.match(get('locationStatus').textContent,/入口尚未启用/);
 // Real HTTP hotspot uses the HTTPS helper: origin + popup + nonce all must match.
 get('locate').dataset.helper='https://location.example/phone-location.html';const popup={};let opened='';phoneWindow.open=url=>{opened=url;return popup};
 get('locate').onclick();const helper=new URL(opened),params=new URLSearchParams(helper.hash.slice(1));assert.equal(params.get('origin'),'http://192.168.4.1');assert.ok(!opened.includes('314159'),'device token never leaves the hotspot');
 const data={type:'passport-position',request:params.get('request'),lat,lon,accuracy:12};
 context.receiveLocation({source:popup,origin:'https://wrong.example',data});assert.equal(get('city').value,zhuhai[0]);
 context.receiveLocation({source:{},origin:helper.origin,data});assert.equal(get('city').value,zhuhai[0]);
 context.receiveLocation({source:popup,origin:helper.origin,data:{...data,request:'0'.repeat(32)}});assert.equal(get('city').value,zhuhai[0]);
 context.receiveLocation({source:popup,origin:helper.origin,data});assert.equal(get('city').value,target[0]);assert.equal(get('locate').disabled,false);
 get('city').value=zhuhai[0];get('city').onchange();context.receiveLocation({source:popup,origin:helper.origin,data});assert.equal(get('city').value,zhuhai[0],'late/replayed helper result is ignored');
 get('locationCode').value='PPOS:'+lat.toFixed(6)+','+lon.toFixed(6)+',12';get('importLocation').onclick();assert.equal(get('city').value,target[0]);
 get('locationCode').value='PPOS:91,113,10';get('importLocation').onclick();assert.match(get('locationStatus').textContent,/无效/);
 phoneWindow.open=()=>null;get('locate').onclick();assert.match(get('locationStatus').textContent,/新窗口/);
 get('locate').dataset.helper='http://location.example';get('locate').onclick();assert.match(get('locationStatus').textContent,/入口尚未启用/);

 // One background is prepared on the phone, persisted before finishing, and retries preserve the selection.
 const choose=async()=>{get('backgroundFile').files=[{size:1000,type:'image/png'}];await get('backgroundFile').onchange()};
 await choose();assert.equal(get('backgroundPreview').hidden,false);assert.match(get('backgroundStatus').textContent,/准备/);
 const start=requests.length;await get('save').onclick();
 const writes=requests.slice(start).filter(r=>r.options.method==='POST').map(r=>r.url.split('?')[0]);
 assert.deepEqual(writes,['/api/profile','/api/background','/api/finish']);assert.equal(backgroundPresent,true);
 await choose();failBackground=true;const finishes=posts().filter(r=>r.url.startsWith('/api/finish')).length;
 await get('save').onclick();assert.equal(posts().filter(r=>r.url.startsWith('/api/finish')).length,finishes);assert.match(get('saveStatus').textContent,/背景保存未确认/);
 failBackground=false;await get('save').onclick();assert.equal(posts().filter(r=>r.url.startsWith('/api/finish')).length,finishes+1);
 get('clearBackground').onclick();await get('save').onclick();assert.equal(backgroundPresent,false);
 assert.equal(requests.filter(r=>r.url.startsWith('/api/background')).at(-1).options.method,'DELETE');
 qualityAttempts=[];blobBytes=q=>q>.45?12000:6000;await choose();assert.deepEqual(qualityAttempts,[.58,.45]);
 assert.equal(get('backgroundEditor').hidden,false);
 get('backgroundZoom').value='200';get('backgroundZoom').oninput();assert.match(get('backgroundState').textContent,/待压缩/);
 get('backgroundX').value='0';get('backgroundX').oninput();get('backgroundY').value='100';get('backgroundY').oninput();
 get('rotateBackground').onclick();assert.equal(vm.runInContext('backgroundRotation',context),90);
 qualityAttempts=[];await get('applyBackground').onclick();assert.deepEqual(qualityAttempts,[.58,.45]);assert.match(get('backgroundStatus').textContent,/5.9 KB/);
 // Saving an edited crop must compress again before uploading, without an explicit Apply click.
 get('backgroundQuality').value='balanced';get('backgroundQuality').onchange();qualityAttempts=[];await get('save').onclick();assert.deepEqual(qualityAttempts,[.68]);
 get('backgroundQuality').value='detail';get('backgroundQuality').onchange();qualityAttempts=[];await get('applyBackground').onclick();assert.deepEqual(qualityAttempts,[.78]);
 get('backgroundQuality').value='fast';get('backgroundQuality').onchange();
 blobBytes=30000;await choose();assert.match(get('backgroundStatus').textContent,/超过所选档位/);
 // A rejected new selection keeps the previously prepared valid background available for retry.
 blobBytes=6000;imageMode='error';await choose();assert.match(get('backgroundStatus').textContent,/无法读取/);imageMode='ok';
 get('backgroundFile').files=[{size:1000,type:'application/pdf'}];await get('backgroundFile').onchange();assert.match(get('backgroundStatus').textContent,/图片/);
 imageMode='stall';get('backgroundFile').files=[{size:1000,type:'image/png'}];const pending=get('backgroundFile').onchange();await flush();
 const timeout=[...timers.values()].find(t=>t.ms===15000);assert.ok(timeout);timeout.fn();await pending;assert.match(get('backgroundStatus').textContent,/超时/);imageMode='ok';
 assert.equal(get('save').disabled,false);
 // FMO is opt-in: no identity generation or remote submission on initial page load.
 assert.equal(requests.filter(r=>r.url.startsWith('/api/fmo')).length,0);
 await get('fmoRefresh').onclick();assert.match(get('fmoStatus').textContent,/先创建/);assert.equal(fmoPub,'');
 await get('fmoInit').onclick();assert.equal(fmoPub,'A'.repeat(43));assert.match(get('fmoIdentity').textContent,/等待有效证书/);
 await get('fmoInit').onclick();assert.equal(fmoPub,'A'.repeat(43),'retry retains device identity');
 await get('fmoRefresh').onclick();assert.match(get('fmoStatus').textContent,/没有本机申请/);
 const beforeApply=posts().filter(r=>r.url.startsWith('/api/fmo/ca')).length;
 get('fmoCallsign').value='bad call';await get('fmoApply').onclick();assert.equal(posts().filter(r=>r.url.startsWith('/api/fmo/ca')).length,beforeApply);
 get('fmoCallsign').value='bg0test';await get('fmoApply').onclick();assert.match(get('fmoStatus').textContent,/合照/);
 get('fmoPhoto').files=[{size:1000,type:'image/png'}];fmoRemote={state:'none'};
 await get('fmoApply').onclick();assert.match(get('fmoStatus').textContent,/等待签发服务审核/);
 assert.equal(posts().filter(r=>r.url.startsWith('/api/fmo/ca')).length,beforeApply+1);
 await get('fmoApply').onclick();assert.equal(posts().filter(r=>r.url.startsWith('/api/fmo/ca')).length,beforeApply+1,'pending approval never re-uploads the photo');
 const pollFmo=[...timers.entries()].find(([,t])=>t.ms===5000);assert.ok(pollFmo);
 fmoRemote={state:'ready',cert:'Y2VydA=='};failFmoImport=true;await get('fmoRefresh').onclick();assert.match(get('fmoStatus').textContent,/签名验证失败/);assert.equal(fmoReady,false);
 failFmoImport=false;await get('fmoRefresh').onclick();assert.equal(fmoReady,true);assert.match(get('fmoStatus').textContent,/校验并保存/);
 fmoRemote={state:'ready',cert:'Y2VydA==',revoked:true};await get('fmoRefresh').onclick();assert.match(get('fmoStatus').textContent,/撤销或过期/);
 fmoRemote={state:'rejected',message:'<img src=x onerror=alert(1)>'};await get('fmoRefresh').onclick();assert.equal(get('fmoStatus').textContent,fmoRemote.message);
 get('fmoHost').value='relay.example.test';get('fmoPort').value='1883';get('fmoRelayCall').value='BG0SRV';get('fmoRelayUid').value='456';get('fmoFingerprint').value='B'.repeat(43);
 await get('fmoSaveRelay').onclick();assert.equal(fmoRelay.host,'relay.example.test');assert.equal(fmoRelay.port,1883);
 get('fmoPort').value='0';await get('fmoSaveRelay').onclick();assert.match(get('fmoStatus').textContent,/完整中继参数/);assert.equal(fmoRelay.port,1883);
 await get('fmoRefreshServers').onclick();assert.match(get('fmoStatus').textContent,/尚未缓存/);
 fmoServers=[{uid:456,name:'测试中继',host:'relay.example.test',callsign:'BG0SRV',port:1883,fingerprint:'B'.repeat(43)}];
 await get('fmoRefreshServers').onclick();assert.ok(get('fmoServerList').options.some(s=>s.value==='456'));
 get('fmoServerList').value='456';await get('fmoSelectServer').onclick();assert.match(get('fmoStatus').textContent,/服务器已选定/);assert.equal(fmoRelay.uid,456);
 Object.assign(fmoServers[0],{stats_known:true,online:0,peak:200,range_km:500});await get('fmoRefreshServers').onclick();assert.ok(get('fmoServerList').options.some(s=>s.text.includes('广播在线 0/200 · 500km')));
 fmoServers[0].stats_known=false;await get('fmoRefreshServers').onclick();assert.ok(get('fmoServerList').options.some(s=>s.value==='456'&&s.text.includes('待更新')));
 Object.assign(fmoServers[0],{stats_known:true,online:'<img onerror=alert(1)>'});await get('fmoRefreshServers').onclick();assert.ok(get('fmoServerList').options.some(s=>s.value==='456'&&s.text.includes('待更新')&&!s.text.includes('<img')));

 fmoServers=[];get('fmoServerList').value='456';await get('fmoSelectServer').onclick();assert.match(get('fmoStatus').textContent,/过期/);
 assert.equal(get('fmoApply').disabled,false);assert.equal(get('fmoPhoto').disabled,false);
 context.stopFmoPoll();
 await get('fmoReadBook').onclick();assert.match(get('fmoBookCount').textContent,/0\/64/);assert.match(get('fmoBookEntries').options[0].textContent,/还没有/);
 fmoBook=Array.from({length:10},(_,i)=>({callsign:'BG0T'+i,uid:i+1,relay_uid:456,first_seen:1800000000,last_seen:1800000000+i,receptions:i+1}));
 const readStart=requests.length;await get('fmoReadBook').onclick();
 assert.equal(requests.slice(readStart).filter(r=>r.url.includes('book=')).length,2);
 assert.equal(get('fmoBookEntries').options.length,10);assert.equal(get('fmoBookEntries').options[0].options[0].textContent,'BG0T9');
 assert.match(get('fmoBookEntries').options[0].options[1].textContent,/初次：.*最近：.*10次/);
 get('fmoBookSearch').value='t3';get('fmoBookSearch').oninput();assert.equal(get('fmoBookEntries').options.length,1);assert.equal(get('fmoBookEntries').options[0].options[0].textContent,'BG0T3');
 get('fmoBookSearch').value='NONE';get('fmoBookSearch').oninput();assert.match(get('fmoBookEntries').options[0].textContent,/没有匹配/);
 get('fmoBookSearch').value='';get('fmoBookSearch').oninput();
 for(const fault of ['unavailable','missing']){fmoBookFault=fault;await get('fmoReadBook').onclick();assert.match(get('fmoBookStatus').textContent,/失败|不完整/);assert.equal(get('fmoBookEntries').options.length,10)}
 fmoBookFault='';fmoBook[0].callsign='<img onerror=alert(1)>';
 await get('fmoReadBook').onclick();assert.match(get('fmoBookStatus').textContent,/格式无效/);assert.equal(get('fmoBookEntries').options.length,10);
 assert.equal(get('fmoReadBook').disabled,false);
 await get('fmoReadAprs').onclick();assert.equal(get('fmoAprsEnabled').checked,false);assert.equal(get('fmoAprsSsid').value,'15');
 let aprsBefore=posts().length;get('fmoAprsEnabled').checked=true;get('fmoAprsGrid').value='SS99';await get('fmoSaveAprs').onclick();assert.equal(posts().length,aprsBefore);assert.match(get('fmoAprsStatus').textContent,/网格/);
 get('fmoAprsGrid').value='PM06eb';get('fmoAprsSsid').value='1';get('fmoAprsFrequency').value='438.5';get('fmoAprsHeight').value='15';get('fmoAprsRig').value='AI Passport';get('fmoAprsAntenna').value='J';
 await get('fmoSaveAprs').onclick();assert.equal(fmoAprs.enabled,true);assert.equal(fmoAprs.grid,'PM06EB');assert.equal(fmoAprs.ssid,1);assert.match(get('fmoAprsStatus').textContent,/不会发送广播/);
 get('fmoAprsLegacy').checked=true;await get('fmoSaveAprs').onclick();assert.equal(fmoAprs.legacy_beacon,true);
 aprsBefore=posts().length;get('fmoAprsRig').value='bad,field';await get('fmoSaveAprs').onclick();assert.equal(posts().length,aprsBefore);
 get('fmoAprsRig').value='中文设备设备设备设备设备';await get('fmoSaveAprs').onclick();assert.equal(posts().length,aprsBefore);
 get('fmoAprsRig').value='AI Passport';failAprsSave=true;get('fmoAprsEnabled').checked=false;await get('fmoSaveAprs').onclick();assert.equal(fmoAprs.enabled,true);assert.match(get('fmoAprsStatus').textContent,/保存失败/);
 failAprsSave=false;await get('fmoSaveAprs').onclick();assert.equal(fmoAprs.enabled,false);assert.match(get('fmoAprsStatus').textContent,/已关闭/);
 assert.equal(get('fmoSaveAprs').disabled,false);
 const caPosts=requests.filter(r=>r.url.startsWith('/api/fmo/ca')&&r.options.method==='POST').length,identityBefore=fmoPub;
 fmoClockValid=false;failFmoClock=true;await get('fmoRefresh').onclick();assert.match(get('fmoStatus').textContent,/校准/);
 await get('fmoApply').onclick();assert.equal(requests.filter(r=>r.url.startsWith('/api/fmo/ca')&&r.options.method==='POST').length,caPosts);assert.equal(fmoPub,identityBefore);assert.equal(get('fmoApply').disabled,false);
 fmoClockValid=true;failFmoClock=false;


 let releaseCrl;fmoCrlGate=new Promise(resolve=>releaseCrl=resolve);const pendingCrl=get('fmoCheckCrl').onclick();await flush();assert.ok([...timers.values()].some(t=>t.ms===90000));assert.equal(get('fmoCheckCrl').disabled,true);releaseCrl();await pendingCrl;fmoCrlGate=null;
 const crlIdentity=fmoPub;await get('fmoCheckCrl').onclick();assert.match(get('fmoCrlStatus').textContent,/暂无法确认/);assert.match(get('fmoCrlStatus').textContent,/已知吊销将阻止本机FMO通联/);
 fmoCrl.state='current';await get('fmoCheckCrl').onclick();assert.match(get('fmoCrlStatus').textContent,/缓存中的两级列表/);assert.match(get('fmoCrlStatus').textContent,/根列表不可用/);
 fmoCrl.user.saved=false;await get('fmoCheckCrl').onclick();assert.match(get('fmoCrlStatus').textContent,/保存未确认/);fmoCrl.user.saved=true;fmoCrl.root.cache='restored';await get('fmoCheckCrl').onclick();assert.match(get('fmoCrlStatus').textContent,/已恢复签名缓存/);
 fmoCrl.state='revoked';await get('fmoCheckCrl').onclick();assert.match(get('fmoCrlStatus').textContent,/命中/);
 fmoCrl.root.message='<img src=x onerror=alert(1)>';await get('fmoCheckCrl').onclick();assert.ok(get('fmoCrlStatus').textContent.includes('<img'));
 failFmoCrl=true;await get('fmoCheckCrl').onclick();assert.match(get('fmoCrlStatus').textContent,/网络断开/);assert.equal(get('fmoCheckCrl').disabled,false);assert.equal(fmoPub,crlIdentity);
 failFmoCrl=false;fmoCrl={state:'current'};await get('fmoCheckCrl').onclick();assert.match(get('fmoCrlStatus').textContent,/无法识别/);assert.equal(get('fmoCheckCrl').disabled,false);

 // FMO Wi-Fi auto-reconnect on wifi_required + /api/time phone sync + legacy import + custom stamp studio.
 {
  const beforeConnects=posts().filter(r=>r.url.startsWith('/api/connect')).length;
  fmoStaConnected=false;state='idle';saved=true;fmoRemote={state:'none'};
  const p=get('fmoRefresh').onclick();await flush();await flush();
  const waitPoll=[...timers.entries()].find(([,t])=>t.ms===1000);assert.ok(waitPoll,'wifi_required must auto-connect saved Wi-Fi and poll');
  timers.delete(waitPoll[0]);waitPoll[1].fn();await p;
  assert.equal(posts().filter(r=>r.url.startsWith('/api/connect')).length,beforeConnects+1);
  assert.match(get('fmoStatus').textContent,/没有本机申请/);
  // Legacy fmo_cred read-only import button.
  fmoReady=false;fmoLegacyAvail=true;await context.fmoLocal();
  assert.equal(get('fmoImportLegacy').hidden,false);assert.match(get('fmoImportLegacy').textContent,/P-BG0OLD/);
  await get('fmoImportLegacy').onclick();assert.equal(fmoReady,true);assert.equal(get('fmoImportLegacy').hidden,true);
  // Custom stamp studio: read, save built-in style/color/label, upload 4608B custom pattern, clear.
  await get('fmoReadStamp').onclick();assert.equal(get('fmoStampStyle').value,'G001');
  get('fmoStampStyle').value='G007';get('fmoStampColor').value='#2E8B57';get('fmoStampLabel').value='BEIJING';
  await get('fmoSaveStamp').onclick();assert.equal(fmoStamp.style_id,'G007');assert.equal(fmoStamp.color,'#2E8B57');assert.equal(fmoStamp.label,'BEIJING');
  get('fmoStampLabel').value='bad,label';await get('fmoSaveStamp').onclick();assert.match(get('fmoStampStatus').textContent,/铭文/);assert.equal(fmoStamp.label,'BEIJING');
  get('fmoStampFile').files=[{size:2048,type:'image/png'}];await get('fmoStampFile').onchange();
  assert.equal(get('fmoUploadStamp').disabled,false);
  await get('fmoUploadStamp').onclick();assert.equal(fmoStamp.custom_present,true);assert.equal(fmoStamp.style_id,'CUSTOM');
  await get('fmoExportStamp').onclick();assert.match(get('fmoStampStatus').textContent,/已下载/);
  const backupPixels=new Uint8Array(4608).fill(0x5a);
  get('fmoStampFile').files=[{name:'passport-custom.fmostamp',size:4608,arrayBuffer:async()=>backupPixels.buffer}];
  await get('fmoStampFile').onchange();assert.match(get('fmoStampStatus').textContent,/已载入点阵备份/);
  await get('fmoUploadStamp').onclick();
  const stampPost=posts().filter(r=>r.url.startsWith('/api/fmo/stamp')).at(-1);
  assert.deepEqual(new Uint8Array(await stampPost.options.body.arrayBuffer()),backupPixels);
  get('fmoStampFile').files=[{name:'broken.fmostamp',size:2}];
  await get('fmoStampFile').onchange();assert.match(get('fmoStampStatus').textContent,/4608/);
  await get('fmoClearStamp').onclick();assert.equal(fmoStamp.custom_present,false);assert.equal(fmoStamp.style_id,'G001');
  // Built-in PASSPORT fallback relay switch + Roger Beep toggle/clear.
  await get('fmoUseBuiltin').onclick();assert.equal(fmoRelay,null);assert.match(get('fmoStatus').textContent,/内置中继台/);
  get('fmoBeepEnabled').checked=false;get('fmoBeepSelect').value='0';await get('fmoBeepApply').onclick();
  assert.equal(fmoBeep.enabled,false);assert.match(get('fmoBeepStatus').textContent,/关闭/);
  get('fmoBeepEnabled').checked=true;await get('fmoBeepApply').onclick();
  assert.equal(fmoBeep.enabled,true);assert.equal(fmoBeep.use_custom,false);
  await get('fmoBeepRefresh').onclick();
  assert.match(get('fmoBeepStatus').textContent,/1 款/);
  const beepPosts=()=>posts().filter(r=>r.url.startsWith('/api/fmo/beep'));
  const chooseTone=()=>{get('fmoBeepEnabled').checked=true;get('fmoBeepSelect').value='6';return get('fmoBeepApply').onclick()};
  failBeepWrite=true;const countBefore=beepPosts().length;
  await chooseTone();
  assert.equal(beepPosts().length,countBefore+1);
  assert.equal(beepPosts().at(-1).options.body.type,'application/octet-stream');
  assert.match(get('fmoBeepStatus').textContent,/设备写入失败/);
  failBeepWrite=false;beepCloudMode='wrong-id';
  await chooseTone();
  assert.equal(beepPosts().length,countBefore+2);
  assert.deepEqual(JSON.parse(beepPosts().at(-1).options.body),{download_id:6});
  assert.equal(fmoBeep.custom_id,6);
  await get('fmoBeepClear').onclick();assert.equal(fmoBeep.custom_present,false);
 }

 for(const request of requests)assert.ok(!/\/api\/(avatar|share|cards|muse)/.test(request.url));
 console.log('Phone setup: strict DOM, offline Wi-Fi/cities/GPS, no portrait/cards, single background compression/upload/delete/retry partial-save ordering, FMO opt-in application/polling/import/expiry relay validation paged/searchable heard book with failure preservation and explicit APRS configuration and signed station snapshot labels and clock-failure photo preflight PASS');
})().catch(e=>{console.error(e);process.exitCode=1});
