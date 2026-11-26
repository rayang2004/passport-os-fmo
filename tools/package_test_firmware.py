"""Package validated local test firmware; never flash a device or publish a release."""
from pathlib import Path
import argparse
import hashlib
import json
import re
import shutil
import struct
import subprocess
import sys
import zipfile

root=Path(__file__).resolve().parents[1]
parser=argparse.ArgumentParser(description=__doc__)
parser.add_argument('build_dir',nargs='?',default='build-public')
parser.add_argument('--codex',action='store_true',help='Add .codex to the test package and output directory names')
parser.add_argument('--regression-log',type=Path,default=root/'output/firmware-tests/host-regression.log',
                    help='Use the host regression log for this build')
args=parser.parse_args()
build=Path(args.build_dir).resolve()
log=args.regression_log
if not log.is_file() or not log.read_text(errors='replace').rstrip().endswith('Host regression tests: PASS'):
    raise SystemExit(f'Complete the host regression into {log} first')
version=re.search(r'set\(PROJECT_VER "([^"]+)"\)',(root/'CMakeLists.txt').read_text())[1]
# CMake metadata can be refreshed by a failed build while the old binary remains.
with (build/'passport-os.bin').open('rb') as image:
    descriptor=image.read(80)
if (len(descriptor)!=80 or struct.unpack_from('<I',descriptor,32)[0]!=0xABCD5432
        or descriptor[48:80].split(b'\0',1)[0]!=version.encode()):
    raise SystemExit(f'Application image version does not match {version}; rebuild before packaging')
check=subprocess.run([sys.executable,str(root/'tools/verify_firmware.py'),str(build),'--public'],capture_output=True,text=True,check=True)
suffix='.codex' if args.codex else ''
name=f'Passport-OS-{version}{suffix}-test'
out=root/'release'/name
out.mkdir(parents=True,exist_ok=True)
for source,target in [(build/'passport-os.bin','passport-os-app.bin'),(build/'FoloToy-AI-Passport-full.bin','passport-os-full.bin'),(root/'partitions.csv','partitions.csv')]:
    shutil.copyfile(source,out/target)
(out/'verification.txt').write_text(check.stdout,encoding='utf-8')
shutil.copyfile(root/'components/passport_fmo/src/upstream_profile.json',out/'FMO-COMPATIBILITY.json')
for source,target in [('LICENSE','LIBSODIUM-PORT-LICENSE.txt'),('libsodium/LICENSE','LIBSODIUM-LICENSE.txt')]:
    shutil.copyfile(root/'managed_components/espressif__libsodium'/source,out/target)
(out/'README.txt').write_text(f'''Passport OS {version} 测试固件

硬件：FoloToy AI Passport，ESP32-C3，8 MB Flash。
本包由项目专用 Lume Linux 沙箱构建；没有进行真机烧录、显示/麦克风或电流验收。

这版包含
- 移除 Muse、人像、姓名签名和名片图库。
- 首页为时间、日期与天气；可在“手机设置”上传一张背景图。
- 手机端背景编辑支持缩放、水平/垂直构图和90°旋转；保存时自动裁成240×320。
  默认流畅档≤8 KiB，均衡档≤12 KiB，细节档≤16 KiB；原图不会上传设备。
  旧背景保持不变，使用新压缩档需重新选择、保存一次。设备仍使用JPEG解码，实际流畅度需真机确认。
- 一分钟无操作后，首页进入3%相对背光的黑底屏保，按分钟刷新；其他应用熄屏。
- 双击确定键进入小智后，支持四个语音场景：
  “进入专注模式”：音量20%、亮度40%、25分钟专注并打开番茄钟。
  已暂停的专注会继续；正在运行的专注不会重新计时；活动中的休息不会自动重置。
  “进入睡前模式”：音量20%、亮度10%、播放已设置城市的电台，30分钟后停止。
  也可说“进入睡前模式，听北京交通广播，十分钟后停”。未设置城市时先询问城市。
  “查看今日安排”：播报设备今天的待办提醒和未完成清单摘要。清单本身没有日期。
  “恢复桌面”：返回首页，保留已有计时、音量和亮度。
- 可在场景中指定音量/亮度，例如“进入专注模式，音量30，亮度60”。
  这些音量/亮度调整会保存；不是修改场景的默认参数。
- 操作失败时可能已经完成部分步骤，小智应报告实际结果，避免盲目重复。
- 打开其他应用/音乐/电台后结束当前小智对话。再次控制请双击确定键。
- 本版没有加入语音唤醒。小智语音工具需要联网并完成小智服务配置。
- 提醒/番茄钟仍使用固定提醒音量，主音量设为0也不会静音提醒。

FMO 实验功能
- minimal.28 添加 PTT 松键结束信令音、内置双音及手机端音色目录、试听和保存。
  通过手机设置选音，可在 FMO 快捷菜单切换内置、自定义或关闭。真机和中继互通待验证。
- minimal.27 快捷菜单增加短消息收件箱，仅接收发给本机呼号或当前 SSID 的 APFM00 MSG。
  最近六条保留至退出 FMO，界面标记来源未验签。待补短消息发送、回执及私呼，接收功能待真机互通验证。
- minimal.5修复配网AP+STA已取得IP却被FMO当成未联网的问题；不改变普通STA应用的联网语义。
- 服务器发现同时支持真实广播的位置字段后无空格格式和文档中的有空格格式，均需验签。
- 设备上按上键进入独立列表，显示服务器名称、选中项与数量，确定连接；收听刷新不覆盖选台。
  仅缓存签名仍有效的发现信息，保留当前服务器；手机设置也能读取和选择有效缓存。
  空列表表示尚未收到/验证可用广播，不能据此判断远程没有服务器。
- minimal.6在运行中及时移除过期发现信息，释放8台列表容量；保留仍有效的选中项。
  选台列表全部过期时明确显示等待新广播，不继续显示旧台；不会中断当前通联或删除手动服务器。
- minimal.7新增本机通联抄收册：手机设置中读取、按呼号搜索初次/最近抄收与去重次数。
  成功播放收到的语音才计数，不把台站广播当成通联；不是双方确认QSO，不保存录音。
  最多64位友台，满后不覆盖旧记录；已有友台继续更新。
  空闲时最多每分钟批量保存，正常退出时再尝试保存；突然断电可能丢失尚未保存的本轮记录。
  原FMO章册命名空间不变，本版不自动迁移原章册、不包含印章图片/云备份。
- minimal.8新增设备快捷菜单：主界面短按下键打开，上下选择、确定进入。
  支持服务器列表、抄收记录、播放音量、手机配置、返回通联和退出FMO。
  记录按最近抄收排序，显示初次/最近时间与去重次数；没有证书或网络也能查看本地记录、进入配网。
  子页面长按下键返回通联；主界面长按上下键调音量，每次5%，复用系统主音量并保存。
  注意：退出入口现为菜单的“退出FMO”，主界面长按下键改为减音量。
  菜单内长按确定不发话，来话不覆盖正在浏览的页面；离线等待由按键通知唤醒。
- minimal.9新增APRS CQ和友台信标：默认只读，不自动发送。
  手机设置打开“FMO APRS广播”，填写公开的4/6/8位Maidenhead网格并明确开启按键发送。
  使用网格中心位置，不读取天气/GPS坐标；信标需填写实际100至1300MHz电台频率，可选设备/天线。
  默认生成FMO V4签名CQ/信标，也可选原版APPASP/PAT-1无签名信标。
  重新进入FMO后，在下键快捷菜单选择“发送APRS CQ”或“发送友台信标”。
  需要有效证书、APRS登录验证；CQ另需当前中继在线。每类至少间隔一分钟，收听忙时拒绝。
  只在按键请求时发送一次，不排队、不自动重试；写入TCP连接不等于公共网络或友台确认接收。
  未向公共APRS网络试发，实际互通待用户真机验证。
- minimal.10显示已验签台站广播的在线/峰值及覆盖范围，通联页、选台页和手机列表均可查看。
  这些是广播快照，不是实时人数查询；缺失或超过签名时窗显示待更新，不当作零。
  旧服务器缓存保持兼容；新增快照单独校验并绑定台站UID/证书指纹/有效期，损坏只隐藏快照。
  升级后仍可使用旧选台缓存，在线信息需等下一次有效广播。尚未实现友台在线名单。
- minimal.22集成 FMO Passport v0.6.10 能力与定制印章，并修复配网申请 FMO 证书时的 Wi-Fi 拦截问题：
  1. 修复配网页申请 FMO 证书提示“请先连接可上网的 Wi-Fi”的问题：AP+STA 连上路由器后自动停止 30 秒后台离信道扫描防止 STA 掉线；`/api/setup` 与 `/api/fmo` 返回实时 `sta_connected` 状态；新增 `POST /api/time` 支持手机直接校时；在“暂不联网/离线修改”模式下点击 FMO 申请、查状态或查 CRL 时，若设备有已保存 Wi-Fi 会自动在 AP+STA 模式下重连路由器并继续请求，同时在 FMO 卡片内提供一键重连按钮。
  2. 对齐 FMO Passport v0.6.10 证书与协议：支持 `P-` 前缀证书呼号（APRS-IS 登录与 `PASSPORT-呼号` MQTT Client ID 自动剥离 `P-`，MQTT 用户名与 4.0 SAS 保持原证书主体）；支持 `APPASP` 台站签名广播与 `PAT-1,ST:<ID>` 印章样式收发；新增“从原 FMO 固件导入有效证书”按钮（严格只读校验原 `fmo_cred` 命名空间，绝不修改或清空原固件凭据）。
  3. 新增 FMO 定制印章与护照章册：内置 12 款 FMO 几何印章（`G001`–`G012`）与自定义印泥颜色/铭文；手机设置页新增“FMO 定制印章”工作台，支持上传 PNG/JPG 图案并自动识别透明/白底/黑底/纯色底去底、离线压缩为 96×96 4 位灰度点阵（4,608 B），双槽原子回读写入 `/storage/fmo-stamp-{{a,b}}.bin`（不触碰首页背景与 CRL 缓存）；设备 FMO 快捷菜单新增“我的印章”（支持上下切换内置/定制印章并确定保存），“抄收记录”升级为带 96×96 视觉印章的护照章册，手机页同步展示友台印章并支持导出 JSON 备份；补齐收藏中继（最多 8 台）并全量通过 ASan/UBSan 测试。
- minimal.21修复两类重启问题：首页进入一分钟低亮屏保时不再在 2.5 KiB 栈的 sys_mon 上同步调 render()/lv_refr_now()，改为唤醒 8 KiB 栈的 home_task 刷屏（并把 sys_mon 栈提升至 3 KiB、收音机定时关机栈提升至 4 KiB）；关机链路改为先协作停止当前应用并通过 WifiManager 停网（同时移除 WifiStation 异步重连中的 ESP_ERROR_CHECK abort）、释放背光 LEDC 轻睡眠保活与 ADC1 轮询、清空残留唤醒源并以 esp_deep_sleep_try_to_start() 配合 GPIO0 稳定高电平检查，开机日志附带打印 reset/wake 原因。
- minimal.20将MQTT Client ID对齐附件0.6.5的PASSPORT-呼号格式；用户名仍是呼号，密码仍是本机证书和签名通行证。
  同呼号设备连接同一Broker时使用相同Client ID，后连接者会替换先前连接，与原版保持一致。
  这不补齐跨签发者证书链、不改变服务器信任，也不代替真实SAS/FAS接入验收。
- minimal.19连接中继后订阅附件同款EMQX节点连接数主题，主界面优先显示“最近节点连接”。
  这是最近收到的单个Broker节点连接快照，包含管理/审计客户端，不等同友台人数或集群总数。
  多节点不盲目相加；断线、重连/换台或120秒未更新后回退APRS广播快照。
  系统主题是否可订阅由服务器ACL决定；没有数据时保留原广播显示，不放宽权限。
  MQTT按主题严格分流，统计数据不占语音队列，分片顺序/长度/切换和数值溢出均校验。
- minimal.18新增“活动公告”：验签JOINT帧，并核对STATUS正文的完整SHA256、呼号/SSID/UID后才显示。
  支持双帧乱序；未签名正文仅在内存中等待最多30秒，不能直接显示。
  最近2条有效公告保留在本次会话，按签名时窗到期移除；长标题/正文按中文与UTF-8边界分页。
  菜单中打开“活动公告”，上下翻阅正文和公告、确定回菜单；文字内容不自动操作设备。
  尚无公告发送、持久历史或跨签发者链；不把收到公告当作QSO或实时在线证明。
- minimal.17接通签名BEACON接收：按手机中手动设置的网格筛选80km内信标；未设置网格不展示。
  显示频率、距离、天线高度和设备/天线名称；长名称验签后按UTF-8边界缩略。
  接收无需开启发送；不使用天气/GPS位置，不自动广播。距离基于所选网格中心，为近似值。
- minimal.16新增“友台广播”菜单：接收已验签的CQ、老友呼叫、语音活动和上线通知。
  本次FMO会话最多保留8条有效通知；拒绝重复/旧窗口回放，签名时窗过期后移除，退出不持久保存。
  仅支持本机已验证中间证书签发的友台，尚不支持跨签发者链；BEACON接收由minimal.17补齐。
  这是短时广播记录，不代表实时在线名单、双向QSO或已检查友台吊销；不会自动连接广播中的服务器。
- minimal.15接通签名CRL持久缓存：手机查询验签后写入独立双文件，回读复验后切换小型元数据。
  每层显示本次是否验证/确认保存，以及旧缓存是否恢复；保存失败不撤销当前内存验证结果。
  FMO启动只读恢复，重新验证完整签名/当前证书链/版本/作用域；不初始化或格式化已有存储。
  过期的未吊销结果不当作新鲜结论；已知吊销、未来生效时间和版本下限可从签名证明恢复。
  仅主动写入时允许初始化逐字节确认全FF的空分区，不改分区、背景、旧资源、身份或抄收册。
  尚无后台自动刷新，真实服务完整证书/签发/实网、物理断电及真机内存验收仍待验证。
- minimal.14新增手机“检查证书吊销列表”：实际Wi-Fi/校时/有效本机证书及空闲内存满足后，主动查询两级CRL。
  使用经验证证书声明的签发服务CRL文件地址，TLS验主机、不跟随跳转；不上传密钥、照片或用户标识。
  分别报告本次更新与内存缓存状态；根地址返回空对象时明确不通过，不把它当未吊销。
  已验证吊销会阻止本机FMO连接，并在工作循环中停止现有MQTT/APRS/音频、清理会话密钥；菜单仍可用。
  检查身份切换后，旧会话停止并要求重新打开FMO；不以“未知”冒充吊销或未吊销。
  后续minimal.15加入签名持久缓存和启动恢复；后台自动刷新、真实签发/实网与真机验收仍待完成。
- minimal.13在设备空服务器列表显示最近一次相关广播的拒绝原因：缺少签发链、证书失败或消息签名失败。
  提示描述未验证报文；不把它的台名、地址加入可信服务器，不放宽连接认证。
  上下浏览或重新进入列表可查看，重新进入FMO清空旧提示。等待仍可能需要广播周期。
  两级CRL校验器在minimal.14接入手动网络检查、内存缓存和已知吊销门禁，仍非完整自动吊销保护。
- minimal.12修复APRS读取被系统信号打断时误断线的问题；空服务器列表按确定可重连发现服务，间隔15秒。
  不清可信缓存，不关闭当前MQTT通联；未校时或未获证书时提示先完成配置。
  仍只验证本机身份附带的中间证书链，不支持跨签发者自动补链；原版内置/旧版选台尚未复刻。
- minimal.11补强证书请求：配网仍优先使用手机时间；设备时间未就绪时，先限时尝试网络校时。
  失败会提示重连Wi-Fi或检查校时网络，不会跳过HTTPS证书/时间校验；照片不会在校时成功前转发。
  校时仅按需启停本次启动的SNTP，不关闭其他组件已经运行的校时。
  慢上传逐次检查上游总预算，失败时关闭本次HTTP会话，避免继续等待未完成的照片正文。
- 新增 FMO 应用；小智也可按“打开FMO”进入，不会自动发话。
- 复用用户提供的 BI4TES FMO Passport 0.6.5 的公开根证书及 fmo.simy.live/ca 签发服务。
  安装包没有已签发用户身份；本机会单独生成密钥，不导出私钥、不覆盖原 fmo_cred。
- 在手机设置中先连接可上网的Wi-Fi，再展开“FMO身份与证书”，创建身份。
  填本人呼号、选择证件合照后，主动点“提交证书申请”；资料经设备HTTPS转发给原签发服务。
  照片不写入设备存储。审核通过后轮询领取证书，校验根/中间/用户签名、本机公钥及有效期后保存。
  签发服务是否接受新申请由该服务决定；未提交任何真实资料做远端验收。
- 进入FMO后通过APRS-IS发现已签名中继（默认只读）（最多8个，可能需等待最长约10分钟的广播周期）。
  只接受本机已验证签发链中的台站；也可由管理员提供完整的手动中继参数。
  选择服务器时上下键移动、短按确定连接，列表内长按确定不会发话。
- 上键浏览、短按确定切台；长按确定开始讲话、松开停止，最长60秒；下键菜单中可退出。
  熄屏后的第一按仅唤醒，再次长按才讲话。频道忙或收到优先路由时停止/拒绝发话。
- 实现8kHz/40ms Opus发送与接收、RADPCM接收、SAS认证及前台半双工资源释放。
  本版没有搬入原FMO的QSO图库、云备份或OTA流程。
  本地尚无独立CRL缓存刷新，客户端撤销状态最终由中继SAS/FAS认证处理；不能保证接入官方或所有第三方网络。
- 真实签发领取、实网中继/音频/PTT与长时间内存稳定性待设备验证，不等同原固件全功能兼容。

镜像选择与备份
1. 烧录前备份整片8 MB Flash。示例（YOUR_PORT替换为实际串口）：
   python -m esptool --chip esp32c3 --port YOUR_PORT read_flash 0 0x800000 backup.bin
2. 已安装Passport OS且确认分区表一致时，推荐应用升级：
   python -m esptool --chip esp32c3 --port YOUR_PORT write_flash 0x10000 passport-os-app.bin
   不先全片擦除；应用升级保留Wi-Fi、城市、背景和存储分区。
3. 首次安装或原分区不一致时，备份后使用完整镜像：
   python -m esptool --chip esp32c3 --port YOUR_PORT write_flash 0x0 passport-os-full.bin
   完整镜像会覆盖配置所在范围，首次开机需重新设置。不要把应用镜像写到0x0。
4. SHA256SUMS包含文件校验值；manifest.json和verification.txt记录版本、布局与SRAM检查。

建议真机试用顺序
配网/城市 → 首页与一分钟屏保 → 实体按键唤醒 → 背景上传/恢复纯色 → 小智四个场景。
重点确认专注计时不被重复重置、电台能播放并定时停止，以及退出/重进小智无异常。
实际续航需使用电流计测量，不能由背光百分比推算。
''',encoding='utf-8')
files=['passport-os-app.bin','passport-os-full.bin','partitions.csv','verification.txt','README.txt','FMO-COMPATIBILITY.json','LIBSODIUM-PORT-LICENSE.txt','LIBSODIUM-LICENSE.txt']
info={f:{'size':(out/f).stat().st_size,'sha256':hashlib.sha256((out/f).read_bytes()).hexdigest()} for f in files}
commit=subprocess.check_output(['git','-C',str(root),'rev-parse','HEAD'],text=True).strip()
manifest={'version':version,'hardware':'FoloToy AI Passport / ESP32-C3 / 8 MB','source_base_commit':commit,'source_modified':True,
          'build_environment':'Dedicated Lume Debian ARM64 guest / ESP-IDF 5.5.3',
          'offsets':{'passport-os-app.bin':'0x10000','passport-os-full.bin':'0x0'},
          'host_regression':'passed','firmware_layout_and_sram':'passed','physical_device_validation':'not performed','files':info}
manifest['fmo']={
    'experimental':True,
    'trust_root_source':'BI4TES FMO Passport 0.6.10, user-provided firmware (same pinned root CA as 0.6.5)',
    'trust_root_json_sha256':hashlib.sha256((root/'components/passport_fmo/src/passport_root.json').read_bytes().rstrip(b'\r\n')).hexdigest(),
    'certificate_service':'https://fmo.simy.live/ca',
    'identity':'device-local key with optional read-only verified import from legacy fmo_cred; original credentials never modified',
    'custom_stamp_studio':'12 built-in geometric stamps (G001-G012) + custom 96x96 4-bit I4 pattern upload with auto bg removal, dual-bank SPIFFS persistence and on-device My Stamp / QSO Stamp Book',
    'apsta_fmo_ca_fix':'stops periodic off-channel scan once STA connects in AP+STA, exposes live sta_connected, adds /api/time phone clock sync and automatic saved Wi-Fi reconnect on wifi_required',
    'real_certificate_issuance_and_network_interoperability':'not validated',
    'manual_relay_discovery_retry':'implemented; empty-list confirm reconnects discovery only, 15-second cooldown; device validation pending',
    'certificate_clock_and_deadline':'implemented; request-scoped SNTP fallback and bounded proxy; device validation pending',
    'relay_verification_diagnostics':'implemented; device empty-list failure reason; hardware validation pending',
    'crl_protocol_verifiers':'integrated with manual HTTPS checks, volatile cache and known-revocation session gate; device validation pending',
    'local_crl_refresh':True,
    'crl_refresh_mode':'manual phone action only',
    'crl_persistent_cache':True,
    'crl_cache_format':'complete signed FCP1 proof, dual files, 96-byte scoped version/hash metadata',
    'crl_startup_restore':'signature and chain reverified; stale clear stays unknown; known revocation retained',
    'crl_session_enforcement':'known verified own-identity revocation blocks; unknown remains unknown; identity rebind stops old session',
    'mqtt_client_identity':'PASSPORT-callsign reference identity; same-callsign sessions replace each other on one broker; certificate and signed authentication unchanged; hardware validation pending',
    'mqtt_node_connection_count':'latest received single broker-node snapshot, not operator or cluster count; 120s expiry; ACL availability and hardware validation pending',
    'signed_activity_announcements':'JOINT/STATUS hash and source binding; two session-only notices; bounded reverse-order waiting and paged device display; hardware validation pending',
    'signed_peer_announcements':'CQ/OMCQ/VOCAL/ONLINE and explicit-grid-only 80km BEACON, eight session-only signed events; not live presence or peer CRL assurance; hardware validation pending',
    'signed_station_online_snapshot':'implemented; broadcast snapshot, not real-time; device validation pending',
    'device_quick_menu':'implemented; device validation pending',
    'roger_beep':'built-in and custom FBEP tone, phone configuration and PTT release; device validation pending',
    'aprs_short_message_inbox':'addressed APFM00 MSG reception, six session-only entries; device validation pending',
    'local_heard_history':'implemented; device validation pending; not reciprocal QSO proof',
    'manual_aprs_cq_and_beacons':'implemented, explicit opt-in; no public transmission validated',
    'passport_gallery_cloud_backup':'not implemented',
}
(out/'manifest.json').write_text(json.dumps(manifest,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
files.append('manifest.json')
(out/'SHA256SUMS').write_text(''.join(hashlib.sha256((out/f).read_bytes()).hexdigest()+'  '+f+'\n' for f in files),encoding='utf-8')
files.append('SHA256SUMS')
archive=root/'release'/(name+'.zip')
with zipfile.ZipFile(archive.with_suffix('.zip.tmp'),'w',zipfile.ZIP_DEFLATED) as z:
    for f in files:z.write(out/f,name+'/'+f)
archive.with_suffix('.zip.tmp').replace(archive)
with zipfile.ZipFile(archive) as z:
    assert z.testzip() is None
print(archive)
print('Package SHA256:',hashlib.sha256(archive.read_bytes()).hexdigest())
