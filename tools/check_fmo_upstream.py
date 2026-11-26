"""Read-only upstream release check. Does not flash, install or submit credentials."""
from pathlib import Path
import argparse,json,re,sys,urllib.request
import hashlib
import struct
import urllib.parse
ROOT=Path(__file__).resolve().parents[1]
PROFILE=ROOT/'main/apps/fmo/upstream_profile.json'
MAX_FIRMWARE_BYTES=8*1024*1024

def inspect_image(data,report,reference):
    size=report['upstream_firmware_bytes']
    if len(data)!=size or hashlib.sha256(data).hexdigest()!=report['upstream_firmware_sha256']:
        raise ValueError('本地镜像与发布记录的大小或 SHA256 不一致')
    return inspect_application(data,reference)

def inspect_application(data,reference):
    candidates=[]
    for offset in (0,0x10000,0x20000):
        image=data[offset:]
        if len(image)<88 or image[0]!=0xe9 or image[32:36]!=b'\x32\x54\xcd\xab':
            continue
        if image[80:112].split(b'\0',1)[0]!=b'fmo-passport':
            continue
        if not 1<=image[1]<=16 or image[23] not in (0,1):
            continue
        end=24
        for _ in range(image[1]):
            if end+8>len(image):
                break
            length=struct.unpack_from('<I',image,end+4)[0]
            end+=8+length
        else:
            end=(end+16)&~15
            total=end+32*image[23]
            if total>len(image) or (image[23] and hashlib.sha256(image[:end]).digest()!=image[end:total]):
                continue
            version=image[48:80].split(b'\0',1)[0].decode('ascii',errors='replace')
            if re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+(?:[-+][a-zA-Z0-9.-]+)?',version):
                candidates.append((offset,version,hashlib.sha256(image[:total]).hexdigest()))
    if len(candidates)!=1:
        raise ValueError('无法唯一定位有效的 FMO Passport 应用镜像')
    offset,version,digest=candidates[0]
    return {'status':'checked','embedded_version':version,'application_offset':offset,
            'application_sha256':digest,
            'application_matches_reference':digest==reference.get('reference_application_sha256'),
            'target_version':reference.get('target_version'),
            'target_version_matches':version==reference.get('target_version')}

def inspect_release(profile,payload):
    play=payload.get('play') if isinstance(payload,dict) else None
    if not isinstance(play,dict) or payload.get('ok') is not True:
        raise ValueError('玩法服务未返回有效元数据，不能确认是否有更新')
    expected=profile['upstream']
    if play.get('author')!=expected['author']:
        raise ValueError('上游作者信息变化，需要人工核对来源')
    fw=play.get('firmware')
    if not isinstance(fw,dict) or fw.get('available') is not True:
        raise ValueError('上游固件当前不可用')
    sha=fw.get('sha256');size=fw.get('size')
    if not isinstance(sha,str) or not re.fullmatch('[0-9a-f]{64}',sha):
        raise ValueError('上游固件校验值无效')
    if type(size) is not int or not 0<size<=MAX_FIRMWARE_BYTES:
        raise ValueError('上游固件大小无效')
    if play.get('firmwareSha256',sha)!=sha:
        raise ValueError('上游两个校验值不一致')
    if type(play.get('firmwareSize',size)) is not int or play.get('firmwareSize',size)!=size:
        raise ValueError('上游两个固件大小不一致')
    if sha==expected['reference_firmware_sha256'] and size!=expected['reference_firmware_bytes']:
        raise ValueError('上游固件大小与同哈希参考制品不一致')
    revision=play.get('revisionId')
    changelog=play.get('changelog')
    notes={}
    if isinstance(changelog,dict):
        notes={lang:changelog[lang][:2000] for lang in ('zh','en')
               if isinstance(changelog.get(lang),str) and changelog[lang].strip()}
    return {
        'upstream_page':expected['page'],
        'reference_version':expected['reference_version'],
        'upstream_share_version':str(play.get('shareVersion',''))[:100],
        'upstream_revision_id':revision if type(revision) is int and revision>0 else None,
        'upstream_release_notes':notes,
        'upstream_firmware_sha256':sha,
        'upstream_firmware_bytes':size,
        'update_available':sha!=expected['reference_firmware_sha256'],
        'source_available':bool(play.get('githubUrl')),
        'integration_complete':False,
        'capabilities':profile['capabilities'],
        'action':'review_protocol_and_api_changes' if sha!=expected['reference_firmware_sha256'] else 'continue_parity_and_device_validation',
        'firmware_installed':False,
        'device_keys_or_trust_roots_modified':False,
    }
def inspect_passport(profile,payload):
    expected=profile['passport_os_upstream'];base=expected['integrated_base_commit']
    if not isinstance(payload,dict) or not re.fullmatch('[0-9a-f]{40}',base):
        raise ValueError('Passport OS 比较数据或基线无效')
    if not isinstance(payload.get('base_commit'),dict) or payload['base_commit'].get('sha')!=base:
        raise ValueError('Passport OS 比较基线不一致')
    url=payload.get('html_url','')
    if not isinstance(url,str) or not url.startswith(expected['repository']+'/compare/'):
        raise ValueError('Passport OS 比较来源不一致')
    status=payload.get('status');ahead=payload.get('ahead_by');behind=payload.get('behind_by')
    if status not in ('identical','ahead','behind','diverged') or type(ahead) is not int or type(behind) is not int or min(ahead,behind)<0:
        raise ValueError('Passport OS 提交关系无效')
    if status!={ (False,False):'identical',(True,False):'ahead',(False,True):'behind',(True,True):'diverged'}[(ahead>0,behind>0)]:
        raise ValueError('Passport OS 提交计数与关系不一致')
    return {'status':'checked','repository':expected['repository'],'integrated_base_commit':base,
            'branch':expected['branch'],'relationship':status,'ahead_by':ahead,'behind_by':behind,
            'update_available':ahead>0,'manual_review_required':status!='identical',
            'action':'review_source_diff_and_preserve_local_integration' if status!='identical' else 'no_new_upstream_commits',
            'source_merged':False,'firmware_installed':False}
def read_metadata(path,url):
    if path:
        with path.open('rb') as stream:raw=stream.read(512*1024+1)
    else:
        request=urllib.request.Request(url,headers={'User-Agent':'PassportOS-FMO-Compatibility/1.0','Accept':'application/json'})
        with urllib.request.urlopen(request,timeout=20) as response:raw=response.read(512*1024+1)
    if len(raw)>512*1024:raise ValueError('上游元数据超出大小限制')
    return json.loads(raw)
def resolve_release_url(manifest_url,link):
    if not isinstance(link,str) or not link:
        raise ValueError('发布记录未提供固件下载地址')
    url=urllib.parse.urljoin(manifest_url,link)
    origin=urllib.parse.urlsplit(manifest_url)
    parsed=urllib.parse.urlsplit(url)
    if parsed.scheme!='https' or parsed.netloc!=origin.netloc:
        raise ValueError('固件下载地址不属于发布站点')
    return url

def read_published_image(manifest_url,link,size):
    class SameOriginRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self,req,fp,code,msg,headers,newurl):
            resolve_release_url(manifest_url,newurl)
            return super().redirect_request(req,fp,code,msg,headers,newurl)
    url=resolve_release_url(manifest_url,link)
    opener=urllib.request.build_opener(SameOriginRedirect())
    with opener.open(url,timeout=20) as stream:
        return stream.read(size+1)

def inspect_ota(reference,payload):
    if not isinstance(payload,dict):
        raise ValueError('OTA 清单无效')
    version=payload.get('version')
    size=payload.get('size')
    sha=payload.get('sha256')
    if (not isinstance(version,str) or not re.fullmatch(r'[0-9]{1,6}\.[0-9]{1,6}\.[0-9]{1,6}',version)
            or type(size) is not int or not 0<size<=MAX_FIRMWARE_BYTES
            or not isinstance(sha,str) or not re.fullmatch('[0-9a-f]{64}',sha)):
        raise ValueError('OTA 版本、大小或 SHA256 无效')
    url=resolve_release_url(reference['ota_manifest_url'],payload.get('url'))
    return {'status':'checked','manifest_version':version,'download_url':url,
            'upstream_firmware_bytes':size,'upstream_firmware_sha256':sha,
            'update_available':sha!=reference['ota_reference_application_sha256']}

def inspect_ota_image(reference,release,data):
    image=inspect_image(data,release,reference)
    if image['application_offset']!=0 or image['application_sha256']!=release['upstream_firmware_sha256']:
        raise ValueError('OTA 下载不是独立应用镜像')
    if image['embedded_version']!=release['manifest_version']:
        raise ValueError('OTA 镜像内嵌版本与清单不一致')
    return image

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--metadata-file',type=Path,help='Inspect an existing FMO metadata snapshot')
    image_options=parser.add_mutually_exclusive_group()
    image_options.add_argument('--firmware-file',type=Path,help='Verify a local upstream firmware against release metadata')
    image_options.add_argument('--candidate-file',type=Path,help='Inspect a local FMO candidate offline without verifying its publication source')
    image_options.add_argument('--verify-published-image',action='store_true',help='Read and verify the official published firmware in memory')
    parser.add_argument('--ota',action='store_true',help='Also inspect the independent FMO device OTA manifest')
    parser.add_argument('--ota-manifest-file',type=Path,help='Use an offline FMO OTA manifest (implies --ota)')
    parser.add_argument('--passport',action='store_true',help='Also compare Passport OS main with the integrated source base')
    parser.add_argument('--passport-metadata-file',type=Path,help='Use an offline GitHub compare response (implies --passport)')
    args=parser.parse_args();profile=json.loads(PROFILE.read_text());failed=False
    if args.candidate_file:
        if args.metadata_file or args.ota or args.ota_manifest_file or args.passport or args.passport_metadata_file:
            parser.error('--candidate-file is an offline inspection and cannot be combined with metadata or Passport OS checks')
        try:
            with args.candidate_file.open('rb') as stream:
                data=stream.read(MAX_FIRMWARE_BYTES+1)
            if len(data)>MAX_FIRMWARE_BYTES:
                raise ValueError('候选固件超出大小限制')
            report={'source_verified':False,'firmware_bytes':len(data),
                    'firmware_sha256':hashlib.sha256(data).hexdigest(),
                    'firmware_image':inspect_application(data,profile['upstream'])}
        except (OSError,ValueError) as error:
            report={'status':'unavailable','error':str(error)};failed=True
        print(json.dumps(report,ensure_ascii=False,indent=2));return int(failed)
    metadata_url=profile['upstream']['metadata_url']
    try:
        payload=read_metadata(args.metadata_file,metadata_url)
        report=inspect_release(profile,payload)
    except (OSError,ValueError) as error:
        report={'status':'unavailable','error':str(error),'firmware_installed':False};failed=True
    if (args.firmware_file or args.verify_published_image) and not failed:
        try:
            limit=report['upstream_firmware_bytes']+1
            if args.firmware_file:
                with args.firmware_file.open('rb') as stream:
                    data=stream.read(limit)
            else:
                play=payload['play']
                link=play['firmware'].get('downloadUrl') or play.get('downloadUrl')
                data=read_published_image(metadata_url,link,report['upstream_firmware_bytes'])
            report['firmware_image']=inspect_image(data,report,profile['upstream'])
            if not report['update_available'] and not report['firmware_image']['target_version_matches']:
                report['action']='locate_target_release'
        except (OSError,ValueError) as error:
            report['firmware_image']={'status':'unavailable','error':str(error)}
            failed=True
    if args.ota or args.ota_manifest_file:
        reference=profile['upstream']
        manifest=reference['ota_manifest_url']
        try:
            ota=inspect_ota(reference,read_metadata(args.ota_manifest_file,manifest))
            if args.verify_published_image:
                data=read_published_image(manifest,ota['download_url'],ota['upstream_firmware_bytes'])
                ota['firmware_image']=inspect_ota_image(reference,ota,data)
            report['fmo_ota']=ota
        except (OSError,ValueError) as error:
            report['fmo_ota']={'status':'unavailable','error':str(error)}
            failed=True
    if args.passport or args.passport_metadata_file:
        expected=profile['passport_os_upstream']
        url=expected['api_repository']+'/compare/'+expected['integrated_base_commit']+'...'+expected['branch']
        try:report['passport_os']=inspect_passport(profile,read_metadata(args.passport_metadata_file,url))
        except (OSError,ValueError) as error:
            report['passport_os']={'status':'unavailable','error':str(error),'source_merged':False};failed=True
    print(json.dumps(report,ensure_ascii=False,indent=2));return int(failed)
if __name__=='__main__':sys.exit(main())
