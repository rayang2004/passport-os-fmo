"""Release checks distinguish unavailable/changed metadata without installing binaries."""
import copy,importlib.util,json
from pathlib import Path
root=Path(__file__).resolve().parents[3]
spec=importlib.util.spec_from_file_location('fmo_upstream',root/'tools/check_fmo_upstream.py');module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
p=json.loads((root/'components/passport_fmo/src/upstream_profile.json').read_text());sha=p['upstream']['reference_firmware_sha256']
snapshot={'ok':True,'play':{'author':'BI4TES','shareVersion':'6500-2','firmwareSha256':sha,'firmware':{'available':True,'sha256':sha,'size':p['upstream']['reference_firmware_bytes']},'githubUrl':''}}
r=module.inspect_release(p,snapshot);assert not r['update_available'] and not r['integration_complete'] and not r['firmware_installed']
changed=copy.deepcopy(snapshot);changed['play']['firmware']['sha256']='a'*64;changed['play']['firmwareSha256']='a'*64
changed['play'].update(revisionId=6726,changelog={'zh':'稳定性修复','en':'x'*2100,'other':'ignored'})
result=module.inspect_release(p,changed)
assert result['update_available'] and result['upstream_revision_id']==6726
assert result['upstream_release_notes']=={'zh':'稳定性修复','en':'x'*2000}
for bad_size in (1, True):
 bad=copy.deepcopy(snapshot);bad['play']['firmwareSize']=bad_size
 try:module.inspect_release(p,bad);raise AssertionError('inconsistent size accepted')
 except ValueError:pass
bad=copy.deepcopy(snapshot);bad['play']['firmware']['size']-=1
try:module.inspect_release(p,bad);raise AssertionError('wrong baseline size accepted')
except ValueError:pass
for mutate in [lambda j:j.update(ok=False),lambda j:j['play'].update(author='other'),lambda j:j['play']['firmware'].update(available=False),lambda j:j['play']['firmware'].update(sha256='bad'),lambda j:j['play']['firmware'].update(size=9000000),lambda j:j['play'].update(firmwareSha256='b'*64)]:
 bad=copy.deepcopy(snapshot);mutate(bad)
 try:module.inspect_release(p,bad);raise AssertionError('invalid metadata accepted')
 except ValueError:pass
print('FMO upstream: unchanged/new release, author and checksum mismatch, unavailable/oversized metadata; no firmware or key mutation PASS')
# GitHub compares are relative to the integrated base, not an assumed latest
# checkout. Rewinds/divergence remain actionable even with no new commits.
base=p['passport_os_upstream']['integrated_base_commit']
compare={'base_commit':{'sha':base},'html_url':p['passport_os_upstream']['repository']+'/compare/'+base+'...main','status':'identical','ahead_by':0,'behind_by':0}
for relation,ahead,behind in [('identical',0,0),('ahead',7,0),('behind',0,3),('diverged',7,3)]:
 value=copy.deepcopy(compare);value.update(status=relation,ahead_by=ahead,behind_by=behind)
 result=module.inspect_passport(p,value)
 assert result['update_available']==bool(ahead)
 assert result['manual_review_required']==(relation!='identical')
 assert not result['source_merged'] and not result['firmware_installed']
for mutate in [lambda j:j.update(base_commit=None),lambda j:j.update(base_commit={'sha':'a'*40}),lambda j:j.update(html_url='https://example.test/compare/x'),lambda j:j.update(ahead_by=True),lambda j:j.update(behind_by=-1),lambda j:j.update(status='ahead'),lambda j:j.update(status='unknown')]:
 bad=copy.deepcopy(compare);mutate(bad)
 try:module.inspect_passport(p,bad);raise AssertionError('invalid compare metadata accepted')
 except ValueError:pass
# Exercise CLI with both snapshots and one unavailable source; successful
# independent results must survive and failure must not look like no update.
import subprocess,tempfile,sys
with tempfile.TemporaryDirectory() as td:
 td=Path(td);fm=td/'fmo.json';pm=td/'passport.json'
 fm.write_text(json.dumps(snapshot));pm.write_text(json.dumps(compare))
 command=[sys.executable,str(root/'tools/check_fmo_upstream.py'),'--metadata-file',str(fm),'--passport-metadata-file',str(pm)]
 run=subprocess.run(command,capture_output=True,text=True);assert run.returncode==0,run.stderr
 assert json.loads(run.stdout)['passport_os']['relationship']=='identical'
 fm.write_text('{')
 run=subprocess.run(command,capture_output=True,text=True);assert run.returncode==1
 report=json.loads(run.stdout);assert report['status']=='unavailable' and report['passport_os']['status']=='checked'
 fm.write_text(json.dumps(snapshot));pm.write_text('{}')
 run=subprocess.run(command,capture_output=True,text=True);assert run.returncode==1
 report=json.loads(run.stdout);assert report['update_available'] is False and report['passport_os']['status']=='unavailable'
print('Dual upstream: exact base/source, ahead/rewind/divergence, invalid counters, offline CLI and independent failure preservation PASS')

# The device feed advances independently of the merged flash package.
reference=p['upstream']
ota={'version':'0.6.14','size':2894864,'sha256':reference['ota_reference_application_sha256'],
     'url':'https://fmo.simy.live/fw/fmo-passport-v0.6.14.bin'}
assert module.inspect_ota(reference,ota)['update_available'] is False
assert module.inspect_ota(reference,dict(ota,version='0.6.15',sha256='b'*64))['update_available']
for invalid in ({'size':True},{'version':'0.6.11/1'},{'url':'http://fmo.simy.live/fw/image.bin'},
                {'url':'https://fmo.simy.live.example/fw/image.bin'},{'sha256':'short'}):
 try:module.inspect_ota(reference,dict(ota,**invalid));raise AssertionError('invalid OTA manifest accepted')
 except ValueError:pass
with tempfile.TemporaryDirectory() as td:
 td=Path(td);fm=td/'fmo.json';om=td/'ota.json'
 fm.write_text('{');om.write_text(json.dumps(ota))
 command=[sys.executable,str(root/'tools/check_fmo_upstream.py'),'--metadata-file',str(fm),'--ota-manifest-file',str(om)]
 run=subprocess.run(command,capture_output=True,text=True)
 report=json.loads(run.stdout)
 assert run.returncode==1 and report['status']=='unavailable' and report['fmo_ota']['status']=='checked'
print('Device OTA: independent results, version, bounds and same HTTPS origin PASS')
