"""Install Linux/amd64 pinned upstream binaries; verify exact release asset SHA-256."""
import hashlib,json,os,sys,tarfile,tempfile,urllib.request
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]

def install():
    lock=json.loads((ROOT/'upstream-lock.json').read_text())
    if sys.platform!='linux' or os.uname().machine not in ('x86_64','amd64'):raise SystemExit('This pinned installer supports Linux/amd64; use official release instructions for another platform.')
    output=ROOT/'.tools';output.mkdir(exist_ok=True)
    for entry in lock['tools']:
        repo,tag,asset=entry['repo'],entry['tag'],entry['asset']
        url='https://github.com/'+repo+'/releases/download/'+tag+'/'+asset
        req=urllib.request.Request(url,headers={'User-Agent':'Sandworm-Pinned-Installer/0.1'})
        with urllib.request.urlopen(req,timeout=90) as response:raw=response.read(150*1024*1024+1)
        if len(raw)>150*1024*1024 or hashlib.sha256(raw).hexdigest()!=entry['sha256']:raise SystemExit('Release checksum mismatch; nothing installed.')
        name='osv-scanner' if repo=='google/osv-scanner' else repo.rsplit('/',1)[1]
        if asset.endswith('.tar.gz'):
            with tempfile.TemporaryFile() as stream:
                stream.write(raw);stream.seek(0)
                with tarfile.open(fileobj=stream,mode='r:gz') as archive:
                    member=archive.getmember(name)
                    if not member.isfile() or member.size>150*1024*1024:raise SystemExit('Unexpected release member.')
                    binary=archive.extractfile(member).read(150*1024*1024+1)
        else:binary=raw
        dest=output/name;temp=output/(name+'.tmp')
        with temp.open('xb') as stream:stream.write(binary)
        temp.chmod(0o755);temp.replace(dest)
        print(name+' '+tag+' installed; asset SHA-256 verified')
if __name__=='__main__':
    try:install()
    except (OSError,ValueError,KeyError,tarfile.TarError):raise SystemExit('Pinned upstream installation failed; check network and official release metadata.') from None
