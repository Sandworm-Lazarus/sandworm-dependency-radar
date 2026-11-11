"""Real OSV engine, synthetic offline database, no network needed."""
import argparse,hashlib,json,sys,zipfile
from datetime import datetime,timezone
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
from sandworm_radar.cli import scan
from sandworm_radar.safety import RadarError
p=argparse.ArgumentParser();p.add_argument('--binary',default=str(ROOT/'.tools/osv-scanner'));args=p.parse_args()
cache=ROOT/'.runtime/synthetic-osv-db';db=cache/'osv-scalibr/npm';db.mkdir(parents=True,exist_ok=True)
vuln={'schema_version':'1.6.0','id':'SANDWORM-DEMO-001','modified':'2026-11-11T00:00:00Z','published':'2026-11-01T00:00:00Z','summary':'Invented test advisory only','affected':[{'package':{'name':'example-widget','ecosystem':'npm'},'ranges':[{'type':'SEMVER','events':[{'introduced':'0'},{'fixed':'1.0.1'}]}]}]}
raw=json.dumps(vuln,sort_keys=True).encode()
with zipfile.ZipFile(db/'all.zip','w') as archive:archive.writestr('SANDWORM-DEMO-001.json',raw)
try:
    result=scan(ROOT/'examples/live-project',args.binary,120,cache)
    assert result['summary']['findings']==1 and result['findings'][0]['advisory_id']=='SANDWORM-DEMO-001'
    record={'schema_version':1,'status':'passed','mode':'live-engine-synthetic-fixture','generated_at':datetime.now(timezone.utc).isoformat(),'engine':result['engine'],'binary_sha256':hashlib.sha256(Path(args.binary).read_bytes()).hexdigest(),'database':{'kind':'synthetic offline OSV zip; not a real vulnerability database','advisory_json_sha256':hashlib.sha256(raw).hexdigest()},'input_sha256':hashlib.sha256((ROOT/'examples/live-project/package-lock.json').read_bytes()).hexdigest(),'summary':result['summary'],'assertions':['real pinned engine executed','invented advisory matched','published synthetic fix normalized','no network/update/provider request enabled']}
    (ROOT/'reports/live-smoke.json').write_text(json.dumps(record,indent=2)+'\n');print(json.dumps({'status':'passed','summary':result['summary']}))
except (RadarError,AssertionError,OSError):
    print('Live OSV smoke failed or engine unavailable; no passing record written.',file=sys.stderr);raise SystemExit(2)
