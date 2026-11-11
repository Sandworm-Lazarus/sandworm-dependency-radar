"""Run regression tests and bind the result to exact repository sources/fixtures."""
import hashlib,json,sys,unittest
from datetime import datetime,timezone
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
suite=unittest.defaultTestLoader.discover(str(ROOT/'tests'),pattern='test_*.py')
result=unittest.TextTestRunner(verbosity=1).run(suite)
files={}
for directory in ['sandworm_radar','tests','examples','scripts','web']:
    for p in sorted((ROOT/directory).rglob('*')):
        if p.is_file() and '__pycache__' not in p.parts and p.suffix in ('.py','.cjs','.js','.json','.html','.css','.svg'):
            files[str(p.relative_to(ROOT))]=hashlib.sha256(p.read_bytes()).hexdigest()
files['upstream-lock.json']=hashlib.sha256((ROOT/'upstream-lock.json').read_bytes()).hexdigest()
report={'schema_version':1,'generated_at':datetime.now(timezone.utc).isoformat(),'passed':result.testsRun-len(result.errors)-len(result.failures)-len(result.skipped),'tests':result.testsRun,'failures':len(result.failures),'errors':len(result.errors),'skipped':len(result.skipped),'status':'passed' if result.wasSuccessful() else 'failed','sha256':files,'scope':'Python engine/CLI/safety regression tests; live engine smoke is recorded separately.'}
(ROOT/'reports').mkdir(exist_ok=True)
(ROOT/'reports/validation.json').write_text(json.dumps(report,indent=2)+'\n')
raise SystemExit(0 if result.wasSuccessful() else 1)
