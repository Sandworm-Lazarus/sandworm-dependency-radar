import copy, io, json, os, sys, tempfile, unittest
from pathlib import Path
from contextlib import redirect_stderr,redirect_stdout
from unittest.mock import patch
from sandworm_radar.engine import normalize, compare
from sandworm_radar.cli import main,scan
from sandworm_radar.safety import RadarError,parse_json,read_json,run_bounded,local_target,write_report,MAX_BYTES
ROOT=Path(__file__).resolve().parents[1]

def fixture():return json.loads((ROOT/'examples/osv-report.json').read_text())
class RadarTests(unittest.TestCase):
 def test_published_fix(self):
  r=normalize(fixture(),'a'*64);self.assertEqual(r['summary']['findings'],1);self.assertEqual(r['findings'][0]['fixed_versions'],['1.0.1']);self.assertEqual(r['findings'][0]['severity_score'],7.5)
 def test_unknown_not_clean(self):
  d=fixture();d['results'][0]['packages'][0]['vulnerabilities'][0]['affected']=[]
  r=normalize(d,'a');self.assertEqual(r['findings'][0]['fix_status'],'not-established')
 def test_other_package_fix_not_attributed(self):
  d=fixture();d['results'][0]['packages'][0]['vulnerabilities'][0]['affected'][0]['package']['name']='another-package'
  self.assertEqual(normalize(d,'a')['findings'][0]['fixed_versions'],[])
 def test_unknown_severity(self):
  d=fixture();d['results'][0]['packages'][0]['groups'][0]['max_severity']=''
  self.assertIsNone(normalize(d,'a')['findings'][0]['severity_score'])
 def test_bad_severity(self):
  d=fixture();d['results'][0]['packages'][0]['groups'][0]['max_severity']='11'
  with self.assertRaises(RadarError):normalize(d,'a')
 def test_same_advisory_two_sources(self):
  d=fixture();s=copy.deepcopy(d['results'][0]);s['source']['path']='sub/package-lock.json';d['results'].append(s)
  r=normalize(d,'a');self.assertEqual(len(r['findings']),1);self.assertEqual(len(r['findings'][0]['sources']),2)
 def test_conflicting_advisory_rejected(self):
  d=fixture();s=copy.deepcopy(d['results'][0]);s['packages'][0]['vulnerabilities'][0]['aliases']=['DIFFERENT'];d['results'].append(s)
  with self.assertRaises(RadarError):normalize(d,'a')
 def test_absolute_source_hidden(self):
  d=fixture();d['results'][0]['source']['path']='/private/email@example.test/file'
  r=normalize(d,'a');self.assertNotIn('email@example.test',json.dumps(r));self.assertEqual(r['findings'][0]['sources'],['[source-path-redacted]'])
 def test_baseline_diff(self):
  before=normalize(fixture(),'a');d=fixture();d['results'][0]['packages'][0]['vulnerabilities']=[];after=normalize(d,'b')
  delta=compare(before,after);self.assertEqual(len(delta['resolved']),1);self.assertEqual(delta['new'],[])
 def test_baseline_identity_validation(self):
  r=normalize(fixture(),'a');r['findings'][0]['id']='made-up'
  with self.assertRaises(RadarError):compare(r,r)
 def test_duplicate_baseline_rejected(self):
  r=normalize(fixture(),'a');r['findings']*=2
  with self.assertRaises(RadarError):compare(r,r)
 def test_baseline_extra_original_field_rejected(self):
  r=normalize(fixture(),'a');r['findings'][0]['original_secret']='must-not-export'
  with self.assertRaises(RadarError):compare(r,r)
 def test_baseline_invalid_summary_types_rejected(self):
  r=normalize(fixture(),'a');r['findings'][0]['fixed_versions']='1.0.1'
  with self.assertRaises(RadarError):compare(r,r)
 def test_windows_source_hidden(self):
  d=fixture();d['results'][0]['source']['path']='C:\\private\\email@example.test\\file'
  self.assertNotIn('email@example.test',json.dumps(normalize(d,'a')))
 def test_missing_schema_rejected(self):
  with self.assertRaises(RadarError):normalize({},'a')
 def test_control_text_rejected(self):
  d=fixture();d['results'][0]['packages'][0]['package']['name']='bad\x00name'
  with self.assertRaises(RadarError):normalize(d,'a')
 def test_scan_requires_explicit_db(self):
  with self.assertRaises(RadarError):scan(ROOT/'examples/live-project')
 def test_cli_sanitizes_parse_error(self):
  with tempfile.TemporaryDirectory() as tmp:
   p=Path(tmp)/'bad.json';p.write_text('{"secret":"SENSITIVE-ORIGINAL",}')
   out,err=io.StringIO(),io.StringIO()
   with redirect_stdout(out),redirect_stderr(err):code=main(['import-report',str(p),'--out',str(Path(tmp)/'out.json')])
   self.assertEqual(code,2);self.assertNotIn('SENSITIVE-ORIGINAL',err.getvalue());self.assertFalse((Path(tmp)/'out.json').exists())
 def test_cli_real_import(self):
  with tempfile.TemporaryDirectory() as tmp:
   p=Path(tmp)/'report.json'
   with redirect_stdout(io.StringIO()):code=main(['import-report',str(ROOT/'examples/osv-report.json'),'--out',str(p)])
   self.assertEqual(code,0);self.assertEqual(json.loads(p.read_text())['summary']['findings'],1)
 def test_scan_output_cannot_replace_source(self):
  with tempfile.TemporaryDirectory() as tmp:
   p=Path(tmp)/'package-lock.json';p.write_text('source-keep')
   with patch('sandworm_radar.cli.scan',return_value=normalize(fixture(),'x')),redirect_stderr(io.StringIO()):
    c=main(['scan',tmp,'--db-cache',tmp,'--out',str(p)])
   self.assertEqual(c,2);self.assertEqual(p.read_text(),'source-keep')
 def test_live_adapter_offline_and_no_credentials(self):
  calls=[];raw=json.dumps(fixture()).encode()
  def fake(args,**kwargs):calls.append((args,kwargs));return (b'osv-scanner version: 2.7.1',0) if '--version' in args else (raw,1)
  with tempfile.TemporaryDirectory() as tmp,patch('sandworm_radar.cli.run_bounded',side_effect=fake),patch.dict(os.environ,{'AWS_SECRET_ACCESS_KEY':'should-not-pass'}):
   r=scan(ROOT/'examples/live-project','osv-scanner',10,tmp)
  self.assertEqual(r['mode'],'live');self.assertIn('--offline',calls[1][0]);self.assertIn('--no-call-analysis=rust',calls[1][0]);self.assertNotIn('AWS_SECRET_ACCESS_KEY',calls[1][1]['env'])
 def test_live_engine_failure_is_not_empty_result(self):
  def fake(args,**kwargs):return (b'osv-scanner version: 2.7.1',0) if '--version' in args else (b'original-sensitive-output',2)
  with tempfile.TemporaryDirectory() as tmp,patch('sandworm_radar.cli.run_bounded',side_effect=fake):
   with self.assertRaises(RadarError):scan(ROOT/'examples/live-project','osv',10,tmp)

class SafetyTests(unittest.TestCase):
 def test_duplicate_json(self):
  with self.assertRaises(RadarError):parse_json('{"a":1,"a":2}')
 def test_nonfinite_json(self):
  with self.assertRaises(RadarError):parse_json('{"a":NaN}')
 def test_invalid_utf8(self):
  with self.assertRaises(RadarError):parse_json(b'\xff')
 def test_deep_json(self):
  with self.assertRaises(RadarError):parse_json('['*60+'0'+']'*60)
 def test_size(self):
  with self.assertRaises(RadarError):parse_json(b' '*(MAX_BYTES+1))
 def test_symlink(self):
  with tempfile.TemporaryDirectory() as tmp:
   p=Path(tmp);(p/'a').write_text('x');(p/'b').symlink_to(p/'a')
   with self.assertRaises(RadarError):local_target(p)
 def test_nonexistent_target(self):
  with self.assertRaises(RadarError):local_target('/not-a-sandworm-path')
 def test_subprocess_bounded_stdout(self):
  with self.assertRaises(RadarError):run_bounded([sys.executable,'-c','print("SENSITIVE"*5000)'],limit=500)
 def test_subprocess_bounded_stderr(self):
  with self.assertRaises(RadarError):run_bounded([sys.executable,'-c','import sys;sys.stderr.write("SENSITIVE"*5000)'],limit=500)
 def test_subprocess_timeout(self):
  with self.assertRaises(RadarError):run_bounded([sys.executable,'-c','import time;time.sleep(5)'],timeout=0.1)
 def test_subprocess_missing(self):
  with self.assertRaises(RadarError):run_bounded(['/not-an-engine'])
 def test_protect_input_file(self):
  with tempfile.TemporaryDirectory() as tmp:
   p=Path(tmp)/'input.json';p.write_text('{}')
   with self.assertRaises(RadarError):write_report(p,{},[p])
 def test_report_never_overwrites_existing(self):
  with tempfile.TemporaryDirectory() as tmp:
   p=Path(tmp)/'output.json';p.write_text('keep')
   with self.assertRaises(RadarError):write_report(p,{})
   self.assertEqual(p.read_text(),'keep')
 def test_read_fifo_refused(self):
  with tempfile.TemporaryDirectory() as tmp:
   p=Path(tmp)/'pipe';os.mkfifo(p)
   with self.assertRaises(RadarError):read_json(p)
 def test_read_symlink_refused(self):
  with tempfile.TemporaryDirectory() as tmp:
   p=Path(tmp);(p/'a').write_text('{}');(p/'b').symlink_to(p/'a')
   with self.assertRaises(RadarError):read_json(p/'b')
 def test_target_fifo_refused(self):
  with tempfile.TemporaryDirectory() as tmp:
   p=Path(tmp);os.mkfifo(p/'pipe')
   with self.assertRaises(RadarError):local_target(p)
 def test_output_symlink_never_follows(self):
  with tempfile.TemporaryDirectory() as tmp:
   p=Path(tmp);(p/'a').write_text('keep');(p/'b').symlink_to(p/'a')
   with self.assertRaises(RadarError):write_report(p/'b',{})
   self.assertEqual((p/'a').read_text(),'keep')
if __name__=='__main__':unittest.main()
