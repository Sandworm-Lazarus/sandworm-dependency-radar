from __future__ import annotations
import argparse, json, os, sys, tempfile
from pathlib import Path
from .engine import normalize, compare
from .safety import RadarError, read_json, parse_json, local_target, run_bounded, sha256, write_report
PIN = '2.7.1'

def scan(target, binary='osv-scanner', timeout=120, db_cache=None):
    target = local_target(target)
    if not db_cache: raise RadarError('select an explicit offline database cache')
    try: cache = Path(db_cache).resolve(strict=True)
    except OSError: raise RadarError('offline database cache unavailable') from None
    if not cache.is_dir() or Path(db_cache).is_symlink(): raise RadarError('invalid offline database cache')
    with tempfile.TemporaryDirectory(prefix='sandworm-osv-') as home:
        env = {'PATH':os.environ.get('PATH',''),'HOME':home,'LANG':'C.UTF-8','LC_ALL':'C.UTF-8','OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY':str(cache)}
        version, code = run_bounded([binary,'--version'],timeout=10,limit=65536,env=env)
        if code or PIN not in version.decode('utf-8',errors='replace').split():
            # Some upstream builds print "osv-scanner version: 2.7.1" or v2.7.1.
            import re
            if code or not re.search(r'(?<![\d.])v?'+re.escape(PIN)+r'(?![\d.])',version.decode('utf-8',errors='replace')):
                raise RadarError('engine version differs from upstream-lock.json')
        raw, code = run_bounded([binary,'scan','source','--offline','--format=json','--recursive','--all-packages','--no-resolve','--no-call-analysis=go','--no-call-analysis=rust',str(target)],timeout=timeout,env=env)
        if code not in (0,1): raise RadarError('OSV scan failed; no completed report was produced')
        data = parse_json(raw)
        report = normalize(data,sha256(raw),mode='live')
        report['engine'] = {'name':'OSV-Scanner','version':PIN,'exit_code':code,'network':'offline','database_status':'upstream-offline-scan-completed'}
        report['database'] = {'timestamp':None,'status':'available-to-engine; timestamp not asserted'}
        return report

def main(argv=None):
    parser=argparse.ArgumentParser(description='Sandworm Dependency Radar: local OSV report review')
    sub=parser.add_subparsers(dest='command',required=True)
    imp=sub.add_parser('import-report'); imp.add_argument('input'); imp.add_argument('--out',required=True); imp.add_argument('--baseline')
    live=sub.add_parser('scan'); live.add_argument('target'); live.add_argument('--binary',default='osv-scanner'); live.add_argument('--timeout',type=int,default=120); live.add_argument('--out',required=True); live.add_argument('--baseline'); live.add_argument('--db-cache',required=True)
    diff=sub.add_parser('diff'); diff.add_argument('before'); diff.add_argument('after'); diff.add_argument('--out',required=True)
    args=parser.parse_args(argv)
    try:
        if args.command=='diff':
            before,bhash=read_json(args.before); after,ahash=read_json(args.after)
            report={'schema_version':1,'project':'sandworm-dependency-radar','mode':'import','summary':{},'findings':[],'comparison':compare(before,after),'inputs_sha256':{'before':bhash,'after':ahash}}
            report['summary']={k:len(report['comparison'][k]) for k in ('new','resolved')}
            inputs=[args.before,args.after]
        else:
            if args.command=='scan': report=scan(args.target,args.binary,args.timeout,args.db_cache); inputs=[]
            else:
                data,digest=read_json(args.input); report=normalize(data,digest); inputs=[args.input]
            if args.baseline:
                baseline,digest=read_json(args.baseline); report['comparison']=compare(baseline,report); report['baseline_sha256']=digest; inputs.append(args.baseline)
        write_report(args.out,report,inputs)
        print(json.dumps({'status':'written','summary':report['summary']},ensure_ascii=False))
        return 0
    except (RadarError,OSError,KeyError,TypeError):
        print('Sandworm: operation failed; check input schema, limits, engine version, and offline database.',file=sys.stderr)
        return 2
if __name__=='__main__': raise SystemExit(main())
