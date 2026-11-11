"""Normalize OSV-Scanner reports without inventing severity or fixed versions."""
from __future__ import annotations
from datetime import datetime, timezone
import hashlib, json
from .safety import RadarError, array, obj, relative_name, text

PROJECT = 'sandworm-dependency-radar'

def _fixes(vuln, package):
    versions = set()
    for affected in array(vuln.get('affected', [])):
        affected = obj(affected)
        ap = obj(affected.get('package', {}))
        if ap.get('name') != package['name'] or ap.get('ecosystem') != package['ecosystem']: continue
        for range_ in array(affected.get('ranges', [])):
            for event in array(obj(range_).get('events', [])):
                event = obj(event)
                if 'fixed' in event: versions.add(text(event['fixed'], limit=200))
    return sorted(versions)

def normalize(data, input_sha256, mode='import'):
    data = obj(data)
    if 'results' not in data: raise RadarError('not an OSV-Scanner report')
    collected, packages = {}, set()
    for source in array(data['results'], 2000):
        source = obj(source); src = relative_name(obj(source.get('source', {})).get('path', ''))
        for item in array(source.get('packages', [])):
            item = obj(item); pkg = obj(item.get('package'))
            package = {key: text(pkg.get(key), limit=300) for key in ('name','version','ecosystem')}
            if not package['name'] or not package['ecosystem']: raise RadarError('package identity missing')
            pid = (package['ecosystem'], package['name'], package['version']); packages.add(pid)
            severity = {}
            for group in array(item.get('groups', [])):
                group = obj(group)
                score = group.get('max_severity')
                if score not in (None, ''):
                    score = str(score)
                    try:
                        numeric = float(score)
                        if not 0 <= numeric <= 10: raise ValueError()
                    except ValueError: raise RadarError('invalid severity score') from None
                    for vid in array(group.get('ids', [])): severity[text(vid)] = numeric
            for vuln in array(item.get('vulnerabilities', [])):
                vuln = obj(vuln); vid = text(vuln.get('id'), limit=200)
                if not vid: raise RadarError('advisory identity missing')
                key = (*pid, vid)
                aliases = sorted({text(a, limit=200) for a in array(vuln.get('aliases', []), 200)})
                fixed = _fixes(vuln, package)
                row = {'id': hashlib.sha256(json.dumps(key,ensure_ascii=False).encode()).hexdigest(), 'package': package, 'advisory_id': vid, 'aliases': aliases,
                       'severity_score': severity.get(vid), 'fixed_versions': fixed,
                       'fix_status': 'fixed-version-published' if fixed else 'not-established', 'sources': [src] if src else []}
                if key in collected:
                    old = collected[key]
                    if {k:v for k,v in old.items() if k!='sources'} != {k:v for k,v in row.items() if k!='sources'}:
                        raise RadarError('conflicting duplicate advisory')
                    old['sources'] = sorted(set(old['sources'] + row['sources']))
                else: collected[key] = row
                if len(collected) > 20000: raise RadarError('finding limit exceeded')
    findings = sorted(collected.values(), key=lambda r:r['id'])
    return {'schema_version':1, 'project':PROJECT, 'mode':mode,
            'generated_at':datetime.now(timezone.utc).isoformat(), 'input_sha256':input_sha256,
            'database':{'timestamp':None,'status':'not-provided-by-import'},
            'summary':{'packages':len(packages),'findings':len(findings),'published_fixes':sum(bool(r['fixed_versions']) for r in findings),
                       'unknown_fix_status':sum(not r['fixed_versions'] for r in findings)},
            'findings':findings,'methodology':{'scope':'reported package/advisory pairs only',
            'severity':'OSV group max_severity when supplied; otherwise null',
            'fixed_versions':'published fixed events matching the package, not an upgrade recommendation',
            'zero_findings':'No reported matches; this does not certify the project is secure.'}}

def _indexed(report):
    report = obj(report)
    if report.get('project') != PROJECT or report.get('schema_version') != 1: raise RadarError('incompatible baseline')
    findings = array(report.get('findings'))
    output = {}
    for finding in findings:
        row = obj(finding)
        if set(row) != {'id','package','advisory_id','aliases','severity_score','fixed_versions','fix_status','sources'}: raise RadarError('incompatible finding fields')
        key = text(row.get('id'),limit=2000)
        if not key or key in output: raise RadarError('duplicate or missing finding identity')
        pkg = obj(row.get('package'))
        if set(pkg) != {'name','version','ecosystem'}: raise RadarError('incompatible package fields')
        for label in ('aliases','fixed_versions'):
            for value in array(row.get(label),200): text(value,limit=200)
        for value in array(row.get('sources'),2000):
            if relative_name(value)!=value: raise RadarError('unsafe baseline source path')
        if row['severity_score'] is not None and (isinstance(row['severity_score'],bool) or not isinstance(row['severity_score'],(int,float)) or not 0<=row['severity_score']<=10): raise RadarError('invalid baseline severity')
        if row['fix_status'] not in {'fixed-version-published','not-established'}: raise RadarError('invalid baseline fix status')
        for field in ('name','version','ecosystem'): text(pkg.get(field),limit=300)
        if key != hashlib.sha256(json.dumps([pkg['ecosystem'],pkg['name'],pkg['version'],text(row.get('advisory_id'),limit=200)],ensure_ascii=False).encode()).hexdigest(): raise RadarError('invalid baseline identity')
        output[key] = row
    return output

def compare(before, after):
    old, new = _indexed(before), _indexed(after)
    return {'new':[new[k] for k in sorted(new.keys()-old.keys())],
            'resolved':[old[k] for k in sorted(old.keys()-new.keys())],
            'retained':len(old.keys() & new.keys()),
            'meaning':'Resolved means absent from the later report, not proof of remediation.'}
