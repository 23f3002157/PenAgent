"""Safe offline CLI. No command starts scanners, creates accounts or resets data."""
import argparse
import json
import sys
from pathlib import Path

from . import core

def main():
    deps=core.ROOT/'local/validation-deps'
    if deps.is_dir(): sys.path.insert(0,str(deps))
    p=argparse.ArgumentParser(description=__doc__); sub=p.add_subparsers(dest='action',required=True)
    a=sub.add_parser('validate-spec'); a.add_argument('spec'); a.add_argument('--full',action='store_true'); a.add_argument('--out')
    a=sub.add_parser('validate-manifest'); a.add_argument('manifest')
    a=sub.add_parser('inventory'); a.add_argument('spec'); a.add_argument('--out',required=True)
    a=sub.add_parser('compare'); a.add_argument('spec'); a.add_argument('penagent'); a.add_argument('zap'); a.add_argument('--out',required=True)
    a=sub.add_parser('audit'); a.add_argument('--out',required=True)
    a=sub.add_parser('readiness'); a.add_argument('--out',required=True)
    a=sub.add_parser('check-identity'); a.add_argument('expected'); a.add_argument('observed')
    args=p.parse_args()
    if args.action in {'validate-spec','inventory'}:
        result=core.inspect_spec(core.load(args.spec),getattr(args,'full',False)); result['sha256']=core.sha(args.spec)
        if args.out: core.save(args.out,result)
        print(json.dumps({'operations':len(result['operations']),'full_schema_validation':result['full_schema_validation'],'warnings':result['warnings']}))
    elif args.action=='validate-manifest':
        m=core.validate_manifest(core.load(args.manifest)); print(m['benchmark_id']+': '+m['readiness'])
    elif args.action=='check-identity':
        core.check_identity(core.load(args.expected),core.load(args.observed)); print('Target identity matches')
    elif args.action=='compare':
        expected=core.operation_set(core.inspect_spec(core.load(args.spec)))
        pa=core.operation_set(core.load(args.penagent)); zap=core.operation_set(core.load(args.zap))
        core.save(args.out,{'documented':sorted(expected),'penagent':sorted(pa),'zap':sorted(zap),
            'shared_imported':sorted(expected&pa&zap),'missing_penagent':sorted(expected-pa),'missing_zap':sorted(expected-zap),
            'note':'Imported operation intersection is not live coverage or scanning authorization'})
    elif args.action=='readiness':
        manifests=[core.validate_manifest(core.load(p)) for p in sorted((core.ROOT/'manifests').glob('*.json'))]
        result={m['benchmark_id']:{'status':m['readiness'],'failed_checks':sorted(k for k,v in m['checks'].items() if not v),
            'eligible_operations':len(m['eligible_operations'])} for m in manifests}
        core.save(args.out,result);print(json.dumps(result,indent=2))
    else:
        files=['specs/original/juice-shop-20.0.0-b2b.yml','specs/prepared/juice-shop-20.0.0-readonly-host.json',
            'manifests/juice-shop-20.0.0.json','manifests/dvws-original.json','manifests/srebench-api.json','deploy/juice-shop.compose.yml']
        result={'assets':{f:(core.ROOT/f).is_file() for f in files},'active_scan_executed':False}
        core.save(args.out,result); print(json.dumps(result,indent=2))

if __name__=='__main__': main()
