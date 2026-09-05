"""Local operator import and integrity inspection; never workspace activation."""
import argparse
import json
from pathlib import Path
from .release_import import import_release, inspect_import
from .model import RuntimeFailure


def main(argv=None):
    parser=argparse.ArgumentParser()
    sub=parser.add_subparsers(dest='command',required=True)
    for name in ('import','inspect'):
        p=sub.add_parser(name);p.add_argument('--preview-root',type=Path,required=True);p.add_argument('--json',action='store_true')
        if name=='import':
            p.add_argument('--candidate',type=Path,required=True);p.add_argument('--acceptance',type=Path,required=True)
        else: p.add_argument('--import-id',required=True)
    args=parser.parse_args(argv)
    try:
        result=import_release(args.preview_root,args.candidate,args.acceptance) if args.command=='import' else inspect_import(args.preview_root,args.import_id)
    except (RuntimeFailure,OSError) as exc:
        print(json.dumps({'status':'FAILED','code':getattr(exc,'code','RELEASE_IMPORT_IO_FAILED')}));return 1
    print(json.dumps(result,sort_keys=True));return 0


if __name__=='__main__': raise SystemExit(main())
