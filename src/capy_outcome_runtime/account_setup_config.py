"""Default-off operator wiring for the dedicated account service."""
import json
import os
import threading
from pathlib import Path

from .account_ipc import Client,Server
from .account_setup import AccountSetup
from .model import RuntimeFailure


def configure(product,args):
    product.account_setup=None;product.account_authority_server=None
    path=getattr(args,'account_setup_config',None)
    if path is None:return
    path=Path(path)
    try:
        if path.is_symlink() or not path.is_file() or path.stat().st_mode & 0o022:raise ValueError()
        config=json.loads(path.read_text())
        if set(config)!={'policies','authority_socket','service_socket','service_uid'}:raise ValueError()
        if type(config['service_uid']) is not int or config['service_uid']<=0 or not product.release_connections:raise ValueError()
        if not config['policies'] or not isinstance(config['policies'],dict):raise ValueError()
        for policy in config['policies'].values():
            if set(policy)!={'workspace_id','environment','account_mode'}:raise ValueError()
            if policy['environment'] not in {'production','sandbox'} or policy['account_mode'] not in {'standard','child'}:raise ValueError()
        for key in ('authority_socket','service_socket'):
            p=Path(config[key])
            if not p.is_absolute() or any(v.is_symlink() for v in (p,*p.parents)):raise ValueError()
    except (OSError,ValueError,TypeError):raise RuntimeFailure('ACCOUNT_CONFIGURATION_INVALID') from None
    setup=AccountSetup(product.release_connections,product.release_previews,config['policies'])
    setup.custody=Client(config['service_socket'],config['service_uid'])
    server=Server(config['authority_socket'],config['service_uid'],setup.dispatch)
    # The unprivileged account service alone joins this dedicated group.
    import pwd
    os.chown(config['authority_socket'],os.geteuid(),pwd.getpwuid(config['service_uid']).pw_gid)
    threading.Thread(target=server.serve_forever,daemon=True,name='account-authority').start()
    product.account_setup=setup;product.account_authority_server=server
