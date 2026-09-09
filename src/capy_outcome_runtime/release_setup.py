"""Default-off release workflow wiring; configuration is operator-owned."""
from pathlib import Path
import os

from .model import RuntimeFailure


def configure(product, args):
    product.release_workflow = product.release_previews = product.release_activation = None
    product.release_connections = None
    if not getattr(args, 'candidate_releases', False):
        return
    from ._release_bridge_client import Client
    from .release_workflow import ReleaseWorkflow
    from .release_preview import ReleasePreviews
    from .release_activation import ReleaseActivation
    from .launcher import SystemdTransientLauncher
    from .web import linux_identity
    socket = getattr(args,'release_bridge_socket',None)
    uid = getattr(args,'release_bridge_uid',None)
    root = getattr(args,'release_control_root',None)
    previews = getattr(args,'release_preview_root',None)
    users = getattr(args,'release_preview_users',None)
    if not socket or type(uid) is not int or uid<=0 or not root or not previews or not users or product.developer_link is None:
        raise RuntimeFailure('RELEASE_CONFIGURATION_REQUIRED')
    identities = [linux_identity(user) for user in users.split(',')]
    if len({v.uid for v in identities}) != len(identities) or any(v.uid in (0,os.getuid(),uid) for v in identities):
        raise RuntimeFailure('RELEASE_PREVIEW_IDENTITIES_INVALID')
    protected = {linux_identity(user).uid for user in (args.owner_user,args.beta_user,getattr(args,'member_user',None)) if user}
    if any(v.uid in protected for v in identities):
        raise RuntimeFailure('RELEASE_PREVIEW_IDENTITIES_INVALID')
    for path in (Path(root),Path(previews)):
        if any(part.is_symlink() for part in (path,*path.parents)):
            raise RuntimeFailure('RELEASE_PATH_INVALID')
    workflow = ReleaseWorkflow(product.runtime_store,product.access_store,product.developer_link,
                               Client(socket,uid),root)
    preview = ReleasePreviews(workflow,previews,
        lambda slot:SystemdTransientLauncher(lambda scope:identities[slot],private_network=True),slots=len(identities),
        connection_control=product.connection_control, broker_socket=args.connection_socket)
    product.release_workflow,product.release_previews = workflow,preview
    product.release_activation = ReleaseActivation(workflow,preview,product.team_software)
    from .release_connections import ReleaseConnectionSetup
    product.release_connections = ReleaseConnectionSetup(workflow, product.connection_control, team=product.team_software)
    workflow.expire_previews = preview.expire
    workflow.start()
