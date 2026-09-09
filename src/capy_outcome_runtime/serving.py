"""Shared single-authority process lease, independent of presentation."""
from pathlib import Path
from .model import RuntimeFailure


def acquire_serving_lease(root):
    """One authority-serving process, including startup mutations and recovery."""
    import fcntl
    root = Path(root)
    root.mkdir(parents=True, exist_ok=True)
    lease = (root / "human-authority-server.lock").open("a")
    try:
        fcntl.flock(lease, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError as exc:
        lease.close()
        raise RuntimeFailure("HUMAN_AUTHORITY_SERVER_ALREADY_RUNNING") from exc
    return lease

