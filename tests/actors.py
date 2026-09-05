"""Synthetic actor fixture for isolated public interface tests."""
from capy_outcome_runtime.access import ActorContext

def actor(principal: str = "owner", kind: str = "owner") -> ActorContext:
    return ActorContext(
        f"authority-{principal}", principal, principal.title(), f"client-{principal}",
        f"membership-{principal}", kind, "team", "Team", f"scope-{principal}",
    )

