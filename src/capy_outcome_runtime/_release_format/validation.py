"""Small strict validators shared by candidate/profile/release."""
from __future__ import annotations

import datetime
import re

from . import codec

_ID_APP_RE = re.compile(r"[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*)+\Z")
_ID_APP_MAX = 128
_PROFILE_ID_RE = re.compile(r"[a-z][a-z0-9._/-]{0,127}\Z")
_CASE_ID_RE = re.compile(r"[a-z][a-z0-9_-]{0,63}\Z")
_FAILURE_RE = re.compile(r"[A-Z][A-Z0-9_]{0,95}\Z")
_PRJ_RE = re.compile(r"prj_[0-9a-f]{32}\Z")
_VER_RE = re.compile(r"ver_[0-9a-f]{32}\Z")
_SES_RE = re.compile(r"ses_[0-9a-f]{32}\Z")
_RC_RE = re.compile(r"rc_[0-9a-f]{32}\Z")
_DOTTED_RE = re.compile(r"[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+\Z")
_SEGMENT_RE = re.compile(r"[a-z][a-z0-9_]*\Z")


def is_bool_strict(v) -> bool:
    return type(v) is bool


def is_int_strict(v) -> bool:
    return type(v) is int


def require_closed(obj: dict, allowed: set[str], what: str):
    if not isinstance(obj, dict):
        raise ValueError(f"{what}: not-object")
    keys = set(obj.keys())
    if keys != allowed:
        raise ValueError(f"{what}: keys {sorted(keys)} != {sorted(allowed)}")


def check_application_id(value, what: str = "application_id"):
    if not isinstance(value, str) or len(value) > _ID_APP_MAX:
        raise ValueError(f"{what}: length")
    if _ID_APP_RE.fullmatch(value) is None:
        raise ValueError(f"{what}: grammar")


def check_profile_id(value):
    if not isinstance(value, str):
        raise ValueError("profile_id: type")
    if _PROFILE_ID_RE.fullmatch(value) is None:
        raise ValueError("profile_id: grammar")
    # No empty/dot/parent segment.
    for seg in value.split("/"):
        if seg in ("", ".", ".."):
            raise ValueError("profile_id: segment")
        if seg.startswith(".") or seg.endswith("."):
            pass  # allowed? spec only forbids empty/dot/parent segment.
    if "." in value:
        # segments split by / then .? Parent check already. Keep simple.
        pass


def check_case_id(value):
    if not isinstance(value, str):
        raise ValueError("case_id: type")
    # ASCII check.
    try:
        value.encode("ascii")
    except UnicodeEncodeError as e:
        raise ValueError("case_id: ascii") from e
    if _CASE_ID_RE.fullmatch(value) is None:
        raise ValueError("case_id: grammar")


def check_failure_code(value):
    if not isinstance(value, str):
        raise ValueError("failure_code: type")
    if _FAILURE_RE.fullmatch(value) is None:
        raise ValueError("failure_code: grammar")


def check_prj(value):
    if not isinstance(value, str) or _PRJ_RE.fullmatch(value) is None:
        raise ValueError("project_id")


def check_ver(value):
    if not isinstance(value, str) or _VER_RE.fullmatch(value) is None:
        raise ValueError("verification_id")


def check_ses(value):
    if not isinstance(value, str) or _SES_RE.fullmatch(value) is None:
        raise ValueError("session_id")


def check_rc(value):
    if not isinstance(value, str) or _RC_RE.fullmatch(value) is None:
        raise ValueError("release_candidate_id")


def check_dotted(value, what: str = "operation_id"):
    if not isinstance(value, str) or not value:
        raise ValueError(f"{what}: empty")
    if _DOTTED_RE.fullmatch(value) is None:
        raise ValueError(f"{what}: grammar")


def check_path_dotted(value, what: str = "path"):
    if not isinstance(value, str) or not value or len(value) > 256:
        raise ValueError(f"{what}: length")
    for seg in value.split("."):
        if _SEGMENT_RE.fullmatch(seg) is None:
            raise ValueError(f"{what}: segment")


def check_verified_at(value):
    if not isinstance(value, str):
        raise ValueError("verified_at: type")
    # Valid UTC ISO8601 with Z, e.g. 2026-09-05T03:52:37.529510Z
    if not value.endswith("Z"):
        raise ValueError("verified_at: zone")
    core = value[:-1]
    # Try fromisoformat after replacing Z.
    try:
        # Allow fractional seconds.
        if "." in core:
            dt = datetime.datetime.strptime(core, "%Y-%m-%dT%H:%M:%S.%f")
        else:
            dt = datetime.datetime.strptime(core, "%Y-%m-%dT%H:%M:%S")
    except ValueError as e:
        raise ValueError("verified_at: format") from e
    # Must be valid calendar date (strptime already checks).
    if dt.year < 1970 or dt.year > 2100:
        raise ValueError("verified_at: range")


def check_hex40(value, what: str):
    if not isinstance(value, str) or not codec.is_hex40(value):
        raise ValueError(f"{what}: hex40")


def check_hex64(value, what: str):
    if not isinstance(value, str) or not codec.is_hex64(value):
        raise ValueError(f"{what}: hex64")


def check_safe_basename(value, what: str = "filename"):
    if not codec.is_safe_basename(value):
        raise ValueError(f"{what}: unsafe {value!r}")


def check_text_plain(value, what: str, max_len: int, allow_empty: bool = False):
    if not isinstance(value, str):
        raise ValueError(f"{what}: type")
    if not allow_empty and not value:
        raise ValueError(f"{what}: empty")
    if len(value) > max_len:
        raise ValueError(f"{what}: too-long")
    # Invalid UTF-8 already decoded; check surrogates, NUL, untrimmed?
    # For profile interaction expectations, spec says nonempty strings.
    # We enforce no NUL and no lone surrogates.
    if "\x00" in value:
        raise ValueError(f"{what}: nul")
    for ch in value:
        o = ord(ch)
        if 0xD800 <= o <= 0xDFFF:
            raise ValueError(f"{what}: surrogate")
