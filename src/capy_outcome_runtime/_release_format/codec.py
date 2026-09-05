"""Canonical JSON and ZIP discipline, safe names, digests."""
from __future__ import annotations

import hashlib
import io
import json
import re
import zipfile

from .constants import WINDOWS_RESERVED
from .errors import AcceptorError

_BASENAME_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")
_HEX64_RE = re.compile(r"[0-9a-f]{64}\Z")
_HEX40_RE = re.compile(r"[0-9a-f]{40}\Z")


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical_bytes(value) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode("utf-8")


class _DupKey(Exception):
    pass


def _object_hook(pairs):
    obj = {}
    for k, v in pairs:
        if k in obj:
            raise _DupKey(k)
        obj[k] = v
    return obj


def _constant(_s):
    raise ValueError("non-finite")


def parse_strict_json(data: bytes):
    """Parse UTF-8 JSON strictly; raise ValueError on any discipline violation."""
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as e:
        raise ValueError("invalid-unicode") from e
    # Reject lone surrogates that decode via surrogates? utf-8 strict already fails.
    # json with strict duplicate detection and no NaN/Infinity.
    try:
        value = json.loads(text, object_pairs_hook=_object_hook, parse_constant=_constant)
    except _DupKey as e:
        raise ValueError("duplicate-key") from e
    except (json.JSONDecodeError, ValueError) as e:
        raise ValueError("json-invalid") from e
    # Encoding also rejects overflow-produced infinity and escaped lone
    # surrogates, which json.loads accepts even with parse_constant.
    try:
        canonical_bytes(value)
    except (ValueError, UnicodeError, TypeError) as exc:
        raise ValueError("json-unencodable") from exc
    # Depth check.
    if _depth(value) > 32:
        raise ValueError("depth")
    return value


def _depth(value, cur: int = 0) -> int:
    if isinstance(value, dict):
        if not value:
            return cur
        return max(_depth(v, cur + 1) for v in value.values())
    if isinstance(value, list):
        if not value:
            return cur
        return max(_depth(v, cur + 1) for v in value)
    return cur


def check_canonical_json_bytes(data: bytes, *, what: str = "json"):
    """Validate canonical discipline and return parsed value.

    Canonical means: UTF-8, sorted keys, compact separators, ensure_ascii=False,
    allow_nan=False, no trailing newline. Raises ValueError if not canonical.
    """
    if data.endswith(b"\n"):
        raise ValueError(f"{what}: trailing newline")
    if not data:
        raise ValueError(f"{what}: empty")
    value = parse_strict_json(data)
    try:
        rebuilt = canonical_bytes(value)
    except (TypeError, ValueError) as e:
        raise ValueError(f"{what}: not-encodable") from e
    if rebuilt != data:
        raise ValueError(f"{what}: not-canonical")
    return value


def is_hex64(s) -> bool:
    return isinstance(s, str) and _HEX64_RE.fullmatch(s) is not None


def is_hex40(s) -> bool:
    return isinstance(s, str) and _HEX40_RE.fullmatch(s) is not None


def is_safe_basename(name) -> bool:
    if not isinstance(name, str):
        return False
    if _BASENAME_RE.fullmatch(name) is None:
        return False
    if name in (".", ".."):
        return False
    if name.endswith("."):
        return False
    if ":" in name or "/" in name or "\\" in name:
        return False
    lowered = name.lower()
    # Strip extension for reserved check.
    base = lowered.split(".")[0]
    if base in WINDOWS_RESERVED:
        return False
    # Alias under case folding is handled by caller via collision map;
    # here just reject names that differ only by case-insensitive reserved?
    # Also reject names that are case-fold aliases of dot/parent (already).
    return True


def check_zip_canonical_members(data: bytes, expected_order: list[str]):
    """Validate outer canonical ZIP discipline for exact member order.

    Returns dict name->bytes. Raises AcceptorError-style ValueError on violation.
    Checks: ZIP_STORED, create_system 3, mode 0100644, date 1980-01-01,
    no extras/comments/encryption/directories/symlinks, no file comments,
    no archive comment, exact order, no trailing data (via rebuild comparison).
    """
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as z:
            if z.comment != b"":
                raise ValueError("zip-comment")
            names = z.namelist()
            if names != expected_order:
                raise ValueError("zip-order")
            infos = z.infolist()
            members: dict[str, bytes] = {}
            for info in infos:
                # Directories forbidden.
                if info.is_dir():
                    raise ValueError("zip-directory")
                if info.filename.endswith("/"):
                    raise ValueError("zip-directory")
                if info.compress_type != zipfile.ZIP_STORED:
                    raise ValueError("zip-compress")
                if info.create_system != 3:
                    raise ValueError("zip-system")
                if (info.external_attr >> 16) != 0o100644:
                    raise ValueError("zip-mode")
                if info.date_time != (1980, 1, 1, 0, 0, 0):
                    raise ValueError("zip-date")
                if info.extra != b"":
                    raise ValueError("zip-extra")
                if info.comment != b"":
                    raise ValueError("zip-entry-comment")
                # Encryption flag (bit 0).
                if info.flag_bits & 0x1:
                    raise ValueError("zip-encrypted")
                # UTF-8 flag is allowed (0x800)? Python sets it for non-ascii;
                # but our names are ascii so flag should be 0. Allow either.
                # Symlink check: unix file type bits.
                members[info.filename] = z.read(info.filename)
    except zipfile.BadZipFile as e:
        raise ValueError("zip-bad") from e
    # Rebuild and compare bytes exactly (detects trailing data and metadata).
    rebuilt = build_canonical_zip(members, expected_order)
    if rebuilt != data:
        raise ValueError("zip-bytes")
    return members


def build_canonical_zip(members: dict[str, bytes], order: list[str]) -> bytes:
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w") as z:
        for name in order:
            item = zipfile.ZipInfo(name, (1980, 1, 1, 0, 0, 0))
            item.create_system = 3
            item.external_attr = 0o100644 << 16
            item.compress_type = zipfile.ZIP_STORED
            z.writestr(item, members[name])
    return output.getvalue()


def check_inner_name_safe(name: str):
    """Validate inner application/bundle member name safety."""
    if not isinstance(name, str) or not name:
        raise ValueError("name-empty")
    if name.endswith("/"):
        raise ValueError("directory")
    if "\\" in name:
        raise ValueError("backslash")
    if name.startswith("/") or name.startswith("\\"):
        raise ValueError("absolute")
    parts = name.split("/")
    for part in parts:
        if part in ("", ".", ".."):
            raise ValueError("traversal")
        if not is_safe_basename_inner_part(part):
            # Inner parts allow same basename rules except we check each part.
            # For files like CAPY.md etc, they pass; for nested like
            # conformance/basic.json each part must be safe.
            raise ValueError("unsafe-part")
    # Windows alias under case folding handled by caller.
    return True


def is_safe_basename_inner_part(part: str) -> bool:
    # Parts may include extensions; reuse basename logic but allow same set.
    # Inner files are like 'capability.toml', 'conformance', etc.
    # Directories like 'conformance' must also be safe.
    if re.fullmatch(r"[A-Za-z0-9._-]{1,128}", part) is None or part.casefold() in {".git", ".hg", ".svn"}:
        # Allow lowercase dir names? They match anyway. Return False otherwise.
        return False
    if part.endswith("."):
        return False
    lowered = part.lower()
    base = lowered.split(".")[0]
    if base in WINDOWS_RESERVED:
        return False
    return True


def check_casefold_collisions(names: list[str]):
    """Reject ambiguous file trees before extraction, on every host.

    Member names have already passed check_inner_name_safe. Each implicit
    directory is part of the namespace too: Alias/x and alias/y must not merge
    on a case-insensitive filesystem, and a file cannot also be a directory.
    Reusing exactly the same directory spelling for siblings is valid.
    """
    prefixes: dict[str, tuple[str, bool]] = {}
    for name in names:
        parts = name.split("/")
        for length in range(1, len(parts) + 1):
            prefix = "/".join(parts[:length])
            is_file = length == len(parts)
            key = prefix.casefold()
            previous = prefixes.get(key)
            if previous is not None:
                spelling, was_file = previous
                if spelling != prefix or was_file != is_file or is_file:
                    raise ValueError("casefold-collision")
            else:
                prefixes[key] = (prefix, is_file)
