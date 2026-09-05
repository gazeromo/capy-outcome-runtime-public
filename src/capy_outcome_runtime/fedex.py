"""Trusted, scope-bound FedEx connection custody for Milestone 4."""

from __future__ import annotations

import json
import os
import re
import tempfile
from pathlib import Path
from typing import Mapping

from .model import RuntimeFailure


CONNECTION_SCHEMA = "capy.connection.fedex/v0"
DEFAULT_BINDING = "fedex-owner"
SAFE_ID = re.compile(r"[a-z0-9][a-z0-9_-]{0,63}")
COUNTRY_CODE = re.compile(r"[A-Z]{2}")
REQUIRED_FIELDS = {
    "environment",
    "client_id",
    "client_secret",
    "account_number",
    "origin_company_name",
    "origin_person_name",
    "origin_phone_number",
    "origin_address_line1",
    "origin_city",
    "origin_state_or_province_code",
    "origin_postal_code",
    "origin_country_code",
}
OPTIONAL_FIELDS = {"child_key", "child_secret", "origin_address_line2"}


def _text(value: object, field: str, *, maximum: int = 256) -> str:
    if not isinstance(value, str):
        raise RuntimeFailure("FEDEX_CONNECTION_INVALID", field)
    normalized = value.strip()
    if not normalized or len(normalized) > maximum or any(char in normalized for char in "\x00\r\n"):
        raise RuntimeFailure("FEDEX_CONNECTION_INVALID", field)
    return normalized


def normalize_connection(values: Mapping[str, object]) -> dict[str, object]:
    """Validate the exact trusted form fields and return the strict source schema."""

    if set(values) - REQUIRED_FIELDS - OPTIONAL_FIELDS or not REQUIRED_FIELDS <= set(values):
        raise RuntimeFailure("FEDEX_CONNECTION_INVALID", "fields")
    environment = _text(values["environment"], "environment", maximum=16)
    if environment not in {"sandbox", "production"}:
        raise RuntimeFailure("FEDEX_CONNECTION_INVALID", "environment")
    child_key = str(values.get("child_key", "")).strip()
    child_secret = str(values.get("child_secret", "")).strip()
    if bool(child_key) != bool(child_secret):
        raise RuntimeFailure("FEDEX_CONNECTION_INVALID", "child_credentials")
    address_lines = [_text(values["origin_address_line1"], "origin_address_line1")]
    second = str(values.get("origin_address_line2", "")).strip()
    if second:
        address_lines.append(_text(second, "origin_address_line2"))
    country = _text(values["origin_country_code"], "origin_country_code", maximum=2).upper()
    if not COUNTRY_CODE.fullmatch(country):
        raise RuntimeFailure("FEDEX_CONNECTION_INVALID", "origin_country_code")
    source: dict[str, object] = {
        "schema": CONNECTION_SCHEMA,
        "environment": environment,
        "client_id": _text(values["client_id"], "client_id"),
        "client_secret": _text(values["client_secret"], "client_secret"),
        "account_number": _text(values["account_number"], "account_number", maximum=64),
        "origin": {
            "company_name": _text(values["origin_company_name"], "origin_company_name"),
            "person_name": _text(values["origin_person_name"], "origin_person_name"),
            "phone_number": _text(values["origin_phone_number"], "origin_phone_number", maximum=64),
            "address_lines": address_lines,
            "city": _text(values["origin_city"], "origin_city", maximum=128),
            "state_or_province_code": _text(
                values["origin_state_or_province_code"], "origin_state_or_province_code", maximum=32
            ),
            "postal_code": _text(values["origin_postal_code"], "origin_postal_code", maximum=32),
            "country_code": country,
        },
    }
    if child_key:
        source["child_credentials"] = {
            "child_key": _text(child_key, "child_key"),
            "child_secret": _text(child_secret, "child_secret"),
        }
    return source


def validate_connection_source(value: object) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) not in (
        {"schema", "environment", "client_id", "client_secret", "account_number", "origin"},
        {"schema", "environment", "client_id", "client_secret", "account_number", "origin", "child_credentials"},
    ):
        raise RuntimeFailure("FEDEX_CONNECTION_INVALID", "source")
    origin = value.get("origin")
    if not isinstance(origin, dict) or set(origin) != {
        "company_name", "person_name", "phone_number", "address_lines", "city",
        "state_or_province_code", "postal_code", "country_code",
    }:
        raise RuntimeFailure("FEDEX_CONNECTION_INVALID", "origin")
    address_lines = origin.get("address_lines")
    if not isinstance(address_lines, list) or not 1 <= len(address_lines) <= 2:
        raise RuntimeFailure("FEDEX_CONNECTION_INVALID", "origin.address_lines")
    form: dict[str, object] = {
        "environment": value.get("environment"),
        "client_id": value.get("client_id"),
        "client_secret": value.get("client_secret"),
        "account_number": value.get("account_number"),
        "origin_company_name": origin.get("company_name"),
        "origin_person_name": origin.get("person_name"),
        "origin_phone_number": origin.get("phone_number"),
        "origin_address_line1": address_lines[0],
        "origin_address_line2": address_lines[1] if len(address_lines) == 2 else "",
        "origin_city": origin.get("city"),
        "origin_state_or_province_code": origin.get("state_or_province_code"),
        "origin_postal_code": origin.get("postal_code"),
        "origin_country_code": origin.get("country_code"),
    }
    child = value.get("child_credentials")
    if child is not None:
        if not isinstance(child, dict) or set(child) != {"child_key", "child_secret"}:
            raise RuntimeFailure("FEDEX_CONNECTION_INVALID", "child_credentials")
        form.update(child)
    normalized = normalize_connection(form)
    if value.get("schema") != CONNECTION_SCHEMA or normalized != value:
        raise RuntimeFailure("FEDEX_CONNECTION_INVALID", "source")
    return normalized


class FedExConnectionStore:
    """Stores one opaque FedEx credential source per authorized scope."""

    def __init__(self, root: Path):
        self.root = root
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.root.chmod(0o700)

    def _path(self, scope_id: str, binding: str = DEFAULT_BINDING) -> Path:
        if not SAFE_ID.fullmatch(scope_id) or not SAFE_ID.fullmatch(binding):
            raise RuntimeFailure("CONNECTION_BINDING_INVALID")
        return self.root / f"{scope_id}--{binding}.json"

    def stage(self, scope_id: str, values: Mapping[str, object], binding: str = DEFAULT_BINDING) -> dict[str, object]:
        source = normalize_connection(values)
        destination = self._path(scope_id, binding)
        payload = json.dumps(source, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
        descriptor, temporary_name = tempfile.mkstemp(prefix=".fedex-", dir=self.root)
        temporary = Path(temporary_name)
        try:
            os.fchmod(descriptor, 0o600)
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, destination)
            destination.chmod(0o600)
        finally:
            temporary.unlink(missing_ok=True)
        return self.inspect(scope_id, binding)

    def _read(self, scope_id: str, binding: str = DEFAULT_BINDING) -> dict[str, object]:
        path = self._path(scope_id, binding)
        metadata = path.lstat()
        if path.is_symlink() or not path.is_file() or metadata.st_mode & 0o077:
            raise RuntimeFailure("FEDEX_CONNECTION_INVALID", "custody")
        try:
            return validate_connection_source(json.loads(path.read_text(encoding="utf-8")))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise RuntimeFailure("FEDEX_CONNECTION_INVALID", "source") from exc

    def resolve(self, scope_id: str, binding: str) -> Path:
        self._read(scope_id, binding)
        return self._path(scope_id, binding)

    def status(self, scope_id: str, binding: str = DEFAULT_BINDING) -> str:
        path = self._path(scope_id, binding)
        if not path.exists():
            return "unavailable"
        try:
            self._read(scope_id, binding)
        except RuntimeFailure:
            return "unhealthy"
        return "configured"

    def inspect(self, scope_id: str, binding: str = DEFAULT_BINDING) -> dict[str, object]:
        status = self.status(scope_id, binding)
        fact: dict[str, object] = {
            "name": "fedex",
            "status": status,
            "default_origin_profile_available": status == "configured",
        }
        if status == "configured":
            source = self._read(scope_id, binding)
            fact["environment"] = source["environment"]
            account = str(source["account_number"])
            fact["account_suffix"] = account[-4:].rjust(4, "•")
            fact["origin_country_code"] = source["origin"]["country_code"]  # type: ignore[index]
        return fact

    def inventory(self, scope_id: str) -> list[dict[str, object]]:
        return [self.inspect(scope_id)]
