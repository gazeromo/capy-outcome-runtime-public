"""Independent FedEx package parser, request builder, and acceptance oracle."""

from __future__ import annotations

import csv
import hashlib
import io
import json
import urllib.error
import urllib.parse
import urllib.request
from datetime import date
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any, Callable

from .fedex import validate_connection_source
from .model import RuntimeFailure
from .store import canonical_json


PACKAGE_COLUMNS = (
    "package_id", "weight_kg", "length_cm", "width_cm", "height_cm", "quantity"
)
MAX_EXPANDED_PACKAGES = 40
PRODUCTION_ORIGIN = "https://apis.fedex.com"
SANDBOX_ORIGIN = "https://apis-sandbox.fedex.com"


def _decimal(value: object, code: str) -> Decimal:
    try:
        number = Decimal(str(value))
    except (InvalidOperation, ValueError) as exc:
        raise RuntimeFailure(code) from exc
    if not number.is_finite():
        raise RuntimeFailure(code)
    return number


def _json_number(value: Decimal) -> int | float:
    return int(value) if value == value.to_integral() else float(value)


def parse_package_csv(payload: bytes) -> list[dict[str, Any]]:
    """Parse the frozen owner CSV independently from any candidate capability."""

    if not payload or len(payload) > 1024 * 1024 or b"\x00" in payload:
        raise RuntimeFailure("FEDEX_PACKAGE_CSV_INVALID")
    try:
        text = payload.decode("utf-8-sig")
        reader = csv.DictReader(io.StringIO(text, newline=""))
    except UnicodeError as exc:
        raise RuntimeFailure("FEDEX_PACKAGE_CSV_INVALID") from exc
    if tuple(reader.fieldnames or ()) != PACKAGE_COLUMNS:
        raise RuntimeFailure("FEDEX_PACKAGE_CSV_INVALID", "columns")
    packages = []
    identifiers = set()
    expanded = 0
    try:
        rows = list(reader)
    except csv.Error as exc:
        raise RuntimeFailure("FEDEX_PACKAGE_CSV_INVALID") from exc
    if not rows:
        raise RuntimeFailure("FEDEX_PACKAGE_CSV_INVALID", "rows")
    for index, row in enumerate(rows, 2):
        if None in row or any(value is None for value in row.values()):
            raise RuntimeFailure("FEDEX_PACKAGE_CSV_INVALID", f"row:{index}")
        package_id = row["package_id"].strip()
        if not package_id or len(package_id) > 128 or package_id in identifiers:
            raise RuntimeFailure("FEDEX_PACKAGE_CSV_INVALID", f"package_id:{index}")
        identifiers.add(package_id)
        weight = _decimal(row["weight_kg"].strip(), "FEDEX_PACKAGE_WEIGHT_INVALID")
        if weight <= 0:
            raise RuntimeFailure("FEDEX_PACKAGE_WEIGHT_INVALID")
        dimensions = []
        for name in ("length_cm", "width_cm", "height_cm"):
            raw = row[name].strip()
            if not raw.isdigit() or int(raw) <= 0:
                raise RuntimeFailure("FEDEX_PACKAGE_DIMENSION_INVALID", f"{name}:{index}")
            dimensions.append(int(raw))
        quantity = row["quantity"].strip()
        if not quantity.isdigit() or int(quantity) <= 0:
            raise RuntimeFailure("FEDEX_PACKAGE_QUANTITY_INVALID", f"quantity:{index}")
        expanded += int(quantity)
        if expanded > MAX_EXPANDED_PACKAGES:
            raise RuntimeFailure("FEDEX_PACKAGE_COUNT_EXCEEDED")
        packages.append({
            "package_id": package_id,
            "weight_kg": _json_number(weight),
            "length_cm": dimensions[0],
            "width_cm": dimensions[1],
            "height_cm": dimensions[2],
            "quantity": int(quantity),
        })
    return packages


def validate_semantic_input(value: object) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != {
        "destination", "ship_date", "include_list_rates", "return_transit_times"
    }:
        raise RuntimeFailure("FEDEX_SEMANTIC_INPUT_INVALID")
    destination = value.get("destination")
    if not isinstance(destination, dict) or set(destination) != {
        "country_code", "postal_code", "city", "state_or_province", "residential"
    }:
        raise RuntimeFailure("FEDEX_SEMANTIC_INPUT_INVALID", "destination")
    strings = {}
    for field in ("country_code", "postal_code", "city", "state_or_province"):
        item = destination.get(field)
        if not isinstance(item, str) or not item.strip() or any(char in item for char in "\x00\r\n"):
            raise RuntimeFailure("FEDEX_SEMANTIC_INPUT_INVALID", field)
        strings[field] = item.strip()
    strings["country_code"] = strings["country_code"].upper()
    if len(strings["country_code"]) != 2 or not strings["country_code"].isalpha():
        raise RuntimeFailure("FEDEX_SEMANTIC_INPUT_INVALID", "country_code")
    if type(destination.get("residential")) is not bool:
        raise RuntimeFailure("FEDEX_SEMANTIC_INPUT_INVALID", "residential")
    try:
        date.fromisoformat(str(value["ship_date"]))
    except ValueError as exc:
        raise RuntimeFailure("FEDEX_SEMANTIC_INPUT_INVALID", "ship_date") from exc
    if type(value["include_list_rates"]) is not bool or type(value["return_transit_times"]) is not bool:
        raise RuntimeFailure("FEDEX_SEMANTIC_INPUT_INVALID", "flags")
    return {
        "destination": {**strings, "residential": destination["residential"]},
        "ship_date": value["ship_date"],
        "include_list_rates": value["include_list_rates"],
        "return_transit_times": value["return_transit_times"],
    }


def build_rate_request(
    connection: dict[str, Any], semantic_input: dict[str, Any], packages: list[dict[str, Any]]
) -> dict[str, Any]:
    connection = validate_connection_source(connection)
    semantic_input = validate_semantic_input(semantic_input)
    origin = connection["origin"]
    destination = semantic_input["destination"]
    rate_types = ["ACCOUNT"]
    if semantic_input["include_list_rates"]:
        rate_types.append("LIST")
    return {
        "accountNumber": {"value": connection["account_number"]},
        "rateRequestControlParameters": {"returnTransitTimes": semantic_input["return_transit_times"]},
        "requestedShipment": {
            "shipDateStamp": semantic_input["ship_date"],
            "pickupType": "USE_SCHEDULED_PICKUP",
            "rateRequestType": rate_types,
            "packagingType": "YOUR_PACKAGING",
            "shipper": {
                "contact": {
                    "personName": origin["person_name"],
                    "companyName": origin["company_name"],
                    "phoneNumber": origin["phone_number"],
                },
                "address": {
                    "streetLines": origin["address_lines"],
                    "city": origin["city"],
                    "stateOrProvinceCode": origin["state_or_province_code"],
                    "postalCode": origin["postal_code"],
                    "countryCode": origin["country_code"],
                },
            },
            "recipient": {
                "address": {
                    "city": destination["city"],
                    "stateOrProvinceCode": destination["state_or_province"],
                    "postalCode": destination["postal_code"],
                    "countryCode": destination["country_code"],
                    "residential": destination["residential"],
                }
            },
            "requestedPackageLineItems": [
                {
                    "groupPackageCount": package["quantity"],
                    "weight": {"units": "KG", "value": package["weight_kg"]},
                    "dimensions": {
                        "length": package["length_cm"],
                        "width": package["width_cm"],
                        "height": package["height_cm"],
                        "units": "CM",
                    },
                }
                for package in packages
            ],
        },
    }


def _money(value: object) -> dict[str, Any] | None:
    if not isinstance(value, dict):
        return None
    currency = value.get("currency") or value.get("currencyCode")
    amount = value.get("amount")
    if not isinstance(currency, str) or not currency or type(amount) not in {int, float, str}:
        return None
    number = _decimal(amount, "FEDEX_PROVIDER_RESPONSE_INVALID")
    return {"amount": _json_number(number), "currency": currency}


def _rate_kind(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    upper = value.upper()
    if "LIST" in upper:
        return "list"
    if "ACCOUNT" in upper or "PAYOR" in upper or "PREFERRED" in upper:
        return "account"
    return None


def normalize_rate_response(
    response: object,
    *,
    environment: str,
    semantic_input: dict[str, Any],
    packages: list[dict[str, Any]],
) -> dict[str, Any]:
    """Normalize only provider-returned facts; missing optional facts stay absent."""

    if not isinstance(response, dict):
        raise RuntimeFailure("FEDEX_PROVIDER_RESPONSE_INVALID")
    output = response.get("output")
    details = output.get("rateReplyDetails") if isinstance(output, dict) else None
    if not isinstance(details, list) or not details:
        raise RuntimeFailure("FEDEX_NO_RATES_RETURNED")
    semantic_input = validate_semantic_input(semantic_input)
    normalized_rates = []
    for detail in details:
        if not isinstance(detail, dict) or not isinstance(detail.get("serviceType"), str):
            raise RuntimeFailure("FEDEX_PROVIDER_RESPONSE_INVALID")
        rate: dict[str, Any] = {
            "service_type": detail["serviceType"],
            "warnings": [],
            "surcharges": [],
        }
        service_name = detail.get("serviceName")
        if isinstance(service_name, str) and service_name:
            rate["service_name"] = service_name
        rated = detail.get("ratedShipmentDetails")
        if not isinstance(rated, list) or not rated:
            raise RuntimeFailure("FEDEX_PROVIDER_RESPONSE_INVALID")
        surcharge_seen = set()
        for rated_detail in rated:
            if not isinstance(rated_detail, dict):
                raise RuntimeFailure("FEDEX_PROVIDER_RESPONSE_INVALID")
            shipment = rated_detail.get("shipmentRateDetail")
            if not isinstance(shipment, dict):
                continue
            kind = _rate_kind(rated_detail.get("rateType") or shipment.get("rateType"))
            money = _money(shipment.get("totalNetFedExCharge") or shipment.get("totalNetCharge"))
            if kind and money:
                rate[f"{kind}_total"] = money
            surcharges = shipment.get("surCharges", shipment.get("surcharges", []))
            if isinstance(surcharges, list):
                for surcharge in surcharges:
                    if not isinstance(surcharge, dict) or not isinstance(surcharge.get("type"), str):
                        continue
                    charge = _money(surcharge)
                    if charge is None:
                        continue
                    item = {"type": surcharge["type"], **charge}
                    key = json.dumps(item, sort_keys=True)
                    if key not in surcharge_seen:
                        surcharge_seen.add(key)
                        rate["surcharges"].append(item)
        operational = detail.get("operationalDetail")
        if isinstance(operational, dict):
            transit = operational.get("transitTime")
            if isinstance(transit, str) and transit:
                rate["transit_days"] = transit
        commit = detail.get("commit")
        if isinstance(commit, dict):
            date_detail = commit.get("dateDetail")
            if isinstance(date_detail, dict):
                delivery = date_detail.get("dayFormat")
                if isinstance(delivery, str) and delivery:
                    rate["delivery_date"] = delivery
        for notice in detail.get("alerts", []):
            if isinstance(notice, dict):
                message = notice.get("message") or notice.get("code")
                if isinstance(message, str) and message and message not in rate["warnings"]:
                    rate["warnings"].append(message)
        if "account_total" not in rate and "list_total" not in rate:
            raise RuntimeFailure("FEDEX_PROVIDER_RESPONSE_INVALID")
        rate["surcharges"].sort(key=lambda item: (item["type"], item["currency"], item["amount"]))
        normalized_rates.append(rate)
    normalized_rates.sort(key=lambda item: (
        Decimal(str(item.get("account_total", item.get("list_total"))["amount"])),
        item.get("delivery_date", "9999-99-99"),
        item["service_type"],
    ))
    count = sum(package["quantity"] for package in packages)
    total = sum(Decimal(str(package["weight_kg"])) * package["quantity"] for package in packages)
    normalized: dict[str, Any] = {
        "provider": "fedex",
        "environment": environment,
        "ship_date": semantic_input["ship_date"],
        "destination_summary": {
            "country_code": semantic_input["destination"]["country_code"],
            "postal_code": semantic_input["destination"]["postal_code"],
        },
        "package_count": count,
        "total_weight": {"value": _json_number(total), "unit": "KG"},
        "rates": normalized_rates,
        "estimate_only": True,
    }
    transaction = response.get("transactionId")
    if isinstance(transaction, str) and transaction:
        normalized["provider_transaction_id"] = transaction
    return normalized


def compare_quote_results(candidate: object, oracle: object) -> dict[str, Any]:
    """Compare material quote facts while allowing independent transaction IDs."""

    if not isinstance(candidate, dict) or not isinstance(oracle, dict):
        raise RuntimeFailure("FEDEX_ORACLE_MISMATCH")
    ignored = {"provider_transaction_id", "quoted_at", "origin_summary"}
    candidate_material = {key: value for key, value in candidate.items() if key not in ignored}
    oracle_material = {key: value for key, value in oracle.items() if key not in ignored}
    if canonical_json(candidate_material) != canonical_json(oracle_material):
        raise RuntimeFailure("FEDEX_ORACLE_MISMATCH")
    return {
        "schema": "capy.fedex-quote-comparison/v0",
        "result": "matched",
        "material_digest": hashlib.sha256(canonical_json(oracle_material)).hexdigest(),
        "service_count": len(oracle_material.get("rates", [])),
    }


class FedExOracleClient:
    """Makes one OAuth request and one direct rate request, returning sanitized facts only."""

    def __init__(self, opener: Callable[..., Any] = urllib.request.urlopen, timeout_seconds: int = 30):
        self.opener = opener
        self.timeout_seconds = timeout_seconds

    def quote(self, connection_path: Path, package_payload: bytes, semantic_input: dict[str, Any]) -> dict[str, Any]:
        try:
            connection = validate_connection_source(json.loads(connection_path.read_text(encoding="utf-8")))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise RuntimeFailure("FEDEX_CONNECTION_INVALID") from exc
        packages = parse_package_csv(package_payload)
        request = build_rate_request(connection, semantic_input, packages)
        origin = SANDBOX_ORIGIN if connection["environment"] == "sandbox" else PRODUCTION_ORIGIN
        form = {
            "grant_type": "client_credentials",
            "client_id": connection["client_id"],
            "client_secret": connection["client_secret"],
        }
        child = connection.get("child_credentials")
        if isinstance(child, dict):
            form.update({"grant_type": "csp_credentials", **child})
        token_request = urllib.request.Request(
            origin + "/oauth/token",
            data=urllib.parse.urlencode(form).encode(),
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            method="POST",
        )
        try:
            with self.opener(token_request, timeout=self.timeout_seconds) as response:
                token_body = json.loads(response.read(64 * 1024))
            token = token_body.get("access_token") if isinstance(token_body, dict) else None
            if not isinstance(token, str) or not token:
                raise RuntimeFailure("FEDEX_OAUTH_RESPONSE_INVALID")
            rate_request = urllib.request.Request(
                origin + "/rate/v1/rates/quotes",
                data=canonical_json(request),
                headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
                method="POST",
            )
            with self.opener(rate_request, timeout=self.timeout_seconds) as response:
                rate_payload = response.read(2 * 1024 * 1024)
            provider_response = json.loads(rate_payload)
        except RuntimeFailure:
            raise
        except urllib.error.HTTPError as exc:
            raise RuntimeFailure("FEDEX_PROVIDER_HTTP", str(exc.code)) from exc
        except (TimeoutError, urllib.error.URLError) as exc:
            raise RuntimeFailure("FEDEX_PROVIDER_TIMEOUT") from exc
        except (UnicodeError, json.JSONDecodeError) as exc:
            raise RuntimeFailure("FEDEX_PROVIDER_RESPONSE_INVALID") from exc
        finally:
            token = ""
        return normalize_rate_response(
            provider_response,
            environment=str(connection["environment"]),
            semantic_input=semantic_input,
            packages=packages,
        )
