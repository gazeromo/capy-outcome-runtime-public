"""Operator-only publisher connection installation and broker service entrypoint."""

from __future__ import annotations

import argparse
import json
import os
import signal
import sys
import threading
from pathlib import Path

from .connections import (
    ConnectionBroker,
    ConnectionControl,
    ConnectionInstance,
    LocalSecretResolver,
)
from .store import RuntimeStore


def private_json(path: Path) -> dict:
    metadata = path.lstat()
    if (
        path.is_symlink() or not path.is_file() or metadata.st_mode & 0o077
        or metadata.st_uid != 0
    ):
        raise SystemExit("private profile is invalid")
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise SystemExit("private profile is invalid")
    return value


class ManagedOriginProfiles:
    """One operator-bound origin, refreshed without granting request-chosen paths.

    Absence is first-time setup; invalid existing files remain failures. Re-read
    on each authorized call so an atomic origin install needs no broker restart.
    """
    def __init__(self, reference, path, validator):
        self.reference, self.path, self.validator = reference, path, validator

    def get(self, reference, default=None):
        if reference != self.reference:
            return default
        try:
            value = private_json(self.path)
        except FileNotFoundError:
            return default
        except (OSError, ValueError, SystemExit):
            # Do not let private profile diagnostics escape broker handling.
            from .model import RuntimeFailure
            raise RuntimeFailure('CONNECTION_UNAVAILABLE') from None
        return self.validator(value)


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(prog="capy-connection")
    commands = result.add_subparsers(dest="command", required=True)
    install = commands.add_parser("install-secret")
    install.add_argument("reference")
    install.add_argument("--secret-root", required=True, type=Path)
    configure = commands.add_parser("configure-fedex-rates")
    configure.add_argument("--runtime-root", required=True, type=Path)
    configure.add_argument("--scope", action="append", default=["owner"])
    configure.add_argument("--profile-reference", default="profile:example-korea")
    configure.add_argument("--environment", choices=("production", "sandbox"), required=True)
    broker = commands.add_parser("serve")
    broker.add_argument("--runtime-root", required=True, type=Path)
    broker.add_argument("--secret-root", required=True, type=Path)
    broker.add_argument("--profile-file", required=True, type=Path)
    broker.add_argument("--profile-reference", default="profile:example-korea")
    broker.add_argument("--socket", required=True, type=Path)
    broker.add_argument("--connections-source", required=True, type=Path)
    broker.add_argument("--account-service-socket", type=Path)
    broker.add_argument("--account-service-uid", type=int)
    return result


def main() -> int:
    args = parser().parse_args()
    if args.command == "install-secret":
        receipt = LocalSecretResolver(args.secret_root).install(args.reference, sys.stdin.buffer)
        print(json.dumps(receipt, sort_keys=True))
        return 0
    store = RuntimeStore(args.runtime_root)
    control = ConnectionControl(store)
    if args.command == "configure-fedex-rates":
        instance = ConnectionInstance(
            "example-fedex-rates", "fedex.rates/v1", "fedex-rates-adapter/v1",
            "publisher", "example", "active",
            {"label": "Example publisher FedEx rates", "environment": args.environment},
            "secret:example-fedex-production", args.profile_reference,
        )
        control.put_instance(instance)
        for scope in dict.fromkeys(args.scope):
            store.register_scope(scope)
            control.grant(
                f"{scope}-example-fedex-quote", instance.id, scope, instance.contract, ["quote"],
                capability_id="shipping.fedex_quote",
            )
        print(json.dumps({"connection_id": instance.id, "scopes": list(dict.fromkeys(args.scope))}, sort_keys=True))
        return 0
    sys.path.insert(0, str(args.connections_source / "src"))
    from capy_connections.fedex_rates import (
        ADAPTER_VERSION,
        FedExRatesAdapter,
        UrlLibTransport,
        validate_profile,
    )

    if ADAPTER_VERSION != "fedex-rates-adapter/v1":
        raise SystemExit("accepted adapter version is unavailable")

    resolver = LocalSecretResolver(args.secret_root)
    profiles = ManagedOriginProfiles(args.profile_reference, args.profile_file, validate_profile)
    # Missing setup must not prevent the service from accepting safe requests.
    # An existing invalid profile still fails readiness/startup closed.
    profiles.get(args.profile_reference)
    executor = None
    account_socket = getattr(args, 'account_service_socket', None)
    account_uid = getattr(args, 'account_service_uid', None)
    if account_socket is not None or account_uid is not None:
        if account_socket is None or type(account_uid) is not int or account_uid <= 0:
            raise SystemExit('account service configuration invalid')
        from .account_ipc import Client
        client = Client(account_socket, account_uid)
        def executor(grant, invocation_id, payload):
            return client.call('quote', authority={
                'grant_id':grant['id'], 'scope_id':grant['scope_id'],
                'capability_id':grant['capability_id'], 'version_digest':grant['version_digest'],
                'connection_id':grant['connection_id'], 'invocation_id':invocation_id}, payload=payload)
    broker = ConnectionBroker(
        control,
        resolver,
        profiles,
        {"fedex-rates-adapter/v1": FedExRatesAdapter(UrlLibTransport())},
        managed_executor=executor,
    )
    stop = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: stop.set())
    signal.signal(signal.SIGINT, lambda *_: stop.set())
    broker.serve(args.socket, stop)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
