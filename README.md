# Capy Outcome Runtime

A source snapshot of Capy's execution runtime and consumer adapter. The runtime keeps invocation authority, results and artifact membership on the server. The consumer exposes the full authorized native tool catalog, queries bounded discovery context and verifies complete local artifact delivery.

## Development

Requires Python 3.11 or newer. Install into a virtual environment:

```sh
python -m pip install -e '.[account-service]' pytest
python tools/verify_snapshot.py
python tools/check_publication.py
PYTHONPATH=src:tests python -m pytest -q tests
```

The full self-contained test selection runs on Linux and macOS. Windows CI runs pure discovery, artifact decoding/projection and format tests against both source and an installed wheel. Native Core execution, credential handling and local artifact materialization currently require POSIX facilities; Windows results do not qualify those paths.

## Discovery and delivery

`/v0/discover` retains the complete authorized catalog for native tool declarations. `/v0/context` accepts a query or continuation cursor and returns bounded deterministic metadata guidance, with current authority checks on each page. Full native declarations retain their initial token cost.

When an output directory is configured, the consumer retrieves every artifact listed by the exact execution, verifies its digest and size, and returns an ordered delivery manifest. `capy_result(id)` retries local delivery without rerunning the application. Without an output directory the result explicitly reports remote-only delivery.

Customer-specific example identifiers have been replaced with generic examples. Configure your own grants, connection profiles and secret references; these example defaults do not select a production account.

## Snapshot scope

This repository has no production authority. It contains source, self-contained synthetic tests, and previously public synthetic format fixtures. Private Git ancestry, deployment configuration, campaign evidence, model transcripts, account data and live credentials are excluded. `SNAPSHOT.json` records every published file hash and the limited source transformations. Do not copy private runtime state into this repository.

Public CI is qualification of this snapshot, not a deployment, acceptance of a private wheel, or an owner-use claim.

## License

Apache License 2.0. See LICENSE and NOTICE.
