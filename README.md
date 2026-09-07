# Capy Outcome Runtime — public source snapshot

This repository publishes an audited runtime source snapshot and self-contained,
provider-free tests with fresh Git history. It is a supporting publication and CI
surface. It does not transfer production authority or publish private project
history, operational records, customer data, conversations, or credentials.

`SNAPSHOT.json` pins the source commit and SHA-256 of every exported file. All73
runtime Python/data files are unchanged from source snapshot
`573b2055ecb79892edc0650469e82c16e2b6747f`. The only test adaptation extracts an
identical synthetic actor helper into a local module, removing a dependency on
unrelated campaign tests. No runtime code was changed for publication.

The runtime includes independently approved accepted-release import, separate
workspace binding, typed portable interaction projection and the existing
application/runtime interfaces. Import does not execute the candidate or grant
workspace use. Bundled A/B/C handoffs are synthetic total/mean/report fixtures;
only the original B/C handoffs are accepted positives. Tests do not create a new
business application acceptance or call a live model/business provider.

## Verification

Use Python3.13 or newer for runtime/interface tests:

```sh
python -m pip install pytest==8.4.2
python tools/verify_snapshot.py
PYTHONPATH=src:tests python -m pytest -q tests
```

The CI matrix separately tests pure format/projection on Ubuntu, macOS and Windows
with Python3.11. Native application execution on macOS or Windows is not claimed.
Bootstrap and linked-client authority tests also run on all three platforms with Python3.11. The Ubuntu focused integration job uses Python3.13. It does not substitute for
separately recorded real Linux systemd product qualification, and is not the full
private legacy regression suite.

The workflow uses standard GitHub-hosted runners, a read-only repository token,
no repository secrets and no private-repository checkout. Publishing this snapshot
does not deploy a service or merge the source into another repository.

## Publication audit

See `PUBLICATION-AUDIT.json`. Before the first push, the selected source/tests were
reviewed for personal, transaction and operational data; nested fixture archives
were inspected as inert bytes; and Gitleaks scanned the export with archive and
recursive decoding enabled. No secrets were detected. No scan proves that all
possible sensitive information is absent. Private historical campaign material
and its Git objects were never copied into this repository.

This publication introduces no new software license grant. Existing provenance
for the vendored format helpers remains in
`src/capy_outcome_runtime/_release_format/PROVENANCE.json`.
