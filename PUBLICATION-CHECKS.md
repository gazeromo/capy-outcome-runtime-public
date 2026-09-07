# Initial publication checks

The first public run33979250224 executed standard hosted runners successfully;
there was no billing admission block. Ubuntu/macOS pure controls and Ubuntu
focused integration passed. Windows stopped at the byte-provenance check for
pyproject.toml before tests: default checkout newline conversion changed bytes.
The repository now disables text conversion in .gitattributes so every platform
checks out the exact audited source/fixture bytes. No runtime or frozen test
expectation changed. The original failed run remains visible in Actions.

Source provenance is verified by tools/verify_snapshot.py. The original public
root commit15f26d63c12a8a6074e87315d160d29c11d65fbb has no parents; it contains no
inherited private Git history. Later commits contain only public publication
configuration/evidence. Private history and runtime authority remain elsewhere.

## Harness-first source update

Snapshot source39cdbc65 contains73 byte-identical runtime files. Selected exported tests pass89 cases locally (Python3.12.9); one expected duplicate-member warning belongs to an adversarial archive test. Gitleaks directory scan with archive depth8, decoding depth5 and allow-comments disabled reports zero findings. No upstream history or new campaign content was imported. Hosted pure/harness-core checks now target all three operating systems; integration remains Ubuntu. Hosted outcomes are recorded in Actions, not inferred from local tests.

First current-source public run34084270114 found a Windows collection failure: web.py imported Unix pwd at module load. Authoritative source follow-up moves pwd into linux_identity; portable web import also passes with Unix account imports denied, and40 focused tests pass locally. Snapshot refreshed from that exact commit; no public-only runtime patch. Earlier failed run retained.

Run34084436608 passed six jobs; Windows harness-core rejected writable fixture modes. Authoritative test-only repair publishes fixture bytes read-only and restores owner write only for deliberate mutations. Production artifact safety checks remain unchanged;9 bootstrap tests pass locally. Refresh uses the exact authoritative test bytes.
