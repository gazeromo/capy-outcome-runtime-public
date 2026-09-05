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
