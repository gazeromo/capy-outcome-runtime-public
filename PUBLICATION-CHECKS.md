# Publication checks

The snapshot imports no private Git history. The existing public history is preserved.
Private campaign evidence and operational configuration are excluded. Product example
identifiers are generic. The preserved private runtime and its accepted wheels are
unchanged; this source snapshot is separately versioned 0.1.2.

Before publication, run the snapshot byte verifier, the recursive private-data guard,
a redacted Gitleaks scan of the complete candidate, and source/installed tests.
The guard checks nested ZIP fixtures as well as text. Secret-pattern findings from
private history remain in private audit storage, not this repository.

Public historical commits predate this snapshot and may retain previously published
example labels. This snapshot does not claim to erase previously public history.
The existing-public-history Gitleaks scan returned no secret-pattern matches; that is not proof that credentials never existed.
