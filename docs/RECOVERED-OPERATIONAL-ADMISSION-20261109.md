# Recovered operational-admission prototype — 9 November 2026

This branch preserves previously untracked engineering from the 4 November ClawSweeper operational-admission investigation. It is **not** an operational release, a new executor authority, or evidence that the original migration is complete.

The recovered files comprise a read-only workflow inventory, cutover audit, GitHub metadata observer, bounded observation executor, four test modules and the original historical admission notes. The local owner-state JSON, generated Python bytecode, CI caches, operational evidence and credentials are deliberately excluded.

## Validation and limitations

- 14 targeted Python tests passed on the recovered source.
- The inventory and cutover audit were exercised read-only against the current ClawSweeper release candidate `76a20378c8d7efd5e63f26345f8d4c7904f61cc9` on 9 November; the audit reported 88 jobs and **zero** admitted for local operational execution.
- The candidate already contains newer estate work in `scripts/ci/workflow-estate.mjs`, `scripts/ci/estate_policy.py` and `scripts/ci/estate_controller.py`. Those are likely to supersede part of the old discovery prototype.
- The 4 November references to GitHub Actions billing and the original workflow counts are **historical**, not current service status.
- A passing inventory, unit suite or read-only observation is not a production release, protected CI acceptance, migration approval, worker activation or live external-effect verification.

**Disposition:** preserved for exact-source review and selective integration into the already owned ClawSweeper release/estate lane. Do not deploy or schedule this extra executor or merge its whole implementation without confirming there is no duplicate mechanism and obtaining the usual source/security/CI acceptance. The active ClawSweeper engineering owner retains integration responsibility.
