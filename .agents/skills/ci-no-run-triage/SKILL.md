---
name: ci-no-run-triage
description: Inspect automatic pre-model GitHub CI failure triage using the canonical notifier and its private receipts. Do not reimplement the classifier or use a model to decide a job's explicit no-run metadata.
---

# Automatic CI triage

Canonical implementation: `src/repair/ci-triage.ts`, invoked automatically by `runGithubActivityNotifier` before the existing OpenClaw hook. Read `docs/engineering/automatic-ci-triage.md` for activation, runtime identity, durable state and rollback.

For an authorised clean build, use `node dist/repair/observe-ci-triage.js --help` and the documented bounded observer. It discovers actual GitHub activity through authenticated GET calls and feeds the same notifier; do not manufacture failed jobs or manually label historical catch-up as natural operation.

A deterministic result proves only that the bound failed-run jobs executed no steps. It does not authorise retries, CI dispatch, status publication, merge, deployment or spending. Ambiguous evidence must retain the existing investigation path. Preserve the ledger on interruption or rollback; never retry an uncertain agent handoff blindly.

This skill is a thin interface to the canonical repository code, not a second classifier or an automatic production deployment.
