---
repo: AyobamiH/clawsweeper
cluster_id: workers-ai-repair-acceptance-68
mode: autonomous
job_intent: implement_issue
allowed_actions:
  - comment
  - fix
  - raise_pr
blocked_actions:
  - merge
  - close
require_human_for:
  - merge
canonical:
  - #68
candidates:
  - #68
cluster_refs:
  - #68
allow_instant_close: false
allow_fix_pr: true
allow_merge: false
allow_unmerged_fix_close: false
allow_post_merge_close: false
require_fix_before_close: false
security_policy: central_security_only
security_sensitive: false
target_branch: clawsweeper/workers-ai-repair-acceptance-68
source: issue_implementation
---

# Workers AI repair-lane acceptance

Implement the controlled acceptance request from issue #68.

## Operator Prompt

Create exactly one new file at `test/fixtures/workers-ai-repair-acceptance.txt`.

Its entire contents must be exactly:

`CLAWSWEEPER_WORKERS_AI_REPAIR_OK`

followed by one newline.

Do not modify production code. Do not merge. Do not deploy. Do not close issue #68.

Run the narrowest validation that proves:
1. the file exists;
2. it contains exactly the required line plus one newline;
3. `git diff --check` passes.

If the requested file already exists with the exact required content, report that fact and do not create unrelated changes.

## Related Refs

- #68

## Likely Files

- test/fixtures/workers-ai-repair-acceptance.txt

## Validation

- `test "$(cat test/fixtures/workers-ai-repair-acceptance.txt)" = "CLAWSWEEPER_WORKERS_AI_REPAIR_OK"`
- `test "$(wc -l < test/fixtures/workers-ai-repair-acceptance.txt)" -eq 1`
- `git diff --check`

## Guardrails

- Do not merge.
- Do not deploy.
- Do not close issue #68.
- Do not change production source.
- Raise at most one repair PR for this fixture.
