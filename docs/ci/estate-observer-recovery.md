# ClawSweeper operational observer recovery — development only

On 10 November 2026 the installed clawsweeper-operational-observer.timer
was active, but its user service had a CHDIR failure every 15 minutes:
WorkingDirectory=/home/johnh/clawsweeper-operational-admission-20261104
no longer existed. The matching executable path also no longer existed.
The original recovered pilot is preserved on signed branch
recovery/operational-admission-verified-20261109 at 47ce0c80, but its
owner-approved recovery record explicitly prohibits wholesale deployment.

This correction is in the source/observation and unit-template layers,
not in the privileged CI runner or production publisher. The new observer:
* Refuses mismatched develop SHA, modified workflow bytes and job-inventory
  omissions by executing the pinned YAML enumerator in check-only mode.
  GitHub refs and the full local source inventory are rechecked after network
  reads; an intervening checkout edit or clean HEAD switch invalidates health.
* Invalidates the previous latest health record before any source/API read,
  including interruption after the first state write or during observation.
* Makes only allowlisted, bounded GitHub API GET requests and never uses
  runner registration, workflow dispatch, review, publication or provider writes.
* Streams both GitHub JSON and Git source readbacks under explicit byte and
  time limits. Oversized, interrupted or failed subprocess output is a HOLD;
  the owned process group is terminated even when the leader has exited.
  Local manifest and workflow source bytes are bounded before deserialisation.
  Every consumed YAML, inventory helper and manifest byte is compared with
  the immutable HEAD blob independently of Git's assume-unchanged/skip-worktree
  flags. Untracked oversized YAML is refused before the heap-limited inventory
  subprocess, and failed subprocesses cannot leave an owned descendant alive.
  Consumed workflow, manifest and inventory-helper source is compared with
  blobs at the captured commit SHA (not a movable HEAD alias). The independent
  Node inventory runs exclusively from an owner-private /run/user/UID snapshot
  materialised from those verified bytes, never by reopening the checked
  source pathnames. A second bounded source comparison rejects persistent
  original-file drift and late untracked workflows. Runtime dependencies
  still come from the owner-managed pinned installation, not the snapshot.
  Nonblocking
  descriptor reads cap bytes even if a path is replaced or grows after stat;
  source HEAD and status are rechecked after the complete inventory.
  Existing receipts are read through a nonblocking, nofollow descriptor only
  after owner, regular-file, size, mode and single-link checks.
* Records exact source SHA and manifest digest, separate main SHA, samples
  of queued/in-progress/pending GitHub runs, and registered-runner count.
  The three run views each have a bounded 30-result window; a snapshot is
  NOT exhaustive admission or proof that 88 workflows executed.
* Uses one owner lock, atomic/fsynced receipts, create-only identity and
  last-attempt.json with an explicit unverified state on failed reads.
  latest.json from an earlier successful run must never overrule a newer
  unverified attempt; consumers must inspect last-attempt and freshness.
* Refuses success when source or GitHub evidence cannot be authenticated.
  It reports effect_count=0 and workflow_admitted=false.

The systemd template is NOT installed and the existing failing timer is NOT
modified. A future installation needs a signed reviewed source revision,
immutable installed observer release, approved source checkout, explicit
owner cutover authorisation, unit syntax verification, and a real healthy
observation readback. No symlinks to vanished worktrees, no rootful/untrusted
runner, and no relabelling of CodeQL evidence.

The change is development-only until these gates pass. It neither admits
previously unaccepted jobs nor changes protected main or installed controls.
