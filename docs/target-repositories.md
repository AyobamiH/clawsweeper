# Target Repositories

- Status: active configuration and onboarding reference
- Owner: ClawSweeper maintainers
- Source of truth: `config/target-repositories.json`, repository profiles,
  target inventory, dashboard/apply configuration, and profile tests
- Last verified: `openclaw/clawsweeper@647503ec44b8e777dd172adf974a945367da0d19`
- Update when: profile policy, supported owners, inventory, dashboard targets,
  apply membership, or onboarding requirements change

Read when enabling ClawSweeper for another OpenClaw repository, changing
`config/target-repositories.json`, or debugging `Unsupported target repo`
failures.

ClawSweeper has two target-repository paths:

- configured runtime profiles in `config/target-repositories.json`
- conservative generic fallbacks for exact event/manual reviews of configured
  owner inventories such as `openclaw/*` and `steipete/*`

`openclaw/openclaw` remains a built-in profile because it has broader
auto-close policy. Every other configured profile declares its own issue and PR
close rules in `apply_close_rules`; do not infer those rules from whether the
repository appears in the dashboard or receives scheduled work. The current
configured profiles allow `implemented_on_main` for issues and PRs, and some
profiles additionally allow age-gated `mostly_implemented_on_main` for PRs.

Review guidance belongs to the selected profile's `promptNote` in
`src/repository-profiles.ts` or `config/target-repositories.json`. The production
prompt assembler selects it with `repositoryProfileFor(item.repo)`, using the
normalized exact owner/repository, not the organization, display name, PR body,
linked repository, or author association. The built-in `openclaw/openclaw`
profile alone supplies its release-owned `CHANGELOG.md` review restriction.
`openclaw/clawsweeper`, ClawHub, and generic targets follow their own release-note
policies; being a non-core target does not grant contributors or workers
permission to edit release-owned files.

Toolchain and setup ownership is also per repository. The explicit
`openclaw/crabbox` profile selects npm and installs its nested worker package
with `npm ci --prefix worker` from the target root. It retains the generic
OpenClaw fallback's close rules, empty validation commands, and absent changed
gate; selecting target-native setup does not broaden apply policy or inherit
the core OpenClaw policy.

Scheduled repository work is controlled by `config/target-repositories.json`.
`target_inventory` decides which repositories are members of the managed fleet,
while each repository/profile's optional `automation` object decides which lanes
may run for that repository. The scheduler does not need a repository name baked
into workflow YAML.

## Automation Lanes

Supported `automation` keys are:

- `hot_intake` — low-latency review intake
- `normal_review` — scheduled review/backfill
- `audit` — state/repository audit
- `apply` — guarded close/comment application
- `comment_sync` — durable review-comment synchronization
- `failed_review_retry` — bounded retry of failed reviews
- `idea_archive_revival` — reopen eligible archived ideas

The code defaults review/audit lanes on and mutation lanes off. An owner-level
`generic_fallbacks[].automation` can narrow those defaults; an explicit
`repositories[].automation` entry overrides that owner policy for one repo.
This means adding a repository to the inventory can safely give it review/audit
coverage without silently granting write behaviour.

The current self-hosted policy explicitly enables apply, comment sync, and
failed-review retry for `AyobamiH/openclaw-operator` and
`AyobamiH/openclaw-ops`. Idea-archive revival is enabled only for
`AyobamiH/openclaw-operator`.

Configuration is necessary but not sufficient authority: the ClawSweeper
GitHub App must also be installed on every target repository. Config answers
"may ClawSweeper manage this repo?"; the App installation answers "may GitHub
allow it to do so?"

ClawHub has two separate meanings in the upstream design. The `clawhub` review
close reason is a handoff from OpenClaw core to the public skill/plugin registry;
that policy remains part of the review engine. Separately, the
`openclaw/clawhub` source repository can itself be a ClawSweeper target when
the operator has installed the App there and explicitly enrolled it. Fleet
configuration must not conflate those two roles.

`PUBLIC_BAY_REPOS` is a separate public-output allowlist for the minimal
repository/item reference cards shown by OpenClaw Bay and Overview. Add a
repository only after confirming that it is public and intended to be visible
on the unauthenticated dashboard. The Worker treats an absent or malformed
allowlist as empty. Membership does not authorize titles, URLs, queries,
failure data, opaque keys, credentials, tokens, or any private-repository data.

## Generic Fallbacks

The fallback lets a newly installed repository dispatch to ClawSweeper
without a TypeScript change. It is intentionally narrow:

- owner must be listed in `generic_fallbacks`
- repo name must match `allow_repo_name_pattern`
- denied repositories are rejected
- scheduled fanout follows `target_inventory.include_private` and the inventory/App credential's actual repository access
- auto-close policy comes from that owner fallback
- `live_test`, when present, is retained for compatibility with historical
  live-proof records and tooling; automatic review-time live proof is retired
- generic `openclaw/*` issues can auto-close only for
  `implemented_on_main`; PRs can auto-close for `implemented_on_main` or
  age-gated `mostly_implemented_on_main`
- `steipete/*` starts review/comment-only for issues and PRs
- scheduled dashboard/backfill rows are added only through target fanout

This is enough for event-driven review after the target repo has the dispatcher
workflow and GitHub App installation.

## Add One Repository

1. Install the ClawSweeper GitHub App on the target repository.
2. Add the repository to `target_inventory.allow_repositories` (and its owner
   to `target_inventory.owners` when onboarding a new owner).
3. Add an explicit `repositories[]` profile when it needs repository-specific
   toolchain, prompt, close rules, or mutation lanes. Otherwise the matching
   owner `generic_fallbacks[]` profile applies.
4. Leave `apply`, `comment_sync`, `failed_review_retry`, and
   `idea_archive_revival` off until that repository is deliberately approved
   for those mutations.
5. For low-latency issue/PR events, add the target dispatcher described in
   [`docs/target-dispatcher.md`](target-dispatcher.md). Scheduled fleet work
   does not require a repository-specific cron.
6. Verify the fanout plan reports the repository and its real default branch
   before enabling live schedules.

After those steps, future scheduled work is selected from configuration; no new
repository-specific schedule branch should be added to `sweep.yml`.

## Add Many Repositories

Batch rollout should use target fanout:

- install the app and dispatcher on a small group first
- leave auto-close disabled unless the owner/repo profile explicitly enables it
- verify event review/comment sync on one issue or PR per repo
- use `pnpm run target-fanout -- plan --mode hot-intake --limit 10 --dry-run`
  to inspect the current owner inventory and selected dispatch commands
- let the scheduled fanout cursor dispatch small batches across
  `target_inventory.owners`; the cursor is stored in the authenticated
  ExactReviewQueue Durable Object rather than `clawsweeper-state`
- fanout passes each repository's default branch as `target_branch`, so repos
  that use `master` or another branch do not fall back to `main`
- add config entries only for repos that need repo-specific guidance or broader
  close policy

If a target dispatch reaches ClawSweeper but receiver token creation fails, the
App is usually not installed on that target repo. If the target workflow skips
before dispatch, the target repo usually cannot access
`CLAWSWEEPER_APP_PRIVATE_KEY`.
