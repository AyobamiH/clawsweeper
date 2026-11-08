/** Fixed-vocabulary progress logging. Never output untrusted detail values. */
// Every permitted label originates in this repository's own workflow code;
// any injected/user/provider string becomes the neutral `progress` label.
const PROGRESS_LABELS = new Set([
  "Codex edit pass finished",
  "GitHub git credential setup failed; continuing",
  "adaptive review budget lookup failed; using configured review timeout",
  "applied mechanical changelog fix",
  "automerge deterministic rebase validated; skipping Codex edit and local review",
  "automerge fast rebase falling back to Codex repair path",
  "automerge shepherd wait finished",
  "automerge shepherd wait timed out",
  "checking target validation plan",
  "compacted generated replacement branch history",
  "completed mechanically resolved rebase",
  "completed resolved rebase",
  "deferring initial automerge rebase to Codex repair pass",
  "deterministic rebase changed branch head; skipping Codex edit pass",
  "fetching contributor PR head",
  "fetching latest base for contributor repair",
  "final base sync result",
  "mechanically resolved additional rebase conflicts",
  "mechanically resolved rebase conflicts",
  "mechanically resolved replacement rebase conflicts",
  "prepared replacement branch has no changes versus base; skipping PR create",
  "preparing target toolchain",
  "rebase conflicts remain after Codex edit pass",
  "rebasing source branch",
  "recovering completed OpenClaw edit after cleanup failure",
  "repair branch push blocked; publishing prepared repair as replacement PR",
  "repair branch push blocked; replacement fallback forbidden by job policy",
  "repairing contributor branch",
  "replacement branch has no changes versus base; skipping PR create",
  "replacement fallback blocked by job policy",
  "retrying Codex edit pass after transient transport error",
  "settling repair before branch push",
  "skipping source branch rebase by job policy",
  "source PR already merged and replacement branch has no changes; skipping PR create",
  "source branch rebase result",
  "starting Codex edit pass",
  "starting fix execution",
  "starting validation/review loop",
  "target checkout clone attempt failed",
  "target validation plan accepted",
  "waiting for automerge continuation after branch repair",
]);

export function formatRepairProgressLine(
  message: unknown,
  details: unknown = {},
  timestamp: Date = new Date(),
): string {
  const label = typeof message === "string" && PROGRESS_LABELS.has(message) ? message : "progress";
  const metadataCount =
    details && typeof details === "object" && !Array.isArray(details)
      ? Math.min(Object.keys(details).length, 1000)
      : 0;
  return `[clawsweeper repair] ${timestamp.toISOString()} ${label} metadata_fields=${metadataCount}`;
}
