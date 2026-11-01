#!/usr/bin/env node
/**
 * Read-only local CI feedback-loop audit. It reports actual recorded durations;
 * it never treats missing steps or GitHub unavailable checks as passed.
 */
import { readdirSync, readFileSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { pathToFileURL } from "node:url";

const RECEIPT_NAME = /^local-fleet-[a-f0-9]{12}(?:\.attempt[0-9]+)?\.json$/;

function secondsBetween(start, end) {
  if (!start || !end) return null;
  const s = Date.parse(start);
  const e = Date.parse(end);
  return Number.isFinite(s) && Number.isFinite(e) && e >= s ? Math.round((e - s) / 100) / 10 : null;
}

function percentile(values, fraction) {
  if (values.length === 0) return null;
  const ordered = [...values].sort((a, b) => a - b);
  return ordered[Math.min(ordered.length - 1, Math.ceil(ordered.length * fraction) - 1)];
}

function aggregateDurations(values) {
  return {
    count: values.length,
    median_seconds: percentile(values, 0.5),
    p90_seconds: percentile(values, 0.9),
    max_seconds: values.length ? Math.max(...values) : null,
  };
}

export function auditCiReceipts({ repo, evidenceDir, limit = 150 }) {
  if (typeof repo !== "string" || !/^[\w.-]+\/[\w.-]+$/.test(repo)) {
    throw new Error("Provide a repository in owner/name format");
  }
  if (!Number.isSafeInteger(limit) || limit < 1 || limit > 150) {
    throw new Error("Receipt limit must be between 1 and 150");
  }
  const entries = readdirSync(evidenceDir)
    .filter((name) => RECEIPT_NAME.test(name))
    .flatMap((name) => {
      try {
        const receipt = JSON.parse(readFileSync(join(evidenceDir, name), "utf8"));
        return receipt.repo?.toLowerCase() === repo.toLowerCase() ? [{ name, receipt }] : [];
      } catch {
        return []; // Malformed receipts aren't evidence of successful execution.
      }
    })
    .sort((a, b) => (b.receipt.started_at ?? "").localeCompare(a.receipt.started_at ?? ""))
    .slice(0, limit);

  const stepDurations = new Map();
  const slowestTests = new Map();
  const outcomes = {};
  const attempts = entries.map(({ name, receipt }) => {
    const steps = (receipt.steps ?? []).map((step) => {
      const duration = secondsBetween(step.started_at, step.finished_at);
      if (duration !== null) {
        const group = stepDurations.get(step.name) ?? [];
        group.push(duration);
        stepDurations.set(step.name, group);
      }
      return {
        name: step.name,
        duration_seconds: duration,
        exit_code: step.exit_code ?? null,
      };
    });
    const outcome = receipt.outcome ?? "unverified";
    outcomes[outcome] = (outcomes[outcome] ?? 0) + 1;
    const priorStepEnd = steps.length
      ? receipt.steps[receipt.steps.length - 1]?.finished_at
      : receipt.started_at;
    const unmeasuredRemainder = secondsBetween(priorStepEnd, receipt.finished_at);
    const logName = name.replace(/\.json$/, ".log");
    try {
      const log = readFileSync(join(evidenceDir, "../../logs/fleet", logName), "utf8");
      for (const line of log.split("\n")) {
        const match = /^[\s]*[✔✖] (.{1,160}) \(([0-9.]+)ms\)$/.exec(line);
        if (!match) continue;
        const duration = Number(match[2]) / 1000;
        if (!Number.isFinite(duration)) continue;
        const prior = slowestTests.get(match[1]) ?? 0;
        slowestTests.set(match[1], Math.max(prior, duration));
      }
    } catch {
      // No raw log: only receipt stage timing can be substantiated.
    }
    return {
      id: receipt.id ?? name,
      attempt: receipt.attempt ?? null,
      sha: receipt.sha,
      outcome,
      started_at: receipt.started_at ?? null,
      finished_at: receipt.finished_at ?? null,
      duration_seconds: secondsBetween(receipt.started_at, receipt.finished_at),
      steps,
      unmeasured_remainder_seconds: unmeasuredRemainder,
      receipt_file: name,
    };
  });
  // Interruption and unrun policy changes do not establish a meaningful
  // execution duration, even when their wall-clock receipts span hours.
  const finished = attempts
    .filter(
      (a) =>
        ![
          "interrupted_unverified",
          "policy_replaced_unrun",
          "not_run_superseded_or_closed",
        ].includes(a.outcome),
    )
    .map((a) => a.duration_seconds)
    .filter((v) => v !== null);
  const steps = [...stepDurations.entries()]
    .map(([name, durations]) => ({ name, ...aggregateDurations(durations) }))
    .sort((a, b) => (b.median_seconds ?? 0) - (a.median_seconds ?? 0));
  const tests = [...slowestTests.entries()]
    .map(([name, seconds]) => ({ name, longest_observed_seconds: Math.round(seconds * 10) / 10 }))
    .sort((a, b) => b.longest_observed_seconds - a.longest_observed_seconds)
    .slice(0, 15);
  return {
    schema_version: 1,
    repo,
    requested_limit: limit,
    sampled_attempts: attempts.length,
    distinct_commits: new Set(attempts.map((a) => a.sha).filter(Boolean)).size,
    outcomes,
    end_to_end: aggregateDurations(finished),
    stage_durations: steps,
    slowest_observed_tests: tests,
    queue_time: { status: "not available in receipt data", measured_seconds: null },
    limitations: [
      "A missing completion step is not a pass or a measured execution duration.",
      "An unmeasured remainder is a lower-bound diagnostic, not an independently timed step.",
      "Provider billing, CircleCI equivalence and merge readiness are not inferred from local receipts.",
      "Historical runs may use different commits, runner versions and policies.",
    ],
    attempts,
  };
}

function main(argv) {
  const options = Object.fromEntries(
    argv.reduce((pairs, value, index, args) => {
      if (value.startsWith("--") && args[index + 1] && !args[index + 1].startsWith("--")) {
        pairs.push([value.slice(2), args[index + 1]]);
      }
      return pairs;
    }, []),
  );
  const repo = options.repo;
  const evidenceDir = options.evidence ?? join(homedir(), ".local/share/local-ci/evidence/fleet");
  const report = auditCiReceipts({ repo, evidenceDir, limit: Number(options.limit ?? 150) });
  const output = JSON.stringify(report, null, 2) + "\n";
  if (options.output) writeFileSync(options.output, output, { flag: "wx", mode: 0o600 });
  process.stdout.write(output);
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? "").href) {
  try {
    main(process.argv.slice(2));
  } catch (error) {
    console.error(error instanceof Error ? error.message : String(error));
    process.exitCode = 1;
  }
}
