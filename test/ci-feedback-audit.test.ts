import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { auditCiReceipts } from "../scripts/ci-feedback-audit.mjs";

test("CI audit preserves failed, interrupted, and incomplete outcomes", () => {
  const root = mkdtempSync(join(tmpdir(), "clawsweeper-ci-audit-"));
  const receipt = (sha: string, outcome: string, seconds: number, steps: unknown[]) => ({
    repo: "AyobamiH/clawsweeper",
    sha,
    outcome,
    started_at: "2026-11-01T00:00:00.000Z",
    finished_at: new Date(Date.parse("2026-11-01T00:00:00.000Z") + seconds * 1000).toISOString(),
    steps,
  });
  const started_at = "2026-11-01T00:00:01.000Z";
  const finished_at = "2026-11-01T00:00:11.000Z";
  try {
    writeFileSync(
      join(root, "local-fleet-aaaaaaaaaaaa.json"),
      JSON.stringify(
        receipt("a".repeat(40), "error", 1600, [
          { name: "checkout", started_at, finished_at, exit_code: 0 },
        ]),
      ),
    );
    writeFileSync(
      join(root, "local-fleet-bbbbbbbbbbbb.json"),
      JSON.stringify(
        receipt("b".repeat(40), "success", 30, [
          { name: "checkout", started_at, finished_at, exit_code: 0 },
          {
            name: "full",
            started_at: finished_at,
            finished_at: "2026-11-01T00:00:29.000Z",
            exit_code: 0,
          },
        ]),
      ),
    );
    writeFileSync(join(root, "local-fleet-cccccccccccc.json"), "not valid json");
    writeFileSync(
      join(root, "local-fleet-dddddddddddd.json"),
      JSON.stringify({ ...receipt("c".repeat(40), "success", 0, []), repo: "other/repo" }),
    );
    const report = auditCiReceipts({ repo: "AyobamiH/clawsweeper", evidenceDir: root });
    assert.equal(report.sampled_attempts, 2);
    assert.equal(report.distinct_commits, 2);
    assert.deepEqual(report.outcomes, { error: 1, success: 1 });
    assert.equal(
      report.stage_durations.find((entry) => entry.name === "checkout")?.median_seconds,
      10,
    );
    assert.equal(
      report.attempts.find((a) => a.outcome === "error")?.unmeasured_remainder_seconds,
      1589,
    );
    assert.equal(report.queue_time.measured_seconds, null);
    assert.equal(report.slowest_observed_tests.length, 0);
    assert.throws(
      () => auditCiReceipts({ repo: "owner/repo", evidenceDir: root, limit: 151 }),
      /limit/,
    );
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("CI audit accepts only checksum-matched historical test timings", () => {
  const root = mkdtempSync(join(tmpdir(), "clawsweeper-ci-audit-integrity-"));
  const repo = "AyobamiH/clawsweeper";
  const started_at = "2026-11-01T00:00:00.000Z";
  const finished_at = "2026-11-01T00:00:20.000Z";
  const fixture = (name: string, log: string, kind: "verified" | "mismatch" | "unsigned") => {
    const bytes = Buffer.from(log);
    const digest = createHash("sha256").update(bytes).digest("hex");
    const receipt = {
      repo,
      started_at,
      finished_at,
      sha: "a".repeat(40),
      outcome: "success",
      steps: [],
      ...(kind === "unsigned"
        ? {}
        : { log_sha256: kind === "mismatch" ? "b".repeat(64) : digest, log_bytes: bytes.length }),
    };
    writeFileSync(join(root, `${name}.json`), JSON.stringify(receipt));
    writeFileSync(join(root, `${name}.log`), log);
  };
  try {
    fixture("local-fleet-aaaaaaaaaaaa", "✔ genuine test (1200.00ms)\n", "verified");
    fixture("local-fleet-bbbbbbbbbbbb", "✔ forged test (9000.00ms)\n", "mismatch");
    fixture("local-fleet-cccccccccccc", "✔ unknown test (8000.00ms)\n", "unsigned");
    writeFileSync(
      join(root, "local-fleet-dddddddddddd.json"),
      JSON.stringify({
        repo,
        started_at,
        finished_at,
        sha: "d".repeat(40),
        outcome: "error",
        steps: [],
      }),
    );
    const report = auditCiReceipts({ repo, evidenceDir: root, logDir: root });
    assert.deepEqual(report.log_integrity, {
      verified: 1,
      mismatch: 1,
      unverified: 1,
      missing: 1,
    });
    assert.deepEqual(report.slowest_observed_tests, [
      { name: "genuine test", longest_observed_seconds: 1.2 },
    ]);
    assert.equal(report.sampled_attempts, 4);
    assert.equal(report.outcomes.error, 1);
    assert.equal(report.outcomes.success, 3);
    assert.equal(
      report.attempts.find((a) => a.receipt_file.includes("bbbb"))?.log_integrity,
      "mismatch",
    );
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});
