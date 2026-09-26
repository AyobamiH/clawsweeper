import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import {
  chmodSync,
  cpSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { delimiter, join, resolve } from "node:path";
import {
  codexFailureDecisionForTest,
  isInfrastructureFailedReviewForTest,
} from "../dist/clawsweeper.js";
import { selectClusterCandidateWithModel } from "../dist/repair/select-cluster-candidate.js";

// Controlled replay through production code; never exhaust a live subscription.
const output = process.argv[2];
if (!output) throw new Error("output path required");
const root = resolve(import.meta.dirname, "..");
const scratch = mkdtempSync(join(tmpdir(), "subscription-boundary-proof-"));
const previousKey = process.env.OPENAI_API_KEY;
delete process.env.OPENAI_API_KEY;
try {
  const diagnostic = "You've hit your usage limit. Try again after the allowance resets.";
  const decision = codexFailureDecisionForTest(
    1,
    "Codex exited",
    JSON.stringify({ type: "turn.failed", error: { message: diagnostic } }),
    "",
  );
  assert.equal(decision.codexTerminalFailure, true);
  const report = `---\nreview_status: failed\nreview_terminal_failure: ${decision.codexTerminalFailure}\n---\n## Summary\n${decision.summary}\n## Evidence\nstream disconnected\n`;
  assert.equal(isInfrastructureFailedReviewForTest(report), false);
  await assert.rejects(
    selectClusterCandidateWithModel({
      repo: "AyobamiH/clawsweeper",
      evidence: [],
      model: "internal",
    }),
    /OPENAI_API_KEY is required/,
  );

  // Run the real scanner CLI with a fixed GitHub input, isolated output and no provider key.
  cpSync(join(root, "dist"), join(scratch, "dist"), { recursive: true });
  cpSync(join(root, "config"), join(scratch, "config"), { recursive: true });
  writeFileSync(join(scratch, "package.json"), '{"type":"module"}\n');
  mkdirSync(join(scratch, "bin"));
  const gh = join(scratch, "bin", "gh");
  writeFileSync(
    gh,
    `#!/usr/bin/env node\nconsole.log(JSON.stringify({id:1,body:"Buy cheap crypto now https://bit.ly/fixture-offer",user:{login:"fixture-author"},author_association:"NONE",updated_at:"2026-09-26T00:00:00Z"}));\n`,
  );
  chmodSync(gh, 0o755);
  const env = {
    ...process.env,
    PATH: `${join(scratch, "bin")}${delimiter}${process.env.PATH ?? ""}`,
  };
  for (const key of [
    "OPENAI_API_KEY",
    "CODEX_API_KEY",
    "PROXY_API_KEY",
    "GH_TOKEN",
    "GITHUB_TOKEN",
  ])
    delete env[key];
  const scan = spawnSync(
    process.execPath,
    [
      join(scratch, "dist/repair/spam-scanner.js"),
      "--repo",
      "AyobamiH/clawsweeper",
      "--comment-id",
      "1",
      "--write-report",
    ],
    { cwd: scratch, env, encoding: "utf8" },
  );
  assert.equal(scan.status, 0, scan.stderr);
  const result = JSON.parse(scan.stdout);
  assert.ok(result.model_candidates > 0);
  assert.equal(result.action, "none");
  assert.match(scan.stderr, /OPENAI_API_KEY missing/);
  const auditFiles = readFileSync(join(scratch, "results/spam-scanner-latest.json"), "utf8");
  assert.equal(JSON.parse(auditFiles).audited, 1);
  const trace = {
    head: execFileSync("git", ["rev-parse", "HEAD"], { cwd: root, encoding: "utf8" }).trim(),
    node: process.version,
    quota: {
      diagnostic,
      summary: decision.summary,
      terminal: decision.codexTerminalFailure,
      infrastructureRetryEligible: false,
    },
    clusterSelection: "refused without API key before provider access",
    spam: {
      candidates: result.model_candidates,
      audited: result.audited,
      action: result.action,
      warning: scan.stderr.trim(),
    },
    limits:
      "Quota is a diagnostic replay; spam GitHub input is a fixture. Production classifier, recovery classifier, cluster selector and scanner CLI executed. No live quota exhaustion, account-wide cooldown or maintainer report generation is claimed.",
  };
  writeFileSync(output, `${JSON.stringify(trace, null, 2)}\n`);
  console.log(JSON.stringify(trace));
} finally {
  if (previousKey === undefined) delete process.env.OPENAI_API_KEY;
  else process.env.OPENAI_API_KEY = previousKey;
  rmSync(scratch, { recursive: true, force: true });
}
