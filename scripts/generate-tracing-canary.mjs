#!/usr/bin/env node
/**
 * Generate an isolated LOCAL-ONLY Worker tracing test config from a clean,
 * committed source revision. This command never invokes the Cloudflare API.
 */
import fs from "node:fs";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const sha = execFileSync("git", ["-C", root, "rev-parse", "HEAD"], { encoding: "utf8" }).trim();
if (!/^[0-9a-f]{40}$/.test(sha)) throw Error("Not an exact git source revision");
const status = execFileSync(
  "git",
  ["-C", root, "status", "--porcelain", "--untracked-files=normal"],
  { encoding: "utf8" },
).trim();
// The generator is deliberately strict: no uncommitted code may be attributed
// to a previous Git SHA (including untracked scripts or tests).
if (status)
  throw Error(
    "Refusing to label an uncommitted or dirty checkout: " +
      status.split("\n").slice(0, 4).join("; "),
  );
const output = path.join(root, "dashboard", ".wrangler-trace-canary.local.toml");
if (fs.existsSync(output)) throw Error("Refusing to overwrite an existing canary config");
const text = [
  "# LOCAL-ONLY: do not deploy this config or route it to production.",
  "# Uses no secrets, DO namespaces, queues, cron triggers, R2 or service bindings.",
  "# The /__local/trace-capability route exists only in this test fixture; it is NOT in production.",
  'name = "clawsweeper-source-trace-local-only"',
  'main = "../test/fixtures/native-cloudflare-tracing-worker.ts"',
  'compatibility_date = "2026-05-11"',
  "workers_dev = false",
  "",
  "[observability]",
  "redact_query_string = true",
  "",
  "[observability.traces]",
  "enabled = true",
  "head_sampling_rate = 1.0",
  "",
  "[vars]",
  'CLAWSWEEPER_REPO = "AyobamiH/clawsweeper"',
  'CLAWSWEEPER_ARCH_TRACE_ENABLED = "1"',
  'CLAWSWEEPER_DEPLOY_SHA = "' + sha + '"',
  "",
].join("\n");
fs.writeFileSync(output, text, { flag: "wx", mode: 0o600 });
console.log(
  JSON.stringify(
    {
      config: output,
      sourceRevisionClaim: sha,
      mode: "local-only",
      deployAuthorised: false,
      attestation: "claim only; NOT provider-verified",
    },
    null,
    2,
  ),
);
