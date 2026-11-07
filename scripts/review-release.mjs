#!/usr/bin/env node
// Read-only release review: use existing Codex admission / Workers AI fallback.
import { execFileSync } from "node:child_process";
import { digest } from "./commercial/contract.mjs";
import { dirname, join, resolve } from "node:path";
import {
  appendFileSync,
  closeSync,
  constants,
  fsyncSync,
  linkSync,
  mkdtempSync,
  openSync,
  rmdirSync,
  realpathSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import {
  assertLiveReleaseReviewBudget,
  prepareSourceReview,
  reviewSource,
  sourceBundle,
} from "./commercial/source-review.mjs";
import { classifyReviewFailure } from "./commercial/review-errors.mjs";

const args = process.argv.slice(2);
const preflight = args[0] === "--preflight";
const exportBundle = args[0] === "--export-bundle";
const values = preflight || exportBundle ? args.slice(1) : args;
if (
  (preflight && values.length !== 3) ||
  (!preflight && values.length !== 4) ||
  !/^[a-f0-9]{40}$/.test(values[1]) ||
  !/^[a-f0-9]{40}$/.test(values[2])
) {
  console.error(
    "usage: node scripts/review-release.mjs [--preflight|--export-bundle] <checkout> <base-sha> <head-sha> [new-output-json]",
  );
  process.exit(2);
}
// Never expose a partial export as complete if the process dies mid-write.
// Stage on the same filesystem, fsync it, then create the final name with
// link(2): an existing file or symlink cannot be overwritten by a retry.
function writeImmutableBundle(destination, content) {
  const output = resolve(destination);
  const parent = dirname(output);
  // Refuse aliased parent paths before publishing. Previously the late
  // O_NOFOLLOW check could fail after a final bundle was already linked.
  if (realpathSync.native(parent) !== parent)
    throw new Error("review bundle parent must not contain symlinks");
  const dirfd = openSync(parent, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
  let stage;
  let stagedFile;
  try {
    stage = mkdtempSync(join(parent, ".clawsweeper-review-stage-"));
    stagedFile = join(stage, "source.json");
    const fd = openSync(
      stagedFile,
      constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY | constants.O_NOFOLLOW,
      0o600,
    );
    try {
      writeFileSync(fd, content);
      fsyncSync(fd);
    } finally {
      closeSync(fd);
    }
    linkSync(stagedFile, output);
    fsyncSync(dirfd);
  } finally {
    closeSync(dirfd);
    if (stagedFile) {
      try {
        unlinkSync(stagedFile);
      } catch {
        /* fail closed; preserve other owner files */
      }
    }
    if (stage) {
      try {
        rmdirSync(stage);
      } catch {
        /* stage is private; never delete foreign paths */
      }
    }
  }
}

const root = resolve(values[0]);
const git = (...params) =>
  execFileSync("git", ["-C", root, ...params], {
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
    maxBuffer: 4 * 1024 * 1024,
  }).trim();
try {
  if (git("rev-parse", "HEAD") !== values[2]) throw new Error("head changed");
  if (git("status", "--porcelain", "--untracked-files=no"))
    throw new Error("tracked checkout is dirty");
  if (git("merge-base", values[1], values[2]) !== values[1])
    throw new Error("base is not an ancestor");
  const bundle = await sourceBundle(root, values[1], false);
  if (bundle.head !== values[2]) throw new Error("bundle head mismatch");
  // This entrypoint only reviews committed source. Untracked non-generated files
  // are never accepted as release evidence.
  const tracked = new Set(
    git("diff", "--name-only", values[1], values[2]).split("\n").filter(Boolean),
  );
  if (bundle.files.some((file) => !tracked.has(file.path)))
    throw new Error("untracked source in review");
  if (exportBundle) {
    // Portable, complete source for an independent reviewer. This is source
    // evidence, not an inference call, review verdict or approval to merge.
    // Never use a mutable checkout, untracked bytes or an already-existing
    // destination as release evidence.
    const evidence = {
      schema: "clawsweeper.release-review-bundle.v1",
      reviewStatus: "unreviewed",
      base: bundle.base,
      head: bundle.head,
      repository: bundle.repository,
      sourceDigest: digest(bundle),
      fileCount: bundle.files.length,
      files: bundle.files,
    };
    const content = JSON.stringify(evidence, null, 2) + "\n";
    if (Buffer.byteLength(content, "utf8") > 45 * 1024 * 1024)
      throw new Error("release review bundle exceeds bounded output size");
    writeImmutableBundle(values[3], content);
    console.log(
      JSON.stringify({
        exported: true,
        reviewStatus: "unreviewed",
        base: bundle.base,
        head: bundle.head,
        sourceDigest: evidence.sourceDigest,
        files: bundle.files.length,
        modelCalls: 0,
      }),
    );
  } else if (preflight) {
    await prepareSourceReview(root, values[1], "repository-release");
    const { selectCommercialRoute } = await import("./commercial/inference.mjs");
    const route = await selectCommercialRoute(process.env);
    if (route.provider === "cloudflare-workers-ai")
      assertLiveReleaseReviewBudget(bundle, process.env);
    console.log(
      JSON.stringify({
        ready: true,
        provider: route.provider,
        model: route.model,
        reason: route.reason,
        head: bundle.head,
        base: bundle.base,
        files: bundle.files.length,
      }),
    );
  } else {
    const result = await reviewSource(
      root,
      values[1],
      resolve(values[3]),
      process.env,
      "repository-release",
    );
    if (result.head !== values[2]) throw new Error("review head changed");
    console.log(
      JSON.stringify({
        passed: result.passed,
        provider: result.provider,
        model: result.model,
        head: result.head,
        base: result.base,
        findings: result.findings.length,
      }),
    );
    if (!result.passed) process.exitCode = 1;
  }
} catch (error) {
  // Sanitised diagnostic only: never log model descriptions, source content or credentials.
  const classified = classifyReviewFailure(error);
  const preflightReason = [
    "head changed",
    "tracked checkout is dirty",
    "base is not an ancestor",
    "bundle head mismatch",
    "untracked source in review",
  ].includes(error?.message)
    ? error.message
    : null;
  const diagnostic = {
    schema: "clawsweeper.release-review-diagnostic.v1",
    status: "refused",
    ...classified,
    ...(preflightReason ? { category: "preflight_refused", reason: preflightReason } : {}),
    head: values[2],
    base: values[1],
  };
  console.error("Release review refused; no clean verdict: " + JSON.stringify(diagnostic));
  // The GitHub annotation contains only fixed taxonomy identifiers. Keep the
  // full sanitised diagnostic in the runner's private evidence directory.
  const safeToken = (value) =>
    typeof value === "string" && /^[a-z][a-z0-9_]{0,63}$/.test(value) ? value : "unspecified";
  const category = safeToken(diagnostic.category);
  const phase = safeToken(diagnostic.phase);
  const reason = safeToken(diagnostic.reason);
  if (process.env.GITHUB_ACTIONS === "true") {
    console.error(
      `::error title=ClawSweeper release refused::category=${category} phase=${phase} reason=${reason}; exact-head review has no approval`,
    );
  }
  if (
    !preflight &&
    process.env.RUNNER_TEMP &&
    resolve(values[3]).startsWith(resolve(process.env.RUNNER_TEMP) + "/")
  ) {
    const evidencePath = resolve(values[3]) + ".diagnostic.json";
    try {
      writeFileSync(evidencePath, JSON.stringify(diagnostic, null, 2) + "\n", {
        flag: "wx",
        mode: 0o600,
      });
    } catch {
      console.error(
        "::warning title=ClawSweeper evidence::sanitised diagnostic could not be persisted",
      );
    }
  }
  if (process.env.GITHUB_STEP_SUMMARY && process.env.GITHUB_ACTIONS === "true") {
    try {
      appendFileSync(
        process.env.GITHUB_STEP_SUMMARY,
        `### ClawSweeper release refused\n\n- Category: \`${category}\`\n- Phase: \`${phase}\`\n- Reason: \`${reason}\`\n- Exact head: \`${values[2]}\`\n- Exact base: \`${values[1]}\`\n- Approval: **not granted**\n`,
      );
    } catch {
      console.error("::warning title=ClawSweeper summary::could not write job summary");
    }
  }
  process.exitCode = 1;
}
