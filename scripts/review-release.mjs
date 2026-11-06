#!/usr/bin/env node
// Read-only release review: use existing Codex admission / Workers AI fallback.
import { execFileSync } from "node:child_process";
import { resolve } from "node:path";
import { prepareSourceReview, reviewSource, sourceBundle } from "./commercial/source-review.mjs";
import { classifyReviewFailure } from "./commercial/review-errors.mjs";

const args = process.argv.slice(2);
const preflight = args[0] === "--preflight";
const values = preflight ? args.slice(1) : args;
if (
  (preflight && values.length !== 3) ||
  (!preflight && values.length !== 4) ||
  !/^[a-f0-9]{40}$/.test(values[1]) ||
  !/^[a-f0-9]{40}$/.test(values[2])
) {
  console.error(
    "usage: node scripts/review-release.mjs [--preflight] <checkout> <base-sha> <head-sha> [new-output-json]",
  );
  process.exit(2);
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
  if (preflight) {
    await prepareSourceReview(root, values[1], "repository-release");
    const { selectCommercialRoute } = await import("./commercial/inference.mjs");
    const route = await selectCommercialRoute(process.env);
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
  process.exitCode = 1;
}
