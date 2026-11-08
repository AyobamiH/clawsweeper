import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { digest } from "../scripts/commercial/contract.mjs";

const executable = fileURLToPath(new URL("../scripts/review-release.mjs", import.meta.url));

function git(root, ...args) {
  const result = spawnSync("git", ["-C", root, ...args], {
    encoding: "utf8",
    env: { ...process.env, GIT_CONFIG_GLOBAL: "/dev/null", GIT_CONFIG_NOSYSTEM: "1" },
  });
  assert.equal(result.status, 0, result.stderr);
  return result.stdout.trim();
}

function fixture(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "clawsweeper-offline-review-bundle-"));
  t.after(() => fs.rmSync(root, { force: true, recursive: true }));
  git(root, "init", "-q");
  git(root, "config", "--local", "user.name", "Fixture");
  git(root, "config", "--local", "user.email", "fixture@example.invalid");
  git(root, "config", "--local", "commit.gpgsign", "false");
  git(
    root,
    "config",
    "--local",
    "remote.origin.url",
    "https://github.com/AyobamiH/clawsweeper.git",
  );
  fs.writeFileSync(path.join(root, "source.ts"), "export const value = 1;\n");
  git(root, "add", ".");
  git(root, "commit", "-qm", "baseline");
  const base = git(root, "rev-parse", "HEAD");
  fs.writeFileSync(path.join(root, "source.ts"), "export const value = 2;\n");
  fs.mkdirSync(path.join(root, "ci"));
  fs.writeFileSync(path.join(root, "ci", "runner.service"), "[Service]\nExecStart=/usr/bin/true\n");
  git(root, "add", ".");
  git(root, "commit", "-qm", "reviewable change");
  return { root, base, head: git(root, "rev-parse", "HEAD"), out: path.join(root, "bundle.json") };
}

function invoke({ root, base, head, out }) {
  return spawnSync(process.execPath, [executable, "--export-bundle", root, base, head, out], {
    encoding: "utf8",
    env: {
      ...process.env,
      GIT_CONFIG_GLOBAL: "/dev/null",
      GIT_CONFIG_NOSYSTEM: "1",
      OPENAI_API_KEY: "",
      CODEX_API_KEY: "",
      CLOUDFLARE_API_TOKEN: "",
    },
  });
}

test("offline export emits all exact code and systemd bytes without making an inference call", (t) => {
  const input = fixture(t);
  const run = invoke(input);
  assert.equal(run.status, 0, run.stderr);
  const summary = JSON.parse(run.stdout);
  assert.equal(summary.modelCalls, 0);
  assert.equal(summary.reviewStatus, "unreviewed");
  const result = JSON.parse(fs.readFileSync(input.out, "utf8"));
  assert.equal(result.head, input.head);
  assert.equal(result.base, input.base);
  assert.equal(result.fileCount, 2);
  assert.equal(result.reviewStatus, "unreviewed");
  assert.equal(
    result.sourceDigest,
    digest({
      schema: "tw.commercial-source-bundle.v2",
      repository: result.repository,
      base: input.base,
      head: input.head,
      files: result.files,
    }),
  );
  assert.deepEqual(
    result.files.map((f) => f.path),
    ["ci/runner.service", "source.ts"],
  );
  assert.equal(result.files[0].after, "[Service]\nExecStart=/usr/bin/true\n");
  assert.equal(result.files[1].before, "export const value = 1;\n");
  assert.equal(result.files[1].after, "export const value = 2;\n");
  assert.equal(fs.statSync(input.out).mode & 0o077, 0);
  const original = fs.readFileSync(input.out);
  const duplicate = invoke(input);
  assert.notEqual(duplicate.status, 0);
  assert.deepEqual(fs.readFileSync(input.out), original);
  const linkedDestination = path.join(input.root, "linked-bundle.json");
  fs.symlinkSync(input.out, linkedDestination);
  const linked = invoke({ ...input, out: linkedDestination });
  assert.notEqual(linked.status, 0);
  assert.equal(fs.lstatSync(linkedDestination).isSymbolicLink(), true);
  assert.deepEqual(fs.readFileSync(input.out), original);
  assert.deepEqual(
    fs.readdirSync(input.root).filter((entry) => entry.startsWith(".clawsweeper-review-stage-")),
    [],
  );
});

test("symlinked export parent refuses before publishing any final output", (t) => {
  const input = fixture(t);
  const temp = fs.mkdtempSync(path.join(os.tmpdir(), "clawsweeper-review-parent-"));
  t.after(() => fs.rmSync(temp, { force: true, recursive: true }));
  const real = path.join(temp, "real");
  const alias = path.join(temp, "alias");
  fs.mkdirSync(real);
  fs.symlinkSync(real, alias);
  const result = invoke({ ...input, out: path.join(alias, "review.json") });
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /"status":"refused"/);
  assert.equal(fs.existsSync(path.join(real, "review.json")), false);
  assert.deepEqual(
    fs.readdirSync(real).filter((entry) => entry.startsWith(".clawsweeper-review-stage-")),
    [],
  );
});

test("changed tracked credential and stale commit refuse before creating a source bundle", (t) => {
  const input = fixture(t);
  const wrong = invoke({ ...input, head: "0".repeat(40) });
  assert.notEqual(wrong.status, 0);
  assert.equal(fs.existsSync(input.out), false);
  fs.writeFileSync(path.join(input.root, "credentials.json"), '{"key":"fixture-only"}\n');
  git(input.root, "add", "credentials.json");
  git(input.root, "commit", "-qm", "credential-looking source");
  const changed = invoke({ ...input, head: git(input.root, "rev-parse", "HEAD") });
  assert.notEqual(changed.status, 0);
  assert.equal(fs.existsSync(input.out), false);
});
