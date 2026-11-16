import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import {
  existsSync,
  mkdtempSync,
  mkdirSync,
  readFileSync,
  rmSync,
  writeFileSync,
  chmodSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";

const project = resolve(dirname(fileURLToPath(import.meta.url)), "../..");
const launcher = "scripts/analysis/ci-triage-launch.sh";

test("normal GitHub notifier and package commands use the same shell launch boundary", () => {
  const pkg = JSON.parse(readFileSync(join(project, "package.json"), "utf8"));
  const wf = readFileSync(join(project, ".github/workflows/github-activity.yml"), "utf8");
  const entry = pkg.scripts["repair:notify-github-activity"];
  assert.equal(entry, "sh " + launcher + " notifier");
  assert.equal(pkg.scripts["ci-triage:observe:verified"], "sh " + launcher + " observer");
  assert.equal(pkg.scripts["ci-triage:notify:verified"], "sh " + launcher + " verified-notifier");
  assert.match(wf, /sh scripts\/analysis\/ci-triage-launch\.sh notifier --write-report/);
  assert.doesNotMatch(wf, /pnpm run repair:notify-github-activity/);
});

test("disabled notifier remains legacy; enabled notifier and observer route through verified bootstrap", () => {
  const root = mkdtempSync(join(tmpdir(), "ci-triage-launch-"));
  try {
    const bin = join(root, "bin");
    mkdirSync(bin);
    const shim = join(bin, "node");
    writeFileSync(
      shim,
      '#!/bin/sh\nprintf \'%s\\n\' "$@" > "$CI_TRIAGE_TEST_ARGS"\n' +
        'printf \'%s\\n\' "${NODE_OPTIONS-unset}" > "$CI_TRIAGE_TEST_OPTIONS"\n',
    );
    chmodSync(shim, 0o700);
    const args = join(root, "args");
    const options = join(root, "options");
    const env = {
      ...process.env,
      PATH: bin + ":" + process.env.PATH,
      CI_TRIAGE_TEST_ARGS: args,
      CI_TRIAGE_TEST_OPTIONS: options,
      NODE_OPTIONS: "--require=/untrusted/preload.js",
    };
    const run = (mode, setting) =>
      spawnSync("sh", [launcher, mode, "--write-report"], {
        cwd: project,
        env: { ...env, CLAWSWEEPER_CI_TRIAGE_ENABLED: setting },
        encoding: "utf8",
        timeout: 4000,
      });
    let result = run("notifier", "0");
    assert.equal(result.status, 0, result.stderr);
    assert.deepEqual(readFileSync(args, "utf8").trim().split("\n"), [
      "dist/repair/notify-github-activity.js",
      "--write-report",
    ]);
    result = run("notifier", "1");
    assert.equal(result.status, 0, result.stderr);
    assert.deepEqual(readFileSync(args, "utf8").trim().split("\n"), [
      "scripts/analysis/ci-triage-preimport.mjs",
      "notifier",
      "--write-report",
    ]);
    assert.equal(readFileSync(options, "utf8").trim(), "unset");
    result = run("observer", "0");
    assert.equal(result.status, 0, result.stderr);
    assert.deepEqual(readFileSync(args, "utf8").trim().split("\n"), [
      "scripts/analysis/ci-triage-preimport.mjs",
      "observer",
      "--write-report",
    ]);
    assert.equal(readFileSync(options, "utf8").trim(), "unset");
    result = run("verified-notifier", "0");
    assert.equal(result.status, 0, result.stderr);
    assert.equal(readFileSync(options, "utf8").trim(), "unset");
    const before = readFileSync(args, "utf8");
    result = run("notifier", "surprise");
    assert.equal(result.status, 64);
    assert.equal(readFileSync(args, "utf8"), before, "invalid flag must not start Node");
    result = run("unreviewed-job", "1");
    assert.equal(result.status, 64);
    assert.equal(readFileSync(args, "utf8"), before, "unknown mode must not start Node");
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("enabled production route clears Node preload before it can run ahead of source verification", () => {
  const root = mkdtempSync(join(tmpdir(), "ci-triage-preload-"));
  try {
    const marker = join(root, "UNVERIFIED_PRELOAD_EXECUTED");
    const preload = join(root, "preload.mjs");
    writeFileSync(
      preload,
      'import {writeFileSync} from "node:fs";\nwriteFileSync(' +
        JSON.stringify(marker) +
        ', "unsafe");\n',
    );
    const env = {
      ...process.env,
      NODE_OPTIONS: "--import=" + preload,
      CLAWSWEEPER_CI_TRIAGE_ENABLED: "1",
      CLAWSWEEPER_CI_TRIAGE_SOURCE_SHA: "",
      CLAWSWEEPER_CI_TRIAGE_BOOTSTRAP_SHA256: "",
      CLAWSWEEPER_CI_TRIAGE_RUNTIME_MANIFEST_SHA256: "",
      CLAWSWEEPER_CI_TRIAGE_RUNTIME_MANIFEST: "",
    };
    for (const mode of ["notifier", "verified-notifier", "observer"]) {
      const result = spawnSync("sh", [launcher, mode, "--write-report"], {
        cwd: project,
        env,
        encoding: "utf8",
        timeout: 15000,
      });
      assert.notEqual(result.status, 0, result.stderr);
      assert.match(result.stderr, /preimport_pin_required/);
      assert.equal(
        existsSync(marker),
        false,
        mode + " must reject before untrusted preload or application module executes",
      );
    }
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});
