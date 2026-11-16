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
  assert.equal(entry, "/bin/sh " + launcher + " notifier");
  assert.equal(pkg.scripts["ci-triage:observe:verified"], "/bin/sh " + launcher + " observer");
  assert.equal(pkg.scripts["ci-triage:notify:verified"], "/bin/sh " + launcher + " verified-notifier");
  assert.match(wf, /\/bin\/sh scripts\/analysis\/ci-triage-launch\.sh notifier --write-report/);
  assert.doesNotMatch(wf, /pnpm run repair:notify-github-activity/);
});

test("verified launcher refuses untrusted PATH Node before the pre-import bootstrap", () => {
  const root = mkdtempSync(join(tmpdir(), "ci-triage-path-"));
  try {
    const bin = join(root, "bin");
    mkdirSync(bin);
    const marker = join(root, "UNTRUSTED_NODE_EXECUTED");
    const shim = join(bin, "node");
    writeFileSync(
      shim,
      '#!/bin/sh\nprintf "unsafe\\n" > ' + JSON.stringify(marker) + "\nexit 86\n",
    );
    chmodSync(shim, 0o700);
    const env = {
      ...process.env,
      PATH: bin + ":" + process.env.PATH,
      CLAWSWEEPER_CI_TRIAGE_ENABLED: "1",
      CLAWSWEEPER_CI_TRIAGE_SOURCE_SHA: "",
      CLAWSWEEPER_CI_TRIAGE_BOOTSTRAP_SHA256: "",
      CLAWSWEEPER_CI_TRIAGE_RUNTIME_MANIFEST_SHA256: "",
      CLAWSWEEPER_CI_TRIAGE_RUNTIME_MANIFEST: "",
    };
    for (const mode of ["notifier", "verified-notifier", "observer"]) {
      const result = spawnSync("/bin/sh", [launcher, mode, "--help"], {
        cwd: project, env, encoding: "utf8", timeout: 15000,
      });
      assert.notEqual(result.status, 0, result.stderr);
      assert.match(result.stderr, /preimport_pin_required/);
      assert.equal(existsSync(marker), false, mode + " must not launch PATH Node");
    }
    for (const mode of ["notifier", "unreviewed-job"]) {
      const result = spawnSync("/bin/sh", [launcher, mode, "--help"], {
        cwd: project,
        env: { ...env, CLAWSWEEPER_CI_TRIAGE_ENABLED: "surprise" },
        encoding: "utf8", timeout: 15000,
      });
      assert.equal(result.status, 64);
      assert.equal(existsSync(marker), false);
    }
    const script = readFileSync(join(project, launcher), "utf8");
    assert.match(script, /exec \/usr\/bin\/node dist\/repair\/notify-github-activity\.js/);
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
