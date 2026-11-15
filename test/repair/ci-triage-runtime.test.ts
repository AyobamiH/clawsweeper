import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { appendFileSync, chmodSync, copyFileSync, mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import {
  CI_TRIAGE_RUNTIME_FILES,
  cleanImplementationSha,
  runtimeDigests,
  verifiedImplementationSha,
} from "../../dist/repair/ci-triage-runtime.js";
import { CiTriageLedger } from "../../dist/repair/ci-triage-ledger.js";

function fixture() {
  const root = mkdtempSync(join(tmpdir(), "ci-runtime-proof-"));
  const git = (...args: string[]) =>
    execFileSync("git", ["-C", root, ...args], {
      encoding: "utf8",
      env: { ...process.env, GIT_CONFIG_GLOBAL: "/dev/null" },
      stdio: ["ignore", "pipe", "pipe"],
    }).trim();
  git("init", "-q");
  writeFileSync(join(root, "tracked.txt"), "source version 1\n");
  git("add", "tracked.txt");
  git(
    "-c",
    "user.name=Fixture",
    "-c",
    "user.email=fixture@example.invalid",
    "-c",
    "commit.gpgsign=false",
    "commit",
    "-qm",
    "fixture source",
  );
  for (const name of CI_TRIAGE_RUNTIME_FILES) {
    mkdirSync(dirname(join(root, name)), { recursive: true });
    writeFileSync(join(root, name), `// fixture ${name}\n`);
  }
  const sha = git("rev-parse", "HEAD");
  const manifest = join(root, "manifest.json");
  const value = {
    schema: "clawsweeper.ci-triage-runtime.v2",
    implementationSha: sha,
    files: runtimeDigests(root),
  };
  writeFileSync(manifest, JSON.stringify(value), { mode: 0o600 });
  return {
    root,
    manifest,
    sha,
    value,
    cleanup: () => rmSync(root, { recursive: true, force: true }),
  };
}

test("runtime identity binds committed source and actual executed JavaScript bytes", () => {
  const f = fixture();
  try {
    assert.equal(cleanImplementationSha(f.root), f.sha);
    assert.equal(verifiedImplementationSha(f.root, f.manifest), f.sha);
    writeFileSync(join(f.root, CI_TRIAGE_RUNTIME_FILES[0]), "// stale build\n");
    assert.throws(
      () => verifiedImplementationSha(f.root, f.manifest),
      /implementation_runtime_changed/,
    );
  } finally {
    f.cleanup();
  }
});

test("dirty source, wrong commit, missing manifest and public manifest fail closed", () => {
  const f = fixture();
  try {
    assert.throws(() => verifiedImplementationSha(f.root, undefined), /manifest_required/);
    chmodSync(f.manifest, 0o644);
    assert.throws(() => verifiedImplementationSha(f.root, f.manifest), /manifest_unsafe/);
    chmodSync(f.manifest, 0o600);
    writeFileSync(f.manifest, JSON.stringify({ ...f.value, implementationSha: "0".repeat(40) }));
    assert.throws(() => verifiedImplementationSha(f.root, f.manifest), /manifest_mismatch/);
    writeFileSync(f.manifest, JSON.stringify(f.value));
    writeFileSync(join(f.root, "tracked.txt"), "uncommitted mutation");
    assert.throws(() => verifiedImplementationSha(f.root, f.manifest), /source_unverified/);
  } finally {
    f.cleanup();
  }
});

test("ledger refuses symlinked state and world-readable directories", () => {
  const root = mkdtempSync(join(tmpdir(), "ci-ledger-path-"));
  try {
    const state = join(root, "state");
    mkdirSync(state, { mode: 0o700 });
    const alias = join(root, "alias");
    symlinkSync(state, alias);
    assert.throws(() => new CiTriageLedger(alias), /state_directory_unsafe/);
    chmodSync(state, 0o755);
    assert.throws(() => new CiTriageLedger(state), /state_directory_unsafe/);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});


test("full production ESM closure binds transitive config, json-types and lib before application import", () => {
  const project = resolve(dirname(fileURLToPath(import.meta.url)), "../..");
  const actual = runtimeDigests(project);
  for (const name of [
    "dist/repair/config.js",
    "dist/repair/json-types.js",
    "dist/repair/lib.js",
  ]) {
    assert.equal(typeof actual[name], "string", `missing protected ${name}`);
  }
  assert.ok(Object.keys(actual).length >= 35, "complete executable closure, not seven entrypoints");
  const f = fixture();
  try {
    for (const name of Object.keys(actual)) {
      mkdirSync(dirname(join(f.root, name)), { recursive: true });
      copyFileSync(join(project, name), join(f.root, name));
    }
    const expanded = { ...f.value, files: runtimeDigests(f.root) };
    writeFileSync(f.manifest, JSON.stringify(expanded));
    assert.equal(verifiedImplementationSha(f.root, f.manifest), f.sha);
    const canary = "globalThis.__unverified_ci_triage_import_side_effect = 1;\n";
    appendFileSync(join(f.root, "dist/repair/config.js"), canary);
    assert.throws(
      () => verifiedImplementationSha(f.root, f.manifest),
      /implementation_runtime_changed/,
    );
    assert.equal(
      (globalThis as Record<string, unknown>).__unverified_ci_triage_import_side_effect,
      undefined,
      "tampered transitive module must not execute during verification",
    );
  } finally {
    f.cleanup();
  }
});

test("runtime closure refuses dynamic import, package resolution and unlisted modules", () => {
  const f = fixture();
  try {
    const entry = join(f.root, CI_TRIAGE_RUNTIME_FILES[0]);
    writeFileSync(entry, 'import("./unlisted.js");\n');
    assert.throws(() => runtimeDigests(f.root), /runtime_dynamic_import/);
    writeFileSync(entry, 'import /* unsupported */ ("./unlisted.js");\n');
    assert.throws(() => runtimeDigests(f.root), /runtime_dynamic_import/);
    writeFileSync(entry, 'import express from "express";\n');
    assert.throws(() => runtimeDigests(f.root), /runtime_package_unsupported/);
    writeFileSync(entry, 'export {\n  unlisted\n} from "./unlisted.js";\n');
    assert.throws(() => runtimeDigests(f.root), /runtime_import_unsupported/);
    writeFileSync(entry, 'import "./missing.js";\n');
    assert.throws(() => runtimeDigests(f.root), /implementation_manifest_unavailable|ENOENT/);
  } finally {
    f.cleanup();
  }
});
