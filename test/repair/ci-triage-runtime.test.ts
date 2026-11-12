import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { chmodSync, mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import test from "node:test";
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
    schema: "clawsweeper.ci-triage-runtime.v1",
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
