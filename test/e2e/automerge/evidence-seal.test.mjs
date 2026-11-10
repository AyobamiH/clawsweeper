import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { AUTOMERGE_E2E_SCENARIOS } from "./run.mjs";
import { AUTOMERGE_E2E_FIXTURES } from "./target-fixtures.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../..");
const sealer = path.join(root, "scripts/e2e/seal-automerge-evidence.mjs");
const sha = "567a3755ba1e097a100c62ace90f89cdafe72b36";
const fakeRunId = "900000002";
const sha256 = (bytes) => crypto.createHash("sha256").update(bytes).digest("hex");

function fixture(t, mutate = () => {}) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "csw-e2e-seal-"));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const input = path.join(dir, "input");
  const vault = path.join(dir, "private-vault");
  fs.mkdirSync(input);
  fs.mkdirSync(vault);
  for (const fixture of AUTOMERGE_E2E_FIXTURES) {
    for (const scenario of AUTOMERGE_E2E_SCENARIOS) {
      const destination = path.join(input, fixture, scenario);
      fs.mkdirSync(destination, { recursive: true });
      fs.writeFileSync(
        path.join(destination, "summary.json"),
        JSON.stringify({ fixture, scenario, status: "passed" }) + "\n",
      );
      fs.writeFileSync(path.join(destination, "details.log"), "test-only-artifact\n");
    }
  }
  mutate({ input, vault, dir });
  const args = [sealer, "--input", input, "--vault", vault, "--expected-head", sha];
  const env = {
    ...process.env,
    GITHUB_RUN_ID: fakeRunId,
    GITHUB_RUN_ATTEMPT: "1",
    GITHUB_SHA: sha,
  };
  const execute = (overrides = {}) =>
    spawnSync(process.execPath, args, {
      encoding: "utf8",
      timeout: 10_000,
      env: { ...env, ...overrides },
    });
  return { input, vault, execute, name: "run-" + fakeRunId + "-attempt-1" };
}

test("seals the unreduced 28 cases with independently verifiable hashes", (t) => {
  const { vault, execute, name } = fixture(t);
  const result = execute();
  assert.equal(result.status, 0, result.stderr);
  const full = path.join(vault, name);
  const receiptBytes = fs.readFileSync(path.join(full, "receipt.json"));
  const receipt = JSON.parse(receiptBytes.toString());
  const manifestBytes = fs.readFileSync(path.join(full, "manifest.json"));
  const manifest = JSON.parse(manifestBytes.toString());
  assert.equal(receipt.verdict, "SEALED_28_CASES");
  assert.equal(receipt.scenario_count, 28);
  assert.equal(receipt.expected_cases, 28);
  assert.equal(receipt.checkout_sha, sha);
  assert.equal(fs.statSync(full).mode & 0o777, 0o755);
  assert.equal(fs.statSync(path.join(full, "tiny/happy-path")).mode & 0o777, 0o755);
  assert.equal(fs.statSync(path.join(full, "tiny/happy-path/summary.json")).mode & 0o777, 0o644);
  assert.equal(receipt.source_head_sha, sha);
  assert.equal(manifest.source_head, sha);
  assert.equal(manifest.files.length, 56);
  assert.equal(receipt.manifest_sha256, sha256(manifestBytes));
  assert.equal(
    fs.readFileSync(path.join(full, "receipt.sha256"), "utf8").trim(),
    sha256(receiptBytes) + "  receipt.json",
  );
  for (const entry of manifest.files) {
    assert.equal(sha256(fs.readFileSync(path.join(full, entry.path))), entry.sha256);
  }
  assert.equal(fs.existsSync(path.join(vault, "." + name + ".partial")), false);
  assert.equal(execute().status, 1, "must refuse a second attempt with the same identity");
});

test("missing scenario cannot be sealed or promoted to accepted", (t) => {
  const { vault, execute, name } = fixture(t, ({ input }) => {
    fs.rmSync(path.join(input, "openclaw-shaped", "final-review-malformed-race", "summary.json"));
  });
  const result = execute();
  assert.equal(result.status, 5, result.stderr);
  assert.equal(fs.existsSync(path.join(vault, name)), false);
  const partial = path.join(vault, "." + name + ".partial");
  const receipt = JSON.parse(fs.readFileSync(path.join(partial, "receipt.json"), "utf8"));
  assert.equal(receipt.verdict, "NOT_VERIFIED");
  assert.deepEqual(receipt.missing_or_failed, ["openclaw-shaped/final-review-malformed-race"]);
});

test("failed scenario is retained as a non-passing partial receipt", (t) => {
  const { vault, execute, name } = fixture(t, ({ input }) => {
    fs.writeFileSync(
      path.join(input, "tiny", "happy-path", "summary.json"),
      JSON.stringify({ status: "failed", fixture: "tiny", scenario: "happy-path" }) + "\n",
    );
  });
  const result = execute();
  assert.equal(result.status, 5, result.stderr);
  assert.equal(fs.existsSync(path.join(vault, name)), false);
});

test("symlinked evidence fails before creating an accepted proof", (t) => {
  const { vault, execute, name } = fixture(t, ({ input }) => {
    fs.symlinkSync("/etc/passwd", path.join(input, "tiny", "happy-path", "escape"));
  });
  const result = execute();
  assert.equal(result.status, 1);
  assert.match(result.stderr, /symbolic link/);
  assert.equal(fs.existsSync(path.join(vault, name)), false);
});

test("missing authoritative GitHub run identity is refused", (t) => {
  const { vault, execute, name } = fixture(t);
  const result = execute({ GITHUB_SHA: "not-a-commit" });
  assert.equal(result.status, 1);
  assert.equal(fs.existsSync(path.join(vault, name)), false);
});
