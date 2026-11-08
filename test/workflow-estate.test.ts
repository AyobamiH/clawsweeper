import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, rmSync, writeFileSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { classifyRunner, inspectEstate, compareRegistry } from "../scripts/ci/workflow-estate.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

test("the entire workflow estate matches the review manifest", () => {
  const observed = inspectEstate(root);
  const manifest = JSON.parse(
    readFileSync(path.join(root, "config/ci-workflow-estate.json"), "utf8"),
  );
  assert.deepEqual(observed, manifest, "changed workflow bytes or jobs require explicit review");
  assert.ok(observed.summary.workflows >= 40);
  assert.ok(observed.summary.jobs >= 86);
  assert.equal(observed.jobs.length, observed.summary.jobs);
  assert.equal(
    new Set(observed.jobs.map((j) => j.workflow + "/" + j.id)).size,
    observed.jobs.length,
  );
  assert.equal(
    observed.summary.jobs,
    Object.entries(observed.summary)
      .filter(([k]) => !["workflows", "jobs"].includes(k))
      .reduce((count, [, value]) => count + value, 0),
  );
});

test("hosted fallback and local labels are not conflated", () => {
  assert.equal(classifyRunner("ubuntu-latest"), "github_hosted");
  assert.equal(classifyRunner("ubuntu-24.04"), "github_hosted");
  assert.equal(classifyRunner("windows-latest"), "github_hosted");
  assert.equal(classifyRunner("macos-15"), "github_hosted");
  assert.equal(
    classifyRunner("$" + "{{ input.lane || 'ubuntu-latest' }}"),
    "dynamic_hosted_fallback",
  );
  assert.equal(classifyRunner("$" + "{{ needs.provision.outputs.plan }}"), "dynamic_or_other");
  assert.equal(classifyRunner(["self-hosted", "Linux", "X64"]), "local_label");
  assert.equal(classifyRunner("ubuntu-latest, self-hosted"), "dynamic_or_other");
  assert.equal(classifyRunner(undefined), "dynamic_or_other");
});

test("registry-only entries are not claimed as live workflow sources", () => {
  const manifest = { sources: [{ path: ".github/workflows/current.yml" }] };
  const reg = compareRegistry(
    {
      workflows: [
        { id: 1, name: "Current", path: ".github/workflows/current.yml", state: "active" },
        { id: 2, name: "Legacy", path: ".github/workflows/legacy.yml", state: "active" },
      ],
    },
    manifest,
  );
  assert.equal(reg.registry_entries, 2);
  assert.deepEqual(
    reg.absent_from_main.map((w) => w.name),
    ["Legacy"],
  );
  assert.throws(() => compareRegistry({ anything: [] }, manifest));
});

test("source byte changes invalidate the pinned hash", () => {
  const base = mkdtempSync(path.join(tmpdir(), "clawsweeper-estate-"));
  try {
    const dir = path.join(base, ".github/workflows");
    mkdirSync(dir, { recursive: true });
    const file = path.join(dir, "safe.yml");
    writeFileSync(
      file,
      "name: Safe\non: [push]\njobs:\n  check:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo healthy\n",
    );
    const first = inspectEstate(base);
    assert.equal(first.summary.github_hosted, 1);
    writeFileSync(
      file,
      "name: Safe\non: [push]\njobs:\n  check:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo changed\n",
    );
    const next = inspectEstate(base);
    assert.notEqual(first.sources[0].sha256, next.sources[0].sha256);
    assert.notDeepEqual(first.jobs, next.jobs);
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});

test("workflow-level secrets and environment approvals reach every inherited job", () => {
  const estate = inspectEstate(root);
  for (const jobId of ["receipt", "capacity"]) {
    const record = estate.jobs.find(
      (j) => j.workflow === ".github/workflows/assist.yml" && j.id === jobId,
    );
    assert.ok(record, jobId);
    assert.ok(record.risks.includes("workflow_secret_inherited"), jobId);
  }
  const dir = mkdtempSync(path.join(tmpdir(), "clawsweeper-estate-inheritance-"));
  try {
    const folder = path.join(dir, ".github/workflows");
    mkdirSync(folder, { recursive: true });
    writeFileSync(
      path.join(folder, "probe.yml"),
      [
        "name: Inherited trust",
        "on: [workflow_dispatch]",
        "env:",
        "  PROVIDER: ${{ secrets.PROVIDER_KEY }}",
        "jobs:",
        "  fresh:",
        "    runs-on: ubuntu-latest",
        "    steps:",
        "      - run: echo safe",
        "  environment-bound:",
        "    runs-on: ubuntu-latest",
        "    environment: production",
        "    steps:",
        "      - run: echo safe",
        "  delegates:",
        "    uses: owner/repo/.github/workflows/gated.yml@main",
        "    secrets: inherit",
        "",
      ].join("\n"),
    );
    const inventory = inspectEstate(dir);
    assert.equal(inventory.summary.jobs, 3);
    const delegated = inventory.jobs.find((j) => j.id === "delegates");
    assert.ok(delegated?.risks.includes("reusable_secrets_inherit"));
    const fresh = inventory.jobs.find((j) => j.id === "fresh");
    const protectedJob = inventory.jobs.find((j) => j.id === "environment-bound");
    assert.ok(fresh?.risks.includes("workflow_secret_inherited"));
    assert.ok(protectedJob?.risks.includes("workflow_secret_inherited"));
    assert.ok(protectedJob?.risks.includes("environment_scoped"));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
