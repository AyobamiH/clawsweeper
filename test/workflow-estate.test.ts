import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, rmSync, writeFileSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  classifyRunner,
  classifyExecutionBoundary,
  inspectEstate,
  compareRegistry,
} from "../scripts/ci/workflow-estate.mjs";

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

test("ClawSweeper workflow estate cannot silently reintroduce billed GitHub-hosted runners", () => {
  const observed = inspectEstate(root);
  assert.ok(observed.summary.workflows >= 41, "do not drop audited workflows");
  assert.ok(observed.summary.jobs >= 88, "do not drop audited job definitions");
  assert.equal(
    observed.summary.github_hosted,
    0,
    "GitHub-hosted runners must never be reintroduced as a billing fallback",
  );
  assert.equal(
    observed.summary.dynamic_hosted_fallback,
    0,
    "dynamic runner expressions must not restore GitHub-hosted execution",
  );
  assert.deepEqual(
    observed.jobs
      .filter((job) => job.kind === "github_hosted" || job.kind === "dynamic_hosted_fallback")
      .map((job) => job.workflow + "/" + job.id),
    [],
    "list every offending exact workflow/job identity",
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

test("workflow-scoped secrets are inherited by jobs without direct secret references", () => {
  const base = mkdtempSync(path.join(tmpdir(), "clawsweeper-workflow-inherited-"));
  try {
    const dir = path.join(base, ".github/workflows");
    mkdirSync(dir, { recursive: true });
    writeFileSync(
      path.join(dir, "inherited.yml"),
      [
        "on: [push]",
        "env:",
        '  TOKEN: "${{ secrets.TOP_SECRET }}"',
        "jobs:",
        "  bare:",
        "    runs-on: ubuntu-latest",
        "    steps: [{ run: 'echo ok' }]",
      ].join("\n") + "\n",
    );
    const observed = inspectEstate(base);
    assert.deepEqual(observed.jobs[0].risks, ["workflow_secret_reference"]);
    assert.deepEqual(observed.jobs[0].needs, []);
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});

test("sensitive needs propagate transitively but not to unrelated jobs", () => {
  const base = mkdtempSync(path.join(tmpdir(), "clawsweeper-needs-"));
  try {
    const dir = path.join(base, ".github/workflows");
    mkdirSync(dir, { recursive: true });
    writeFileSync(
      path.join(dir, "chain.yml"),
      [
        "on: [push]",
        "jobs:",
        "  origin:",
        "    runs-on: ubuntu-latest",
        "    permissions: { contents: write }",
        "    steps: [{ run: 'echo origin' }]",
        "  middle:",
        "    needs: origin",
        "    runs-on: ubuntu-latest",
        "    steps: [{ run: 'echo middle' }]",
        "  final:",
        "    needs: [middle]",
        "    runs-on: ubuntu-latest",
        "    steps: [{ run: 'echo final' }]",
        "  unrelated:",
        "    runs-on: ubuntu-latest",
        "    steps: [{ run: 'echo unrelated' }]",
      ].join("\n") + "\n",
    );
    const byId = new Map(inspectEstate(base).jobs.map((job) => [job.id, job]));
    assert.ok(byId.get("origin").risks.includes("write_permission"));
    assert.ok(byId.get("middle").risks.includes("sensitive_upstream_dependency"));
    assert.ok(byId.get("final").risks.includes("sensitive_upstream_dependency"));
    assert.deepEqual(byId.get("unrelated").risks, []);
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});

test("unknown and cyclic needs fail closed instead of marking jobs safe", () => {
  const base = mkdtempSync(path.join(tmpdir(), "clawsweeper-invalid-needs-"));
  try {
    const dir = path.join(base, ".github/workflows");
    mkdirSync(dir, { recursive: true });
    const file = path.join(dir, "invalid.yml");
    const prefix = ["on: [push]", "jobs:", "  a:", "    runs-on: ubuntu-latest"];
    writeFileSync(file, [...prefix, "    needs: missing"].join("\n") + "\n");
    assert.throws(() => inspectEstate(base), /Unknown needs dependency/);
    writeFileSync(
      file,
      [...prefix, "    needs: b", "  b:", "    runs-on: ubuntu-latest", "    needs: a"].join("\n") +
        "\n",
    );
    assert.throws(() => inspectEstate(base), /Cyclic needs dependency/);
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});

test("every estate job has an explicit default-deny execution boundary", () => {
  const observed = inspectEstate(root);
  assert.equal(
    Object.values(observed.execution_boundaries).reduce((a, b) => a + b, 0),
    observed.summary.jobs,
  );
  assert.ok(
    observed.jobs.every((job) => job.execution_boundary && !/accepted|approved/.test(job.status)),
  );
  const crabbox = observed.jobs.filter((job) => job.workflow.endsWith("/crabbox-hydrate.yml"));
  assert.equal(crabbox.length, 1);
  assert.equal(crabbox[0].execution_boundary, "external_crabbox_ephemeral");
  assert.equal(crabbox[0].status, "external_ephemeral_not_generic_jit");
  assert.ok(crabbox[0].runs_on.includes("crabbox"));
});

test("sensitive, native Windows and dynamic jobs never become generic read-only jobs", () => {
  const fixture = (changes) => ({
    kind: "github_hosted",
    workflow: ".github/workflows/example.yml",
    runs_on: "ubuntu-latest",
    risks: [],
    ...changes,
  });
  assert.equal(
    classifyExecutionBoundary(fixture({ runs_on: "windows-2025", risks: ["write_permission"] })),
    "genuine_windows_required",
  );
  // The real native Windows job uses GitHub's exact 'Windows' runner label,
  // not a hosted windows-* image. Never classify it as generic local CI.
  assert.equal(
    classifyExecutionBoundary(
      fixture({ kind: "local_label", runs_on: ["self-hosted", "Windows", "X64"] }),
    ),
    "genuine_windows_required",
  );
  assert.equal(
    classifyExecutionBoundary(
      fixture({ kind: "local_label", runs_on: ["self-hosted", "Linux", "X64"] }),
    ),
    "local_label_unverified",
  );
  const windowsJob = inspectEstate(root).jobs.find(
    (job) => job.workflow.endsWith("/ci.yml") && job.id === "windows-codex-launch",
  );
  assert.ok(windowsJob, "the native Windows launcher must remain in the audit");
  assert.equal(windowsJob.execution_boundary, "genuine_windows_required");
  assert.ok(windowsJob.runs_on.includes("Windows"));
  assert.equal(
    classifyExecutionBoundary(fixture({ risks: ["sensitive_upstream_dependency"] })),
    "guarded_sensitive_effects",
  );
  assert.equal(
    classifyExecutionBoundary(fixture({ kind: "dynamic_or_other", runs_on: "${{ matrix.os }}" })),
    "dynamic_runner_requires_review",
  );
  assert.equal(
    classifyExecutionBoundary(
      fixture({ kind: "local_label", runs_on: ["self-hosted", "crabbox"] }),
    ),
    "external_crabbox_ephemeral",
  );
  assert.equal(
    classifyExecutionBoundary(fixture({ workflow: ".github/workflows/codeql.yml" })),
    "dedicated_codeql_security",
  );
});
