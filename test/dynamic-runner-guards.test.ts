import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { parseDocument } from "yaml";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

function workflow(name) {
  const source = readFileSync(path.join(root, ".github/workflows", name), "utf8");
  const doc = parseDocument(source, { strict: true, uniqueKeys: true });
  assert.deepEqual(doc.errors, [], name + " must be valid YAML");
  return doc.toJS();
}

function failOnSkippedProof(job, dependency, children) {
  const guard = job.steps.find((step) => step.name?.startsWith("Refuse stale or absent"));
  assert.ok(guard, "cleanup must report unavailable proof as failed");
  assert.match(guard.if, /always\(\)/);
  assert.match(guard.if, new RegExp("needs\\." + dependency + "\\.result == 'success'"));
  for (const child of children)
    assert.ok(guard.if.includes("needs." + child + ".result == 'skipped'"));
  assert.match(guard.run, /exit 1/);
  assert.ok(job.if?.includes("always()"), "cleanup must run following proof failure");
}

test("Cloudflare operator fixture is attempt-bound and never falls back to hosted validation", () => {
  const jobs = workflow("cloudflare-operator-fixtures.yml").jobs;
  const validation = jobs.validate;
  assert.match(validation["runs-on"], /needs\.launch\.outputs\.runner/);
  assert.match(validation["runs-on"], /clawsweeper-unprovisioned-runner-held/);
  assert.doesNotMatch(validation["runs-on"], /ubuntu-latest/);
  assert.match(validation.if, /needs\.launch\.result == 'success'/);
  assert.match(
    validation.if,
    /needs\.launch\.outputs\.attempt == format\('\{0\}', github\.run_attempt\)/,
  );
  assert.ok(validation.if.includes("startsWith(needs.launch.outputs.runner, 'csw-')"));
  assert.ok(validation.if.includes("endsWith(needs.launch.outputs.runner, '-execute')"));
  assert.equal(validation.needs, "launch");
  assert.deepEqual(jobs.cleanup.needs, ["launch", "validate"]);
  failOnSkippedProof(jobs.cleanup, "launch", ["validate"]);
});

test("Cloudflare repair proofs require fresh provisioned runners and preserve cleanup DAG", () => {
  const jobs = workflow("cloudflare-repair-provision.yml").jobs;
  for (const [name, runner] of [
    ["plan-proof", "plan"],
    ["execute-proof", "execute"],
  ]) {
    const proof = jobs[name];
    assert.ok(proof["runs-on"].includes("needs.provision.outputs." + runner));
    assert.ok(proof["runs-on"].includes("clawsweeper-unprovisioned-runner-held"));
    assert.doesNotMatch(proof["runs-on"], /ubuntu-latest/);
    assert.match(proof.if, /needs\.provision\.result == 'success'/);
    assert.match(
      proof.if,
      /needs\.provision\.outputs\.attempt == format\('\{0\}', github\.run_attempt\)/,
    );
    assert.ok(proof.if.includes("startsWith(needs.provision.outputs." + runner + ", 'csw-')"));
    assert.ok(
      proof.if.includes("endsWith(needs.provision.outputs." + runner + ", '-" + runner + "')"),
    );
    assert.equal(proof.needs, "provision");
  }
  assert.deepEqual(jobs.cleanup.needs, ["deploy", "provision", "plan-proof", "execute-proof"]);
  failOnSkippedProof(jobs.cleanup, "provision", ["plan-proof", "execute-proof"]);
  assert.deepEqual(jobs.review.needs, ["plan-proof", "execute-proof", "cleanup"]);
});

test("issue implementation intake remains owner configured, fail-closed and not event-selected", () => {
  const jobs = workflow("repair-issue-implementation-intake.yml").jobs;
  const intake = jobs.intake;
  // A repository variable must never be able to reroute privileged intake
  // to ubuntu-latest or another persistent/shared self-hosted runner.
  // Only an exact per-run-and-attempt privileged label is eligible.
  assert.equal(
    intake.if,
    "${{ vars.CLAWSWEEPER_ISSUE_IMPLEMENTATION_INTAKE_RUNNER == format('clawsweeper-ci-privileged-{0}-{1}-intake', github.run_id, github.run_attempt) }}",
  );
  assert.deepEqual(intake["runs-on"], [
    "self-hosted",
    "Linux",
    "X64",
    "${{ vars.CLAWSWEEPER_ISSUE_IMPLEMENTATION_INTAKE_RUNNER || 'clawsweeper-unprovisioned-runner-held' }}",
  ]);
  assert.equal(JSON.stringify(intake["runs-on"]).includes("client_payload"), false);
  assert.equal(JSON.stringify(intake["runs-on"]).includes("ubuntu-latest"), false);
});
