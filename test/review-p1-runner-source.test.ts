import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { parse as parseYaml } from "yaml";

const parse = (name: string): any => parseYaml(readFileSync(".github/workflows/" + name, "utf8"));
const expr = (name: string) => "$" + "{{ " + name + " }}";

test("privileged repair orchestration requires immutable JIT source", () => {
  const workflow = parse("repair-cluster-worker.yml");
  for (const id of ["receipt", "provision", "cleanup"]) {
    const job = workflow.jobs[id];
    assert.deepEqual(job["runs-on"], [
      "self-hosted",
      "Linux",
      "X64",
      "clawsweeper-ci-ops-" + expr("github.run_id") + "-repair-" + id,
    ]);
    const steps = job.steps;
    const preflight = steps.findIndex(
      (s: any) => s.name === "Require owner-approved immutable workflow source before checkout",
    );
    const checkout = steps.findIndex((s: any) => s.uses === "actions/checkout@v7");
    const verify = steps.findIndex(
      (s: any) => s.name === "Verify checked-out approved tooling before local actions",
    );
    assert.equal(preflight, 0);
    assert.ok(verify > checkout && checkout > preflight);
    assert.match(steps[preflight].run, /test "\$GITHUB_REF" = "refs\/heads\/main"/);
    assert.match(steps[preflight].run, /test "\$GITHUB_SHA" = "\$APPROVED_SHA"/);
    assert.equal(steps[checkout].with.ref, expr("vars.CLAWSWEEPER_TRUSTED_MAIN_SHA"));
    assert.match(steps[verify].run, /git rev-parse HEAD/);
  }
});

test("disposable compute output never permits owner-runner fallback", () => {
  const workflow = parse("repair-cluster-worker.yml");
  const { provision, cluster, execute } = workflow.jobs;
  for (const field of ["plan", "execute", "attempt"]) {
    assert.equal(provision.outputs[field], expr("steps.validate_outputs.outputs." + field));
  }
  const check = provision.steps.find((step: any) => step.id === "validate_outputs");
  assert.ok(check);
  assert.match(check.run, /test "\$ATTEMPT" = "\$GITHUB_RUN_ATTEMPT"/);
  assert.match(check.run, /test "\$PLAN" = "csw-\$nonce-plan"/);
  assert.match(check.run, /test "\$EXECUTE" = "csw-\$nonce-execute"/);
  for (const job of [cluster, execute]) {
    for (const fragment of [
      "needs.provision.result == 'success'",
      "needs.provision.outputs.plan != ''",
      "needs.provision.outputs.execute != ''",
      "needs.provision.outputs.attempt",
    ])
      assert.ok(job.if.includes(fragment), fragment);
    assert.doesNotMatch(job["runs-on"], /clawsweeper-operations|CLAWSWEEPER_OPERATIONAL_RUNNER/);
  }
  const tmp = mkdtempSync(join(tmpdir(), "csw-provision-"));
  try {
    const repo = "AyobamiH/clawsweeper",
      runId = "12345678";
    const nonce = spawnSync(
      "bash",
      ["-c", 'printf "%s" "$GITHUB_REPOSITORY:$GITHUB_RUN_ID" | sha256sum | cut -c1-16'],
      { encoding: "utf8", env: { ...process.env, GITHUB_REPOSITORY: repo, GITHUB_RUN_ID: runId } },
    ).stdout.trim();
    const validEnv = {
      ...process.env,
      GITHUB_REPOSITORY: repo,
      GITHUB_RUN_ID: runId,
      GITHUB_RUN_ATTEMPT: "4",
      ATTEMPT: "4",
      GITHUB_OUTPUT: join(tmp, "output"),
      PLAN: "csw-" + nonce + "-plan",
      EXECUTE: "csw-" + nonce + "-execute",
    };
    const valid = spawnSync("bash", ["-e", "-c", check.run], { env: validEnv, encoding: "utf8" });
    assert.equal(valid.status, 0, valid.stderr);
    assert.match(readFileSync(validEnv.GITHUB_OUTPUT, "utf8"), /plan=csw-/);
    for (const change of [
      { PLAN: "" },
      { EXECUTE: "" },
      { ATTEMPT: "3" },
      { PLAN: "clawsweeper-operations" },
      { EXECUTE: "clawsweeper-operations" },
      { PLAN: "csw-" + nonce + "-execute" },
      { EXECUTE: "csw-" + nonce + "-plan" },
    ]) {
      const result = spawnSync("bash", ["-e", "-c", check.run], {
        env: { ...validEnv, ...change },
        encoding: "utf8",
      });
      assert.notEqual(result.status, 0, JSON.stringify(change));
    }
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
});

test("release review and offline replay use isolated, trusted-main source only", () => {
  for (const [file, jobId, slot] of [
    ["workers-ai-fallback-acceptance.yml", "release-source-review", "release-review"],
    ["release-offline-replay.yml", "replay", "offline-replay"],
  ]) {
    const job = parse(file).jobs[jobId];
    assert.deepEqual(job["runs-on"], [
      "self-hosted",
      "Linux",
      "X64",
      "clawsweeper-ci-ops-" + expr("github.run_id") + "-" + slot,
    ]);
    const steps = job.steps;
    const guard = steps.findIndex(
      (s: any) => s.name === "Require owner-approved immutable workflow source before checkout",
    );
    const checkout = steps.findIndex((s: any) => s.uses === "actions/checkout@v7");
    const verify = steps.findIndex(
      (s: any) => s.name === "Verify checked-out approved tooling before local actions",
    );
    assert.ok(guard >= 0 && checkout > guard && verify > checkout);
    assert.match(steps[guard].run, /GITHUB_SHA/);
    assert.equal(steps[checkout].with.ref, expr("vars.CLAWSWEEPER_TRUSTED_MAIN_SHA"));
    assert.doesNotMatch(
      JSON.stringify(job.env ?? {}),
      /CLOUDFLARE_WORKERS_AI_TOKEN|CLAWSWEEPER_QUOTA_SECRET/,
    );
  }
  const review = parse("workers-ai-fallback-acceptance.yml").jobs["release-source-review"];
  const step = review.steps.find((s: any) => s.name === "Review exact source without mutation");
  assert.equal(step.env.CLOUDFLARE_WORKERS_AI_TOKEN, expr("secrets.CLOUDFLARE_WORKERS_AI_TOKEN"));
  assert.equal(step.env.CLAWSWEEPER_QUOTA_SECRET, expr("secrets.CLAWSWEEPER_QUOTA_SECRET"));
});
