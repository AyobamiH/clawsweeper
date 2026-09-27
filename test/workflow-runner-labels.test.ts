import assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import test from "node:test";
import { parse } from "yaml";

test("active workflows cannot select Blacksmith runners", () => {
  for (const name of readdirSync(".github/workflows").filter((entry) => /\.ya?ml$/.test(entry))) {
    const text = readFileSync(join(".github/workflows", name), "utf8");
    assert.doesNotMatch(text, /blacksmith-/i, name);
  }
});

test("repair jobs use provisioned Cloudflare identities and always clean up", () => {
  const workflow = parse(readFileSync(".github/workflows/repair-cluster-worker.yml", "utf8"));
  assert.equal(workflow.concurrency.group, "cloudflare-repair-compute");
  assert.equal(workflow.concurrency["cancel-in-progress"], false);
  assert.equal(workflow.jobs.cluster["runs-on"], "${{ needs.provision.outputs.plan }}");
  assert.equal(workflow.jobs.execute["runs-on"], "${{ needs.provision.outputs.execute }}");
  assert.deepEqual(workflow.jobs.cleanup.needs, ["receipt", "provision", "cluster", "execute"]);
  assert.match(workflow.jobs.cleanup.if, /always\(\)/);
  assert.equal(workflow.env.CLAWSWEEPER_RUNNER, "codex");
  assert.equal(workflow.env.OPENAI_API_KEY, "");
  assert.equal(workflow.env.CLAWSWEEPER_QUOTA_ENABLED, "1");
  assert.equal(workflow.env.CLAWSWEEPER_REVIEW_REPO, "${{ github.repository }}");
});
