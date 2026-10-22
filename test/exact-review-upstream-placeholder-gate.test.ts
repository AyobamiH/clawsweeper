import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import { parse } from "yaml";

test("upstream OpenClaw placeholder recovery is explicit opt-in maintenance", () => {
  const source = readFileSync(".github/workflows/exact-review-reconcile.yml", "utf8");
  const workflow = parse(source) as {
    jobs?: Record<
      string,
      {
        steps?: Array<{
          name?: string;
          if?: string;
          with?: Record<string, string>;
          env?: Record<string, string>;
        }>;
      }
    >;
  };
  const steps = Object.values(workflow.jobs ?? {}).flatMap((job) => job.steps ?? []);
  const token = steps.find((step) => step.name === "Create target write token");
  const recover = steps.find((step) => step.name === "Recover orphaned review placeholders");
  const gate = "vars.CLAWSWEEPER_ENABLE_UPSTREAM_OPENCLAW_PLACEHOLDER_RECOVERY == '1'";

  assert.match(token?.if ?? "", /CLAWSWEEPER_ENABLE_UPSTREAM_OPENCLAW_PLACEHOLDER_RECOVERY/);
  assert.match(recover?.if ?? "", /CLAWSWEEPER_ENABLE_UPSTREAM_OPENCLAW_PLACEHOLDER_RECOVERY/);
  assert.ok((token?.if ?? "").includes(gate));
  assert.ok((recover?.if ?? "").includes(gate));
  assert.equal(token?.with?.owner, "openclaw");
  assert.equal(token?.with?.repositories, "openclaw");
  assert.equal(recover?.env?.TARGET_REPO, "openclaw/openclaw");
});
