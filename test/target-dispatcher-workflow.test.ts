import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import { parse } from "yaml";

const liveWorkflow = readFileSync(".github/workflows/clawsweeper-dispatch.yml", "utf8").replace(
  /\r\n/g,
  "\n",
);
const documentation = readFileSync("docs/target-dispatcher.md", "utf8").replace(/\r\n/g, "\n");
const templateMatch = documentation.match(/```yaml\n(name: ClawSweeper Dispatch[\s\S]*?)\n```/);

assert.ok(templateMatch, "target dispatcher workflow template is missing");
const documentedWorkflow = `${templateMatch[1]}\n`;

type WorkflowStep = {
  name?: string;
  if?: string;
  run?: string;
  env?: Record<string, string>;
  with?: Record<string, string>;
  "continue-on-error"?: boolean;
};

function dispatchSteps(source: string): WorkflowStep[] {
  const workflow = parse(source) as {
    jobs?: { dispatch?: { steps?: WorkflowStep[] } };
  };
  return workflow.jobs?.dispatch?.steps ?? [];
}

function namedStep(steps: WorkflowStep[], name: string): WorkflowStep {
  const step = steps.find((candidate) => candidate.name === name);
  assert.ok(step, `missing workflow step: ${name}`);
  return step;
}

function normalizeWhitespace(value: string | undefined): string {
  return (value ?? "").replace(/\s+/g, " ").trim();
}

test("external target dispatcher and owner-operated CI preserve identical dispatch behaviour", () => {
  // The external copyable template has no access to the owner's locally
  // installed JIT runner or Git-ref claim script. Every actual dispatch,
  // event trigger and credential boundary stays identical. Only the owner
  // runner and optional acknowledgement implementations may differ.
  const documented = parse(documentedWorkflow);
  const local = parse(liveWorkflow);
  assert.deepEqual(local.on, documented.on);
  assert.deepEqual(local.concurrency, documented.concurrency);
  assert.deepEqual(local.permissions, documented.permissions);
  assert.equal(documented.jobs.dispatch["runs-on"], "ubuntu-latest");
  assert.deepEqual(local.jobs.dispatch["runs-on"], [
    "self-hosted",
    "Linux",
    "X64",
    "clawsweeper-ci-ops-${{ github.run_id }}-dispatch",
  ]);
  assert.doesNotMatch(liveWorkflow, /runs-on: ubuntu-(latest|24\.04)/);
  const localSteps = dispatchSteps(liveWorkflow).filter(
    (step) => step.name !== "Checkout trusted workflow source for durable comment claims",
  );
  const documentedSteps = dispatchSteps(documentedWorkflow);
  assert.deepEqual(
    localSteps.map((step) => step.name),
    documentedSteps.map((step) => step.name),
  );
  const acknowledgementNames = new Set([
    "Acknowledge received pull request",
    "Acknowledge and dispatch ClawSweeper comment",
  ]);
  for (let i = 0; i < localSteps.length; i++) {
    if (!acknowledgementNames.has(localSteps[i].name ?? "")) {
      assert.deepEqual(localSteps[i], documentedSteps[i]);
      continue;
    }
    assert.equal(localSteps[i].if, documentedSteps[i].if);
    assert.equal(localSteps[i]["continue-on-error"], documentedSteps[i]["continue-on-error"]);
  }
});

test("target dispatcher acknowledges non-draft PR receipts before review dispatch", () => {
  for (const source of [liveWorkflow, documentedWorkflow]) {
    const steps = dispatchSteps(source);
    const tokenIndex = steps.findIndex(
      (step) => step.name === "Create target PR acknowledgement token",
    );
    const acknowledgementIndex = steps.findIndex(
      (step) => step.name === "Acknowledge received pull request",
    );
    const dispatchIndex = steps.findIndex(
      (step) => step.name === "Dispatch exact ClawSweeper review",
    );
    assert.ok(tokenIndex >= 0 && tokenIndex < acknowledgementIndex);
    assert.ok(acknowledgementIndex < dispatchIndex);

    const token = namedStep(steps, "Create target PR acknowledgement token");
    const acknowledgement = namedStep(steps, "Acknowledge received pull request");
    const expectedGate = [
      "${{",
      "github.event_name == 'pull_request_target' &&",
      "(",
      "github.event.action == 'ready_for_review' ||",
      "(github.event.action == 'opened' && github.event.pull_request.draft == false)",
      ") &&",
      "env.HAS_CLAWSWEEPER_APP_PRIVATE_KEY == 'true'",
      "}}",
    ].join(" ");

    assert.equal(normalizeWhitespace(token.if), expectedGate);
    assert.equal(normalizeWhitespace(acknowledgement.if), expectedGate);
    assert.equal(token["continue-on-error"], true);
    assert.equal(acknowledgement["continue-on-error"], true);
    assert.deepEqual(
      Object.keys(token.with ?? {}).filter((key) => key.startsWith("permission-")),
      ["permission-issues"],
    );
    assert.equal(token.with?.["permission-issues"], "write");
    assert.equal(acknowledgement.env?.ACK_TOKEN, "${{ steps.pr_ack_token.outputs.token }}");

    const run = acknowledgement.run ?? "";
    if (source === liveWorkflow) {
      assert.match(run, /comment-effect-claim\.mjs scan/);
      assert.match(run, /comment-effect-claim\.mjs claim/);
      assert.match(run, /Acknowledgement inventory unverifiable; refusing POST/);
      assert.doesNotMatch(run, /issues\/\$ITEM_NUMBER\/comments\?per_page=100/);
      assert.equal(acknowledgement.env?.CLAIM_TOKEN, "${{ steps.token.outputs.token }}");
    } else {
      assert.match(run, /issues\/\$ITEM_NUMBER\/comments\?per_page=100/);
      assert.match(run, /--arg marker_prefix "clawsweeper-pr-ack:"/);
      assert.match(run, /--arg marker_suffix " item=\$ITEM_NUMBER -->"/);
    }
    assert.match(run, /"<!-- clawsweeper-pr-ack:\$SOURCE_ACTION item=\$ITEM_NUMBER -->"/);
    assert.match(
      run,
      /"Pull request received\. I will update this pull request when review starts\."/,
    );
    assert.match(run, /issues\/\$ITEM_NUMBER\/comments"\s*\\\s*--method POST/);
  }
});
