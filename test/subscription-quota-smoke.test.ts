import assert from "node:assert/strict";
import fs from "node:fs";
import test from "node:test";

function read(path: string) {
  return fs.readFileSync(path, "utf8");
}

test("allowance read degrades to provider-unavailable JSON without failing CI", () => {
  const worker = read("src/subscription-quota-worker.ts");
  assert.match(worker, /command === "read"/);
  assert.match(worker, /available: false/);
  assert.match(worker, /windows: \[\]/);
  assert.match(worker, /error: "chatgpt_allowance_unavailable"/);
  const readFailure = worker.slice(worker.indexOf('if (command === "read")'));
  assert.ok(
    readFailure.indexOf("process.exitCode = 1") > readFailure.indexOf("} else {"),
    "read-mode provider unavailability must not set a failing process exit code",
  );
});

test("CI classifies unavailable Codex allowance and proves refusal boundaries", () => {
  const workflow = read(".github/workflows/ci.yml");
  assert.match(workflow, /available="\$\(jq -r '\.available == true'/);
  assert.match(workflow, /reason="\$\(jq -r '/);
  assert.match(workflow, /Codex provider unavailable/);
  assert.match(workflow, /steps\.allowance\.outputs\.available != 'true'/);
  assert.match(workflow, /hosted-review-scan-smoke\.mjs .*--refusal-only/);
});
