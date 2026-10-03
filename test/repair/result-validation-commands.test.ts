import assert from "node:assert/strict";
import test from "node:test";
import { repairValidationCommandFailures } from "../../src/repair/result-validation-commands.ts";

test("repair result validation commands accept deterministic supported commands", () => {
  assert.deepEqual(
    repairValidationCommandFailures([
      "git diff --check",
      "pnpm check:changed",
      "node scripts/assert-file-text.mjs test/fixtures/example.txt EXPECTED",
    ]),
    [],
  );
});

test("repair result validation commands reject shell substitution before execution", () => {
  const failures = repairValidationCommandFailures([
    'test "$(cat test/fixtures/workers-ai-repair-acceptance.txt)" = "CLAWSWEEPER_WORKERS_AI_REPAIR_OK"',
    'test "$(wc -l < test/fixtures/workers-ai-repair-acceptance.txt)" -eq 1',
  ]);
  assert.equal(failures.length, 2);
  assert.match(failures[0] ?? "", /unsafe validation command/);
  assert.match(failures[1] ?? "", /unsafe validation command/);
});

test("repair result validation commands reject ambiguous shell composition", () => {
  const failures = repairValidationCommandFailures([
    "git diff --check && pnpm check:changed",
    "cat file | grep expected",
  ]);
  assert.equal(failures.length, 2);
});
