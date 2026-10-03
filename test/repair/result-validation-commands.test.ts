import assert from "node:assert/strict";
import test from "node:test";
import {
  normalizeRepairValidationCommands,
  repairValidationCommandFailures,
} from "../../dist/repair/result-validation-commands.js";

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

test("normalizer canonicalizes an exact text assertion and removes redundant matching counts", () => {
  const normalized = normalizeRepairValidationCommands([
    'test "$(cat test/fixtures/workers-ai-repair-acceptance.txt)" = "CLAWSWEEPER_WORKERS_AI_REPAIR_OK"',
    'test "$(wc -l < test/fixtures/workers-ai-repair-acceptance.txt)" -eq 1',
    'test "$(wc -c < test/fixtures/workers-ai-repair-acceptance.txt)" -eq 33',
    "git diff --check",
  ]);
  assert.equal(normalized.changed, true);
  assert.deepEqual(normalized.commands, [
    "node scripts/assert-file-text.mjs test/fixtures/workers-ai-repair-acceptance.txt CLAWSWEEPER_WORKERS_AI_REPAIR_OK",
    "git diff --check",
  ]);
  assert.deepEqual(repairValidationCommandFailures(normalized.commands), []);
});

test("normalizer does not silently repair unmatched count assertions", () => {
  const commands = [
    'test "$(wc -l < test/fixtures/example.txt)" -eq 1',
    'test "$(wc -c < test/fixtures/example.txt)" -eq 7',
  ];
  const normalized = normalizeRepairValidationCommands(commands);
  assert.equal(normalized.changed, false);
  assert.deepEqual(normalized.commands, commands);
  assert.equal(repairValidationCommandFailures(normalized.commands).length, 2);
});

test("normalizer preserves ambiguous shell composition for fail-closed rejection", () => {
  const commands = ["git diff --check && pnpm check:changed", "cat file | grep expected"];
  const normalized = normalizeRepairValidationCommands(commands);
  assert.equal(normalized.changed, false);
  assert.deepEqual(normalized.commands, commands);
  assert.equal(repairValidationCommandFailures(normalized.commands).length, 2);
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
