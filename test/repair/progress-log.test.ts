import assert from "node:assert/strict";
import test from "node:test";
import { formatRepairProgressLine } from "../../src/repair/progress-log.ts";

const when = new Date("2026-11-07T00:00:00Z");

test("fixed milestone remains observable without logging metadata values", () => {
  const message = formatRepairProgressLine(
    "starting fix execution",
    {
      repo: "demo/repo",
      token: "secret-would-leak-in-ci",
      error: "headers.Authorization=Bearer private-token",
      env: { GH_TOKEN: "private-token" },
    },
    when,
  );
  assert.match(message, /starting fix execution metadata_fields=4$/);
  assert.doesNotMatch(message, /secret-would-leak|Bearer|private-token|demo\/repo|Authorization/);
});

test("untrusted milestone names cannot reach shared GitHub Actions logs", () => {
  const arbitrary = "GitHub git credential setup failed; continuing\nTOKEN=abc123";
  const result = formatRepairProgressLine(arbitrary, {}, when);
  assert.match(result, / progress metadata_fields=0$/);
  assert.doesNotMatch(result, /TOKEN|abc123/);
});

test("record fields are bounded without inspecting getters or their values", () => {
  const values = {} as Record<string, unknown>;
  Object.defineProperty(values, "error", {
    enumerable: true,
    get() {
      throw new Error("secret getter must not be evaluated");
    },
  });
  assert.match(
    formatRepairProgressLine("preparing target toolchain", values, when),
    /metadata_fields=1$/,
  );
  assert.match(
    formatRepairProgressLine("starting fix execution", ["secret"], when),
    /metadata_fields=0$/,
  );
  assert.match(
    formatRepairProgressLine("starting fix execution", "secret", when),
    /metadata_fields=0$/,
  );
});
