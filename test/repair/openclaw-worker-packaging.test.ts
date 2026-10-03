import assert from "node:assert/strict";
import fs from "node:fs";
import test from "node:test";

test("repair build packages the OpenClaw process worker", () => {
  const tsconfig = JSON.parse(fs.readFileSync("tsconfig.repair.json", "utf8")) as {
    include?: string[];
  };
  assert.ok(
    tsconfig.include?.includes("src/openclaw-process-worker.ts"),
    "repair build must emit dist/openclaw-process-worker.js for the OpenClaw runtime",
  );
});
