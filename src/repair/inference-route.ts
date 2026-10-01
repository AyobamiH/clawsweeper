#!/usr/bin/env node
import { selectInferenceRoute } from "../inference-router.js";

try {
  process.stdout.write(JSON.stringify(await selectInferenceRoute()));
} catch (error) {
  process.stdout.write(
    JSON.stringify({
      available: false,
      runner: "none",
      reason: error instanceof Error ? error.message : String(error),
    }),
  );
  process.exitCode = 1;
}
