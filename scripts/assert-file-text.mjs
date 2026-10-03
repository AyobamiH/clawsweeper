#!/usr/bin/env node
import { readFileSync } from "node:fs";

const [, , filePath, expectedText] = process.argv;
if (!filePath || expectedText === undefined) {
  console.error("usage: node scripts/assert-file-text.mjs <path> <expected-text>");
  process.exit(2);
}

let actual;
try {
  actual = readFileSync(filePath, "utf8");
} catch {
  console.error("validation file could not be read");
  process.exit(1);
}

const expected = `${expectedText}\n`;
if (actual !== expected) {
  console.error("validation file content did not match the expected single line");
  process.exit(1);
}

console.log("exact text file validation passed");
