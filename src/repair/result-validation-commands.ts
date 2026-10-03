import { parseAllowedValidationCommand } from "./validation-command-utils.js";

const EXACT_TEXT_ASSERTION = /^test "\$\(cat ([A-Za-z0-9_./-]+)\)" = "([A-Za-z0-9_.:+/-]+)"$/;
const EXACT_LINE_COUNT_ASSERTION = /^test "\$\(wc -l < ([A-Za-z0-9_./-]+)\)" -eq ([0-9]+)$/;
const EXACT_BYTE_COUNT_ASSERTION = /^test "\$\(wc -c < ([A-Za-z0-9_./-]+)\)" -eq ([0-9]+)$/;

export function normalizeRepairValidationCommands(value: unknown): {
  commands: unknown;
  changed: boolean;
} {
  if (!Array.isArray(value)) return { commands: value, changed: false };

  const exactByPath = new Map<string, string>();
  for (const command of value) {
    if (typeof command !== "string") continue;
    const match = EXACT_TEXT_ASSERTION.exec(command.trim());
    if (!match) continue;
    const [, filePath, expectedText] = match;
    if (!filePath || expectedText === undefined) continue;
    exactByPath.set(filePath, expectedText);
  }

  let changed = false;
  const normalized: string[] = [];
  const emittedExact = new Set<string>();

  for (const command of value) {
    if (typeof command !== "string") {
      normalized.push(String(command));
      continue;
    }
    const trimmed = command.trim();
    const exact = EXACT_TEXT_ASSERTION.exec(trimmed);
    if (exact) {
      const [, filePath, expectedText] = exact;
      if (!filePath || expectedText === undefined) {
        normalized.push(command);
        continue;
      }
      const canonical = `node scripts/assert-file-text.mjs ${filePath} ${expectedText}`;
      parseAllowedValidationCommand(canonical);
      if (!emittedExact.has(filePath)) {
        normalized.push(canonical);
        emittedExact.add(filePath);
      }
      changed = true;
      continue;
    }

    const lineCount = EXACT_LINE_COUNT_ASSERTION.exec(trimmed);
    if (lineCount) {
      const [, filePath, countText] = lineCount;
      const expected = filePath ? exactByPath.get(filePath) : undefined;
      if (expected !== undefined && countText === "1") {
        changed = true;
        continue;
      }
    }

    const byteCount = EXACT_BYTE_COUNT_ASSERTION.exec(trimmed);
    if (byteCount) {
      const [, filePath, countText] = byteCount;
      const expected = filePath ? exactByPath.get(filePath) : undefined;
      if (
        expected !== undefined &&
        Number(countText) === Buffer.byteLength(`${expected}\n`, "utf8")
      ) {
        changed = true;
        continue;
      }
    }

    normalized.push(command);
  }

  return { commands: normalized, changed };
}

export function repairValidationCommandFailures(value: unknown): string[] {
  if (!Array.isArray(value)) return [];
  const failures: string[] = [];
  for (const command of value) {
    try {
      parseAllowedValidationCommand(command);
    } catch (error) {
      failures.push(
        `fix_artifact.validation_commands contains unsupported or unsafe command: ${
          error instanceof Error ? error.message : String(error)
        }`,
      );
    }
  }
  return failures;
}
