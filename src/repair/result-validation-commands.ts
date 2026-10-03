import { parseAllowedValidationCommand } from "./validation-command-utils.js";

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
