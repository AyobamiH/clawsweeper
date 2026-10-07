// Classification verifies live maintainer permissions or a trusted exact-head verdict.
// These per-run inputs do not grant merge authority or change workflow defaults.
export function repairDispatchAuthorizationInputs(command: {
  maintainer_authorized?: unknown;
  trusted_bot?: unknown;
}): string[] {
  if (command.maintainer_authorized !== true && command.trusted_bot !== true) {
    throw new Error(
      "repair dispatch requires maintainer authorization or trusted ClawSweeper automation",
    );
  }
  return ["-f", "authorize_execute=true", "-f", "authorize_fix_pr=true"];
}
