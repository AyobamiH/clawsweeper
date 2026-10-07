import type { JsonValue } from "./json-types.js";

export function shouldCloseSupersededSourcePrs(value: JsonValue) {
  return parseBooleanEnv(value, true);
}

export function shouldSeedReplacementBranchFromSource(fixArtifact: JsonValue) {
  return String(fixArtifact?.repair_strategy ?? "") === "replace_uneditable_branch";
}

export function sourceBranchWriteBlockReason(repo: string, pullRequest: JsonValue) {
  const headRepo = String(pullRequest?.head?.repo?.full_name ?? "");
  const headRef = String(pullRequest?.head?.ref ?? "");
  if (!headRepo || !headRef) return "source PR is missing head repo/ref";
  if (headRepo.toLowerCase() === repo.toLowerCase()) return null;
  if (pullRequest?.maintainer_can_modify === true) return null;
  return "source PR branch is a fork with maintainer_can_modify=false";
}

export function noRebasePublicationBlockReason({
  allowRebase,
  sourceRewritten,
}: {
  allowRebase: boolean;
  sourceRewritten: boolean;
}) {
  if (allowRebase || !sourceRewritten) return null;
  return "repair publication would rewrite source ancestry while rebasing is forbidden";
}

export function noRebaseWritablePassBlockReason({
  allowRebase,
  headBefore,
  headAfter,
  rebaseInProgress,
  mergeInProgress,
  unmergedPaths,
}: {
  allowRebase: boolean;
  headBefore: string;
  headAfter: string;
  rebaseInProgress: boolean;
  mergeInProgress: boolean;
  unmergedPaths: string[];
}) {
  if (allowRebase) return null;
  if (headAfter !== headBefore)
    return "writable repair pass changed HEAD while rebasing is forbidden";
  if (rebaseInProgress)
    return "writable repair pass left a rebase in progress while rebasing is forbidden";
  if (mergeInProgress)
    return "writable repair pass left a merge in progress while rebasing is forbidden";
  if (unmergedPaths.length > 0) {
    return (
      "writable repair pass left unresolved merge state while rebasing is forbidden: " +
      unmergedPaths.join(", ")
    );
  }
  return null;
}

function parseBooleanEnv(value: JsonValue, fallback: boolean) {
  if (value == null || value === "") return fallback;
  if (/^(1|true|yes|on)$/i.test(String(value))) return true;
  if (/^(0|false|no|off)$/i.test(String(value))) return false;
  return fallback;
}
