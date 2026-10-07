import assert from "node:assert/strict";
import test from "node:test";

import {
  noRebasePublicationBlockReason,
  noRebaseWritablePassBlockReason,
  shouldCloseSupersededSourcePrs,
  shouldSeedReplacementBranchFromSource,
  sourceBranchWriteBlockReason,
} from "../../dist/repair/execute-fix-policy.js";

test("superseded source PR closeout defaults on for replacement PRs", () => {
  assert.equal(shouldCloseSupersededSourcePrs(undefined), true);
  assert.equal(shouldCloseSupersededSourcePrs(""), true);
  assert.equal(shouldCloseSupersededSourcePrs("1"), true);
  assert.equal(shouldCloseSupersededSourcePrs("true"), true);
});

test("superseded source PR closeout can be explicitly disabled", () => {
  assert.equal(shouldCloseSupersededSourcePrs("0"), false);
  assert.equal(shouldCloseSupersededSourcePrs("false"), false);
});

test("only replacement fixes seed the repair branch from a source PR head", () => {
  assert.equal(
    shouldSeedReplacementBranchFromSource({ repair_strategy: "replace_uneditable_branch" }),
    true,
  );
  assert.equal(shouldSeedReplacementBranchFromSource({ repair_strategy: "new_fix_pr" }), false);
  assert.equal(
    shouldSeedReplacementBranchFromSource({ repair_strategy: "repair_contributor_branch" }),
    false,
  );
});

test("sourceBranchWriteBlockReason allows same-repo branches despite maintainer flag", () => {
  assert.equal(
    sourceBranchWriteBlockReason("openclaw/openclaw", {
      maintainer_can_modify: false,
      head: {
        ref: "feature",
        repo: { full_name: "openclaw/openclaw" },
      },
    }),
    null,
  );
});

test("sourceBranchWriteBlockReason treats repository identity case-insensitively", () => {
  assert.equal(
    sourceBranchWriteBlockReason("ayobamih/wagging-web-wins", {
      maintainer_can_modify: false,
      head: {
        ref: "fixture",
        repo: { full_name: "AyobamiH/wagging-web-wins" },
      },
    }),
    null,
  );
});

test("sourceBranchWriteBlockReason allows fork branches with maintainer edits", () => {
  assert.equal(
    sourceBranchWriteBlockReason("openclaw/openclaw", {
      maintainer_can_modify: true,
      head: {
        ref: "feature",
        repo: { full_name: "contributor/openclaw" },
      },
    }),
    null,
  );
});

test("sourceBranchWriteBlockReason blocks fork branches without maintainer edits", () => {
  assert.equal(
    sourceBranchWriteBlockReason("openclaw/openclaw", {
      maintainer_can_modify: false,
      head: {
        ref: "feature",
        repo: { full_name: "contributor/openclaw" },
      },
    }),
    "source PR branch is a fork with maintainer_can_modify=false",
  );
});

test("sourceBranchWriteBlockReason blocks missing head details", () => {
  assert.equal(
    sourceBranchWriteBlockReason("openclaw/openclaw", {
      maintainer_can_modify: true,
      head: { repo: { full_name: "contributor/openclaw" } },
    }),
    "source PR is missing head repo/ref",
  );
});

test("no-rebase publication policy rejects rewritten source ancestry", () => {
  assert.equal(
    noRebasePublicationBlockReason({ allowRebase: false, sourceRewritten: false }),
    null,
  );
  assert.match(
    noRebasePublicationBlockReason({ allowRebase: false, sourceRewritten: true }) ?? "",
    /rewrite source ancestry/,
  );
  assert.equal(noRebasePublicationBlockReason({ allowRebase: true, sourceRewritten: true }), null);
});

test("no-rebase writable pass policy rejects ancestry and merge-state changes", () => {
  const base = {
    allowRebase: false,
    headBefore: "a".repeat(40),
    headAfter: "a".repeat(40),
    rebaseInProgress: false,
    mergeInProgress: false,
    unmergedPaths: [],
  };

  assert.equal(noRebaseWritablePassBlockReason(base), null);
  assert.match(
    noRebaseWritablePassBlockReason({ ...base, headAfter: "b".repeat(40) }) ?? "",
    /changed HEAD/,
  );
  assert.match(
    noRebaseWritablePassBlockReason({ ...base, rebaseInProgress: true }) ?? "",
    /rebase in progress/,
  );
  assert.match(
    noRebaseWritablePassBlockReason({ ...base, mergeInProgress: true }) ?? "",
    /merge in progress/,
  );
  assert.match(
    noRebaseWritablePassBlockReason({ ...base, unmergedPaths: ["src/a.ts"] }) ?? "",
    /src\/a\.ts/,
  );
  assert.equal(
    noRebaseWritablePassBlockReason({
      ...base,
      allowRebase: true,
      headAfter: "b".repeat(40),
      rebaseInProgress: true,
      mergeInProgress: true,
      unmergedPaths: ["src/a.ts"],
    }),
    null,
  );
});
