import assert from "node:assert/strict";
import test from "node:test";
import {
  buildClaim,
  claimCommentEffect,
  exactMatchingReference,
  findExistingCommentMarker,
  runClaimCLI,
} from "../../scripts/ci/comment-effect-claim.mjs";

const src = "a".repeat(40);
const input = {
  repo: "AyobamiH/clawsweeper",
  number: 41,
  sourceId: 182,
  effect: "command_status",
  commitSha: src,
};

function backend() {
  const refs = new Map();
  let attempts = 0;
  const api = {
    getRef: async (ref) => refs.get(ref) || null,
    createRef: async (ref, sha) => {
      attempts++;
      if (refs.has(ref)) throw new Error("422 existing");
      const record = { ref, object: { type: "commit", sha } };
      refs.set(ref, record);
      return record;
    },
  };
  return {
    refs,
    api,
    get attempts() {
      return attempts;
    },
  };
}

test("first durable claim succeeds, same source never creates twice", async () => {
  const b = backend();
  assert.equal(await claimCommentEffect(input, b.api), "claimed");
  assert.equal(await claimCommentEffect(input, b.api), "already_claimed");
  assert.equal(b.attempts, 1);
});

test("uncertain POST with completed remote creation never creates again", async () => {
  const b = backend();
  const api = {
    ...b.api,
    createRef: async (ref, sha) => {
      await b.api.createRef(ref, sha);
      throw new Error("network failed after remote success");
    },
  };
  assert.equal(await claimCommentEffect(input, api), "already_claimed");
  assert.equal(await claimCommentEffect(input, api), "already_claimed");
  assert.equal(b.attempts, 1);
});

test("uncertain POST without readback remains held", async () => {
  let attempts = 0;
  const api = {
    getRef: async () => null,
    createRef: async () => {
      attempts++;
      throw new Error("timeout");
    },
  };
  await assert.rejects(claimCommentEffect(input, api), /comment_claim_creation_uncertain/);
  assert.equal(attempts, 1);
});

test("two racing claims cannot create more than one remote ref", async () => {
  const b = backend();
  const results = await Promise.all([
    claimCommentEffect(input, b.api),
    claimCommentEffect(input, b.api),
  ]);
  assert.deepEqual(results.sort(), ["already_claimed", "claimed"]);
  assert.equal(b.attempts, 2); // Second attempted POST receives 422; no effect.
  assert.equal(b.refs.size, 1);
});

test("existing forged or malformed ref cannot authorize a second post", async () => {
  const b = backend();
  b.refs.set(buildClaim(input).ref, {
    ref: buildClaim(input).ref,
    object: { type: "tree", sha: src },
  });
  await assert.rejects(claimCommentEffect(input, b.api), /unverifiable_comment_claim_ref/);
  assert.equal(b.attempts, 0);
});

test("source ref moving does not duplicate first durable comment claim", async () => {
  const b = backend();
  assert.equal(await claimCommentEffect(input, b.api), "claimed");
  assert.equal(
    await claimCommentEffect({ ...input, commitSha: "b".repeat(40) }, b.api),
    "already_claimed",
  );
  assert.equal(b.attempts, 1);
});

test("PR acknowledgement is identical across opened and ready-for-review", () => {
  const one = buildClaim({
    repo: "AyobamiH/clawsweeper",
    number: 41,
    sourceId: 41,
    effect: "pr_ack",
  });
  const two = buildClaim({
    repo: "ayobamih/ClawSweeper",
    number: "41",
    sourceId: "41",
    effect: "pr_ack",
  });
  assert.equal(one.ref, two.ref);
});

test("bad repository, effect, source id and SHA fail before network", async () => {
  const b = backend();
  for (const altered of [
    { repo: "other-repo" },
    { effect: "delete_repo" },
    { number: "-1" },
    { sourceId: "0" },
    { commitSha: "not-a-sha" },
  ])
    await assert.rejects(claimCommentEffect({ ...input, ...altered }, b.api));
  assert.equal(b.attempts, 0);
});

test("CLI refuses repository mismatch without any GitHub call", async () => {
  await assert.rejects(
    runClaimCLI([input.repo, "41", "182", "command_status", src], {
      GH_TOKEN: "fixture",
      GITHUB_REPOSITORY: "other/repo",
    }),
    /comment_claim_repository_mismatch/,
  );
});

test("complete pagination finds old PR acknowledgement beyond page 1", async () => {
  const body = "<!-- clawsweeper-pr-ack:opened item=41 -->";
  const visited = [];
  const result = await findExistingCommentMarker(
    { repo: input.repo, number: 41, sourceId: 41, effect: "pr_ack" },
    async (page) => {
      visited.push(page);
      return page === 1 ? Array.from({ length: 100 }, () => ({ body: "ordinary" })) : [{ body }];
    },
  );
  assert.equal(result, "present");
  assert.deepEqual(visited, [1, 2]);
});

test("complete pagination finds matching command status and refuses incomplete inventory", async () => {
  const found = await findExistingCommentMarker(input, async (page) =>
    page === 1 ? [{ body: "<!-- clawsweeper-command-ack:182 -->" }] : [],
  );
  assert.equal(found, "present");
  const missing = await findExistingCommentMarker(input, async () => []);
  assert.equal(missing, "absent");
  await assert.rejects(
    findExistingCommentMarker(
      input,
      async () => Array.from({ length: 100 }, () => ({ body: "ordinary" })),
      2,
    ),
    /comment_inventory_unbounded/,
  );
  await assert.rejects(
    findExistingCommentMarker(input, async () => ({ message: "provider error" })),
    /comment_inventory_unverifiable/,
  );
});

test("workflow only posts after complete inventory and an owner claim", async () => {
  const { readFileSync } = await import("node:fs");
  const workflow = readFileSync(".github/workflows/clawsweeper-dispatch.yml", "utf8");
  assert.match(workflow, /name: Checkout trusted workflow source for durable comment claims/);
  assert.match(workflow, /ref: \$\{\{ github\.sha \}\}/);
  assert.match(workflow, /persist-credentials: false/);
  assert.match(workflow, /comment-effect-claim\.mjs scan/);
  assert.match(workflow, /comment-effect-claim\.mjs claim/);
  assert.match(workflow, /pr_ack/);
  assert.match(workflow, /command_status/);
  assert.match(workflow, /\$CLAIM_TOKEN/);
  assert.doesNotMatch(workflow, /comments\?per_page=100"/);
  const pr = workflow.slice(
    workflow.indexOf("- name: Acknowledge received pull request"),
    workflow.indexOf("- name: Dispatch exact ClawSweeper review"),
  );
  assert.ok(pr.indexOf("scan_existing") < pr.indexOf("comment-effect-claim.mjs claim"));
  assert.ok(pr.indexOf("comment-effect-claim.mjs claim") < pr.lastIndexOf("--method POST"));
  const comment = workflow.slice(
    workflow.indexOf("- name: Acknowledge and dispatch ClawSweeper comment"),
  );
  assert.ok(
    comment.indexOf("comment-effect-claim.mjs scan") <
      comment.indexOf("comment-effect-claim.mjs claim"),
  );
  assert.ok(comment.indexOf("comment-effect-claim.mjs claim") < comment.indexOf("--method POST"));
});

test("GitHub matching refs returns only exact note identity and bounds ambiguity", () => {
  const ref = buildClaim(input).ref;
  const record = { ref, object: { type: "commit", sha: src } };
  assert.deepEqual(
    exactMatchingReference(ref, [{ ...record, ref: ref + "extra" }, record]),
    record,
  );
  assert.equal(exactMatchingReference(ref, []), null);
  assert.throws(() => exactMatchingReference(ref, null), /unbounded_comment_claim_refs/);
  assert.throws(() => exactMatchingReference(ref, [record, record]), /ambiguous_comment_claim_ref/);
});

test("exact static marker matching cannot be redirected by regex-shaped input", async () => {
  const calls = [];
  const page = async (index) => {
    calls.push(index);
    return [
      { body: "<!-- clawsweeper-command-ack:1182 -->" },
      { body: "<!-- clawsweeper-command-ack:182 -->" },
    ];
  };
  assert.equal(await findExistingCommentMarker(input, page), "present");
  assert.deepEqual(calls, [1]);
  await assert.rejects(
    findExistingCommentMarker({ ...input, sourceId: "182|.*" }, page),
    /invalid_source_id/,
  );
  assert.deepEqual(calls, [1], "rejected IDs never reach GitHub pagination");
});

test("PR markers require canonical full item numbers, not prefixes", async () => {
  const target = { repo: input.repo, number: 41, sourceId: 41, effect: "pr_ack" };
  assert.equal(
    await findExistingCommentMarker(target, async () => [
      { body: "<!-- clawsweeper-pr-ack:opened item=410 -->" },
      { body: "<!-- clawsweeper-pr-ack:ready_for_review item=41 -->" },
    ]),
    "present",
  );
  assert.equal(
    await findExistingCommentMarker(target, async () => [
      { body: "<!-- clawsweeper-pr-ack:opened item=410 -->" },
    ]),
    "absent",
  );
});

test("untrusted values never create runtime regular expressions", async () => {
  const { readFileSync } = await import("node:fs");
  const source = readFileSync("scripts/ci/comment-effect-claim.mjs", "utf8");
  assert.doesNotMatch(source, /new RegExp\s*\(/);
  assert.match(source, /matchAll\(marker\)/);
});
