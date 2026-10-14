import test from "node:test";
import assert from "node:assert/strict";
import { link, mkdtemp, readFile, rm, symlink, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import {
  API_ORIGIN,
  collectChanges,
  digest,
  materialise,
  pathAllowed,
  safePath,
  validateChanges,
  validateContract,
  validateNpmProject,
  validateSnapshot,
} from "../../scripts/commercial/contract.mjs";
import {
  boundedJson,
  oidcToken,
  prepare,
  publish,
  runnerIdentity,
} from "../../scripts/commercial/broker.mjs";
import { modelEnvironment, permissionArguments } from "../../scripts/commercial/codex-runtime.mjs";
import { dockerArguments } from "../../scripts/commercial/validate.mjs";
import { validateSemanticReview } from "../../scripts/commercial/review.mjs";

const ORDER = "eeb44f8b-a15b-4a20-b3a8-cdb48e6517ee";
const OPERATION = "b2cb485c-e620-4b13-805c-95589cbb34c7";
const contract = () =>
  validateContract({
    orderId: ORDER,
    operationId: OPERATION,
    generation: 2,
    quoteHash: "f".repeat(64),
    requestedOutcome: "Correct the total and add a regression test.",
    repository: {
      fullName: "fixture/project",
      id: "19",
      baseSha: "a".repeat(40),
      baseBranch: "main",
    },
    scope: {
      allowedPaths: ["src/", "test/"],
      acceptanceCriteria: ["The total regression test passes."],
      requiredChecks: [{ name: "test", appId: 15368 }],
      maxFiles: 3,
      maxPatchBytes: 8192,
    },
  });
const snapshot = () => ({
  schema: "tw.repository-snapshot.v1",
  repositoryId: "19",
  baseSha: "a".repeat(40),
  files: [{ path: "src/total.js", mode: "100644", content: "export const total = 1;\n" }],
});
const environment = () => ({
  TW_API_ORIGIN: API_ORIGIN,
  TW_ORDER_ID: ORDER,
  TW_OPERATION_ID: OPERATION,
  GITHUB_RUN_ID: "5555",
  GITHUB_RUN_ATTEMPT: "1",
  ACTIONS_ID_TOKEN_REQUEST_URL: "https://vstoken.actions.githubusercontent.com/oidc?x=1",
  ACTIONS_ID_TOKEN_REQUEST_TOKEN: "test-only-actions-token",
});
const temp = async (t) => {
  const root = await mkdtemp(path.join(os.tmpdir(), "tw-contract-proof-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  return root;
};
const json = (value) => Response.json(value);

test("contract binds the exact order, repository, quote and check issuer without retaining credential fields", () => {
  const input = { ...contract(), snapshotUrl: "https://bad.example/secret", bearerToken: "secret" };
  assert.equal(validateContract(input).bearerToken, undefined);
  assert.equal(validateContract(input).snapshotUrl, undefined);
  assert.throws(() => validateContract(input, { orderId: OPERATION }), /mismatch/);
  input.scope.requiredChecks = [{ name: "test" }];
  assert.throws(() => validateContract(input), /pinned issuers/);
});

test("traversal, alternate separators, git metadata and NUL paths fail before filesystem access", () => {
  for (const file of [
    "../secret",
    "/secret",
    "src/../secret",
    "src\\file",
    ".git/config",
    "src//x",
    "src/a\0b",
    "src/a:b",
  ])
    assert.throws(() => safePath(file));
  assert.equal(pathAllowed("src2/test.js", contract().scope), false);
  assert.equal(pathAllowed("src/.env", contract().scope), false);
});

test("snapshot rejects wrong commit, collisions, links and credential files", () => {
  for (const value of [
    { ...snapshot(), baseSha: "b".repeat(40) },
    {
      ...snapshot(),
      files: [...snapshot().files, { path: "src", mode: "100644", content: "collision" }],
    },
    {
      ...snapshot(),
      files: [...snapshot().files, { path: "SRC/TOTAL.js", mode: "100644", content: "collision" }],
    },
    { ...snapshot(), files: [{ path: "src/a", mode: "120000", content: "/etc/passwd" }] },
    { ...snapshot(), files: [{ path: ".env", mode: "100644", content: "TOKEN=x" }] },
  ])
    assert.throws(() => validateSnapshot(value, contract()));
});

test("real filesystem extraction and collection produce a bounded candidate", async (t) => {
  const root = await temp(t);
  await materialise(root, snapshot());
  await writeFile(path.join(root, "src/total.js"), "export const total = 2;\n");
  const changes = await collectChanges(root, snapshot(), contract());
  assert.deepEqual(changes, [
    { path: "src/total.js", mode: "100644", content: "export const total = 2;\n" },
  ]);
});

test("real symlink output cannot escape the generated workspace", async (t) => {
  const root = await temp(t);
  await materialise(root, snapshot());
  await symlink("/etc/passwd", path.join(root, "src/leak"));
  await assert.rejects(collectChanges(root, snapshot(), contract()), /symlink/);
});

test("real hardlink output is rejected before candidate publication", async (t) => {
  const root = await temp(t);
  await materialise(root, snapshot());
  await link(path.join(root, "src/total.js"), path.join(root, "src/duplicate.js"));
  await assert.rejects(collectChanges(root, snapshot(), contract()), /hardlink/);
});

test("candidate rejects no-op, out-of-scope, duplicate and over-budget changes", () => {
  assert.throws(() => validateChanges(snapshot().files, contract(), snapshot()), /unchanged/);
  assert.throws(
    () =>
      validateChanges(
        [{ path: ".github/workflows/test.yml", mode: "100644", content: "x" }],
        contract(),
        snapshot(),
      ),
    /allowed paths/,
  );
  const change = { path: "src/total.js", mode: "100644", content: "changed" };
  assert.throws(() => validateChanges([change, change], contract(), snapshot()), /duplicate/);
  assert.throws(
    () => validateChanges([{ ...change, content: "x".repeat(8193) }], contract(), snapshot()),
    /budget/,
  );
});

test("model process environment removes merchant, GitHub, Actions and API credentials", () => {
  const actual = modelEnvironment({
    PATH: "/bin",
    HOME: "/tmp/home",
    CODEX_HOME: "/tmp/auth",
    GH_TOKEN: "secret",
    ACTIONS_ID_TOKEN_REQUEST_TOKEN: "secret",
    TW_FULFILMENT_RUNNER_TOKEN: "secret",
    STRIPE_SECRET_KEY: "secret",
    OPENAI_API_KEY: "secret",
    CODEX_API_KEY: "secret",
    CLAWSWEEPER_QUOTA_SECRET: "secret",
  });
  assert.deepEqual(actual, {
    PATH: "/bin",
    HOME: "/tmp/home",
    CODEX_HOME: "/tmp/auth",
    CLAWSWEEPER_CODEX_LOGIN_METHOD: "chatgpt",
  });
});

test("test container has no network, no capabilities and only an explicit credential-free environment", () => {
  const args = dockerArguments("/tmp/project", ["npm", "test"], {
    name: "tw-proof",
    uid: 1000,
    gid: 1000,
  });
  assert.equal(args[args.indexOf("--network") + 1], "none");
  assert.ok(args.includes("--cap-drop=ALL"));
  assert.ok(args.includes("--security-opt=no-new-privileges"));
  assert.ok(args.includes("--read-only"));
  assert.deepEqual(
    args.flatMap((item, i) => (item === "--env" ? [args[i + 1]] : [])),
    ["HOME=/tmp", "CI=true"],
  );
  assert.throws(() => dockerArguments("/tmp/thing,src=/etc", ["npm"], { name: "test" }));
});

test("dependency preparation refuses arbitrary registries, missing integrity and linked packages", () => {
  const manifest = { scripts: { test: "node --test" } };
  const dependency = {
    resolved: "https://registry.npmjs.org/example/-/example-1.0.0.tgz",
    integrity: "sha512-YQ==",
  };
  const lock = (entry) => ({
    lockfileVersion: 3,
    packages: { "": {}, "node_modules/example": entry },
  });
  validateNpmProject(manifest, lock(dependency));
  for (const entry of [
    { ...dependency, resolved: "https://169.254.169.254/x" },
    { ...dependency, integrity: undefined },
    { ...dependency, link: true },
    { ...dependency, resolved: "git+ssh://git@github.com/x/y" },
  ])
    assert.throws(() => validateNpmProject(manifest, lock(entry)));
  assert.throws(() => validateNpmProject({ ...manifest, workspaces: ["x"] }, lock(dependency)));
});

test("OIDC requests only the fixed merchant audience and blocks redirected identity hosts", async () => {
  let requested;
  const token = await oidcToken(environment(), async (url, options) => {
    requested = { url, options };
    return json({ value: "header.payload.signature" });
  });
  assert.equal(token, "header.payload.signature");
  assert.equal(
    requested.url.searchParams.get("audience"),
    API_ORIGIN + "/api/v2/agent/internal/executions",
  );
  assert.equal(requested.options.redirect, "error");
  await assert.rejects(
    oidcToken({ ...environment(), ACTIONS_ID_TOKEN_REQUEST_URL: "https://attacker.example/token" }),
    /origin/,
  );
});

test("trusted preparation removes broker capabilities before writing an artifact", async (t) => {
  const root = await temp(t);
  const calls = [];
  const fetcher = async (url, options) => {
    calls.push({ url: String(url), options });
    if (url.hostname.endsWith(".actions.githubusercontent.com"))
      return json({ value: "header.payload.signature" });
    if (url.pathname.endsWith("/claim"))
      return json({ ...contract(), bearerToken: "never-forward", snapshotUrl: "never-forward" });
    return json(snapshot());
  };
  await prepare(root, environment(), fetcher);
  const stored = await readFile(path.join(root, "contract.json"), "utf8");
  assert.ok(!stored.includes("never-forward"));
  const snapshotCall = calls.find((call) => call.url.includes("/snapshot?"));
  assert.ok(snapshotCall.url.includes("runId=5555"));
  assert.ok(!snapshotCall.url.includes("signature"));
  assert.equal(snapshotCall.options.headers.Authorization, "Bearer header.payload.signature");
});

test("publication binds validated changes and refuses a tampered candidate", async (t) => {
  const root = await temp(t);
  await writeFile(path.join(root, "contract.json"), JSON.stringify(contract()));
  await writeFile(path.join(root, "snapshot.json"), JSON.stringify(snapshot()));
  const changes = [{ path: "src/total.js", mode: "100644", content: "fixed" }];
  const candidate = {
    changes,
    review: {
      reviewer: "codex-fresh-read-only-v1",
      passed: true,
      summary: "Fix matches the requested total",
      criteria: [
        { criterionIndex: 0, passed: true, rationale: "src/total.js has corrected total" },
      ],
      candidateDigest: digest(changes),
      contractDigest: digest(contract()),
    },
    validation: {
      profile: "node",
      passed: true,
      candidateDigest: digest(changes),
      contractDigest: digest(contract()),
      commands: [
        { command: "npm ci --ignore-scripts", exitCode: 0 },
        { command: "npm test", exitCode: 0 },
      ],
    },
  };
  await writeFile(path.join(root, "reviewed-candidate.json"), JSON.stringify(candidate));
  let posted;
  await publish(root, environment(), async (url, options) => {
    if (url.hostname.endsWith(".actions.githubusercontent.com"))
      return json({ value: "header.payload.signature" });
    posted = JSON.parse(options.body);
    return json({ accepted: true });
  });
  assert.equal(posted.repositoryId, "19");
  assert.equal(posted.operationId, OPERATION);
  assert.equal(posted.generation, 2);
  assert.equal(posted.githubRunAttempt, 1);
  candidate.changes[0].content = "tampered";
  await writeFile(path.join(root, "reviewed-candidate.json"), JSON.stringify(candidate));
  await assert.rejects(publish(root, environment()), /bound validation/);
});

test("broker response limits and wrong merchant origins fail closed", async () => {
  await assert.rejects(boundedJson(new Response("a".repeat(200)), 20), /budget/);
  assert.throws(
    () => runnerIdentity({ ...environment(), TW_API_ORIGIN: "https://attacker.example" }),
    /origin/,
  );
});

test("model permissions have no general disk-read root and never use legacy sandbox defaults", () => {
  const args = permissionArguments("/isolated/workspace", "read", "/pinned/codex");
  const filesystem = args.find((value) => value.startsWith("permissions.commercial.filesystem="));
  assert.ok(filesystem.includes('":minimal" = "read"'));
  assert.ok(filesystem.includes('"/isolated/workspace" = "read"'));
  assert.ok(filesystem.includes('"/pinned/codex" = "read"'));
  assert.ok(!filesystem.includes('":root"'));
  assert.ok(args.includes("permissions.commercial.network.enabled=false"));
  assert.ok(!args.includes("--sandbox"));
});

test("semantic review requires every criterion and refuses missing or failed evidence", () => {
  const changes = [{ path: "src/total.js", mode: "100644", content: "fixed" }];
  const good = {
    passed: true,
    summary: "The total is corrected",
    criteria: [
      {
        criterionIndex: 0,
        passed: true,
        rationale: "Implementation updates total and the regression expectation agrees.",
      },
    ],
  };
  const evidence = validateSemanticReview(good, contract(), changes);
  assert.equal(evidence.candidateDigest, digest(changes));
  assert.equal(evidence.contractDigest, digest(contract()));
  for (const bad of [
    { ...good, passed: false },
    { ...good, criteria: [] },
    { ...good, criteria: [{ ...good.criteria[0], criterionIndex: 1 }] },
    { ...good, criteria: [{ ...good.criteria[0], passed: false }] },
  ])
    assert.throws(() => validateSemanticReview(bad, contract(), changes));
});
