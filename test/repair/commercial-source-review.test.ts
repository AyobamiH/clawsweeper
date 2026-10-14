import assert from "node:assert/strict";
import test from "node:test";
import { execFileSync } from "node:child_process";
import { chmod, link, mkdir, mkdtemp, rm, symlink, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import {
  SOURCE_FILE_LIMIT,
  sourceBundle,
  sourceReviewDecision,
} from "../../scripts/commercial/source-review.mjs";
import { digest } from "../../scripts/commercial/contract.mjs";
const bundle = {
  schema: "tw.commercial-source-bundle.v2",
  repository: "AyobamiH/clawsweeper",
  head: "a".repeat(40),
  base: "b".repeat(40),
  files: [
    { path: "scripts/commercial/generate.mjs", before: null, after: "export const safe = true;" },
  ],
};
const decision = () => ({
  sourceDigest: digest(bundle),
  complete: true,
  summary: "The complete change was inspected.",
  findings: [],
});
test("complete provider source review is bound to the exact source bundle", () => {
  assert.equal(sourceReviewDecision(decision(), bundle).passed, true);
});
test("incomplete review cannot pass even without findings", () => {
  assert.equal(sourceReviewDecision({ ...decision(), complete: false }, bundle).passed, false);
});
test("actionable source findings keep the release gate closed", () => {
  assert.equal(
    sourceReviewDecision(
      {
        ...decision(),
        findings: [
          {
            severity: "P1",
            file: bundle.files[0].path,
            line: 1,
            description: "A concrete defect.",
          },
        ],
      },
      bundle,
    ).passed,
    false,
  );
});
for (const [name, patch] of [
  ["wrong source hash", { sourceDigest: "0".repeat(64) }],
  ["unknown completion", { complete: "yes" }],
  [
    "unbound file",
    { findings: [{ severity: "P1", file: "other.js", line: 1, description: "not supplied" }] },
  ],
  [
    "invalid line",
    { findings: [{ severity: "P1", file: bundle.files[0].path, line: 0, description: "invalid" }] },
  ],
  ["provider extras", { secret: "must-not-enter-receipt" }],
]) {
  test(`rejects ${name}`, () => {
    assert.throws(() => sourceReviewDecision({ ...decision(), ...patch }, bundle));
  });
}

async function repositoryFixture(t) {
  const directory = await mkdtemp(path.join(os.tmpdir(), "tw-source-review-regression-"));
  const root = path.join(directory, "repository");
  await mkdir(root);
  t.after(() => rm(directory, { recursive: true, force: true }));
  const env = { ...process.env, GIT_CONFIG_GLOBAL: "/dev/null", GIT_CONFIG_NOSYSTEM: "1" };
  const git = (...args) =>
    execFileSync("git", ["-C", root, ...args], {
      env,
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
    });
  git("init", "-q");
  git("config", "user.name", "Local source fixture");
  git("config", "user.email", "fixture@example.invalid");
  git("config", "commit.gpgsign", "false");
  git("config", "core.filemode", "true");
  git("remote", "add", "origin", "https://github.com/AyobamiH/clawsweeper.git");
  await writeFile(path.join(root, "script.js"), "export const value = 1;\n");
  await writeFile(path.join(root, ".gitignore"), "src\n");
  await mkdir(path.join(root, "src"));
  await writeFile(path.join(root, "src/value.js"), "export const x = 1;\n");
  git("add", ".gitignore", "script.js");
  git("add", "-f", "src/value.js");
  git("commit", "-qm", "synthetic baseline");
  return { directory, root, git, base: git("rev-parse", "HEAD").trim() };
}

test("source capture binds executable permissions as well as exact text", async (t) => {
  const f = await repositoryFixture(t);
  await writeFile(path.join(f.root, "script.js"), "export const value = 2;\n");
  const regular = await sourceBundle(f.root, f.base);
  await chmod(path.join(f.root, "script.js"), 0o755);
  const executable = await sourceBundle(f.root, f.base);
  assert.notEqual(digest(regular), digest(executable));
  assert.equal(regular.files[0].beforeMode, "100644");
  assert.equal(regular.files[0].afterMode, "100644");
  assert.equal(executable.files[0].afterMode, "100755");
});
test("source capture rejects a symlinked parent before reading outside the repository", async (t) => {
  const f = await repositoryFixture(t);
  const outside = path.join(f.directory, "outside");
  await mkdir(outside);
  await writeFile(path.join(outside, "value.js"), "synthetic outside contents");
  await rm(path.join(f.root, "src"), { recursive: true });
  await symlink(outside, path.join(f.root, "src"));
  await assert.rejects(() => sourceBundle(f.root, f.base), /parent is not a regular directory/);
});
test("source capture rejects final symlinks and hardlinks", async (t) => {
  const f = await repositoryFixture(t);
  const outside = path.join(f.directory, "outside.js");
  await writeFile(outside, "synthetic outside contents");
  await rm(path.join(f.root, "script.js"));
  await symlink(outside, path.join(f.root, "script.js"));
  await assert.rejects(() => sourceBundle(f.root, f.base));
  await rm(path.join(f.root, "script.js"));
  await link(outside, path.join(f.root, "script.js"));
  await assert.rejects(() => sourceBundle(f.root, f.base), /unsupported source file/);
});
test("source capture binds a genuine removal to its exact original bytes and mode", async (t) => {
  const f = await repositoryFixture(t);
  await rm(path.join(f.root, "script.js"));
  const captured = await sourceBundle(f.root, f.base);
  assert.deepEqual(captured.files, [
    {
      path: "script.js",
      before: "export const value = 1;\n",
      after: null,
      beforeMode: "100644",
      afterMode: null,
    },
  ]);
});
test("source capture rejects tracked changes inside excluded generated directories", async (t) => {
  const f = await repositoryFixture(t);
  await mkdir(path.join(f.root, ".artifacts"));
  await writeFile(path.join(f.root, ".artifacts/tracked.js"), "original\n");
  f.git("add", ".artifacts/tracked.js");
  f.git("commit", "-qm", "tracked fixture artifact");
  const base = f.git("rev-parse", "HEAD").trim();
  await writeFile(path.join(f.root, ".artifacts/tracked.js"), "changed\n");
  await assert.rejects(() => sourceBundle(f.root, base), /tracked change inside excluded/);
});
test("only untracked build and proof output is excluded from source review", async (t) => {
  const f = await repositoryFixture(t);
  await writeFile(path.join(f.root, "script.js"), "export const value = 2;\n");
  const before = await sourceBundle(f.root, f.base);
  for (const root of [".artifacts", ".wrangler"]) {
    await mkdir(path.join(f.root, root));
    await writeFile(path.join(f.root, root, "fixture.json"), '{"generated":true}');
  }
  const after = await sourceBundle(f.root, f.base);
  assert.equal(digest(before), digest(after));
});
test("source capture rejects spoofed repository origins", async (t) => {
  const f = await repositoryFixture(t);
  await writeFile(path.join(f.root, "script.js"), "changed\n");
  f.git("remote", "set-url", "origin", "https://example.invalid/?github.com/AyobamiH/clawsweeper");
  await assert.rejects(() => sourceBundle(f.root, f.base), /restricted to the two owned/);
});
test("source capture rejects oversized and malformed UTF-8 files", async (t) => {
  const f = await repositoryFixture(t);
  await writeFile(path.join(f.root, "script.js"), "x".repeat(SOURCE_FILE_LIMIT + 1));
  await assert.rejects(() => sourceBundle(f.root, f.base), /unsupported source file/);
  await writeFile(path.join(f.root, "script.js"), Buffer.from([0xff]));
  await assert.rejects(() => sourceBundle(f.root, f.base));
});

test("source capture still detects mode-only changes when repository Git ignores file modes", async (t) => {
  const f = await repositoryFixture(t);
  f.git("config", "core.filemode", "false");
  await writeFile(path.join(f.root, "src/value.js"), "export const x = 2;\n");
  const before = await sourceBundle(f.root, f.base);
  await chmod(path.join(f.root, "script.js"), 0o755);
  const after = await sourceBundle(f.root, f.base);
  assert.notEqual(digest(before), digest(after));
  assert.equal(after.files.find((file) => file.path === "script.js")?.afterMode, "100755");
  assert.equal(f.git("config", "--get", "core.filemode").trim(), "false");
});
