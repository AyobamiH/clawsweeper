import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { EventEmitter } from "node:events";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { isolatedTestGitEnvironment, runNodeTests } from "../scripts/run-node-tests.mjs";

test("test-only Git config disables signing without changing the parent environment", () => {
  const original = {
    GIT_CONFIG_COUNT: "1",
    GIT_CONFIG_KEY_0: "user.name",
    GIT_CONFIG_VALUE_0: "fixture tester",
  };
  const env = isolatedTestGitEnvironment(original);
  assert.equal(original.GIT_CONFIG_COUNT, "1");
  assert.deepEqual(env, {
    ...original,
    GIT_CONFIG_COUNT: "2",
    GIT_CONFIG_KEY_1: "commit.gpgsign",
    GIT_CONFIG_VALUE_1: "false",
  });
  assert.throws(() => isolatedTestGitEnvironment({ GIT_CONFIG_COUNT: "-1" }), /Invalid/);
});

test("a disposable Git repository can commit with host signing explicitly enabled", () => {
  const root = mkdtempSync(join(tmpdir(), "clawsweeper-test-git-isolation-"));
  try {
    const base = {
      ...process.env,
      GIT_CONFIG_COUNT: "1",
      GIT_CONFIG_KEY_0: "commit.gpgsign",
      GIT_CONFIG_VALUE_0: "true",
    };
    const env = isolatedTestGitEnvironment(base);
    const run = (...args: string[]) =>
      execFileSync("git", args, { cwd: root, env, encoding: "utf8" }).trim();
    run("init", "-q");
    run("config", "user.name", "Test Fixture");
    run("config", "user.email", "test@example.invalid");
    assert.equal(run("config", "--get", "commit.gpgsign"), "false");
    run("commit", "--allow-empty", "-m", "test fixture commit");
    assert.match(run("rev-parse", "HEAD"), /^[0-9a-f]{40}$/);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("runner passes signing isolation to child without modifying the parent", async () => {
  const root = mkdtempSync(join(tmpdir(), "clawsweeper-runner-git-isolation-"));
  let childEnv: NodeJS.ProcessEnv | undefined;
  try {
    mkdirSync(join(root, "test"));
    writeFileSync(join(root, "test", "example.test.ts"), "// fixture\n");
    const parentCount = process.env.GIT_CONFIG_COUNT;
    const result = await runNodeTests({
      target: "unit",
      cwd: root,
      concurrency: 1,
      spawnProcess(_command: string, _args: string[], options: { env: NodeJS.ProcessEnv }) {
        childEnv = options.env;
        const child = new EventEmitter();
        queueMicrotask(() => child.emit("exit", 0, null));
        return child;
      },
    });
    assert.deepEqual(result, { code: 0, signal: null });
    assert.ok(childEnv);
    const count = Number(childEnv.GIT_CONFIG_COUNT) - 1;
    assert.equal(childEnv[`GIT_CONFIG_KEY_${count}`], "commit.gpgsign");
    assert.equal(childEnv[`GIT_CONFIG_VALUE_${count}`], "false");
    assert.equal(process.env.GIT_CONFIG_COUNT, parentCount);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});
