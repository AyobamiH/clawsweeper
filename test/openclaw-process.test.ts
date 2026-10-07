import assert from "node:assert/strict";
import { chmodSync, existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { useFakeScanner } from "./agent-input-scan-helpers.ts";

import { runAgentProcess } from "../dist/agent-runner.js";
import { parseOpenclawJsonEnvelope, runOpenclawProcess } from "../dist/openclaw-process.js";
import { codexProcessErrorCode } from "../dist/codex-process.js";

function fakeOpenclaw(root: string): string {
  const binary = join(root, "fake-openclaw");
  writeFileSync(
    binary,
    `#!/usr/bin/env node
const fs = require("node:fs");
const record = {
  args: process.argv.slice(2),
  stateDir: process.env.OPENCLAW_STATE_DIR,
  configPath: process.env.OPENCLAW_CONFIG_PATH,
  workspaceDir: process.env.OPENCLAW_WORKSPACE_DIR,
  config: JSON.parse(fs.readFileSync(process.env.OPENCLAW_CONFIG_PATH, "utf8")),
  prompt: fs.readFileSync(process.argv[process.argv.indexOf("--message-file") + 1], "utf8"),
  env: {
    GITHUB_TOKEN: process.env.GITHUB_TOKEN ?? null,
    GH_TOKEN: process.env.GH_TOKEN ?? null,
    CLAWSWEEPER_WEBHOOK_SECRET: process.env.CLAWSWEEPER_WEBHOOK_SECRET ?? null,
    CLAWSWEEPER_APP_PRIVATE_KEY: process.env.CLAWSWEEPER_APP_PRIVATE_KEY ?? null,
    KIMI_API_KEY: process.env.KIMI_API_KEY ?? null,
    OPENAI_API_KEY: process.env.OPENAI_API_KEY ?? null,
  },
};
fs.writeFileSync(process.env.OPENCLAW_TEST_RECORD, JSON.stringify(record));
if (process.env.OPENCLAW_TEST_READ_PATH) {
  const sessionId = record.args[record.args.indexOf("--session-id") + 1];
  const sessionFile = require("node:path").join(record.stateDir, "agents", "main", "sessions", sessionId + ".jsonl");
  fs.mkdirSync(require("node:path").dirname(sessionFile), { recursive: true });
  const toolCallId = "read-checkout";
  const entries = [
    {
      type: "message",
      message: {
        role: "assistant",
        content: [{ type: "toolCall", id: toolCallId, name: "read", arguments: { path: process.env.OPENCLAW_TEST_READ_PATH } }],
      },
    },
    {
      type: "message",
      message: {
        role: "toolResult",
        toolCallId,
        toolName: "read",
        isError: process.env.OPENCLAW_TEST_READ_ERROR === "1",
        content: [{ type: "text", text: "file contents" }],
      },
    },
  ];
  if (process.env.OPENCLAW_TEST_RECEIPT_EXTRA) {
    entries.push(...JSON.parse(process.env.OPENCLAW_TEST_RECEIPT_EXTRA));
  }
  fs.writeFileSync(sessionFile, entries.map((entry) => JSON.stringify(entry)).join("\\n") + "\\n");
}
process.stderr.write(process.env.OPENCLAW_TEST_STDERR || "");
process.stdout.write(process.env.OPENCLAW_TEST_STDOUT || JSON.stringify({ payloads: [{ text: "done" }], meta: { stopReason: "stop" } }));
`,
  );
  chmodSync(binary, 0o755);
  return binary;
}

test("OpenClaw process serializes worker setup failures instead of losing diagnostics", () => {
  const root = mkdtempSync(join(tmpdir(), "clawsweeper-openclaw-worker-setup-test-"));
  try {
    const result = runOpenclawProcess({
      label: "worker-setup-failure",
      prompt: "prompt",
      model: "openai/test",
      cwd: root,
      env: process.env,
      timeoutMs: 10_000,
      stdoutPath: join(root, "missing-parent", "stdout.log"),
      stderrPath: join(root, "missing-parent", "stderr.log"),
    });
    assert.equal(result.status, null);
    assert.equal(codexProcessErrorCode(result.error), "ENOENT");
    assert.match(result.error?.message ?? "", /missing-parent/);
    assert.doesNotMatch(result.error?.message ?? "", /worker failed with exit/);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

function runCleanupScenario(options: {
  inspection?: boolean;
  failure?: string;
  repeatFailure?: boolean;
  finalOnFailure?: string;
  timeoutMs?: number;
}) {
  const root = mkdtempSync(join(tmpdir(), "clawsweeper-openclaw-cleanup-test-"));
  const binary = join(root, "fake-openclaw-cleanup");
  const attemptsPath = join(root, "attempts.jsonl");
  const stdoutPath = join(root, "stdout.log");
  const stderrPath = join(root, "stderr.log");
  const failure =
    options.failure ??
    "Agent exec cleanup failed: Agent runtime cleanup did not settle; state ownership retained until this process exits";
  writeFileSync(
    binary,
    `#!/usr/bin/env node
const fs = require("node:fs");
const attemptsPath = process.env.OPENCLAW_TEST_ATTEMPTS;
const previous = fs.existsSync(attemptsPath) ? fs.readFileSync(attemptsPath, "utf8").trim().split("\\n") : [];
const config = JSON.parse(fs.readFileSync(process.env.OPENCLAW_CONFIG_PATH, "utf8"));
fs.appendFileSync(attemptsPath, JSON.stringify({stateDir:process.env.OPENCLAW_STATE_DIR, tools:config.tools, args:process.argv.slice(2)}) + "\\n");
process.stderr.write("attempt-" + (previous.length + 1));
if (previous.length === 0 || ${JSON.stringify(options.repeatFailure === true)}) {
  const final = ${JSON.stringify(options.finalOnFailure ?? "")};
  process.stdout.write(JSON.stringify({ok:false, status:"error", final, payloads:[], error:{message:${JSON.stringify(failure)}}}));
  process.exitCode = 1;
} else {
  process.stdout.write(JSON.stringify({ok:true, status:"ok", final:"tracked checkout content", toolSummary:{calls:1,tools:["read"],failures:0}}));
}
`,
  );
  chmodSync(binary, 0o755);
  const result = runOpenclawProcess({
    label: "cleanup-regression",
    prompt: "Read the challenged line.",
    model: "openai/test",
    cwd: root,
    env: { ...process.env, CLAWSWEEPER_OPENCLAW_BIN: binary, OPENCLAW_TEST_ATTEMPTS: attemptsPath },
    timeoutMs: options.timeoutMs ?? 10_000,
    stdoutPath,
    stderrPath,
    ...(options.inspection
      ? {
          checkoutInspection: {
            expectedText: "tracked checkout content",
            expectedPath: "tracked.txt",
          },
        }
      : {}),
  });
  return {
    root,
    result,
    stdoutPath,
    stderrPath,
    attempts: readFileSync(attemptsPath, "utf8")
      .trim()
      .split("\n")
      .map((line) => JSON.parse(line)),
  };
}

test("OpenClaw never repeats a potentially mutating agent after an empty cleanup error", () => {
  const scenario = runCleanupScenario({});
  try {
    assert.equal(scenario.attempts.length, 1);
    assert.equal(scenario.result.status, 1);
    assert.match(scenario.result.error?.message ?? "", /cleanup did not settle/);
  } finally {
    rmSync(scenario.root, { recursive: true, force: true });
  }
});

test("OpenClaw retries only read-only checkout inspection with fresh state and retained diagnostics", () => {
  const scenario = runCleanupScenario({ inspection: true });
  try {
    assert.equal(scenario.result.status, 0, scenario.result.error?.message);
    assert.equal(scenario.result.stdout, "");
    assert.equal(scenario.attempts.length, 2);
    assert.notEqual(scenario.attempts[0].stateDir, scenario.attempts[1].stateDir);
    for (const attempt of scenario.attempts) {
      assert.equal(existsSync(attempt.stateDir), false);
      assert.deepEqual(attempt.tools.allow, ["read"]);
      assert.equal(attempt.tools.exec.mode, "deny");
    }
    assert.match(readFileSync(scenario.stdoutPath, "utf8"), /cleanup did not settle/);
    assert.match(
      readFileSync(`${scenario.stdoutPath}.retry-1`, "utf8"),
      /tracked checkout content/,
    );
    assert.equal(readFileSync(scenario.stderrPath, "utf8"), "attempt-1");
    assert.equal(readFileSync(`${scenario.stderrPath}.retry-1`, "utf8"), "attempt-2");
  } finally {
    rmSync(scenario.root, { recursive: true, force: true });
  }
});

test("OpenClaw read-only cleanup retry stops after the second failure", () => {
  const scenario = runCleanupScenario({ inspection: true, repeatFailure: true });
  try {
    assert.equal(scenario.attempts.length, 2);
    assert.equal(scenario.result.status, 1);
    assert.match(scenario.result.error?.message ?? "", /cleanup did not settle/);
  } finally {
    rmSync(scenario.root, { recursive: true, force: true });
  }
});

test("OpenClaw does not replay other failures, useful output or an exhausted retry budget", () => {
  for (const options of [
    { inspection: true, failure: "provider unavailable" },
    { inspection: true, finalOnFailure: "do not repeat this result" },
    { inspection: true, timeoutMs: 900 },
  ]) {
    const scenario = runCleanupScenario(options);
    try {
      assert.equal(scenario.attempts.length, 1);
      assert.equal(scenario.result.status, 1);
    } finally {
      rmSync(scenario.root, { recursive: true, force: true });
    }
  }
});

test("OpenClaw process emits isolated config and invocation, joins payloads, and cleans state", () => {
  const root = mkdtempSync(join(tmpdir(), "clawsweeper-openclaw-test-"));
  const recordPath = join(root, "record.json");
  const binary = fakeOpenclaw(root);
  try {
    const result = runOpenclawProcess({
      label: "Review #42",
      prompt: "Inspect this patch.",
      model: "kimi/kimi-for-coding",
      reasoningEffort: "high",
      cwd: root,
      env: {
        ...process.env,
        CLAWSWEEPER_OPENCLAW_BIN: binary,
        CLAWSWEEPER_OPENCLAW_PROVIDERS_JSON: JSON.stringify({
          kimi: {
            baseUrl: "https://api.kimi.com/coding/",
            apiKey: "${KIMI_API_KEY}",
            api: "anthropic-messages",
            models: [{ id: "kimi-for-coding" }],
          },
        }),
        OPENCLAW_TEST_RECORD: recordPath,
        OPENCLAW_TEST_STDOUT: JSON.stringify({
          payloads: [{ text: "first" }, { text: "second" }],
          meta: { stopReason: "stop" },
        }),
      },
      timeoutMs: 12_345,
    });
    assert.equal(result.status, 0, result.stderr);
    assert.equal(result.error, undefined);
    assert.equal(result.stdout, "first\nsecond");
    const record = JSON.parse(readFileSync(recordPath, "utf8"));
    assert.equal(record.workspaceDir, root);
    assert.equal(record.prompt, "Inspect this patch.");
    assert.deepEqual(record.config, {
      agents: {
        defaults: { skipBootstrap: true, sandbox: { mode: "off" }, timeoutSeconds: 13 },
      },
      tools: {
        profile: "coding",
        fs: { workspaceOnly: true },
        exec: { host: "gateway", mode: "full" },
      },
      models: {
        mode: "merge",
        providers: {
          kimi: {
            baseUrl: "https://api.kimi.com/coding/",
            apiKey: "${KIMI_API_KEY}",
            api: "anthropic-messages",
            // name defaults to the id: OpenClaw config validation requires it.
            models: [{ id: "kimi-for-coding", name: "kimi-for-coding" }],
          },
        },
      },
    });
    assert.deepEqual(record.args.slice(0, 2), ["agent", "exec"]);
    assert.equal(
      record.args[record.args.indexOf("--message-file") + 1].endsWith("/prompt.md"),
      true,
    );
    assert.equal(record.args[record.args.indexOf("--cwd") + 1], root);
    assert.equal(record.args[record.args.indexOf("--state-dir") + 1], record.stateDir);
    assert.equal(record.args[record.args.indexOf("--config") + 1], record.configPath);
    assert.equal(record.args[record.args.indexOf("--model") + 1], "kimi/kimi-for-coding");
    assert.equal(record.args[record.args.indexOf("--timeout") + 1], "13");
    assert.equal(record.args[record.args.indexOf("--thinking") + 1], "high");
    assert.equal(record.args.at(-1), "--json");
    assert.equal(existsSync(record.stateDir), false);
    assert.equal(existsSync(record.configPath), false);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("Workers AI headless reviews force OpenClaw code mode with lean tools", () => {
  const root = mkdtempSync(join(tmpdir(), "clawsweeper-openclaw-workers-ai-code-mode-test-"));
  const recordPath = join(root, "record.json");
  const binary = fakeOpenclaw(root);
  try {
    const result = runOpenclawProcess({
      label: "workers-ai-code-mode",
      prompt: "Inspect this repository.",
      model: "workersai/@cf/zai-org/glm-5.3",
      cwd: root,
      env: {
        ...process.env,
        CLAWSWEEPER_OPENCLAW_BIN: binary,
        OPENCLAW_TEST_RECORD: recordPath,
      },
      timeoutMs: 10_000,
    });
    assert.equal(result.status, 0, result.error?.message);
    const record = JSON.parse(readFileSync(recordPath, "utf8"));
    assert.equal(record.args[record.args.indexOf("--code-mode") + 1], "code");
    assert.equal(record.args.includes("--local-model-lean"), true);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("OpenClaw checkout inspection uses agent exec and Workers AI code mode", () => {
  const root = mkdtempSync(join(tmpdir(), "clawsweeper-openclaw-checkout-mode-test-"));
  const recordPath = join(root, "record.json");
  const binary = fakeOpenclaw(root);
  try {
    const result = runOpenclawProcess({
      label: "checkout-mode",
      prompt: "Read the challenged line.",
      model: "workersai/@cf/zai-org/glm-5.3",
      cwd: root,
      env: {
        ...process.env,
        CLAWSWEEPER_OPENCLAW_BIN: binary,
        OPENCLAW_TEST_RECORD: recordPath,
        OPENCLAW_TEST_STDOUT: JSON.stringify({
          ok: true,
          status: "ok",
          final: "tracked checkout content",
          payloads: [{ text: "tracked checkout content" }],
          codeModeEngaged: true,
          bridgeCalls: { search: 0, describe: 0, call: 1 },
        }),
      },
      timeoutMs: 10_000,
      checkoutInspection: {
        expectedText: "tracked checkout content",
        expectedPath: "tracked.txt",
      },
    });
    assert.equal(result.status, 0, result.error?.message);
    const record = JSON.parse(readFileSync(recordPath, "utf8"));
    assert.deepEqual(record.args.slice(0, 2), ["agent", "exec"]);
    assert.equal(record.args.includes("--session-id"), false);
    assert.equal(record.args[record.args.indexOf("--code-mode") + 1], "code");
    assert.equal(record.args.includes("--local-model-lean"), true);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("OpenClaw checkout inspection requires challenge text and structured read evidence", () => {
  const root = mkdtempSync(join(tmpdir(), "clawsweeper-openclaw-test-"));
  const recordPath = join(root, "record.json");
  const binary = fakeOpenclaw(root);
  const checkoutInspection = {
    expectedText: "tracked checkout content",
    expectedPath: "tracked.txt",
  };
  const directReadEnvelope = (text: string) =>
    JSON.stringify({
      ok: true,
      status: "ok",
      final: text,
      payloads: [{ text }],
      toolSummary: { calls: 1, tools: ["read"], failures: 0, totalToolTimeMs: 1 },
    });
  try {
    const result = runOpenclawProcess({
      label: "checkout-inspection",
      prompt: "Read the challenged line.",
      model: "openai/test",
      cwd: root,
      env: {
        ...process.env,
        CLAWSWEEPER_OPENCLAW_BIN: binary,
        OPENCLAW_TEST_RECORD: recordPath,
        OPENCLAW_TEST_STDOUT: directReadEnvelope("tracked checkout content"),
      },
      timeoutMs: 10_000,
      checkoutInspection,
    });
    assert.equal(result.status, 0, result.error?.message);
    assert.equal(result.stdout, "");
    const record = JSON.parse(readFileSync(recordPath, "utf8"));
    assert.deepEqual(record.config.tools, {
      allow: ["read"],
      fs: { workspaceOnly: true },
      exec: { host: "gateway", mode: "deny" },
    });

    const wrongText = runOpenclawProcess({
      label: "checkout-inspection-wrong-text",
      prompt: "Read the challenged line.",
      model: "openai/test",
      cwd: root,
      env: {
        ...process.env,
        CLAWSWEEPER_OPENCLAW_BIN: binary,
        OPENCLAW_TEST_RECORD: recordPath,
        OPENCLAW_TEST_STDOUT: directReadEnvelope("different checkout content"),
      },
      timeoutMs: 10_000,
      checkoutInspection,
    });
    assert.equal(wrongText.status, 1);
    assert.match(wrongText.error?.message ?? "", /runner challenge/);

    const missingEvidence = runOpenclawProcess({
      label: "checkout-inspection-missing-evidence",
      prompt: "Read the challenged line.",
      model: "openai/test",
      cwd: root,
      env: {
        ...process.env,
        CLAWSWEEPER_OPENCLAW_BIN: binary,
        OPENCLAW_TEST_RECORD: recordPath,
        OPENCLAW_TEST_STDOUT: JSON.stringify({
          ok: true,
          status: "ok",
          final: "tracked checkout content",
          payloads: [{ text: "tracked checkout content" }],
        }),
      },
      timeoutMs: 10_000,
      checkoutInspection,
    });
    assert.equal(missingEvidence.status, 1);
    assert.match(missingEvidence.error?.message ?? "", /structured read evidence/);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});
test("OpenClaw JSON parser accepts a complete envelope after diagnostic stdout", () => {
  const parsed = parseOpenclawJsonEnvelope(
    [
      "[session-sqlite] maintenance completed",
      "[provider-transport-fetch] status=200",
      JSON.stringify({
        payloads: [{ text: "CLAWSWEEPER_WORKERS_AI_OK" }],
        meta: { stopReason: "stop" },
      }),
    ].join("\n"),
  );
  assert.equal(parsed.failure, undefined);
  assert.equal(parsed.text, "CLAWSWEEPER_WORKERS_AI_OK");
});

test("OpenClaw JSON parser still rejects diagnostic-only stdout", () => {
  const parsed = parseOpenclawJsonEnvelope("[provider] status=200\nnot-json");
  assert.match(parsed.failure?.message ?? "", /invalid JSON/);
  assert.equal(parsed.text, "");
});

test("OpenClaw exit-zero error envelopes synthesize process failures", () => {
  const root = mkdtempSync(join(tmpdir(), "clawsweeper-openclaw-test-"));
  const binary = fakeOpenclaw(root);
  try {
    for (const [name, envelope, expected] of [
      [
        "meta error",
        { payloads: [], meta: { error: { message: "provider unavailable" } } },
        /provider unavailable/,
      ],
      [
        "error payload",
        { payloads: [{ text: "tool failed", isError: true }], meta: {} },
        /tool failed/,
      ],
      [
        "fallback exhaustion",
        { payloads: [], meta: { executionTrace: { exhausted: true } } },
        /fallbacks were exhausted/,
      ],
    ] as const) {
      const result = runOpenclawProcess({
        label: name,
        prompt: "prompt",
        model: "openai/test",
        cwd: root,
        env: {
          ...process.env,
          CLAWSWEEPER_OPENCLAW_BIN: binary,
          OPENCLAW_TEST_RECORD: join(root, `${name}.json`),
          OPENCLAW_TEST_STDOUT: JSON.stringify(envelope),
        },
        timeoutMs: 10_000,
      });
      assert.equal(result.status, 1);
      assert.match(result.error?.message ?? "", expected);
    }
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("OpenClaw timeout stop reasons are exposed as ETIMEDOUT", () => {
  const parsed = parseOpenclawJsonEnvelope(
    JSON.stringify({ payloads: [], meta: { aborted: true, stopReason: "timeout" } }),
  );
  assert.match(parsed.failure?.message ?? "", /timeout/);

  const root = mkdtempSync(join(tmpdir(), "clawsweeper-openclaw-test-"));
  const binary = fakeOpenclaw(root);
  try {
    const result = runOpenclawProcess({
      label: "timeout",
      prompt: "prompt",
      model: "openai/test",
      cwd: root,
      env: {
        ...process.env,
        CLAWSWEEPER_OPENCLAW_BIN: binary,
        OPENCLAW_TEST_RECORD: join(root, "timeout.json"),
        OPENCLAW_TEST_STDOUT: JSON.stringify({
          payloads: [],
          meta: { aborted: true, stopReason: "timeout" },
        }),
      },
      timeoutMs: 10_000,
    });
    assert.equal(result.status, 1);
    assert.equal(codexProcessErrorCode(result.error), "ETIMEDOUT");
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("OpenClaw invalid JSON fails closed with a bounded stderr tail", () => {
  const root = mkdtempSync(join(tmpdir(), "clawsweeper-openclaw-test-"));
  const binary = fakeOpenclaw(root);
  try {
    const result = runOpenclawProcess({
      label: "invalid-json",
      prompt: "prompt",
      model: "openai/test",
      cwd: root,
      env: {
        ...process.env,
        CLAWSWEEPER_OPENCLAW_BIN: binary,
        OPENCLAW_TEST_RECORD: join(root, "invalid.json"),
        OPENCLAW_TEST_STDOUT: "not-json",
        OPENCLAW_TEST_STDERR: `${"x".repeat(12_000)}stderr-tail-marker`,
      },
      timeoutMs: 10_000,
    });
    assert.equal(result.status, 1);
    assert.match(result.error?.message ?? "", /invalid JSON/);
    assert.match(result.error?.message ?? "", /stderr-tail-marker/);
    assert.ok(Buffer.byteLength(result.error?.message ?? "") < 9 * 1024);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("OpenClaw runner writes the normalized last message and notes ignored steering", (t) => {
  useFakeScanner(t);
  const root = mkdtempSync(join(tmpdir(), "clawsweeper-openclaw-test-"));
  const binary = fakeOpenclaw(root);
  const outputPath = join(root, "last-message.txt");
  try {
    const result = runAgentProcess({
      label: "steerable-openclaw",
      scanSource: { kind: "prompt" },
      prompt: "prompt",
      model: "internal",
      reasoningEffort: "medium",
      cwd: root,
      env: {
        ...process.env,
        CLAWSWEEPER_RUNNER: "openclaw",
        CLAWSWEEPER_OPENCLAW_MODEL: "openai/test",
        CLAWSWEEPER_OPENCLAW_BIN: binary,
        OPENCLAW_TEST_RECORD: join(root, "steerable.json"),
      },
      timeoutMs: 10_000,
      codexExtraArgs: ["--output-last-message", outputPath, "--json", "-"],
      appServer: { statePath: join(root, "thread.json") },
    });
    assert.equal(result.status, 0, result.stderr);
    assert.equal(readFileSync(outputPath, "utf8"), "done");
    assert.equal(result.stderr.match(/CLAWSWEEPER_STEERABLE_CODEX is Codex-specific/g)?.length, 1);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("OpenClaw provider config rejects malformed and non-object JSON without echoing it", () => {
  for (const value of ["{secret-api-key", "[]"]) {
    const result = runOpenclawProcess({
      label: "bad-provider-config",
      prompt: "prompt",
      model: "openai/test",
      cwd: process.cwd(),
      env: { CLAWSWEEPER_OPENCLAW_PROVIDERS_JSON: value },
      timeoutMs: 1_000,
    });
    assert.match(result.error?.message ?? "", /CLAWSWEEPER_OPENCLAW_PROVIDERS_JSON/);
    assert.doesNotMatch(result.error?.message ?? "", /secret-api-key/);
  }
});

test("OpenClaw kimi models get built-in provider defaults when none are configured", () => {
  const root = mkdtempSync(join(tmpdir(), "clawsweeper-openclaw-test-"));
  const recordPath = join(root, "record.json");
  const binary = fakeOpenclaw(root);
  try {
    const result = runOpenclawProcess({
      label: "kimi-defaults",
      prompt: "hi",
      model: "kimi/k3",
      cwd: root,
      env: {
        ...process.env,
        CLAWSWEEPER_OPENCLAW_BIN: binary,
        CLAWSWEEPER_OPENCLAW_MODEL: "kimi/k3",
        CLAWSWEEPER_OPENCLAW_PROVIDERS_JSON: "",
        OPENCLAW_TEST_RECORD: recordPath,
      },
      timeoutMs: 60_000,
    });
    assert.equal(result.status, 0, result.stderr);
    const record = JSON.parse(readFileSync(recordPath, "utf8"));
    assert.deepEqual(record.config.models, {
      mode: "merge",
      providers: {
        kimi: {
          baseUrl: "https://api.kimi.com/coding/",
          apiKey: "${KIMI_API_KEY}",
          api: "anthropic-messages",
          models: [
            { id: "kimi-for-coding", name: "Kimi Code", contextWindow: 262144, maxTokens: 65536 },
            { id: "k3", name: "Kimi K3", contextWindow: 1048576, maxTokens: 131072 },
          ],
        },
      },
    });
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("OpenClaw non-kimi models get no built-in provider block", () => {
  const root = mkdtempSync(join(tmpdir(), "clawsweeper-openclaw-test-"));
  const recordPath = join(root, "record.json");
  const binary = fakeOpenclaw(root);
  try {
    const result = runOpenclawProcess({
      label: "no-defaults",
      prompt: "hi",
      model: "openai/gpt-5.6-sol",
      cwd: root,
      env: {
        ...process.env,
        CLAWSWEEPER_OPENCLAW_BIN: binary,
        CLAWSWEEPER_OPENCLAW_MODEL: "openai/gpt-5.6-sol",
        OPENCLAW_TEST_RECORD: recordPath,
      },
      timeoutMs: 60_000,
    });
    assert.equal(result.status, 0, result.stderr);
    const record = JSON.parse(readFileSync(recordPath, "utf8"));
    assert.equal(record.config.models, undefined);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("OpenClaw subprocess env strips workflow credentials and keeps provider keys", () => {
  const root = mkdtempSync(join(tmpdir(), "clawsweeper-openclaw-test-"));
  const recordPath = join(root, "record.json");
  const binary = fakeOpenclaw(root);
  try {
    const result = runOpenclawProcess({
      label: "env-allowlist",
      prompt: "hi",
      model: "kimi/k3",
      cwd: root,
      env: {
        ...process.env,
        CLAWSWEEPER_OPENCLAW_BIN: binary,
        OPENCLAW_TEST_RECORD: recordPath,
        GITHUB_TOKEN: "workflow-github",
        GH_TOKEN: "workflow-gh",
        CLAWSWEEPER_WEBHOOK_SECRET: "workflow-webhook",
        CLAWSWEEPER_APP_PRIVATE_KEY: "workflow-app",
        KIMI_API_KEY: "provider-kimi",
      },
      timeoutMs: 60_000,
    });
    assert.equal(result.status, 0, result.stderr);
    const record = JSON.parse(readFileSync(recordPath, "utf8"));
    assert.equal(record.env.GITHUB_TOKEN, null);
    assert.equal(record.env.GH_TOKEN, null);
    assert.equal(record.env.CLAWSWEEPER_WEBHOOK_SECRET, null);
    assert.equal(record.env.CLAWSWEEPER_APP_PRIVATE_KEY, null);
    assert.equal(record.env.KIMI_API_KEY, "provider-kimi");
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("OpenClaw cerebras models get built-in provider defaults", () => {
  const root = mkdtempSync(join(tmpdir(), "clawsweeper-openclaw-test-"));
  const recordPath = join(root, "record.json");
  const binary = fakeOpenclaw(root);
  try {
    const result = runOpenclawProcess({
      label: "cerebras-defaults",
      prompt: "hi",
      model: "cerebras/zai-glm-4.7",
      cwd: root,
      env: {
        ...process.env,
        CLAWSWEEPER_OPENCLAW_BIN: binary,
        CLAWSWEEPER_OPENCLAW_MODEL: "cerebras/zai-glm-4.7",
        OPENCLAW_TEST_RECORD: recordPath,
      },
      timeoutMs: 60_000,
    });
    assert.equal(result.status, 0, result.stderr);
    const record = JSON.parse(readFileSync(recordPath, "utf8"));
    assert.deepEqual(record.config.models, {
      mode: "merge",
      providers: {
        cerebras: {
          baseUrl: "https://api.cerebras.ai/v1",
          apiKey: "${CEREBRAS_API_KEY}",
          api: "openai-completions",
          models: [
            { id: "zai-glm-4.7", name: "Z.ai GLM 4.7", contextWindow: 128000, maxTokens: 8192 },
          ],
        },
      },
    });
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("OpenClaw zai models get built-in Coding Plan endpoint defaults", () => {
  const root = mkdtempSync(join(tmpdir(), "clawsweeper-openclaw-test-"));
  const recordPath = join(root, "record.json");
  const binary = fakeOpenclaw(root);
  try {
    const result = runOpenclawProcess({
      label: "zai-defaults",
      prompt: "hi",
      model: "zai/glm-5.2",
      cwd: root,
      env: {
        ...process.env,
        CLAWSWEEPER_OPENCLAW_BIN: binary,
        CLAWSWEEPER_OPENCLAW_MODEL: "zai/glm-5.2",
        OPENCLAW_TEST_RECORD: recordPath,
      },
      timeoutMs: 60_000,
    });
    assert.equal(result.status, 0, result.stderr);
    const record = JSON.parse(readFileSync(recordPath, "utf8"));
    assert.deepEqual(record.config.models, {
      mode: "merge",
      providers: {
        zai: {
          baseUrl: "https://api.z.ai/api/coding/paas/v4",
          apiKey: "${ZAI_API_KEY}",
          api: "openai-completions",
          models: [{ id: "glm-5.2", name: "GLM-5.2", contextWindow: 1000000, maxTokens: 131072 }],
        },
      },
    });
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});
