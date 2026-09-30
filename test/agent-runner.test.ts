import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { chmodSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { useFakeScanner } from "./agent-input-scan-helpers.ts";

import {
  agentRunner,
  codexAgentArgs,
  runAgentCheckoutInspection,
  runAgentProcess,
} from "../dist/agent-runner.js";

test("agent runner defaults to Codex and fails closed on unknown values", () => {
  assert.equal(agentRunner({}), "codex");
  assert.equal(agentRunner({ CLAWSWEEPER_RUNNER: "codex" }), "codex");
  assert.equal(agentRunner({ CLAWSWEEPER_RUNNER: "openclaw" }), "openclaw");
  assert.throws(
    () => agentRunner({ CLAWSWEEPER_RUNNER: "claude" }),
    /Invalid CLAWSWEEPER_RUNNER.*codex.*openclaw/,
  );
});

test("agent runner preserves review-style Codex argument composition", () => {
  assert.deepEqual(
    codexAgentArgs({
      label: "review-42",
      scanSource: { kind: "prompt" },
      prompt: "review",
      model: "gpt-public",
      reasoningEffort: "high",
      cwd: "/tmp",
      env: {},
      timeoutMs: 1_000,
      codexExtraArgs: [
        "-c",
        'forced_login_method="api"',
        "-c",
        'approval_policy="never"',
        "-C",
        "/target",
        "--output-schema",
        "/schema.json",
        "--output-last-message",
        "/answer.json",
        "--json",
        "-",
      ],
    }),
    [
      "exec",
      "--model",
      "gpt-public",
      "-c",
      'model_reasoning_effort="high"',
      "-c",
      'forced_login_method="api"',
      "-c",
      'approval_policy="never"',
      "-C",
      "/target",
      "--output-schema",
      "/schema.json",
      "--output-last-message",
      "/answer.json",
      "--json",
      "-",
    ],
  );
});

test("agent runner preserves ordered repair-worker Codex arguments", () => {
  const ordered = [
    "--cd",
    "/target",
    "--model",
    "gpt-public",
    "--sandbox",
    "workspace-write",
    "-c",
    'approval_policy="never"',
    "-c",
    'model_reasoning_effort="high"',
    "--json",
    "-",
  ];
  assert.deepEqual(
    codexAgentArgs({
      label: "repair",
      scanSource: { kind: "prompt" },
      prompt: "repair",
      model: "gpt-public",
      reasoningEffort: "high",
      cwd: "/target",
      env: {},
      timeoutMs: 1_000,
      codexExtraArgs: ordered,
    }),
    ["exec", ...ordered],
  );
});

test("runAgentProcess delegates the default path to Codex with unchanged argv and stdin", (t) => {
  const root = mkdtempSync(join(tmpdir(), "clawsweeper-agent-runner-test-"));
  const binary = join(root, "fake-codex");
  const argsPath = join(root, "args.json");
  const promptPath = join(root, "prompt.txt");
  const diagnosticPromptPath = join(root, "diagnostic.prompt.md");
  const schemaPath = join(root, "schema.json");
  const prompt = "prompt over stdin\r\n🦞 exact bytes\n";
  const schema = '{"type":"object","description":"exact schema bytes"}\n';
  writeFileSync(schemaPath, schema);
  writeFileSync(diagnosticPromptPath, "stale prompt", { mode: 0o644 });
  useFakeScanner(
    t,
    `
assert.equal(fs.existsSync(${JSON.stringify(diagnosticPromptPath)}), false);
assert.equal(inputs.find(({name}) => name === 'prompt').bytes.toString(), ${JSON.stringify(prompt)});
assert.equal(inputs.find(({name}) => name === 'schema').bytes.toString(), ${JSON.stringify(schema)});
`,
  );
  writeFileSync(
    binary,
    `#!/usr/bin/env node
const fs = require("node:fs");
fs.writeFileSync(process.env.AGENT_RUNNER_ARGS_PATH, JSON.stringify(process.argv.slice(2)));
fs.writeFileSync(process.env.AGENT_RUNNER_PROMPT_PATH, fs.readFileSync(0, "utf8"));
process.stdout.write("ok");
`,
  );
  chmodSync(binary, 0o755);
  try {
    const result = runAgentProcess({
      label: "default-codex",
      scanSource: { kind: "prompt" },
      prompt,
      diagnosticPromptPath,
      model: "internal",
      reasoningEffort: "low",
      cwd: root,
      env: {
        ...process.env,
        CODEX_BIN: binary,
        AGENT_RUNNER_ARGS_PATH: argsPath,
        AGENT_RUNNER_PROMPT_PATH: promptPath,
      },
      timeoutMs: 10_000,
      codexExtraArgs: ["--sandbox", "read-only", "--output-schema", schemaPath, "-"],
    });
    assert.equal(result.status, 0, result.stderr);
    assert.deepEqual(JSON.parse(readFileSync(argsPath, "utf8")), [
      "exec",
      "-c",
      'model_reasoning_effort="low"',
      "--sandbox",
      "read-only",
      "--output-schema",
      schemaPath,
      "-",
    ]);
    assert.equal(readFileSync(promptPath, "utf8"), prompt);
    assert.equal(readFileSync(diagnosticPromptPath, "utf8"), prompt);
    assert.equal(statSync(diagnosticPromptPath).mode & 0o777, 0o600);
    assert.equal(readFileSync(schemaPath, "utf8"), schema);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("Workers AI OpenClaw models omit unsupported thinking levels", (t) => {
  useFakeScanner(t);
  const root = mkdtempSync(join(tmpdir(), "clawsweeper-agent-runner-workers-ai-thinking-test-"));
  const binary = join(root, "fake-openclaw");
  const argsPath = join(root, "args.json");
  writeFileSync(
    binary,
    `#!/usr/bin/env node
const fs = require("node:fs");
fs.writeFileSync(process.env.OPENCLAW_TEST_ARGS, JSON.stringify(process.argv.slice(2)));
process.stdout.write(JSON.stringify({ payloads: [{ text: "ok" }], meta: { stopReason: "stop" } }));
`,
  );
  chmodSync(binary, 0o755);
  try {
    const result = runAgentProcess({
      label: "workers-ai-thinking",
      scanSource: { kind: "prompt" },
      prompt: "Return ok.",
      model: "internal",
      reasoningEffort: "low",
      cwd: root,
      env: {
        ...process.env,
        CLAWSWEEPER_RUNNER: "openclaw",
        CLAWSWEEPER_OPENCLAW_MODEL: "workersai/@cf/zai-org/glm-5.3",
        CLAWSWEEPER_OPENCLAW_BIN: binary,
        OPENCLAW_TEST_ARGS: argsPath,
      },
      timeoutMs: 10_000,
    });
    assert.equal(result.status, 0, result.error?.message);
    const args = JSON.parse(readFileSync(argsPath, "utf8"));
    assert.equal(args.includes("--thinking"), false);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("OpenClaw receives Codex output schema as an explicit final-output contract", (t) => {
  useFakeScanner(t);
  const root = mkdtempSync(join(tmpdir(), "clawsweeper-agent-runner-openclaw-schema-test-"));
  const binary = join(root, "fake-openclaw");
  const argsPath = join(root, "args.json");
  const promptPath = join(root, "seen-prompt.txt");
  const schemaPath = join(root, "decision.schema.json");
  const outputPath = join(root, "last-message.json");
  const diagnosticPromptPath = join(root, "diagnostic.prompt.md");
  const schema = {
    type: "object",
    additionalProperties: false,
    required: ["decision", "summary"],
    properties: {
      decision: { type: "string" },
      summary: { type: "string" },
    },
  };
  writeFileSync(schemaPath, JSON.stringify(schema));
  writeFileSync(
    binary,
    `#!/usr/bin/env node
const fs = require("node:fs");
const args = process.argv.slice(2);
fs.writeFileSync(process.env.OPENCLAW_TEST_ARGS, JSON.stringify(args));
const messageFile = args[args.indexOf("--message-file") + 1];
fs.writeFileSync(process.env.OPENCLAW_TEST_PROMPT, fs.readFileSync(messageFile, "utf8"));
const final = JSON.stringify({ decision: "keep_open", summary: "schema ok" });
process.stdout.write(JSON.stringify({ ok: true, status: "ok", final, payloads: [{ text: final }] }));
`,
  );
  chmodSync(binary, 0o755);
  try {
    const result = runAgentProcess({
      label: "openclaw-schema-contract",
      scanSource: { kind: "prompt" },
      prompt: "Review this item.",
      diagnosticPromptPath,
      model: "internal",
      cwd: root,
      env: {
        ...process.env,
        CLAWSWEEPER_RUNNER: "openclaw",
        CLAWSWEEPER_OPENCLAW_MODEL: "workersai/@cf/zai-org/glm-5.3",
        CLAWSWEEPER_OPENCLAW_BIN: binary,
        OPENCLAW_TEST_ARGS: argsPath,
        OPENCLAW_TEST_PROMPT: promptPath,
      },
      timeoutMs: 10_000,
      codexExtraArgs: [
        "--output-schema",
        schemaPath,
        "--output-last-message",
        outputPath,
      ],
    });
    assert.equal(result.status, 0, result.error?.message);
    const seenPrompt = readFileSync(promptPath, "utf8");
    assert.match(seenPrompt, /Required final output contract/);
    assert.match(seenPrompt, /Return only one JSON value/);
    assert.match(seenPrompt, /"required":\["decision","summary"\]/);
    assert.equal(readFileSync(diagnosticPromptPath, "utf8"), seenPrompt);
    assert.equal(
      readFileSync(outputPath, "utf8"),
      JSON.stringify({ decision: "keep_open", summary: "schema ok" }),
    );
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("OpenClaw nonzero exit preserves a valid final result for schema validation", (t) => {
  useFakeScanner(t);
  const root = mkdtempSync(join(tmpdir(), "clawsweeper-agent-runner-openclaw-nonzero-test-"));
  const binary = join(root, "fake-openclaw");
  const outputPath = join(root, "last-message.json");
  const decision = '{"decision":"keep_open","confidence":"low","summary":"valid result"}';
  writeFileSync(
    binary,
    `#!/usr/bin/env node
process.stdout.write(JSON.stringify({
  ok: true,
  status: "ok",
  final: ${JSON.stringify(decision)},
  payloads: [{ text: ${JSON.stringify(decision)} }],
}));
process.exitCode = 1;
`,
  );
  chmodSync(binary, 0o755);
  try {
    const result = runAgentProcess({
      label: "openclaw-nonzero-final",
      scanSource: { kind: "prompt" },
      prompt: "Return the requested JSON.",
      model: "internal",
      cwd: root,
      env: {
        ...process.env,
        CLAWSWEEPER_RUNNER: "openclaw",
        CLAWSWEEPER_OPENCLAW_MODEL: "workersai/@cf/zai-org/glm-5.3",
        CLAWSWEEPER_OPENCLAW_BIN: binary,
      },
      timeoutMs: 10_000,
      codexExtraArgs: ["--output-last-message", outputPath],
    });
    assert.equal(result.status, 1);
    assert.equal(result.error, undefined);
    assert.equal(result.stdout, decision);
    assert.equal(readFileSync(outputPath, "utf8"), decision);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("OpenClaw runner accepts provider model ids with nested path segments", (t) => {
  useFakeScanner(t);
  const root = mkdtempSync(join(tmpdir(), "clawsweeper-agent-runner-workers-ai-test-"));
  const binary = join(root, "fake-openclaw");
  writeFileSync(
    binary,
    `#!/usr/bin/env node
const fs = require("node:fs");
const result = { payloads: [{ text: "ok" }], meta: { stopReason: "stop" } };
process.stdout.write(JSON.stringify(result));
`,
  );
  chmodSync(binary, 0o755);
  try {
    const result = runAgentProcess({
      label: "workers-ai-model-id",
      scanSource: { kind: "prompt" },
      prompt: "Return ok.",
      model: "internal",
      cwd: root,
      env: {
        ...process.env,
        CLAWSWEEPER_RUNNER: "openclaw",
        CLAWSWEEPER_OPENCLAW_MODEL: "workersai/@cf/zai-org/glm-5.3",
        CLAWSWEEPER_OPENCLAW_BIN: binary,
      },
      timeoutMs: 10_000,
    });
    assert.equal(result.status, 0, result.error?.message);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("OpenClaw runner requires a provider/model override", () => {
  assert.throws(
    () =>
      runAgentProcess({
        label: "missing-model",
        scanSource: { kind: "prompt" },
        prompt: "prompt",
        model: "internal",
        cwd: process.cwd(),
        env: { CLAWSWEEPER_RUNNER: "openclaw" },
        timeoutMs: 1_000,
      }),
    /CLAWSWEEPER_OPENCLAW_MODEL is required/,
  );
});

test("OpenClaw checkout inspection attests the exact tracked path without checkout writes", (t) => {
  useFakeScanner(t);
  const root = mkdtempSync(join(tmpdir(), "clawsweeper-agent-runner-test-"));
  const binary = join(root, "fake-openclaw");
  execFileSync("git", ["init", "-q"], { cwd: root });
  const trackedPath = join(root, "tracked.txt");
  writeFileSync(trackedPath, "first line\ntracked checkout content\nlast line\n");
  execFileSync("git", ["add", "tracked.txt"], { cwd: root });
  execFileSync(
    "git",
    [
      "-c",
      "user.name=test",
      "-c",
      "user.email=test@example.com",
      "commit",
      "-q",
      "-m",
      "tracked text",
    ],
    { cwd: root },
  );
  writeFileSync(
    binary,
    `#!/usr/bin/env node
const fs = require("node:fs");
const path = require("node:path");
const prompt = fs.readFileSync(process.argv[process.argv.indexOf("--message-file") + 1], "utf8");
const relativePath = JSON.parse(prompt.match(/^Path: (.+)$/m)[1]);
const lineNumber = Number(prompt.match(/^Return exactly line (\\d+)/m)[1]);
const challenged = fs.readFileSync(path.join(process.env.OPENCLAW_WORKSPACE_DIR, relativePath), "utf8").split(/\\r?\\n/)[lineNumber - 1].trim();
process.stdout.write(JSON.stringify({
  ok: true,
  status: "ok",
  final: challenged,
  payloads: [{ text: challenged }],
  ...(process.env.OPENCLAW_TEST_NO_RECEIPT === "1"
    ? {}
    : { toolSummary: { calls: 1, tools: ["read"], failures: 0, totalToolTimeMs: 1 } }),
}));
`,
  );
  chmodSync(binary, 0o755);
  const baseEnv = {
    ...process.env,
    CLAWSWEEPER_RUNNER: "openclaw",
    CLAWSWEEPER_OPENCLAW_MODEL: "openai/test",
    CLAWSWEEPER_OPENCLAW_BIN: binary,
  };
  try {
    chmodSync(trackedPath, 0o444);
    chmodSync(root, 0o555);
    const scan = { scanSource: { kind: "prompt" as const }, initialPrompt: "Review the checkout." };
    const verified = runAgentCheckoutInspection({
      ...scan,
      cwd: root,
      env: baseEnv,
      timeoutMs: 10_000,
    });
    assert.equal(verified.status, 0, verified.error?.message);

    const missingEvidence = runAgentCheckoutInspection({
      ...scan,
      cwd: root,
      env: { ...baseEnv, OPENCLAW_TEST_NO_RECEIPT: "1" },
      timeoutMs: 10_000,
    });
    assert.equal(missingEvidence.status, 1);
    assert.match(missingEvidence.error?.message ?? "", /structured read evidence/);
  } finally {
    chmodSync(root, 0o755);
    chmodSync(trackedPath, 0o644);
    rmSync(root, { recursive: true, force: true });
  }
});

test("OpenClaw checkout inspection gets a bounded remote-provider latency budget", (t) => {
  useFakeScanner(t);
  const root = mkdtempSync(join(tmpdir(), "clawsweeper-agent-runner-timeout-test-"));
  const binary = join(root, "fake-openclaw");
  const argsPath = join(root, "args.json");
  execFileSync("git", ["init", "-q"], { cwd: root });
  writeFileSync(join(root, "tracked.txt"), "tracked checkout content long enough for challenge\n");
  execFileSync("git", ["add", "tracked.txt"], { cwd: root });
  execFileSync(
    "git",
    ["-c", "user.name=test", "-c", "user.email=test@example.com", "commit", "-q", "-m", "tracked"],
    { cwd: root },
  );
  writeFileSync(
    binary,
    `#!/usr/bin/env node
const fs = require("node:fs");
const path = require("node:path");
fs.writeFileSync(process.env.OPENCLAW_TEST_ARGS, JSON.stringify(process.argv.slice(2)));
const prompt = fs.readFileSync(process.argv[process.argv.indexOf("--message-file") + 1], "utf8");
const relativePath = JSON.parse(prompt.match(/^Path: (.+)$/m)[1]);
const lineNumber = Number(prompt.match(/^Return exactly line (\\d+)/m)[1]);
const challenged = fs.readFileSync(path.join(process.env.OPENCLAW_WORKSPACE_DIR, relativePath), "utf8").split(/\\r?\\n/)[lineNumber - 1].trim();
process.stdout.write(JSON.stringify({
  ok: true,
  status: "ok",
  final: challenged,
  payloads: [{ text: challenged }],
  codeModeEngaged: true,
  bridgeCalls: { search: 0, describe: 0, call: 1 },
}));
`,
  );
  chmodSync(binary, 0o755);
  try {
    const result = runAgentCheckoutInspection({
      cwd: root,
      env: {
        ...process.env,
        CLAWSWEEPER_RUNNER: "openclaw",
        CLAWSWEEPER_OPENCLAW_MODEL: "workersai/@cf/zai-org/glm-5.3",
        CLAWSWEEPER_OPENCLAW_BIN: binary,
        OPENCLAW_TEST_ARGS: argsPath,
      },
      timeoutMs: 180_000,
      scanSource: { kind: "prompt" },
      initialPrompt: "Review the checkout.",
    });
    assert.equal(result.status, 0, result.error?.message);
    const args = JSON.parse(readFileSync(argsPath, "utf8"));
    assert.equal(args[args.indexOf("--timeout") + 1], "120");
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("OpenClaw checkout inspection latency budget is capped", (t) => {
  useFakeScanner(t);
  const root = mkdtempSync(join(tmpdir(), "clawsweeper-agent-runner-timeout-cap-test-"));
  const binary = join(root, "fake-openclaw");
  const argsPath = join(root, "args.json");
  execFileSync("git", ["init", "-q"], { cwd: root });
  writeFileSync(join(root, "tracked.txt"), "tracked checkout content long enough for challenge\n");
  execFileSync("git", ["add", "tracked.txt"], { cwd: root });
  execFileSync(
    "git",
    ["-c", "user.name=test", "-c", "user.email=test@example.com", "commit", "-q", "-m", "tracked"],
    { cwd: root },
  );
  writeFileSync(
    binary,
    `#!/usr/bin/env node
const fs = require("node:fs");
const path = require("node:path");
fs.writeFileSync(process.env.OPENCLAW_TEST_ARGS, JSON.stringify(process.argv.slice(2)));
const prompt = fs.readFileSync(process.argv[process.argv.indexOf("--message-file") + 1], "utf8");
const relativePath = JSON.parse(prompt.match(/^Path: (.+)$/m)[1]);
const lineNumber = Number(prompt.match(/^Return exactly line (\\d+)/m)[1]);
const challenged = fs.readFileSync(path.join(process.env.OPENCLAW_WORKSPACE_DIR, relativePath), "utf8").split(/\\r?\\n/)[lineNumber - 1].trim();
process.stdout.write(JSON.stringify({
  ok: true,
  status: "ok",
  final: challenged,
  payloads: [{ text: challenged }],
  codeModeEngaged: true,
  bridgeCalls: { search: 0, describe: 0, call: 1 },
}));
`,
  );
  chmodSync(binary, 0o755);
  try {
    const result = runAgentCheckoutInspection({
      cwd: root,
      env: {
        ...process.env,
        CLAWSWEEPER_RUNNER: "openclaw",
        CLAWSWEEPER_OPENCLAW_MODEL: "workersai/@cf/zai-org/glm-5.3",
        CLAWSWEEPER_OPENCLAW_BIN: binary,
        CLAWSWEEPER_OPENCLAW_CHECKOUT_INSPECTION_TIMEOUT_MS: "600000",
        OPENCLAW_TEST_ARGS: argsPath,
      },
      timeoutMs: 300_000,
      scanSource: { kind: "prompt" },
      initialPrompt: "Review the checkout.",
    });
    assert.equal(result.status, 0, result.error?.message);
    const args = JSON.parse(readFileSync(argsPath, "utf8"));
    assert.equal(args[args.indexOf("--timeout") + 1], "180");
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("OpenClaw checkout inspection reports challenge setup failures", (t) => {
  useFakeScanner(t);
  const root = mkdtempSync(join(tmpdir(), "clawsweeper-agent-runner-missing-test-"));
  try {
    const result = runAgentCheckoutInspection({
      scanSource: { kind: "prompt" },
      initialPrompt: "Inspect checkout.",
      cwd: join(root, "missing"),
      env: {
        ...process.env,
        CLAWSWEEPER_RUNNER: "openclaw",
        CLAWSWEEPER_OPENCLAW_MODEL: "openai/test",
      },
      timeoutMs: 10_000,
    });
    assert.notEqual(result.status, 0);
    assert.match(result.error?.message ?? "", /ENOENT/);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("checkout inspection lists tracked files beyond the 1 MB spawn default", (t) => {
  useFakeScanner(t);
  const root = mkdtempSync(join(tmpdir(), "clawsweeper-agent-runner-large-index-test-"));
  try {
    execFileSync("git", ["init", "-q"], { cwd: root });
    const blob = execFileSync("git", ["hash-object", "-w", "--stdin"], {
      cwd: root,
      input: "tracked checkout content\n",
      encoding: "utf8",
    }).trim();
    // Index-only entries: ~6000 x 220-byte paths push `git ls-files --stage -z` past 1 MB.
    const indexInfo = Array.from(
      { length: 6000 },
      (_, index) => `100644 blob ${blob}\t${"deep/".repeat(40)}file-${index}.txt\n`,
    ).join("");
    execFileSync("git", ["update-index", "--index-info"], { cwd: root, input: indexInfo });
    const listing = execFileSync("git", ["ls-files", "--stage", "-z"], {
      cwd: root,
      maxBuffer: 16 * 1024 * 1024,
    });
    assert.ok(listing.length > 1024 * 1024, `listing is ${listing.length} bytes`);

    const result = runAgentCheckoutInspection({
      scanSource: { kind: "prompt" },
      initialPrompt: "Inspect checkout.",
      cwd: root,
      env: {
        ...process.env,
        CLAWSWEEPER_RUNNER: "openclaw",
        CLAWSWEEPER_OPENCLAW_MODEL: "openai/test",
      },
      timeoutMs: 30_000,
    });
    assert.notEqual(result.error?.code, "ENOBUFS", result.error?.message);
    assert.match(result.error?.message ?? "", /could not select a tracked text line/);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});
