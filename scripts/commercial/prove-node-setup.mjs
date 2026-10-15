import assert from "node:assert/strict";
import { createHash, randomUUID } from "node:crypto";
import { readFileSync, writeFileSync, mkdirSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { resolve, join } from "node:path";
import { spawnSync } from "node:child_process";
import { parse } from "yaml";

const actionRoot = resolve(process.argv[2] || "");
assert.ok(process.argv[2], "Pass the checkout of the pinned setup-node action");
const actionSha = "a0853c24544627f65ddf259abe73b1d18a591444";
const action = join(actionRoot, "dist/setup/index.js");
const workflow = parse(readFileSync(".github/workflows/commercial-fulfilment.yml", "utf8"));
const setups = Object.entries(workflow.jobs).flatMap(([job, value]) =>
  value.steps
    .filter((step) => step.uses?.startsWith("actions/setup-node@"))
    .map((step) => ({ job, step })),
);
assert.equal(setups.length, 6);
for (const { job, step } of setups) {
  assert.equal(step.uses, "actions/setup-node@" + actionSha, job);
  assert.equal(step.with["package-manager-cache"], false, job);
  assert.equal(step.with["node-version"], "24.18.1", job);
}
const image = "node:24.18.1-bookworm-slim";
const imageId = spawnSync("docker", ["image", "inspect", image, "--format", "{{.Id}}"], {
  encoding: "utf8",
});
assert.equal(imageId.status, 0, imageId.stderr);
const temp = mkdtempSync(join(tmpdir(), "tw-node-setup-"));
const evidenceDir = resolve(".artifacts/node-setup-proof");
mkdirSync(evidenceDir, { recursive: true });
writeFileSync(join(temp, "package.json"), readFileSync("package.json"));
writeFileSync(
  join(temp, "runner.cjs"),
  `const fs = require("node:fs");
const cp = require("node:child_process");
if (cp.spawnSync("pnpm", ["--version"]).status === 0) throw new Error("pnpm must be absent");
for (const k of ["GITHUB_PATH", "GITHUB_OUTPUT", "GITHUB_ENV", "GITHUB_STATE"]) {
  process.env[k] = "/tmp/" + k;
  fs.writeFileSync(process.env[k], "");
}
fs.mkdirSync("/tmp/toolcache", {recursive:true});
require("/action/dist/setup/index.js");
`,
);
const scenarios = [];
try {
  for (const [name, cache, expected] of [
    ["default", "true", 1],
    ["explicit-no-cache", "false", 0],
  ]) {
    const lease = "tw-node-setup-" + randomUUID();
    const args = [
      "run",
      "--rm",
      "--name",
      lease,
      "--network",
      "none",
      "--read-only",
      "--cap-drop",
      "ALL",
      "--security-opt",
      "no-new-privileges",
      "--pids-limit",
      "128",
      "--memory",
      "512m",
      "--cpus",
      "1",
      "--user",
      "1000:1000",
      "--tmpfs",
      "/tmp:rw,nosuid,nodev,mode=1777,size=128m",
      "--mount",
      "type=bind,src=" + temp + ",dst=/workspace,readonly",
      "--mount",
      "type=bind,src=" + actionRoot + ",dst=/action,readonly",
      "--workdir",
      "/workspace",
      "--env",
      "GITHUB_WORKSPACE=/workspace",
      "--env",
      "RUNNER_TEMP=/tmp",
      "--env",
      "RUNNER_TOOL_CACHE=/tmp/toolcache",
      "--env",
      "RUNNER_OS=Linux",
      "--env",
      "INPUT_PACKAGE-MANAGER-CACHE=" + cache,
      "--entrypoint",
      "node",
      image,
      "/workspace/runner.cjs",
    ];
    const result = spawnSync("docker", args, {
      encoding: "utf8",
      timeout: 60000,
      maxBuffer: 2 * 1024 * 1024,
    });
    const log = result.stdout + "\n" + result.stderr;
    writeFileSync(join(evidenceDir, name + ".log"), log);
    assert.equal(result.status, expected, name + ": " + log);
    if (name === "default") assert.match(log, /Unable to locate executable file: pnpm/);
    else assert.doesNotMatch(log, /::error::|Unable to locate executable/);
    scenarios.push({
      name,
      cache,
      exitCode: result.status,
      lease,
      removed: true,
      log: name + ".log",
    });
  }
  const result = {
    schema: "tw.node-setup-proof.v1",
    result: "passed",
    observedAt: new Date().toISOString(),
    baseSha: "316e0ad825b2f261f8cab8c199e1ea99411b3e69",
    provider: "local-container",
    orchestrator: "docker",
    image,
    imageId: imageId.stdout.trim(),
    actionSha,
    actionBundleSha256: createHash("sha256").update(readFileSync(action)).digest("hex"),
    packageSha256: createHash("sha256").update(readFileSync("package.json")).digest("hex"),
    workflowSha256: createHash("sha256")
      .update(readFileSync(".github/workflows/commercial-fulfilment.yml"))
      .digest("hex"),
    jobs: setups.map(({ job }) => job),
    network: "none",
    realCredentials: false,
    modelTurns: 0,
    scenarios,
    limits: [
      "Uses the preinstalled identical Node version; does not test its download.",
      "Does not exercise GitHub OIDC, runner provisioning, model inference or customer delivery.",
    ],
  };
  writeFileSync(join(evidenceDir, "result.json"), JSON.stringify(result, null, 2) + "\n");
  console.log(JSON.stringify(result, null, 2));
} finally {
  rmSync(temp, { recursive: true, force: true });
}
