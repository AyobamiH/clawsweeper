import assert from "node:assert/strict";
import { createHash, createHmac } from "node:crypto";
import { execFile } from "node:child_process";
import { createServer } from "node:http";
import { cp, mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";

const run = promisify(execFile);
const repositoryRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const clientFiles = ["subscription-quota-client.js", "codex-spawn.js", "command.js"];
const fixtureSecret = "commercial-bootstrap-fixture-only";

// Exercise the same compiled import and admission call as both model jobs, in
// a directory with neither source TypeScript nor installed project dependencies.
const childScript = `
let clientImported = false;
try {
  const { admitSubscription } = await import("./dist/subscription-quota-client.js");
  clientImported = true;
  const allowed = await admitSubscription();
  console.log(JSON.stringify({ clientImported, allowed }));
  process.exitCode = allowed ? 0 : 2;
} catch (error) {
  const messages = ["Shared subscription quota configuration missing", "Shared subscription quota unavailable"];
  console.log(JSON.stringify({ clientImported, refused: true, reason: messages.includes(error.message) ? error.message : "unexpected_failure" }));
  process.exitCode = 3;
}
`;

export async function proveBootstrap() {
  const root = await mkdtemp(path.join(os.tmpdir(), "tw-commercial-bootstrap-"));
  const calls = [];
  let scenario = "allowed";
  const server = createServer(async (request, response) => {
    const chunks = [];
    for await (const chunk of request) chunks.push(chunk);
    const text = Buffer.concat(chunks).toString("utf8");
    const expected = `sha256=${createHmac("sha256", fixtureSecret).update(text).digest("hex")}`;
    const valid =
      request.method === "POST" &&
      request.url === "/internal/subscription-quota" &&
      request.headers["x-clawsweeper-exact-review-signature"] === expected &&
      JSON.parse(text).action === "admit";
    calls.push({ scenario, valid });
    response.writeHead(valid && scenario !== "unavailable" ? 200 : 503, {
      "Content-Type": "application/json",
    });
    response.end(JSON.stringify({ allowed: valid && scenario === "allowed" }));
  });
  try {
    await cp(path.join(repositoryRoot, "dist"), path.join(root, "dist"), { recursive: true });
    await writeFile(path.join(root, "package.json"), '{"type":"module"}\n');
    await new Promise((resolve, reject) => {
      server.once("error", reject);
      server.listen(0, "127.0.0.1", resolve);
    });
    const origin = `http://127.0.0.1:${server.address().port}`;
    // No inherited API, GitHub, Cloudflare, merchant or real ChatGPT credentials.
    // PATH deliberately has no Codex executable. No model is invoked by proof.
    const env = {
      HOME: root,
      CODEX_HOME: path.join(root, "no-auth"),
      PATH: "",
    };
    const exercise = async (configured) => {
      const args = ["--input-type=module", "-e", childScript];
      const options = {
        cwd: root,
        env: {
          ...env,
          ...(configured
            ? {
                CLAWSWEEPER_QUOTA_ENABLED: "1",
                CLAWSWEEPER_QUOTA_URL: origin,
                CLAWSWEEPER_QUOTA_SECRET: fixtureSecret,
              }
            : {}),
        },
        timeout: 10000,
        maxBuffer: 16384,
      };
      let result;
      let exitCode = 0;
      try {
        result = await run(process.execPath, args, options);
      } catch (error) {
        if (typeof error.code !== "number") throw error;
        result = error;
        exitCode = error.code;
      }
      return { ...JSON.parse(result.stdout.trim()), exitCode };
    };
    const missing = await exercise(false);
    assert.deepEqual(missing, {
      clientImported: true,
      refused: true,
      reason: "Shared subscription quota configuration missing",
      exitCode: 3,
    });
    const allowed = await exercise(true);
    assert.deepEqual(allowed, { clientImported: true, allowed: true, exitCode: 0 });
    scenario = "denied";
    const denied = await exercise(true);
    assert.deepEqual(denied, { clientImported: true, allowed: false, exitCode: 2 });
    scenario = "unavailable";
    const unavailable = await exercise(true);
    assert.deepEqual(unavailable, {
      clientImported: true,
      refused: true,
      reason: "Shared subscription quota unavailable",
      exitCode: 3,
    });
    assert.deepEqual(
      calls,
      ["allowed", "denied", "unavailable"].map((scenario) => ({ scenario, valid: true })),
    );
    const { stdout: sourceSha } = await run("git", ["rev-parse", "HEAD"], { cwd: repositoryRoot });
    const { stdout: proposed } = await run(
      "git",
      [
        "status",
        "--porcelain",
        "--",
        ".github/workflows/commercial-fulfilment.yml",
        "scripts/commercial",
        "test/repair/commercial-fulfilment.test.ts",
        "test/repair/commercial-workflow.test.ts",
      ],
      { cwd: repositoryRoot },
    );
    const hashes = {};
    for (const name of clientFiles)
      hashes[name] = createHash("sha256")
        .update(await readFile(path.join(root, "dist", name)))
        .digest("hex");
    const proof = {
      schema: "tw.commercial-bootstrap-proof.v1",
      observedAt: new Date().toISOString(),
      sourceSha: sourceSha.trim(),
      proposedChangesPresent: Boolean(proposed.trim()),
      node: process.version,
      environment: "isolated temporary artifact checkout",
      clientModuleSha256: hashes,
      cases: { missing, allowed, denied, unavailable },
      coordinatorRequests: calls.length,
      modelTurns: 0,
      realCredentials: false,
      result: "passed",
      limits:
        "Real compiled allowance client with a loopback fixture coordinator only. No live allowance, model turn, hosted workflow, provisioning, payment or customer delivery is proven.",
    };
    await mkdir(path.join(repositoryRoot, ".artifacts"), { recursive: true });
    await writeFile(
      path.join(repositoryRoot, ".artifacts/commercial-bootstrap-proof.json"),
      JSON.stringify(proof, null, 2) + "\n",
      { mode: 0o600 },
    );
    return proof;
  } finally {
    server.closeAllConnections();
    await new Promise((resolve) => server.close(resolve));
    await rm(root, { recursive: true, force: true });
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  proveBootstrap()
    .then((proof) => console.log(JSON.stringify(proof)))
    .catch((error) => {
      console.error(
        `Commercial bootstrap proof failed: ${error.code === "ENOENT" ? "run pnpm build first" : "compiled startup or admission contract failed"}`,
      );
      process.exitCode = 1;
    });
}
