import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import path from "node:path";
import { sandboxPreflight } from "./codex-runtime.mjs";

// No model turn or real credential is used. This must run on the same Linux
// containment class as commercial generation, before claiming it is ready.
await mkdir(".artifacts", { recursive: true });
const root = await mkdtemp(path.resolve(".artifacts/commercial-sandbox-proof-"));
const workspace = path.join(root, "workspace");
const auth = path.join(root, "synthetic-auth");
const binary = process.argv[2] || "codex";
try {
  await mkdir(workspace);
  await mkdir(auth);
  await writeFile(
    path.join(auth, "auth.json"),
    JSON.stringify({ sentinel: "SYNTHETIC_NOT_A_CREDENTIAL" }),
  );
  await writeFile(path.join(auth, "config.toml"), 'forced_login_method="chatgpt"\n');
  const env = { PATH: process.env.PATH, HOME: root, CODEX_HOME: auth };
  const write = await sandboxPreflight(workspace, "write", env, binary);
  const read = await sandboxPreflight(workspace, "read", env, binary);
  const evidence = {
    schema: "tw.commercial-sandbox-proof.v1",
    observedAt: new Date().toISOString(),
    sourceSha: process.env.GITHUB_SHA || null,
    platform: process.platform,
    node: process.version,
    modelTurns: 0,
    realCredentials: false,
    checks: { write, read },
    limits:
      "Sandbox boundary proof only; no customer order, payment, PR or independent delivery verification was exercised.",
  };
  await writeFile(
    ".artifacts/commercial-sandbox-proof.json",
    JSON.stringify(evidence, null, 2) + "\n",
  );
  console.log(JSON.stringify(evidence));
} catch {
  console.error("Commercial sandbox proof failed closed; no model was started.");
  process.exitCode = 1;
} finally {
  await rm(root, { recursive: true, force: true });
}
