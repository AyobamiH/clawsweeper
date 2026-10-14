import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { validate, VALIDATION_IMAGE } from "./validate.mjs";

// Exercises real Docker boundaries using synthetic source and credentials only.
const root = path.resolve(".artifacts/commercial-docker-proof");
await mkdir(root, { recursive: true });
const contract = {
  schema: "tw.execution-contract.v1",
  orderId: "11111111-1111-4111-8111-111111111111",
  operationId: "22222222-2222-4222-8222-222222222222",
  generation: 1,
  quoteHash: "a".repeat(64),
  requestedOutcome: "Return the agreed greeting from greet().",
  repository: {
    fullName: "example/controlled-proof",
    id: "123456",
    baseSha: "b".repeat(40),
    baseBranch: "main",
  },
  scope: {
    allowedPaths: ["src/"],
    acceptanceCriteria: ["greet() returns Hello commercial fulfilment."],
    requiredChecks: [{ name: "test", appId: 15368 }],
    maxFiles: 2,
    maxPatchBytes: 4096,
    validationProfile: "node",
  },
};
const manifest = {
  name: "controlled-proof",
  version: "1.0.0",
  type: "module",
  scripts: { test: "node --test test.mjs" },
};
const lock = {
  name: "controlled-proof",
  version: "1.0.0",
  lockfileVersion: 3,
  packages: { "": { name: "controlled-proof", version: "1.0.0" } },
};
const fixtureTest = String.raw`import assert from 'node:assert/strict';
import {existsSync,writeFileSync} from 'node:fs';
import net from 'node:net';
import {greet} from './src/greet.mjs';
assert.equal(greet(),'Hello commercial fulfilment.');
for(const key of ['GITHUB_TOKEN','ACTIONS_ID_TOKEN_REQUEST_TOKEN','STRIPE_SECRET_KEY','OPENAI_API_KEY','TW_PROOF_SECRET']) assert.equal(process.env[key],undefined);
assert.equal(existsSync('/home/johnh/.codex/auth.json'),false);
assert.equal(existsSync('/var/run/docker.sock'),false);
assert.throws(()=>writeFileSync('/etc/tw-proof','x'),{code:'EROFS'});
await new Promise((resolve,reject)=>{
  const socket=net.connect({host:'192.0.2.1',port:443});
  socket.setTimeout(1500);
  socket.once('connect',()=>{socket.destroy();reject(new Error('network allowed'));});
  socket.once('timeout',()=>{socket.destroy();reject(new Error('network indeterminate'));});
  socket.once('error',error=>{assert(['ENETUNREACH','EACCES','EPERM'].includes(error.code));resolve();});
});
`;
const snapshot = {
  schema: "tw.repository-snapshot.v1",
  repositoryId: contract.repository.id,
  baseSha: contract.repository.baseSha,
  files: [
    { path: "package.json", content: JSON.stringify(manifest), mode: "100644" },
    { path: "package-lock.json", content: JSON.stringify(lock), mode: "100644" },
    { path: "src/greet.mjs", content: "export const greet = () => 'old';\n", mode: "100644" },
    { path: "test.mjs", content: fixtureTest, mode: "100644" },
  ],
};
async function fixture(directory, positive) {
  assert.equal(typeof positive, "boolean");
  // Static source fixtures avoid constructing executable text from a value.
  const source = positive
    ? "export const greet = () => 'Hello commercial fulfilment.';\n"
    : "export const greet = () => 'wrong';\n";
  await mkdir(directory, { recursive: true });
  for (const [name, value] of Object.entries({
    "contract.json": contract,
    "snapshot.json": snapshot,
    "candidate.json": {
      schema: "tw.unverified-candidate.v1",
      changes: [
        {
          path: "src/greet.mjs",
          content: source,
          mode: "100644",
        },
      ],
    },
  }))
    await writeFile(path.join(directory, name), JSON.stringify(value));
}
process.env.TW_PROOF_SECRET = "SYNTHETIC_NOT_A_SECRET";
await fixture(root, true);
await validate(root);
const result = JSON.parse(await readFile(path.join(root, "validated-candidate.json"), "utf8"));
assert.equal(result.validation.passed, true);
const negative = path.join(root, "negative");
await fixture(negative, false);
await assert.rejects(() => validate(negative), /credential-free acceptance tests failed/);
const evidence = {
  schema: "tw.commercial-docker-proof.v1",
  observedAt: new Date().toISOString(),
  sourceSha: execFileSync("git", ["rev-parse", "HEAD"], { encoding: "utf8" }).trim(),
  provider: "local-container",
  image: VALIDATION_IMAGE,
  imageId: execFileSync("docker", ["image", "inspect", VALIDATION_IMAGE, "--format", "{{.Id}}"], {
    encoding: "utf8",
  }).trim(),
  positive: result.validation,
  negativeRejected: true,
  checks: {
    hostCredentialsAbsent: true,
    merchantEnvironmentAbsent: true,
    dockerSocketAbsent: true,
    rootFilesystemReadOnly: true,
    networkDenied: true,
  },
  limits:
    "Controlled synthetic public project; no model, merchant payment, workflow OIDC, customer PR or independent delivery verification exercised.",
};
await writeFile(
  ".artifacts/commercial-docker-proof.json",
  JSON.stringify(evidence, null, 2) + "\n",
);
console.log(JSON.stringify(evidence));
