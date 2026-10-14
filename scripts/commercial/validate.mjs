import { spawn } from "node:child_process";
import { cp, mkdir, mkdtemp, readFile, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  assert,
  digest,
  materialise,
  validateChanges,
  validateContract,
  validateNpmProject,
  validateSnapshot,
} from "./contract.mjs";

import { validateInferenceEvidence } from "./inference.mjs";

export const VALIDATION_IMAGE = "node:24.18.1-bookworm-slim";

export function dockerArguments(
  root,
  command,
  { network = "none", name, uid = process.getuid(), gid = process.getgid() } = {},
) {
  assert(path.isAbsolute(root) && !root.includes(","), "invalid validation directory");
  assert(/^[a-z0-9-]{1,100}$/.test(name), "invalid container identity");
  assert(network === "none" || network === "bridge", "invalid container network");
  return [
    "run",
    "--rm",
    "--name",
    name,
    "--network",
    network,
    "--read-only",
    "--cap-drop=ALL",
    "--security-opt=no-new-privileges",
    "--pids-limit=128",
    "--memory=2g",
    "--cpus=2",
    "--ulimit",
    "nofile=1024:1024",
    "--user",
    `${uid}:${gid}`,
    "--tmpfs",
    "/tmp:rw,nosuid,nodev,size=512m",
    "--mount",
    `type=bind,src=${root},dst=/workspace`,
    "--workdir",
    "/workspace",
    "--env",
    "HOME=/tmp",
    "--env",
    "CI=true",
    VALIDATION_IMAGE,
    ...command,
  ];
}

async function docker(args, timeoutMs = 10 * 60_000) {
  return new Promise((resolve, reject) => {
    // Never forward Actions or merchant environment into a repository process.
    const child = spawn("docker", args, {
      env: { PATH: process.env.PATH, HOME: process.env.HOME },
      stdio: ["ignore", "ignore", "ignore"],
    });
    const timer = setTimeout(() => {
      const index = args.indexOf("--name");
      if (index >= 0) spawn("docker", ["kill", args[index + 1]], { stdio: "ignore" });
      child.kill("SIGKILL");
    }, timeoutMs);
    child.once("error", (error) => {
      clearTimeout(timer);
      reject(error);
    });
    child.once("close", (code) => {
      clearTimeout(timer);
      resolve(code);
    });
  });
}

export async function validate(directory) {
  const contract = validateContract(
    JSON.parse(await readFile(path.join(directory, "contract.json"), "utf8")),
  );
  const snapshot = validateSnapshot(
    JSON.parse(await readFile(path.join(directory, "snapshot.json"), "utf8")),
    contract,
  );
  const candidate = JSON.parse(await readFile(path.join(directory, "candidate.json"), "utf8"));
  assert(candidate.schema === "tw.unverified-candidate.v1", "unsupported candidate");
  const changes = validateChanges(candidate.changes, contract, snapshot);
  const generationEvidence = candidate.generationEvidence
    ? validateInferenceEvidence(candidate.generationEvidence, "generate", contract, changes)
    : undefined;
  const root = await mkdtemp(path.join(os.tmpdir(), "tw-commercial-validation-"));
  const project = path.join(root, "project");
  await materialise(project, snapshot, changes);
  const manifest = JSON.parse(await readFile(path.join(project, "package.json"), "utf8"));
  const lock = JSON.parse(await readFile(path.join(project, "package-lock.json"), "utf8"));
  validateNpmProject(manifest, lock);
  // Install from checked manifests only. Never load customer .npmrc, execute
  // lifecycle scripts, or put repository code in the network-enabled container.
  const dependencies = path.join(root, "dependencies");
  await mkdir(dependencies);
  await writeFile(path.join(dependencies, "package.json"), JSON.stringify(manifest));
  await writeFile(path.join(dependencies, "package-lock.json"), JSON.stringify(lock));
  const suffix = `${contract.operationId}-${Date.now()}`;
  const installed = await docker(
    dockerArguments(
      dependencies,
      [
        "npm",
        "ci",
        "--ignore-scripts",
        "--no-audit",
        "--no-fund",
        "--cache=/tmp/npm-cache",
        "--userconfig=/dev/null",
        "--globalconfig=/tmp/tw-empty-global-npmrc",
      ],
      { network: "bridge", name: `tw-deps-${suffix}` },
    ),
  );
  assert(installed === 0, "bounded dependency installation failed");
  await cp(path.join(dependencies, "node_modules"), path.join(project, "node_modules"), {
    recursive: true,
    errorOnExist: true,
  }).catch((error) => {
    // A dependency-free package legitimately has no node_modules directory.
    if (error.code !== "ENOENT" || Object.keys(lock.packages).length !== 1) throw error;
  });
  const tested = await docker(
    dockerArguments(
      project,
      ["npm", "test", "--userconfig=/dev/null", "--globalconfig=/tmp/tw-empty-global-npmrc"],
      { name: `tw-test-${suffix}` },
    ),
  );
  assert(tested === 0, "credential-free acceptance tests failed");
  await writeFile(
    path.join(directory, "validated-candidate.json"),
    JSON.stringify({
      schema: "tw.validated-candidate.v1",
      changes,
      ...(generationEvidence ? { generationEvidence } : {}),
      validation: {
        profile: "node",
        passed: true,
        candidateDigest: digest(changes),
        contractDigest: digest(contract),
        image: VALIDATION_IMAGE,
        commands: [
          { command: "npm ci --ignore-scripts", exitCode: installed },
          { command: "npm test", exitCode: tested },
        ],
      },
    }),
    { mode: 0o600 },
  );
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  validate(process.argv[2])
    .then(() =>
      console.log(
        "Credential-free local validation passed; independent PR verification remains required.",
      ),
    )
    .catch(() => {
      console.error("Commercial validation failed; no candidate was published.");
      process.exitCode = 1;
    });
}
