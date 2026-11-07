#!/usr/bin/env node
/** Bounded, run-bound repair artifacts over the existing authenticated state blob transport. */
import { createHash, randomUUID } from "node:crypto";
import { execFile, spawnSync } from "node:child_process";
import {
  constants,
  closeSync,
  existsSync,
  fstatSync,
  fsyncSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  openSync,
  readFileSync,
  readdirSync,
  readSync,
  renameSync,
  rmSync,
  writeSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { parseArgs, promisify } from "node:util";

import { publishStateBlob } from "../src/state-blob-client.ts";
import { downloadStateBlob, statStateBlob } from "./worker-blobs.ts";

export const REPAIR_ARTIFACT_MAX_BYTES = 24 * 1024 * 1024;
export const REPAIR_ARTIFACT_MAX_FILES = 512;
const MANIFEST_MAX_BYTES = 256 * 1024;
const DIGEST = /^[0-9a-f]{64}$/;
const ROOT_DEFAULT = ".clawsweeper-repair/runs";

export type RepairArtifactBinding = {
  repository: string;
  run_id: string;
  run_attempt: string;
  workflow_sha: string;
  job_path: string;
  phase: "plan" | "execute";
};
type WorkerClient = {
  transport?: "worker";
  baseUrl: string;
  webhookSecret: string;
  fetch?: typeof fetch;
};
export type RepairArtifactGitClient = {
  transport: "git-results";
  stateDirectory: string;
  expectedOrigin?: string;
  env?: NodeJS.ProcessEnv;
};
type Client = WorkerClient | RepairArtifactGitClient;
const COMMIT = /^[0-9a-f]{40}$/;
const STATE_ORIGIN = "https://github.com/AyobamiH/clawsweeper-state";
const PUBLISHER = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "../dist/repair/publish-main.js",
);
const execFileAsync = promisify(execFile);
type Entry = { path: string; bytes: number; digest: string };
type Manifest = {
  schema_version: 1;
  binding: RepairArtifactBinding;
  files: Entry[];
  total_bytes: number;
};
export type RepairArtifactReference = {
  manifest_path: string;
  manifest_digest: string;
  manifest_bytes: number;
  state_commit?: string;
};
type Options = { binding: RepairArtifactBinding; client: Client; root: string };

function digest(content: Buffer): string {
  return createHash("sha256").update(content).digest("hex");
}

function object(value: unknown, keys: string[], label: string): Record<string, unknown> {
  if (
    !value ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    Object.keys(value).sort().join(",") !== [...keys].sort().join(",")
  ) {
    throw new Error("Invalid repair artifact " + label);
  }
  return value as Record<string, unknown>;
}

function safePath(value: unknown): string {
  if (
    typeof value !== "string" ||
    value.length > 512 ||
    !value ||
    value.split("/").length > 16 ||
    value
      .split("/")
      .some((part) => !/^[A-Za-z0-9_.-]{1,128}$/.test(part) || part === "." || part === "..")
  ) {
    throw new Error("Unsafe repair artifact path");
  }
  return value;
}

function binding(value: unknown): RepairArtifactBinding {
  const item = object(
    value,
    ["repository", "run_id", "run_attempt", "workflow_sha", "job_path", "phase"],
    "binding",
  );
  if (
    typeof item.repository !== "string" ||
    !/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(item.repository) ||
    typeof item.run_id !== "string" ||
    !/^[1-9]\d{0,19}$/.test(item.run_id) ||
    typeof item.run_attempt !== "string" ||
    !/^[1-9]\d{0,5}$/.test(item.run_attempt) ||
    typeof item.workflow_sha !== "string" ||
    !/^[0-9a-f]{40}$/.test(item.workflow_sha) ||
    (item.phase !== "plan" && item.phase !== "execute")
  ) {
    throw new Error("Invalid repair artifact workflow binding");
  }
  const jobPath = safePath(item.job_path);
  if (!jobPath.startsWith("jobs/") || !jobPath.endsWith(".md"))
    throw new Error("Invalid repair job binding");
  return {
    repository: item.repository,
    run_id: item.run_id,
    run_attempt: item.run_attempt,
    workflow_sha: item.workflow_sha,
    job_path: jobPath,
    phase: item.phase,
  };
}

export function repairArtifactBindingFromEnv(
  env: NodeJS.ProcessEnv,
  phase: string,
): RepairArtifactBinding {
  return binding({
    repository: env.GITHUB_REPOSITORY,
    run_id: env.GITHUB_RUN_ID,
    run_attempt: env.GITHUB_RUN_ATTEMPT,
    workflow_sha: env.GITHUB_SHA,
    job_path: env.CLUSTER_JOB_PATH,
    phase,
  });
}

function prefix(
  value: RepairArtifactBinding,
  transport: "worker" | "git-results" = "worker",
): string {
  const item = binding(value);
  return (
    (transport === "git-results" ? "results" : "assets") +
    "/repair-artifacts/v1/" +
    item.repository +
    "/" +
    item.run_id +
    "/" +
    item.run_attempt +
    "/" +
    item.workflow_sha +
    "/" +
    digest(Buffer.from(item.job_path)) +
    "/" +
    item.phase
  );
}

function client(value: Client): Client {
  if (value.transport === "git-results") return gitClient(value);
  let url: URL;
  try {
    url = new URL(value.baseUrl);
  } catch (cause) {
    throw new Error("Repair artifact Worker URL is invalid", { cause });
  }
  if (
    url.protocol !== "https:" ||
    url.username ||
    url.password ||
    url.search ||
    url.hash ||
    !value.webhookSecret
  ) {
    throw new Error("Repair artifact transport requires an HTTPS Worker URL and secret");
  }
  return { ...value, baseUrl: url.href.replace(/\/+$/, "") };
}

/** Reject existing symlink ancestors as well as a symlink final destination. */
function safeDirectory(value: string, create = false): string {
  const absolute = path.resolve(value);
  const parsed = path.parse(absolute);
  if (absolute === parsed.root) throw new Error("Repair artifact root cannot be a filesystem root");
  let current = parsed.root;
  for (const part of absolute.slice(parsed.root.length).split(path.sep)) {
    current = path.join(current, part);
    try {
      const stat = lstatSync(current);
      if (!stat.isDirectory() || stat.isSymbolicLink())
        throw new Error("Repair artifact directory is unsafe");
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
      if (create) mkdirSync(current, { mode: 0o700 });
    }
  }
  return absolute;
}

function snapshot(rootPath: string): {
  files: Entry[];
  payloads: Map<string, Buffer>;
  total_bytes: number;
} {
  const root = safeDirectory(rootPath);
  if (!existsSync(root)) throw new Error("Repair artifact directory is unavailable");
  const paths: string[] = [];
  function walk(directory: string, relative = "") {
    for (const name of readdirSync(directory).sort()) {
      const relativePath = safePath(relative ? relative + "/" + name : name);
      const absolute = path.join(directory, name);
      const stat = lstatSync(absolute);
      if (stat.isSymbolicLink()) throw new Error("Repair artifacts cannot contain symlinks");
      if (stat.isDirectory()) walk(absolute, relativePath);
      else if (stat.isFile() && stat.nlink === 1) paths.push(relativePath);
      else throw new Error("Repair artifacts require regular, singly linked files");
      if (paths.length > REPAIR_ARTIFACT_MAX_FILES)
        throw new Error("Repair artifact file count exceeds bound");
    }
  }
  walk(root);
  if (!paths.length) throw new Error("Repair artifact directory is empty");
  paths.sort();
  const payloads = new Map<string, Buffer>();
  let total = 0;
  const files = paths.map((relativePath) => {
    const fd = openSync(
      path.join(root, relativePath),
      constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK,
    );
    try {
      const before = fstatSync(fd);
      if (!before.isFile() || before.nlink !== 1)
        throw new Error("Repair artifact file changed type");
      total += before.size;
      if (!Number.isSafeInteger(total) || total > REPAIR_ARTIFACT_MAX_BYTES)
        throw new Error("Repair artifact bytes exceed bound");
      const content = Buffer.alloc(before.size);
      let offset = 0;
      while (offset < content.length) {
        const count = readSync(fd, content, offset, content.length - offset, null);
        if (!count) throw new Error("Repair artifact file changed during snapshot");
        offset += count;
      }
      const extra = readSync(fd, Buffer.alloc(1), 0, 1, null);
      const after = fstatSync(fd);
      if (
        extra ||
        before.size !== after.size ||
        before.mtimeMs !== after.mtimeMs ||
        before.ctimeMs !== after.ctimeMs
      ) {
        throw new Error("Repair artifact file changed during snapshot");
      }
      const entry = { path: relativePath, bytes: content.length, digest: digest(content) };
      payloads.set(entry.digest, content);
      return entry;
    } finally {
      closeSync(fd);
    }
  });
  return { files, payloads, total_bytes: total };
}

function parseManifest(content: Buffer, expected: RepairArtifactBinding): Manifest {
  if (content.length > MANIFEST_MAX_BYTES)
    throw new Error("Repair artifact manifest exceeds bound");
  const value = object(
    JSON.parse(content.toString("utf8")),
    ["schema_version", "binding", "files", "total_bytes"],
    "manifest",
  );
  const actualBinding = binding(value.binding);
  if (
    value.schema_version !== 1 ||
    JSON.stringify(actualBinding) !== JSON.stringify(binding(expected))
  ) {
    throw new Error("Repair artifact manifest belongs to another workflow run, job or phase");
  }
  if (
    !Array.isArray(value.files) ||
    !value.files.length ||
    value.files.length > REPAIR_ARTIFACT_MAX_FILES
  ) {
    throw new Error("Repair artifact file count is invalid");
  }
  const seen = new Set<string>();
  let previous = "";
  let total = 0;
  const files: Entry[] = value.files.map((raw) => {
    const item = object(raw, ["path", "bytes", "digest"], "file descriptor");
    const filePath = safePath(item.path);
    if (
      filePath <= previous ||
      seen.has(filePath) ||
      filePath
        .split("/")
        .slice(0, -1)
        .some((_, index, parts) => seen.has(parts.slice(0, index + 1).join("/")))
    ) {
      throw new Error("Repair artifact paths are duplicated, conflicting or unsorted");
    }
    if (
      !Number.isSafeInteger(item.bytes) ||
      Number(item.bytes) < 0 ||
      typeof item.digest !== "string" ||
      !DIGEST.test(item.digest)
    )
      throw new Error("Invalid repair artifact file identity");
    total += Number(item.bytes);
    if (!Number.isSafeInteger(total) || total > REPAIR_ARTIFACT_MAX_BYTES)
      throw new Error("Repair artifact bytes exceed bound");
    previous = filePath;
    seen.add(filePath);
    return { path: filePath, bytes: Number(item.bytes), digest: item.digest };
  });
  if (value.total_bytes !== total)
    throw new Error("Repair artifact manifest total is inconsistent");
  return { schema_version: 1, binding: actualBinding, files, total_bytes: total };
}

async function downloadVerified(
  options: Client,
  blobPath: string,
  bytes: number,
  hash: string,
  destination: string,
  stateCommit?: string,
) {
  if (options.transport === "git-results") {
    const content = readGitArtifact(options, stateCommit ?? "", blobPath, bytes, hash);
    safeDirectory(path.dirname(destination), true);
    writeFileSync(destination, content, { mode: 0o600, flag: "wx" });
    verifyWritten(destination, bytes, hash);
    return;
  }
  const stat = await statStateBlob({ ...options, blobPath });
  if (
    !stat ||
    stat.path !== blobPath ||
    stat.bytes !== bytes ||
    stat.digest !== hash ||
    !stat.digestVerified
  ) {
    throw new Error("Repair artifact remote identity or size mismatch");
  }
  const result = await downloadStateBlob({
    ...options,
    blobPath,
    destination,
    expected: { bytes, digest: hash },
  });
  if (result.bytes !== bytes || result.digest !== hash)
    throw new Error("Repair artifact download identity mismatch");
  verifyWritten(destination, bytes, hash);
}

function verifyWritten(destination: string, bytes: number, hash: string) {
  const fd = openSync(
    destination,
    constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK,
  );
  try {
    const written = fstatSync(fd);
    if (!written.isFile() || written.size !== bytes)
      throw new Error("Repair artifact written size mismatch");
    if (digest(readFileSync(fd)) !== hash)
      throw new Error("Repair artifact written digest mismatch");
  } finally {
    closeSync(fd);
  }
}

async function publishVerified(
  options: WorkerClient,
  blobPath: string,
  content: Buffer,
  temporary: string,
) {
  const hash = digest(content);
  await publishStateBlob({
    baseUrl: options.baseUrl,
    webhookSecret: options.webhookSecret,
    ...(options.fetch ? { fetchImpl: options.fetch } : {}),
    path: blobPath,
    content,
  });
  const destination = path.join(temporary, randomUUID());
  try {
    await downloadVerified(options, blobPath, content.length, hash, destination);
  } finally {
    rmSync(destination, { force: true });
  }
}

function gitBytes(options: RepairArtifactGitClient, args: string[], maxBuffer = 64 * 1024): Buffer {
  const result = spawnSync("git", ["-C", options.stateDirectory, ...args], {
    env: { ...(options.env ?? process.env), GIT_TERMINAL_PROMPT: "0" },
    timeout: 60_000,
    maxBuffer,
    windowsHide: true,
  });
  if (result.error || result.status !== 0)
    throw new Error(
      "Repair artifact git " + args[0] + " failed; no publication or restore claimed",
    );
  return result.stdout;
}

function gitClient(value: RepairArtifactGitClient): RepairArtifactGitClient {
  const result = { ...value, stateDirectory: safeDirectory(value.stateDirectory) };
  const top = gitBytes(result, ["rev-parse", "--show-toplevel"]).toString("utf8").trim();
  const origin = gitBytes(result, ["remote", "get-url", "--all", "origin"]).toString("utf8").trim();
  const pushOrigin = gitBytes(result, ["remote", "get-url", "--push", "--all", "origin"])
    .toString("utf8")
    .trim();
  const expected = result.expectedOrigin ?? STATE_ORIGIN;
  if (
    top !== result.stateDirectory ||
    origin.replace(/\.git$/, "") !== expected.replace(/\.git$/, "") ||
    pushOrigin.replace(/\.git$/, "") !== expected.replace(/\.git$/, "")
  )
    throw new Error(
      "Repair artifact state checkout or origin differs from the authorised repository",
    );
  if (
    (result.env ?? process.env).CLAWSWEEPER_PUBLISH_BRANCH &&
    (result.env ?? process.env).CLAWSWEEPER_PUBLISH_BRANCH !== "state"
  )
    throw new Error("Repair artifact state branch must be state");
  return result;
}

function fetchGitCommit(options: RepairArtifactGitClient, commit: string) {
  if (!COMMIT.test(commit))
    throw new Error("Repair artifact state commit must be a full immutable Git SHA");
  gitBytes(options, ["fetch", "--no-tags", "--depth=1", "origin", commit]);
  const actual = gitBytes(options, ["rev-parse", "FETCH_HEAD^{commit}"]).toString("utf8").trim();
  if (actual !== commit) throw new Error("Repair artifact fetched state commit mismatch");
}

function readGitArtifact(
  options: RepairArtifactGitClient,
  commit: string,
  blobPath: string,
  bytes: number,
  hash: string,
): Buffer {
  if (!COMMIT.test(commit) || !blobPath.startsWith("results/repair-artifacts/v1/"))
    throw new Error("Repair artifact Git identity is invalid");
  const descriptor = gitBytes(options, ["ls-tree", "-l", "-z", commit, "--", blobPath]).toString(
    "utf8",
  );
  const entries = descriptor.split("\0");
  const match =
    entries.length === 2 && entries[1] === ""
      ? /^100644 blob ([0-9a-f]{40}) +([0-9]+)\t(.+)$/.exec(entries[0]!)
      : null;
  if (!match || match[3] !== blobPath || Number(match[2]) !== bytes)
    throw new Error("Repair artifact Git file mode or size mismatch");
  const content = gitBytes(options, ["cat-file", "blob", match[1]!], Math.max(1, bytes + 1));
  if (content.length !== bytes || digest(content) !== hash)
    throw new Error("Repair artifact Git file digest or size mismatch");
  return content;
}

async function publishGitArtifacts(
  options: RepairArtifactGitClient,
  bound: RepairArtifactBinding,
  payloads: Map<string, Buffer>,
): Promise<string> {
  const env = options.env ?? process.env;
  const secret = env.CLAWSWEEPER_STATE_COORDINATOR_SECRET || env.CLAWSWEEPER_WEBHOOK_SECRET || "";
  const coordinator = env.CLAWSWEEPER_STATE_COORDINATOR_URL || env.QUEUE_URL || "";
  let url: URL;
  try {
    url = new URL(coordinator);
  } catch (cause) {
    throw new Error("Repair artifact publication requires the existing state writer coordinator", {
      cause,
    });
  }
  if (
    env.CLAWSWEEPER_STATE_COORDINATOR_ENABLED !== "1" ||
    !secret ||
    (url.protocol !== "https:" &&
      !(url.protocol === "http:" && ["127.0.0.1", "localhost", "[::1]"].includes(url.hostname)))
  )
    throw new Error("Repair artifact publication requires the existing state writer coordinator");
  if (!existsSync(PUBLISHER))
    throw new Error("Build the existing repair publisher before artifact publication");
  gitBytes(options, ["diff", "--quiet"]);
  gitBytes(options, ["diff", "--cached", "--quiet"]);
  const base = prefix(bound, "git-results");
  for (const [blobPath, content] of payloads) {
    if (!blobPath.startsWith(base + "/") || content.length > REPAIR_ARTIFACT_MAX_BYTES)
      throw new Error("Repair artifact publication escapes its bounded run prefix");
  }
  const sparse = gitBytes(options, ["config", "--default", "false", "--get", "core.sparseCheckout"])
    .toString("utf8")
    .trim();
  if (sparse === "true") gitBytes(options, ["sparse-checkout", "add", "--", base]);
  const temporary = mkdtempSync(path.join(tmpdir(), "repair-artifact-git-publish-"));
  try {
    for (const [blobPath, content] of payloads) {
      const existing = path.join(options.stateDirectory, blobPath);
      safeDirectory(path.dirname(existing));
      if (existsSync(existing)) verifyWritten(existing, content.length, digest(content));
      const destination = path.join(temporary, blobPath);
      safeDirectory(path.dirname(destination), true);
      writeFileSync(destination, content, { mode: 0o600, flag: "wx" });
      verifyWritten(destination, content.length, digest(content));
    }
    const configuredWait = Number(env.CLAWSWEEPER_STATE_COORDINATOR_ACQUIRE_TIMEOUT_MS);
    const acquireWait =
      Number.isSafeInteger(configuredWait) && configuredWait > 0
        ? Math.min(configuredWait, 120_000)
        : 120_000;
    try {
      await execFileAsync(
        process.execPath,
        [
          PUBLISHER,
          "--message",
          `chore: retain repair artifact ${bound.run_id}/${bound.run_attempt}/${bound.phase}`,
          ...[...payloads.keys()].flatMap((item) => ["--path", item]),
        ],
        {
          cwd: temporary,
          env: {
            ...env,
            CLAWSWEEPER_STATE_DIR: options.stateDirectory,
            CLAWSWEEPER_PUBLISH_BRANCH: "state",
            GIT_TERMINAL_PROMPT: "0",
            CLAWSWEEPER_STATE_COORDINATOR_ACQUIRE_TIMEOUT_MS: String(acquireWait),
            GITHUB_REPOSITORY: bound.repository,
            GITHUB_RUN_ID: bound.run_id,
            GITHUB_RUN_ATTEMPT: bound.run_attempt,
            GITHUB_SHA: bound.workflow_sha,
          },
          timeout: 900_000,
          maxBuffer: 1024 * 1024,
          windowsHide: true,
        },
      );
    } catch (cause) {
      // A failed or ambiguous push is never silently retried by this adapter.
      throw new Error(
        "Coordinated repair artifact publication failed; reconcile state before retry",
        { cause },
      );
    }
    const commit = gitBytes(options, ["rev-parse", "HEAD^{commit}"]).toString("utf8").trim();
    if (!COMMIT.test(commit))
      throw new Error("Repair artifact publisher returned an invalid state commit");
    const remote = gitBytes(options, ["ls-remote", "--exit-code", "origin", "refs/heads/state"])
      .toString("utf8")
      .trim();
    if (remote !== commit + "\trefs/heads/state")
      throw new Error(
        "Repair artifact state branch changed before publication readback; reconcile before retry",
      );
    fetchGitCommit(options, commit);
    for (const [blobPath, content] of payloads)
      readGitArtifact(options, commit, blobPath, content.length, digest(content));
    return commit;
  } finally {
    rmSync(temporary, { recursive: true, force: true });
  }
}

export async function preflightRepairArtifacts(options: {
  binding: RepairArtifactBinding;
  client: Client;
}) {
  const bound = binding(options.binding);
  const connection = client(options.client);
  const content = Buffer.from(
    JSON.stringify({ schema_version: 1, kind: "repair-artifact-preflight", binding: bound }) + "\n",
  );
  const hash = digest(content);
  const blobPath = prefix(bound, connection.transport) + "/preflight/" + hash + ".json";
  let stateCommit: string | undefined;
  if (connection.transport === "git-results") {
    stateCommit = await publishGitArtifacts(connection, bound, new Map([[blobPath, content]]));
  } else {
    const temporary = mkdtempSync(path.join(tmpdir(), "repair-artifact-preflight-"));
    try {
      await publishVerified(connection, blobPath, content, temporary);
    } finally {
      rmSync(temporary, { recursive: true, force: true });
    }
  }
  return {
    binding: bound,
    preflight_path: blobPath,
    preflight_digest: hash,
    preflight_bytes: content.length,
    transport: connection.transport ?? "worker",
    ...(stateCommit ? { state_commit: stateCommit } : {}),
    verified: true,
  };
}

export async function publishRepairArtifacts(options: Options) {
  const bound = binding(options.binding);
  const connection = client(options.client);
  const inventory = snapshot(options.root);
  const manifest: Manifest = {
    schema_version: 1,
    binding: bound,
    files: inventory.files,
    total_bytes: inventory.total_bytes,
  };
  const content = Buffer.from(JSON.stringify(manifest) + "\n");
  if (content.length > MANIFEST_MAX_BYTES)
    throw new Error("Repair artifact manifest exceeds bound");
  const hash = digest(content);
  const base = prefix(bound, connection.transport);
  const manifestPath = base + "/manifests/" + hash + ".json";
  let stateCommit: string | undefined;
  if (connection.transport === "git-results") {
    const payloads = new Map(
      [...inventory.payloads].map(([hash, bytes]) => [base + "/files/" + hash, bytes]),
    );
    payloads.set(manifestPath, content);
    stateCommit = await publishGitArtifacts(connection, bound, payloads);
  } else {
    const temporary = mkdtempSync(path.join(tmpdir(), "repair-artifact-publish-"));
    try {
      for (const [fileDigest, payload] of inventory.payloads)
        await publishVerified(connection, base + "/files/" + fileDigest, payload, temporary);
      // Publish the manifest only after every file has passed authenticated readback.
      await publishVerified(connection, manifestPath, content, temporary);
    } finally {
      rmSync(temporary, { recursive: true, force: true });
    }
  }
  return {
    binding: bound,
    manifest_path: manifestPath,
    manifest_digest: hash,
    manifest_bytes: content.length,
    transport: connection.transport ?? "worker",
    ...(stateCommit ? { state_commit: stateCommit } : {}),
    files: manifest.files.length,
    total_bytes: manifest.total_bytes,
    verified: true,
  };
}

export async function restoreRepairArtifacts(
  options: Options & { reference: RepairArtifactReference },
) {
  const bound = binding(options.binding);
  const connection = client(options.client);
  const ref = options.reference;
  if (
    !DIGEST.test(ref.manifest_digest) ||
    !Number.isSafeInteger(ref.manifest_bytes) ||
    ref.manifest_bytes < 1 ||
    ref.manifest_bytes > MANIFEST_MAX_BYTES ||
    ref.manifest_path !==
      prefix(bound, connection.transport) + "/manifests/" + ref.manifest_digest + ".json" ||
    (connection.transport === "git-results"
      ? !COMMIT.test(ref.state_commit ?? "")
      : ref.state_commit !== undefined)
  ) {
    throw new Error("Repair artifact reference does not match the expected workflow binding");
  }
  const root = safeDirectory(options.root);
  if (connection.transport === "git-results") fetchGitCommit(connection, ref.state_commit!);
  const temporary = mkdtempSync(path.join(tmpdir(), "repair-artifact-manifest-"));
  let stage: string | undefined;
  try {
    const manifestFile = path.join(temporary, "manifest.json");
    await downloadVerified(
      connection,
      ref.manifest_path,
      ref.manifest_bytes,
      ref.manifest_digest,
      manifestFile,
      ref.state_commit,
    );
    const manifest = parseManifest(readFileSync(manifestFile), bound);
    if (existsSync(root) && readdirSync(root).length) {
      if (JSON.stringify(snapshot(root).files) !== JSON.stringify(manifest.files)) {
        throw new Error("Refusing to overwrite existing repair artifacts");
      }
      return {
        binding: bound,
        ...ref,
        files: manifest.files.length,
        total_bytes: manifest.total_bytes,
        verified: true,
        unchanged: true,
      };
    }
    const parent = safeDirectory(path.dirname(root), true);
    stage = mkdtempSync(path.join(parent, ".repair-artifacts-stage-"));
    for (const file of manifest.files) {
      const destination = path.join(stage, ...file.path.split("/"));
      await downloadVerified(
        connection,
        prefix(bound, connection.transport) + "/files/" + file.digest,
        file.bytes,
        file.digest,
        destination,
        ref.state_commit,
      );
    }
    safeDirectory(root);
    if (existsSync(root) && readdirSync(root).length)
      throw new Error("Repair artifact destination changed during restore");
    // Same-filesystem rename exposes the complete verified tree, never partial downloads.
    renameSync(stage, root);
    stage = undefined;
    return {
      binding: bound,
      ...ref,
      files: manifest.files.length,
      total_bytes: manifest.total_bytes,
      verified: true,
      unchanged: false,
    };
  } finally {
    if (stage) rmSync(stage, { recursive: true, force: true });
    rmSync(temporary, { recursive: true, force: true });
  }
}

function writeReceipt(file: string, value: unknown) {
  safeDirectory(path.dirname(file), true);
  if (existsSync(file) && !lstatSync(file).isFile())
    throw new Error("Unsafe repair artifact receipt");
  const temporary = file + ".tmp-" + randomUUID();
  const fd = openSync(
    temporary,
    constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW,
    0o600,
  );
  try {
    writeSync(fd, JSON.stringify(value, null, 2) + "\n");
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
  try {
    renameSync(temporary, file);
  } finally {
    rmSync(temporary, { force: true });
  }
}

function appendSafe(file: string | undefined, text: string) {
  if (!file) return;
  const fd = openSync(
    file,
    constants.O_WRONLY | constants.O_APPEND | constants.O_NOFOLLOW | constants.O_NONBLOCK,
  );
  try {
    if (!fstatSync(fd).isFile()) throw new Error("Unsafe workflow output file");
    writeSync(fd, text);
  } finally {
    closeSync(fd);
  }
}

async function main() {
  const [operation, ...args] = process.argv.slice(2);
  if (!["preflight", "publish", "restore"].includes(operation ?? ""))
    throw new Error("Expected preflight, publish or restore");
  const { values } = parseArgs({
    args,
    options: { phase: { type: "string" }, root: { type: "string", default: ROOT_DEFAULT } },
  });
  const bound = repairArtifactBindingFromEnv(process.env, values.phase ?? "");
  const transport = process.env.REPAIR_ARTIFACT_TRANSPORT || "worker";
  if (transport !== "worker" && transport !== "git-results")
    throw new Error("Unsupported repair artifact transport");
  const connection: Client =
    transport === "git-results"
      ? { transport, stateDirectory: process.env.CLAWSWEEPER_STATE_DIR ?? "" }
      : {
          baseUrl: process.env.CLAWSWEEPER_STATE_WORKER_URL ?? "",
          webhookSecret: process.env.CLAWSWEEPER_WEBHOOK_SECRET ?? "",
        };
  const options = { binding: bound, client: connection, root: values.root };
  const result =
    operation === "preflight"
      ? await preflightRepairArtifacts(options)
      : operation === "publish"
        ? await publishRepairArtifacts(options)
        : await restoreRepairArtifacts({
            ...options,
            reference: {
              manifest_path: process.env.REPAIR_ARTIFACT_MANIFEST_PATH ?? "",
              manifest_digest: process.env.REPAIR_ARTIFACT_MANIFEST_DIGEST ?? "",
              manifest_bytes: Number(process.env.REPAIR_ARTIFACT_MANIFEST_BYTES),
              ...(transport === "git-results"
                ? { state_commit: process.env.REPAIR_ARTIFACT_STATE_COMMIT ?? "" }
                : {}),
            },
          });
  const receipt = { operation, ...result, completed_at: new Date().toISOString() };
  const receiptPath = path.resolve(
    ".artifacts",
    "repair-artifacts-" + operation + "-" + bound.phase + ".json",
  );
  writeReceipt(receiptPath, receipt);
  if ("manifest_path" in result) {
    appendSafe(
      process.env.GITHUB_OUTPUT,
      "manifest_path=" +
        result.manifest_path +
        "\nmanifest_digest=" +
        result.manifest_digest +
        "\nmanifest_bytes=" +
        result.manifest_bytes +
        "\n",
    );
  }
  if ("state_commit" in result && result.state_commit) {
    appendSafe(process.env.GITHUB_OUTPUT, "state_commit=" + result.state_commit + "\n");
    appendSafe(
      process.env.GITHUB_STEP_SUMMARY,
      "\nImmutable private state commit: `" + result.state_commit + "`.\n",
    );
  }
  appendSafe(
    process.env.GITHUB_STEP_SUMMARY,
    "\n### Verified repair artifact " +
      operation +
      " (" +
      bound.phase +
      ")\n\n" +
      "Run " +
      bound.run_id +
      ", attempt " +
      bound.run_attempt +
      ", revision \x60" +
      bound.workflow_sha +
      "\x60.\n\n" +
      ("manifest_path" in result
        ? "Authenticated manifest: \x60" +
          result.manifest_path +
          "\x60\n\nSHA-256: \x60" +
          result.manifest_digest +
          "\x60; bytes: " +
          result.manifest_bytes +
          ".\n"
        : "Authenticated write, metadata and content readback succeeded before inference.\n"),
  );
  process.stdout.write(JSON.stringify(receipt) + "\n");
}

if (process.argv[1] && pathToFileURL(path.resolve(process.argv[1])).href === import.meta.url) {
  main().catch((error: unknown) => {
    const secret = process.env.CLAWSWEEPER_WEBHOOK_SECRET ?? "";
    const message = error instanceof Error ? error.message : String(error);
    process.stderr.write(
      "repair-artifacts: " + (secret ? message.replaceAll(secret, "<redacted>") : message) + "\n",
    );
    process.exitCode = 1;
  });
}
