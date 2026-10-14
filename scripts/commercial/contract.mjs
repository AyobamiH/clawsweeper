import { createHash } from "node:crypto";
import { constants } from "node:fs";
import { mkdir, open, readdir, realpath, writeFile } from "node:fs/promises";
import path from "node:path";

export const API_ORIGIN = "https://tailwaggingwebdesign.com";
export const SNAPSHOT_LIMIT = 20 * 1024 * 1024;
export const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/i;
const SHA = /^[a-f0-9]{40}$/;
const DIGEST = /^[a-f0-9]{64}$/;
const FORBIDDEN =
  /^(?:\.git|\.github|\.donestate|\.codex)(?:\/|$)|(?:^|\/)(?:\.env(?:\..*)?|\.npmrc|\.netrc|auth\.json)$/i;

export function assert(value, message) {
  if (!value) throw new Error(message);
}

export function canonical(value) {
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  if (value && typeof value === "object")
    return `{${Object.keys(value)
      .sort()
      .map((k) => `${JSON.stringify(k)}:${canonical(value[k])}`)
      .join(",")}}`;
  return JSON.stringify(value);
}

export function digest(value) {
  return createHash("sha256")
    .update(typeof value === "string" ? value : canonical(value))
    .digest("hex");
}

export function safePath(value) {
  assert(
    typeof value === "string" && value.length > 0 && value.length <= 500,
    "invalid repository path",
  );
  assert(
    !/[\\:*?]/.test(value) &&
      !value.startsWith("/") &&
      [...value].every(
        (character) => character.charCodeAt(0) >= 32 && character.charCodeAt(0) !== 127,
      ),
    "invalid repository path",
  );
  assert(
    value
      .split("/")
      .every((part) => part && part !== "." && part !== ".." && part.toLowerCase() !== ".git"),
    "invalid repository path",
  );
  return value;
}

export function validateContract(value, identity = {}) {
  assert(value && typeof value === "object", "missing execution contract");
  for (const key of ["orderId", "operationId"])
    assert(UUID.test(value[key] || ""), `invalid ${key}`);
  assert(
    Number.isSafeInteger(value.generation) && value.generation > 0,
    "invalid execution generation",
  );
  assert(DIGEST.test(value.quoteHash || ""), "invalid quote hash");
  const repository = value.repository;
  assert(
    repository && /^[A-Za-z0-9_.-]{1,100}\/[A-Za-z0-9_.-]{1,100}$/.test(repository.fullName || ""),
    "invalid repository",
  );
  assert(
    typeof repository.id === "string" &&
      /^[1-9][0-9]{0,19}$/.test(repository.id) &&
      SHA.test(repository.baseSha || ""),
    "invalid repository binding",
  );
  assert(
    typeof repository.baseBranch === "string" &&
      repository.baseBranch.length <= 200 &&
      !/[\s~^:?*[\\]/.test(repository.baseBranch) &&
      !repository.baseBranch.includes(".."),
    "invalid base branch",
  );
  const scope = value.scope;
  assert(
    scope &&
      Array.isArray(scope.allowedPaths) &&
      scope.allowedPaths.length > 0 &&
      scope.allowedPaths.length <= 100,
    "missing path boundaries",
  );
  for (const entry of scope.allowedPaths)
    safePath(entry.endsWith("/") ? entry.slice(0, -1) : entry);
  assert(
    Array.isArray(scope.acceptanceCriteria) &&
      scope.acceptanceCriteria.length > 0 &&
      scope.acceptanceCriteria.length <= 20 &&
      scope.acceptanceCriteria.every(
        (x) => typeof x === "string" && x.length > 0 && x.length <= 2000,
      ),
    "invalid acceptance criteria",
  );
  assert(
    Array.isArray(scope.requiredChecks) &&
      scope.requiredChecks.length > 0 &&
      scope.requiredChecks.length <= 20 &&
      scope.requiredChecks.every(
        (check) =>
          check &&
          typeof check.name === "string" &&
          check.name.length > 0 &&
          check.name.length <= 200 &&
          Number.isSafeInteger(check.appId) &&
          check.appId > 0,
      ),
    "independent acceptance checks with pinned issuers required",
  );
  assert(
    Number.isSafeInteger(scope.maxFiles) && scope.maxFiles >= 1 && scope.maxFiles <= 25,
    "invalid file budget",
  );
  assert(
    Number.isSafeInteger(scope.maxPatchBytes) &&
      scope.maxPatchBytes >= 1 &&
      scope.maxPatchBytes <= 1024 * 1024,
    "invalid patch budget",
  );
  assert(
    scope.validationProfile === undefined || scope.validationProfile === "node",
    "unsupported runtime",
  );
  assert(
    typeof value.requestedOutcome === "string" &&
      value.requestedOutcome.length > 0 &&
      value.requestedOutcome.length <= 20000,
    "invalid objective",
  );
  for (const [key, expected] of Object.entries(identity))
    assert(value[key] === expected, `execution ${key} mismatch`);
  // Whitelist fields: never forward snapshot URLs, broker capabilities or credentials.
  return {
    schema: "tw.execution-contract.v1",
    orderId: value.orderId,
    operationId: value.operationId,
    generation: value.generation,
    quoteHash: value.quoteHash,
    requestedOutcome: value.requestedOutcome,
    repository: {
      fullName: repository.fullName,
      id: repository.id,
      baseSha: repository.baseSha,
      baseBranch: repository.baseBranch,
    },
    scope: {
      allowedPaths: [...scope.allowedPaths],
      acceptanceCriteria: [...scope.acceptanceCriteria],
      requiredChecks: scope.requiredChecks.map((check) => ({
        name: check.name,
        appId: check.appId,
      })),
      maxFiles: scope.maxFiles,
      maxPatchBytes: scope.maxPatchBytes,
      validationProfile: "node",
    },
  };
}

export function validateSnapshot(value, contract) {
  assert(value?.schema === "tw.repository-snapshot.v1", "unsupported snapshot");
  assert(
    value.repositoryId === contract.repository.id && value.baseSha === contract.repository.baseSha,
    "snapshot subject mismatch",
  );
  assert(
    Array.isArray(value.files) && value.files.length > 0 && value.files.length <= 2000,
    "invalid snapshot file count",
  );
  const seen = new Set();
  let total = 0;
  for (const file of value.files) {
    safePath(file.path);
    assert(
      !/(?:^|\/)(?:\.env(?:\..*)?|\.netrc|auth\.json|id_rsa|id_ed25519|[^/]*\.(?:pem|key|p12|pfx))$/i.test(
        file.path,
      ),
      "credential file is excluded from execution snapshots",
    );
    assert(!seen.has(file.path.toLowerCase()), "duplicate snapshot path");
    seen.add(file.path.toLowerCase());
    assert(file.mode === "100644" || file.mode === "100755", "snapshot links are unsupported");
    assert(
      typeof file.content === "string" && !file.content.includes("\0"),
      "binary files are unsupported",
    );
    assert(Buffer.byteLength(file.content) <= 1024 * 1024, "snapshot file exceeds budget");
    total += Buffer.byteLength(file.content);
    assert(total <= SNAPSHOT_LIMIT, "snapshot exceeds budget");
  }
  // File/directory collisions are rejected before filesystem writes.
  for (const file of value.files) {
    const parts = file.path.toLowerCase().split("/");
    parts.pop();
    while (parts.length) {
      assert(!seen.has(parts.join("/")), "snapshot path collision");
      parts.pop();
    }
  }
  return value;
}

export function pathAllowed(file, scope) {
  safePath(file);
  return (
    !FORBIDDEN.test(file) &&
    scope.allowedPaths.some((entry) =>
      entry.endsWith("/") ? file.startsWith(entry) : file === entry,
    )
  );
}

export function validateChanges(changes, contract, snapshot) {
  assert(
    Array.isArray(changes) && changes.length > 0 && changes.length <= contract.scope.maxFiles,
    "invalid changed file count",
  );
  const base = new Map(snapshot.files.map((file) => [file.path, file]));
  const seen = new Set();
  let bytes = 0;
  for (const file of changes) {
    assert(file && pathAllowed(file.path, contract.scope), "candidate escapes allowed paths");
    assert(!seen.has(file.path.toLowerCase()), "duplicate candidate path");
    seen.add(file.path.toLowerCase());
    assert(file.mode === "100644" || file.mode === "100755", "candidate links are unsupported");
    assert(
      file.content === null || (typeof file.content === "string" && !file.content.includes("\0")),
      "invalid candidate content",
    );
    assert(file.content !== null || base.has(file.path), "cannot delete missing path");
    assert(
      !base.has(file.path) ||
        base.get(file.path).content !== file.content ||
        base.get(file.path).mode !== file.mode,
      "candidate contains unchanged file",
    );
    bytes +=
      Buffer.byteLength(file.content || "") + Buffer.byteLength(base.get(file.path)?.content || "");
    assert(bytes <= contract.scope.maxPatchBytes, "candidate exceeds patch budget");
  }
  return [...changes].sort((a, b) => a.path.localeCompare(b.path));
}

export async function materialise(root, snapshot, changes = []) {
  const files = new Map(snapshot.files.map((file) => [file.path, file]));
  for (const file of changes) {
    if (file.content === null) files.delete(file.path);
    else files.set(file.path, file);
  }
  validateSnapshot(
    { ...snapshot, files: [...files.values()] },
    { repository: { id: snapshot.repositoryId, baseSha: snapshot.baseSha } },
  );
  await mkdir(root, { recursive: true });
  for (const file of files.values()) {
    const target = path.join(root, safePath(file.path));
    await mkdir(path.dirname(target), { recursive: true });
    await writeFile(target, file.content, {
      mode: file.mode === "100755" ? 0o755 : 0o644,
      flag: "wx",
    });
  }
}

export async function collectChanges(root, snapshot, contract) {
  assert(
    process.platform === "linux",
    "candidate collection requires Linux descriptor confinement",
  );
  const canonicalRoot = await realpath(root);
  const files = new Map();
  let visited = 0;
  let readBytes = 0;
  const visit = async (directory, prefix = "") => {
    for (const entry of await readdir(directory, { withFileTypes: true })) {
      assert(++visited <= 5000, "workspace file count exceeded");
      const relative = prefix + entry.name;
      safePath(relative);
      assert(!entry.isSymbolicLink(), "symlink output is forbidden");
      if (entry.isDirectory()) await visit(path.join(directory, entry.name), relative + "/");
      else {
        assert(entry.isFile(), "special file output is forbidden");
        const file = await open(
          path.join(directory, entry.name),
          constants.O_RDONLY | constants.O_NOFOLLOW,
        );
        let stat;
        let bytes;
        try {
          const openedPath = await realpath(`/proc/self/fd/${file.fd}`);
          assert(openedPath.startsWith(canonicalRoot + "/"), "opened file escaped workspace");
          stat = await file.stat();
          assert(stat.isFile() && stat.nlink === 1, "hardlink or special file output is forbidden");
          // Read through the checked descriptor, never a re-resolved path. A
          // surviving untrusted process cannot swap a parent symlink between
          // inspection and read to make the collector disclose credentials.
          const buffer = Buffer.alloc(1024 * 1024 + 1);
          let length = 0;
          while (length < buffer.length) {
            const result = await file.read(buffer, length, buffer.length - length, length);
            if (!result.bytesRead) break;
            length += result.bytesRead;
          }
          assert(length <= 1024 * 1024, "candidate file exceeds budget");
          bytes = buffer.subarray(0, length);
          readBytes += length;
          assert(
            readBytes <= SNAPSHOT_LIMIT + contract.scope.maxPatchBytes,
            "workspace output exceeds budget",
          );
        } finally {
          await file.close();
        }
        const content = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
        assert(!content.includes("\0"), "binary output is forbidden");
        files.set(relative, {
          path: relative,
          content,
          mode: stat.mode & 0o111 ? "100755" : "100644",
        });
      }
    }
  };
  await visit(root);
  const changes = [];
  const base = new Map(snapshot.files.map((file) => [file.path, file]));
  for (const [name, before] of base) {
    const after = files.get(name);
    if (!after) changes.push({ path: name, content: null, mode: before.mode });
    else if (after.content !== before.content || after.mode !== before.mode) changes.push(after);
  }
  for (const [name, file] of files) if (!base.has(name)) changes.push(file);
  return validateChanges(changes, contract, snapshot);
}

export function validateNpmProject(manifest, lock) {
  assert(
    manifest && typeof manifest.scripts?.test === "string" && manifest.scripts.test.trim(),
    "repository requires an npm test script",
  );
  assert(
    !manifest.workspaces &&
      lock?.lockfileVersion === 3 &&
      lock.packages &&
      typeof lock.packages === "object",
    "only npm lockfile-v3 single-package repositories are supported",
  );
  assert(Object.keys(lock.packages).length <= 3000, "dependency count exceeds budget");
  for (const [name, entry] of Object.entries(lock.packages)) {
    if (name === "") continue;
    safePath(name);
    assert(name.startsWith("node_modules/") && !entry.link, "linked dependencies are unsupported");
    const url = new URL(entry.resolved || "");
    assert(
      url.protocol === "https:" &&
        url.hostname === "registry.npmjs.org" &&
        !url.username &&
        !url.password &&
        !url.port &&
        !url.hash &&
        !url.search,
      "dependency registry is not allowed",
    );
    assert(
      typeof entry.integrity === "string" && /^sha512-[A-Za-z0-9+/]+=*$/.test(entry.integrity),
      "dependency integrity is required",
    );
  }
}
