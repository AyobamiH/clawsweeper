import { spawn } from "node:child_process";
import { constants } from "node:fs";
import { access, mkdtemp, readFile, realpath, rm, writeFile } from "node:fs/promises";
import { createRequire } from "node:module";
import os from "node:os";
import path from "node:path";
import { assert } from "./contract.mjs";

export const CODEX_VERSION = "0.157.1";

export function modelEnvironment(source = process.env) {
  const env = {};
  for (const name of ["PATH", "HOME", "CODEX_HOME", "LANG", "LC_ALL", "TMPDIR"])
    if (source[name]) env[name] = source[name];
  env.CLAWSWEEPER_CODEX_LOGIN_METHOD = "chatgpt";
  return env;
}

export function permissionArguments(root, mode = "write", runtimeBinary) {
  assert(
    path.isAbsolute(root) && ["read", "write"].includes(mode),
    "invalid model permission root",
  );
  // A named split-filesystem policy starts with no general disk-read access.
  // :minimal adds only system binaries/libraries. Authentication stays in the
  // unsandboxed Codex broker and is absent from model tool subprocesses.
  assert(!runtimeBinary || path.isAbsolute(runtimeBinary), "invalid Codex runtime path");
  const executable = runtimeBinary ? `, ${JSON.stringify(runtimeBinary)} = "read"` : "";
  const filesystem = `{ ":minimal" = "read", ${JSON.stringify(root)} = ${JSON.stringify(mode)}${executable} }`;
  return [
    "--config",
    'forced_login_method="chatgpt"',
    "--config",
    'default_permissions="commercial"',
    "--config",
    `permissions.commercial.filesystem=${filesystem}`,
    "--config",
    "permissions.commercial.network.enabled=false",
    "--config",
    'shell_environment_policy.inherit="core"',
  ];
}

export async function resolveRuntimeBinary(binary, env) {
  assert(process.platform === "linux", "commercial execution requires Linux");
  let entry;
  for (const candidate of path.isAbsolute(binary)
    ? [binary]
    : (env.PATH || "")
        .split(path.delimiter)
        .filter(Boolean)
        .map((directory) => path.join(directory, binary))) {
    try {
      await access(candidate, constants.X_OK);
      entry = await realpath(candidate);
      break;
    } catch {}
  }
  assert(entry, "Codex executable unavailable");
  if (!entry.endsWith(".js")) return entry;
  assert(["x64", "arm64"].includes(process.arch), "unsupported Codex platform");
  const packageFile = createRequire(entry).resolve(
    `@openai/codex-linux-${process.arch}/package.json`,
  );
  const metadata = JSON.parse(await readFile(packageFile, "utf8"));
  assert(
    metadata.name === "@openai/codex" &&
      metadata.version === `${CODEX_VERSION}-linux-${process.arch}`,
    "unexpected native Codex package",
  );
  const target =
    process.arch === "x64" ? "x86_64-unknown-linux-musl" : "aarch64-unknown-linux-musl";
  return realpath(path.join(path.dirname(packageFile), "vendor", target, "bin", "codex"));
}

export function processResult(command, args, { cwd, env, input, timeoutMs = 60_000 } = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, {
      cwd,
      env,
      stdio: ["pipe", "pipe", "pipe"],
      detached: true,
    });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (bytes) => {
      if (stdout.length < 65536) stdout += bytes.toString();
    });
    child.stderr.on("data", (bytes) => {
      if (stderr.length < 65536) stderr += bytes.toString();
    });
    const kill = () => {
      try {
        process.kill(-child.pid, "SIGKILL");
      } catch {}
    };
    const timer = setTimeout(kill, timeoutMs);
    child.once("error", (error) => {
      clearTimeout(timer);
      reject(error);
    });
    child.once("close", (code) => {
      clearTimeout(timer);
      resolve({ code, stdout, stderr });
    });
    child.stdin.on("error", () => {});
    child.stdin.end(input || "");
  });
}

export async function sandboxPreflight(root, mode, env = modelEnvironment(), binary = "codex") {
  const version = await processResult(binary, ["--version"], { env });
  assert(
    version.code === 0 && version.stdout.trim() === `codex-cli ${CODEX_VERSION}`,
    "unexpected Codex binary version",
  );
  const runtimeBinary = await resolveRuntimeBinary(binary, env);
  const privateRoot = await mkdtemp(path.join(os.tmpdir(), "tw-private-sentinel-"));
  const sentinel = path.join(privateRoot, "secret.txt");
  const writable = path.join(root, ".tw-sandbox-proof");
  await writeFile(sentinel, "PRIVATE_AUTHORITY_SENTINEL", { mode: 0o600 });
  const script = [
    "import errno, pathlib, socket, sys",
    "root, outside, auth, mode = sys.argv[1:]",
    "for forbidden in [outside, auth]:",
    "    try:",
    "        pathlib.Path(forbidden).read_bytes()",
    "    except (PermissionError, FileNotFoundError):",
    "        pass",
    "    else:",
    '        raise RuntimeError("private path readable")',
    'target = pathlib.Path(root) / ".tw-sandbox-proof"',
    "try:",
    '    target.write_text("bounded")',
    "except (PermissionError, OSError):",
    '    if mode == "write": raise',
    "else:",
    '    if mode == "read": raise RuntimeError("read-only workspace writable")',
    "sock = None",
    "try:",
    "    sock = socket.socket()",
    "    sock.settimeout(1)",
    '    sock.connect(("192.0.2.1", 443))',
    "except OSError as error:",
    "    if error.errno not in (errno.EPERM, errno.EACCES, errno.ENETUNREACH): raise",
    "else:",
    '    raise RuntimeError("network available")',
    "finally:",
    "    if sock: sock.close()",
    'print("commercial-sandbox-boundary-passed")',
  ].join("\n");
  try {
    const result = await processResult(
      binary,
      [
        ...permissionArguments(root, mode, runtimeBinary),
        "sandbox",
        "--permission-profile",
        "commercial",
        "-C",
        root,
        "--",
        "/usr/bin/python3",
        "-c",
        script,
        root,
        sentinel,
        path.join(env.CODEX_HOME, "auth.json"),
        mode,
      ],
      { env, cwd: root },
    );
    assert(
      result.code === 0 && result.stdout.trim() === "commercial-sandbox-boundary-passed",
      "model sandbox boundary could not be proven",
    );
    return {
      version: CODEX_VERSION,
      filesystem: mode,
      authReadDenied: true,
      outsideReadDenied: true,
      networkDenied: true,
    };
  } finally {
    await rm(privateRoot, { recursive: true, force: true });
    await rm(writable, { force: true });
  }
}

export async function runModel(
  root,
  prompt,
  { mode = "write", outputSchema, outputFile, binary = "codex", env = modelEnvironment() } = {},
) {
  assert(env.CODEX_HOME, "isolated ChatGPT authentication is required");
  const config = await readFile(path.join(env.CODEX_HOME, "config.toml"), "utf8");
  assert(/forced_login_method\s*=\s*"chatgpt"/.test(config), "ChatGPT login boundary missing");
  await sandboxPreflight(root, mode, env, binary);
  const runtimeBinary = await resolveRuntimeBinary(binary, env);
  const result = await processResult(
    binary,
    [
      "--ask-for-approval",
      "never",
      ...permissionArguments(root, mode, runtimeBinary),
      "exec",
      "--strict-config",
      "--ignore-user-config",
      "--json",
      "--skip-git-repo-check",
      "--ephemeral",
      ...(outputSchema ? ["--output-schema", outputSchema] : []),
      ...(outputFile ? ["--output-last-message", outputFile] : []),
      "-",
    ],
    { cwd: root, env, input: prompt, timeoutMs: 30 * 60_000 },
  );
  assert(result.code === 0, "bounded model run did not complete");
}
