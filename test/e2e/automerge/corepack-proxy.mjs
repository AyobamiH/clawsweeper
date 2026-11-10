#!/usr/bin/env node

import { spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const args = process.argv.slice(2);
const isolateHistoricalIndexFailure =
  process.env.CLAWSWEEPER_E2E_COREPACK_PNPM_ONLY === "1" &&
  args[0] === "enable" &&
  !args.some((arg) => ["pnpm", "pnpx", "yarn", "yarnpkg"].includes(arg));

// The historical run had two independent runtime-freezer defects. Supplying
// pnpm here bypasses only the earlier Yarn-shim defect so the same production
// CLI can reach and reproduce the linked Git-index identity failure.
const delegatedArgs = isolateHistoricalIndexFailure ? [...args, "pnpm"] : args;
const realCorepack = process.env.CLAWSWEEPER_E2E_REAL_COREPACK;

/**
 * Seed only the disposable E2E target profile with precisely pinned Corepack
 * bytes from the trusted test image. The production runtime and source are
 * unchanged; Corepack itself still executes prepare and validates the cached
 * package-manager release. No target repo or network response is trusted.
 */
export function seedHermeticE2EPnpm(
  argsToPrepare,
  env,
  sourceRoot = "/opt/clawsweeper-e2e-corepack/v1/pnpm",
) {
  if (argsToPrepare[0] !== "prepare") return false;
  const requested = String(argsToPrepare[1] ?? "");
  const match = requested.match(/^pnpm@(11\.10\.0|11\.2\.2)(?:\+sha512\.[0-9a-f]{128})?$/i);
  if (!match) return false;
  const targetHome = String(env.COREPACK_HOME ?? "");
  if (!/^\/tmp\/clawsweeper-target-user-[^/]+\/corepack$/.test(targetHome)) return false;
  const source = path.join(sourceRoot, match[1]);
  if (!fs.existsSync(source)) return false;
  if (!fs.lstatSync(source).isDirectory() || fs.lstatSync(source).isSymbolicLink()) {
    throw new Error("unsafe E2E Corepack source");
  }
  if (!fs.statSync(path.join(source, ".corepack")).isFile()) {
    throw new Error("incomplete E2E pinned Corepack cache");
  }
  const versionRoot = path.join(targetHome, "v1", "pnpm");
  fs.mkdirSync(versionRoot, { recursive: true, mode: 0o700 });
  const destination = path.join(versionRoot, match[1]);
  if (!fs.existsSync(destination)) {
    fs.cpSync(source, destination, { recursive: true, errorOnExist: true, force: false });
  }
  return true;
}

export function runE2ECorepackProxy(argsToRun, env, sourceRoot) {
  const real = env.CLAWSWEEPER_E2E_REAL_COREPACK;
  if (!real) throw new Error("CLAWSWEEPER_E2E_REAL_COREPACK is required");
  const seeded = seedHermeticE2EPnpm(argsToRun, env, sourceRoot);
  // Hermetic images cannot delegate unsupported package managers or flags:
  // Corepack may fetch registry bytes before returning even for a failed call.
  const offlineRequired = env.CLAWSWEEPER_E2E_REQUIRE_OFFLINE_COREPACK === "1";
  if (offlineRequired) {
    const targetHome = String(env.COREPACK_HOME ?? "");
    if (!/^\/tmp\/clawsweeper-target-user-[^/]+\/corepack$/.test(targetHome)) {
      throw new Error("hermetic E2E Corepack requires disposable target home");
    }
    if (argsToRun[0] === "prepare") {
      if (
        !seeded ||
        !(argsToRun.length === 2 || (argsToRun.length === 3 && argsToRun[2] === "--activate"))
      ) {
        throw new Error("pinned E2E Corepack seed unavailable");
      }
    } else if (argsToRun[0] === "enable") {
      const enablePnpm =
        (argsToRun.length === 2 && argsToRun[1] === "pnpm") ||
        (argsToRun.length === 4 &&
          argsToRun[1] === "--install-directory" &&
          argsToRun[2] === path.join(targetHome, "bin") &&
          argsToRun[3] === "pnpm");
      if (!enablePnpm) throw new Error("unsupported hermetic E2E Corepack command");
    } else {
      throw new Error("unsupported hermetic E2E Corepack command");
    }
  }
  const result = spawnSync(real, argsToRun, {
    cwd: process.cwd(),
    env: offlineRequired || seeded ? { ...env, COREPACK_ENABLE_NETWORK: "0" } : env,
    stdio: "inherit",
  });
  if (result.error) throw result.error;
  return result.status ?? 1;
}

// The E2E command bin invokes this module through a symlink; compare resolved
// filesystem identities so the CLI executes while test imports remain inert.
if (
  process.argv[1] &&
  fs.realpathSync(process.argv[1]) === fs.realpathSync(fileURLToPath(import.meta.url))
) {
  if (!realCorepack) fail("CLAWSWEEPER_E2E_REAL_COREPACK is required");
  try {
    process.exitCode = runE2ECorepackProxy(delegatedArgs, process.env);
  } catch (error) {
    fail(error instanceof Error ? error.message : "E2E Corepack proxy failed");
  }
}

function fail(message) {
  process.stderr.write(`${message}\n`);
  process.exit(1);
}
