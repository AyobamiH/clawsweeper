#!/usr/bin/env node
/**
 * Read-only audit of all live workflow source files and jobs.
 * Classification is NOT an execution approval or a runner cutover.
 */
import { readdirSync, readFileSync, writeFileSync } from "node:fs";
import { createHash } from "node:crypto";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { parseDocument } from "yaml";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const sha256 = (v) => createHash("sha256").update(v).digest("hex");

export function classifyRunner(value) {
  if (Array.isArray(value))
    return value.includes("self-hosted") ? "local_label" : "dynamic_or_other";
  if (typeof value !== "string") return "dynamic_or_other";
  if (/^(ubuntu|windows|macos)-(?:latest|[0-9][0-9.]*)$/.test(value)) return "github_hosted";
  if (/\$\{\{/.test(value) && /ubuntu-(?:latest|[0-9][0-9.]*)/.test(value))
    return "dynamic_hosted_fallback";
  if (/\$\{\{/.test(value)) return "dynamic_or_other";
  if (value === "self-hosted") return "local_label";
  return "dynamic_or_other";
}

export function inspectEstate(root = ROOT) {
  const workflowDir = path.join(root, ".github", "workflows");
  const workflows = readdirSync(workflowDir)
    .filter((f) => /\.ya?ml$/.test(f))
    .sort();
  const jobs = [];
  const sources = [];
  for (const file of workflows) {
    const contents = readFileSync(path.join(workflowDir, file), "utf8");
    const parsed = parseDocument(contents, { uniqueKeys: true, strict: true });
    if (parsed.errors.length) throw Error("Invalid YAML " + file + ": " + parsed.errors[0].message);
    const doc = parsed.toJS();
    if (!doc || typeof doc !== "object" || !doc.jobs || typeof doc.jobs !== "object")
      throw Error("Missing jobs mapping: " + file);
    const on = doc.on || {};
    const events = Array.isArray(on) ? on : typeof on === "string" ? [on] : Object.keys(on);
    const sourcePath = ".github/workflows/" + file;
    const sourceHash = sha256(contents);
    sources.push({ path: sourcePath, sha256: sourceHash, events: [...events].sort() });
    for (const [jobId, job] of Object.entries(doc.jobs)) {
      if (!job || typeof job !== "object") throw Error("Invalid job " + file + "/" + jobId);
      const runner = job["runs-on"];
      const kind = job.uses && runner === undefined ? "reusable" : classifyRunner(runner);
      const serialized = JSON.stringify(job);
      // GitHub inherits workflow-level env into EVERY job, even a job that
      // appears harmless when its own YAML block is inspected in isolation.
      // Consciously over-classify secrets on overridden keys: an audit hint
      // can block promotion but must never grant execution privileges.
      const inherited = JSON.stringify(doc.env ?? null);
      const effective = JSON.stringify({ inherited: doc.env ?? null, job });
      // Hints cannot grant permission to run: inspect exact sources before acceptance.
      const permissionString = JSON.stringify({
        top: doc.permissions ?? null,
        job: job.permissions ?? null,
      });
      const risks = [
        ...(serialized.includes("secrets.") ? ["secret_reference"] : []),
        ...(inherited.includes("secrets.") ? ["workflow_secret_inherited"] : []),
        ...(job.environment !== undefined ? ["environment_scoped"] : []),
        ...(job.secrets === "inherit" ? ["reusable_secrets_inherit"] : []),
        ...(permissionString.includes("write") ? ["write_permission"] : []),
        ...(/\b(docker\s+(?:run|build|compose)|podman\s+|\/var\/run\/docker\.sock)\b/.test(
          effective,
        )
          ? ["container_runtime"]
          : []),
        ...(/\b(wrangler|gcloud|aws\s|cloudflare)\b/i.test(serialized) ? ["cloud_service"] : []),
        ...(/\b(gh\s+(?:api|pr|issue|workflow)|git\s+push)\b/.test(serialized)
          ? ["possible_write_effect"]
          : []),
      ];
      jobs.push({
        workflow: sourcePath,
        id: jobId,
        display_name: job.name || jobId,
        kind,
        runs_on: runner ?? null,
        events: [...events].sort(),
        risks,
        source_sha256: sourceHash,
        status:
          kind === "local_label"
            ? "labelled_local_not_operationally_verified"
            : "unmigrated_or_requires_proof",
      });
    }
  }
  jobs.sort((a, b) => (a.workflow + "/" + a.id).localeCompare(b.workflow + "/" + b.id, "en"));
  const summary = { workflows: workflows.length, jobs: jobs.length };
  for (const kind of [
    "github_hosted",
    "dynamic_hosted_fallback",
    "local_label",
    "dynamic_or_other",
    "reusable",
  ])
    summary[kind] = jobs.filter((j) => j.kind === kind).length;
  return { schema: "clawsweeper.workflow-estate.v1", summary, sources, jobs };
}

export function compareRegistry(snapshot, estate) {
  const known = new Set(estate.sources.map((x) => x.path));
  const listed = Array.isArray(snapshot) ? snapshot : snapshot.workflows;
  if (!Array.isArray(listed)) throw Error("GitHub registry snapshot must contain workflows[]");
  return {
    registry_entries: listed.length,
    absent_from_main: listed
      .filter((w) => !known.has(w.path))
      .map((w) => ({
        name: w.name,
        path: w.path,
        state: w.state,
        id: w.id,
      }))
      .sort((a, b) => a.path.localeCompare(b.path, "en")),
  };
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const args = process.argv.slice(2);
  const estate = inspectEstate();
  const manifest = path.join(ROOT, "config", "ci-workflow-estate.json");
  if (args.includes("--write")) writeFileSync(manifest, JSON.stringify(estate, null, 2) + "\n");
  if (args.includes("--check")) {
    const baseline = JSON.parse(readFileSync(manifest, "utf8"));
    if (JSON.stringify(baseline) !== JSON.stringify(estate)) {
      console.error("workflow_estate_drift: regenerate and review all source changes");
      process.exitCode = 1;
    }
  }
  const regPos = args.indexOf("--registry");
  if (regPos !== -1) {
    if (!args[regPos + 1]) throw Error("--registry requires a path");
    const reg = compareRegistry(JSON.parse(readFileSync(args[regPos + 1], "utf8")), estate);
    console.log(JSON.stringify({ summary: estate.summary, registry: reg }, null, 2));
  } else console.log(JSON.stringify(estate.summary));
}
