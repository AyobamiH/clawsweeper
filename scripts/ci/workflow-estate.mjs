#!/usr/bin/env node
/**
 * Read-only audit of all live workflow source files and jobs.
 * Classification is NOT an execution approval or a runner cutover.
 */
import { readdirSync, readFileSync, writeFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
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

// This is an audit boundary, never runner admission or permission to migrate.
export function classifyExecutionBoundary(job) {
  const labels = Array.isArray(job.runs_on) ? job.runs_on : [job.runs_on];
  if (job.kind === "reusable") return "reusable_workflow_requires_review";
  // Crabbox owns its own ephemeral runner and stateful hydration lifecycle.
  // It must never silently enter the generic ClawSweeper JIT fleet.
  if (labels.includes("crabbox")) return "external_crabbox_ephemeral";
  if (job.workflow.endsWith("/codeql.yml")) return "dedicated_codeql_security";
  if (labels.some((label) => typeof label === "string" && /^windows(?:$|-)/i.test(label)))
    return "genuine_windows_required";
  if (job.risks.includes("container_runtime") || job.workflow.endsWith("/automerge-e2e.yml"))
    return "isolated_container_required";
  if (job.risks.length > 0) return "guarded_sensitive_effects";
  if (job.kind === "local_label") return "local_label_unverified";
  if (job.kind === "dynamic_or_other" || job.kind === "dynamic_hosted_fallback")
    return "dynamic_runner_requires_review";
  return "untrusted_compute_isolation_required";
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
    // A job inherits workflow-scope expressions even if its own body mentions no secret.
    const workflowSecret = /secrets(?:\.|\[)/.test(
      JSON.stringify({ env: doc.env, defaults: doc.defaults, concurrency: doc.concurrency }),
    );
    const workflowJobs = [];
    for (const [jobId, job] of Object.entries(doc.jobs)) {
      if (!job || typeof job !== "object") throw Error("Invalid job " + file + "/" + jobId);
      const runner = job["runs-on"];
      const kind = job.uses && runner === undefined ? "reusable" : classifyRunner(runner);
      const serialized = JSON.stringify(job);
      // Hints cannot grant permission to run: inspect exact sources before acceptance.
      const permissionString = JSON.stringify({
        top: doc.permissions ?? null,
        job: job.permissions ?? null,
      });
      const needs =
        typeof job.needs === "string" ? [job.needs] : Array.isArray(job.needs) ? job.needs : [];
      if (!needs.every((need) => typeof need === "string" && !need.includes("${{")))
        throw Error("Dynamic needs require manual review: " + file + "/" + jobId);
      const risks = [
        ...(/secrets(?:\.|\[)/.test(serialized) ? ["secret_reference"] : []),
        ...(job.secrets === "inherit" ? ["reusable_secret_inheritance"] : []),
        ...(workflowSecret ? ["workflow_secret_reference"] : []),
        ...(permissionString.includes("write") ? ["write_permission"] : []),
        ...(/\b(docker\s+(?:run|build|compose)|podman\s+|\/var\/run\/docker\.sock)\b/.test(
          serialized,
        )
          ? ["container_runtime"]
          : []),
        ...(/\b(wrangler|gcloud|aws\s|cloudflare)\b/i.test(serialized) ? ["cloud_service"] : []),
        ...(/\b(gh\s+(?:api|pr|issue|workflow)|git\s+push)\b/.test(serialized)
          ? ["possible_write_effect"]
          : []),
      ];
      workflowJobs.push({
        workflow: sourcePath,
        id: jobId,
        needs,
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
    // A downstream job is not independently low-risk merely because its body
    // contains no secret/write hints: its needs ancestors may have effects.
    const byId = new Map(workflowJobs.map((job) => [job.id, job]));
    const complete = new Set();
    function resolveRisk(id, visiting = new Set()) {
      const item = byId.get(id);
      if (!item) throw Error("Unknown needs dependency: " + file + "/" + id);
      if (visiting.has(id)) throw Error("Cyclic needs dependency: " + file + "/" + id);
      if (complete.has(id)) return item.risks.length > 0;
      visiting.add(id);
      let sensitiveAncestor = false;
      for (const upstreamId of item.needs) {
        if (resolveRisk(upstreamId, visiting)) sensitiveAncestor = true;
      }
      visiting.delete(id);
      if (sensitiveAncestor) item.risks.push("sensitive_upstream_dependency");
      complete.add(id);
      return item.risks.length > 0;
    }
    for (const item of workflowJobs) resolveRisk(item.id);
    for (const item of workflowJobs) {
      item.execution_boundary = classifyExecutionBoundary(item);
      if (item.execution_boundary === "external_crabbox_ephemeral")
        item.status = "external_ephemeral_not_generic_jit";
    }
    jobs.push(...workflowJobs);
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
  const execution_boundaries = {};
  for (const job of jobs)
    execution_boundaries[job.execution_boundary] =
      (execution_boundaries[job.execution_boundary] ?? 0) + 1;
  return { schema: "clawsweeper.workflow-estate.v2", summary, execution_boundaries, sources, jobs };
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
  if (args.includes("--write")) {
    writeFileSync(manifest, JSON.stringify(estate, null, 2) + "\n");
    // Keep the generated source manifest compatible with the mandatory format:check.
    execFileSync(path.join(ROOT, "node_modules", ".bin", "oxfmt"), [manifest], {
      cwd: ROOT,
      stdio: "pipe",
    });
  }
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
