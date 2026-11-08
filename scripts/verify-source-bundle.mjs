#!/usr/bin/env node
/**
 * Independent source/artifact/provider byte binding for ClawSweeper.
 *
 * All three copies MUST match byte-for-byte:
 *  (1) a dry-run build from a verified clean Git source,
 *  (2) a separately produced, non-aliased reproducible build,
 *  (3) the active Worker's content downloaded from the correct Cloudflare
 *      account and bound to the single active version.
 *
 * This deliberately refuses multipart or ambiguous provider content until
 * its exact version/module mapping can be independently verified.
 */
import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import {execFileSync} from "node:child_process";
import os from "node:os";

const MAX_BUNDLE_BYTES = 16 * 1024 * 1024;
const sha256 = bytes=>crypto.createHash("sha256").update(bytes).digest("hex");
const SHA = /^[a-f0-9]{40}$/;

function fileBytes(filename) {
  if(typeof filename!=="string" || !path.isAbsolute(filename))throw Error("local_bundle_path_missing");
  const stat=fs.lstatSync(filename);
  if(!stat.isFile()||stat.isSymbolicLink()||stat.size===0||stat.size>MAX_BUNDLE_BYTES)
    throw Error("local_bundle_invalid_or_oversize");
  return {bytes:fs.readFileSync(filename),stat,realpath:fs.realpathSync(filename)};
}
function sourceCheck(root,expectedRevision,configFile,expectedWorker) {
  if(typeof root!=="string"||!path.isAbsolute(root)||!SHA.test(expectedRevision))
    throw Error("exact_source_checkout_missing");
  const run=(args)=>execFileSync("git",["-C",root,...args],{encoding:"utf8",maxBuffer:300000}).trim();
  const head=run(["rev-parse","HEAD"]);
  if(head!==expectedRevision)throw Error("source_revision_mismatch");
  if(run(["status","--porcelain","--untracked-files=normal"]))
    throw Error("source_checkout_not_clean");
  if(typeof configFile!=="string"||!path.isAbsolute(configFile))
    throw Error("production_deploy_config_missing");
  const config=fs.realpathSync(configFile),dir=fs.realpathSync(root);
  if(!config.startsWith(dir+path.sep))throw Error("config_outside_exact_source");
  const rel=path.relative(dir,config);
  try{run(["ls-files","--error-unmatch",rel])}catch{throw Error("untracked_production_config")}
  const configText=fs.readFileSync(config,"utf8");
  const original=configText.split(/^\s*\[/m)[0];
  const match=original.match(/^\s*name\s*=\s*"([^"]+)"/m);
  if(match?.[1]!==expectedWorker)throw Error("worker_configuration_identity_mismatch");
  const stanza=(name)=>{
    const collected=[];
    let active=false;
    for(const line of configText.split(/\r?\n/)){
      if(line.trim().startsWith("[")){
        if(active)break;
        active=line.trim()==="["+name+"]";
        continue;
      }
      if(active)collected.push(line);
    }
    return collected.join("\n");
  };
  const observability=stanza("observability");
  const tracing=stanza("observability.traces");
  if(!/^\s*redact_query_string\s*=\s*true\s*$/m.test(observability))
    throw Error("production_query_redaction_missing");
  if(!/^\s*enabled\s*=\s*false\s*$/m.test(tracing))
    throw Error("production_tracing_must_remain_disabled");
  return {revision:head,configuration:rel,configSha256:sha256(Buffer.from(configText))};
}

export function independentlyVerifyBundle({
  sourceRoot,sourceRevision,productionConfigFile,expectedWorkerName,
  candidateBundleFile,reproducedBundleFile,providerContentBytes,
}) {
  const source=sourceCheck(sourceRoot,sourceRevision,productionConfigFile,expectedWorkerName);
  const first=fileBytes(candidateBundleFile),second=fileBytes(reproducedBundleFile);
  if(first.realpath===second.realpath || (first.stat.ino===second.stat.ino&&first.stat.dev===second.stat.dev))
    throw Error("independent_build_artifacts_not_distinct");
  const firstDigest=sha256(first.bytes),secondDigest=sha256(second.bytes);
  if(firstDigest!==secondDigest)throw Error("reproduced_build_bytes_mismatch");
  if(!Buffer.isBuffer(providerContentBytes)||providerContentBytes.length===0||
    providerContentBytes.length>MAX_BUNDLE_BYTES)throw Error("provider_content_missing_or_unsupported");
  const providerDigest=sha256(providerContentBytes);
  if(providerDigest!==firstDigest)throw Error("provider_content_digest_mismatch");
  return {
    sourceRevision:source.revision,productionConfig:source.configuration,
    bundleSha256:firstDigest,providerContentSha256:providerDigest,
    byteCount:first.bytes.length,
    independentlyHashedProviderContent:true,
    twoIndependentLocalBuilds:true,
    configSha256:source.configSha256,
    verifiedIdentity:expectedWorkerName,
  };
}


/**
 * The release gate itself produces the build evidence. No caller-provided
 * unverified build paths are accepted in production.
 * Wrangler is always called with --dry-run and no Cloudflare credentials.
 */
export async function reproduceAndVerifyWorkerBundle({
  sourceRoot,sourceRevision,productionConfigFile,expectedWorkerName,
  providerContentBytes,wranglerExecutable,
}) {
  const source=sourceCheck(sourceRoot,sourceRevision,productionConfigFile,expectedWorkerName);
  if(typeof wranglerExecutable!=="string"||!path.isAbsolute(wranglerExecutable)||
    !fs.existsSync(wranglerExecutable))throw Error("missing_source_or_wrangler");
  const versionText=execFileSync(wranglerExecutable,["--version"],{
    cwd:sourceRoot,encoding:"utf8",timeout:12000,
  });
  const version=/\b4\.107\.0\b/.exec(versionText)?.[0];
  if(!version)throw Error("unpinned_wrangler_version");
  const temporary=fs.mkdtempSync(path.join(os.tmpdir(),"clawsweeper-reproducible-"));
  const dir1=path.join(temporary,"build-one"),dir2=path.join(temporary,"build-two");
  const environment={...process.env,
    WRANGLER_SEND_METRICS:"false",CLOUDFLARE_SEND_METRICS:"false"};
  delete environment.CLOUDFLARE_API_TOKEN;
  delete environment.CLOUDFLARE_ACCOUNT_ID;
  delete environment.CF_API_TOKEN;
  delete environment.OPENCLAW_CLOUDFLARE_API_TOKEN;
  const build=outdir=>{
    fs.mkdirSync(outdir,{recursive:true,mode:0o700});
    try {
      execFileSync(wranglerExecutable,["deploy","--config",productionConfigFile,
        "--dry-run","--outdir",outdir],{
        cwd:sourceRoot,env:environment,timeout:120000,stdio:"pipe",
        maxBuffer:2*1024*1024,
      });
    }catch{throw Error("wrangler_dryrun_failed")}
    const bundle=path.join(outdir,"worker.js");
    if(!fs.existsSync(bundle))throw Error("dryrun_bundle_missing");
    return bundle;
  };
  try{
    const first=build(dir1),second=build(dir2);
    const verified=independentlyVerifyBundle({
      sourceRoot,sourceRevision,productionConfigFile,expectedWorkerName,
      candidateBundleFile:first,reproducedBundleFile:second,providerContentBytes,
    });
    return {
      ...verified,configSha256:source.configSha256,
      wranglerVersion:version,
      wranglerDryRunsVerified:true,
      productionTracingEnabled:false,
    };
  }finally{
    fs.rmSync(temporary,{recursive:true,force:true});
  }
}
