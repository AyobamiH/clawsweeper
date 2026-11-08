#!/usr/bin/env node
/**
 * Fail-closed, READ-ONLY source-to-Cloudflare deployment admission.
 *
 * Cloudflare's version endpoint returns metadata and a script etag, NOT the
 * content bytes of that specific version. The /content/v2 endpoint returns the
 * CURRENT active script, not a version-addressed blob. Therefore the checker:
 *   - reads the single active deployment + version before content;
 *   - downloads current script bytes from the correct ACCOUNT/WORKER;
 *   - rechecks the active deployment/version/etag after content;
 *   - hashes the bytes and compares two independent exact-source dry-run builds;
 *   - verifies an owner HMAC binding the same source SHA, bundle hash,
 *     provider etag and deployment/version IDs;
 *   - refuses multipart/unknown content formats or version races.
 *
 * Neither this gate nor its dry-run builder deploys or enables tracing.
 */
import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import {fileURLToPath} from "node:url";
import {execFileSync} from "node:child_process";
import {reproduceAndVerifyWorkerBundle} from "./verify-source-bundle.mjs";

export const EXPECTED_ACCOUNT = "91b59577e757131d68d55a471fe32aca";
export const EXPECTED_WORKER = "clawsweeper-status";
export const PRODUCTION_HEALTH = "https://clawsweeper.openclaw.ai/api/health";
export const FALLBACK_HEALTH = "https://clawsweeper-status.services-91b.workers.dev/api/health";
const API = "https://api.cloudflare.com/client/v4";
const SHA = /^[a-f0-9]{40}$/;
const UUID = /^[a-f0-9-]{36}$/i;
const MAX_RESPONSE = 16*1024*1024;
const sha256 = buffer=>crypto.createHash("sha256").update(buffer).digest("hex");

export function validateDeployment(result) {
 const deployments=result?.result?.deployments;
 if(result?.success!==true||!Array.isArray(deployments)||!deployments.length)
  throw Error("provider_deployments_unavailable");
 const current=deployments[0];
 if(!UUID.test(current?.id||"")||!Array.isArray(current.versions))
  throw Error("provider_deployments_invalid");
 const live=current.versions.filter(v=>v&&typeof v.percentage==="number"&&v.percentage>0);
 if(live.length!==1||live[0].percentage!==100||!UUID.test(live[0].version_id||""))
  throw Error("gradual_or_uncertain_deployment");
 return {deploymentId:current.id,versionId:live[0].version_id,createdAt:current.created_on};
}

function stableProviderState(before,after) {
 return before.deploymentId===after.deploymentId &&
  before.versionId===after.versionId &&
  before.scriptEtag===after.scriptEtag;
}

export function verifySignedSourceAttestation(
 receipt,keyHex,expectedSource,versionId,providerScriptEtag,deploymentId,independentBundle,
) {
 if(!receipt||!/^[a-f0-9]{64,128}$/i.test(keyHex||""))
  throw Error("owner_receipt_missing");
 if(!independentBundle?.independentlyHashedProviderContent||
   !independentBundle?.twoIndependentLocalBuilds||
   !independentBundle?.wranglerDryRunsVerified||
   independentBundle?.sourceRevision!==expectedSource||
   independentBundle?.verifiedIdentity!==EXPECTED_WORKER||
   !/^[a-f0-9]{64}$/.test(independentBundle?.bundleSha256||"")||
   independentBundle?.providerContentSha256!==independentBundle?.bundleSha256)
  throw Error("independent_bundle_evidence_missing");
 const claims=receipt.claims;
 if(!claims||claims.schema!=="clawsweeper-production-source/v1"||
   claims.account_id!==EXPECTED_ACCOUNT||claims.script_name!==EXPECTED_WORKER||
   claims.source_sha!==expectedSource||claims.version_id!==versionId||
   claims.deployment_id!==deploymentId||claims.provider_script_etag!==providerScriptEtag||
   claims.bundle_sha256!==independentBundle.bundleSha256||
   claims.production_config_sha256!==independentBundle.configSha256||
   claims.wrangler_version!==independentBundle.wranglerVersion)
  throw Error("owner_receipt_claim_mismatch");
 if(!/^[a-f0-9]{64}$/i.test(receipt.signature||""))
  throw Error("owner_receipt_signature_invalid");
 const expected=crypto.createHmac("sha256",Buffer.from(keyHex,"hex")).update(JSON.stringify(claims)).digest();
 const observed=Buffer.from(receipt.signature,"hex");
 if(expected.length!==observed.length||!crypto.timingSafeEqual(expected,observed))
  throw Error("owner_receipt_signature_invalid");
 return {
  sourceSha:expectedSource,versionId,deploymentId,
  bundleSha256:independentBundle.bundleSha256,
  configSha256:independentBundle.configSha256,
  providerContentSha256:independentBundle.providerContentSha256,
  wranglerVersion:independentBundle.wranglerVersion,
  sourceBytesVerified:true,providerBytesVerified:true,
  attestation:"HMAC + reproducible local builds + stable active provider script bytes",
 };
}

async function readJson(transport,url,headers={}) {
 const control=new AbortController();
 const deadline=setTimeout(()=>control.abort(),8000);
 try{
  const response=await transport(url,{method:"GET",headers,signal:control.signal,redirect:"error"});
  if(!response.ok)throw Error("provider_json_http_error");
  const length=Number(response.headers.get("content-length")||0);
  if(length>131072)throw Error("provider_json_too_large");
  const raw=await response.text();
  if(raw.length>131072)throw Error("provider_json_too_large");
  return JSON.parse(raw);
 }finally{clearTimeout(deadline)}
}

async function readRawCurrentScript(transport,url,headers={}) {
 const control=new AbortController();
 const deadline=setTimeout(()=>control.abort(),8000);
 try{
  const response=await transport(url,{method:"GET",headers,signal:control.signal,redirect:"error"});
  if(!response.ok)throw Error("provider_content_http_error");
  const type=(response.headers.get("content-type")||"").split(";")[0].trim().toLowerCase();
  // Multipart scripts/assets cannot be hashed as a single Worker entrypoint
  // without a provider-authenticated module manifest. Refuse them for now.
  if(!["application/javascript","text/javascript","application/x-javascript","text/plain",
        "application/octet-stream"].includes(type))
    throw Error("provider_content_format_unverifiable");
  const length=Number(response.headers.get("content-length")||0);
  if(length>MAX_RESPONSE)throw Error("provider_content_too_large");
  if(!response.body)throw Error("provider_content_missing");
  const stream=response.body.getReader(),chunks=[];
  let size=0;
  for(;;){
    const {done,value}=await stream.read();
    if(done)break;
    size+=value.byteLength;
    if(size>MAX_RESPONSE){await stream.cancel();throw Error("provider_content_too_large")}
    chunks.push(Buffer.from(value));
  }
  if(size===0)throw Error("provider_content_missing");
  const etag=response.headers.get("etag")?.replace(/^W\//,"").replace(/^"|"$/g,"")||null;
  if(!etag)throw Error("provider_content_etag_missing");
  return {content:Buffer.concat(chunks),etag,sha256:sha256(Buffer.concat(chunks))};
 }finally{clearTimeout(deadline)}
}

export async function checkProductionTracing(opts={}) {
 const expectedSource=opts.expectedSource;
 if(!SHA.test(expectedSource||""))throw Error("missing_exact_expected_source_sha");
 const transport=opts.transport||fetch;
 const problems=[],healths=[];
 for(const url of [PRODUCTION_HEALTH,FALLBACK_HEALTH]){
  try{
   const health=await readJson(transport,url);
   const claim=health?.deployment_sha;
   if(health?.ok!==true||health?.service!==EXPECTED_WORKER||!SHA.test(claim||""))
    problems.push("health_invalid");
   else if(claim!==expectedSource)problems.push("live_source_sha_mismatch");
   healths.push({url,service:health?.service||null,deploymentSha:typeof claim==="string"?claim:null});
  }catch{problems.push("health_readback_failed");healths.push({url,error:"unavailable"})}
 }
 if(healths.length===2&&healths[0].deploymentSha&&healths[1].deploymentSha&&
    healths[0].deploymentSha!==healths[1].deploymentSha)
  problems.push("public_domain_source_mismatch");
 let provider=null,attestation=null;
 if(!opts.apiToken){
  problems.push("correct_account_api_credential_missing");
 }else{
  const endpoint=`${API}/accounts/${EXPECTED_ACCOUNT}/workers/scripts/${EXPECTED_WORKER}`;
  const headers={Authorization:"Bearer "+opts.apiToken,Accept:"application/json"};
  try{
   const readProviderState=async ()=>{
    const active=validateDeployment(await readJson(transport,`${endpoint}/deployments?per_page=3`,headers));
    const version=await readJson(transport,`${endpoint}/versions/${active.versionId}`,headers);
    const etag=version?.result?.resources?.script?.etag;
    if(version?.success!==true||version?.result?.id!==active.versionId||
      typeof etag!=="string"||!etag)throw Error("provider_version_metadata_missing");
    return {...active,scriptEtag:etag,versionUploadSource:version?.result?.metadata?.source||null};
   };
   const before=await readProviderState();
   provider={accountId:EXPECTED_ACCOUNT,workerName:EXPECTED_WORKER,...before};
   if(!opts.signedReceipt||!opts.receiptKey){
    problems.push("trusted_source_bundle_receipt_missing");
   }else{
    const raw=await readRawCurrentScript(transport,`${endpoint}/content/v2`,{
     Authorization:headers.Authorization,Accept:"application/javascript",
    });
    const after=await readProviderState();
    if(!stableProviderState(before,after))throw Error("provider_version_changed_during_readback");
    if(raw.etag!==before.scriptEtag)throw Error("provider_content_etag_version_mismatch");
    // Production admission always performs its own exact-source build and
    // byte comparison. Do not accept caller-injected "verification" callbacks.
    const independentBundle=await reproduceAndVerifyWorkerBundle({
      sourceRoot:opts.sourceRoot,sourceRevision:expectedSource,
      productionConfigFile:opts.productionConfigFile,expectedWorkerName:EXPECTED_WORKER,
      providerContentBytes:raw.content,wranglerExecutable:opts.wranglerExecutable,
    });
    attestation=verifySignedSourceAttestation(opts.signedReceipt,opts.receiptKey,
      expectedSource,before.versionId,before.scriptEtag,before.deploymentId,independentBundle);
   }
  }catch(error){
   // Only fixed local error codes are emitted; never print provider response,
   // any raw content, signed receipt, request headers or credentials.
   const known=new Set(["provider_deployments_unavailable","provider_deployments_invalid",
    "gradual_or_uncertain_deployment","provider_version_metadata_missing",
    "provider_version_changed_during_readback","provider_content_etag_version_mismatch",
    "provider_content_http_error","provider_content_format_unverifiable",
    "provider_content_too_large","provider_content_missing","provider_content_etag_missing",
    "source_revision_mismatch","source_checkout_not_clean","untracked_production_config",
    "production_query_redaction_missing","unpinned_wrangler_version", "dryrun_bundle_missing", "production_deploy_config_missing", "config_outside_exact_source", "exact_source_checkout_missing", "local_bundle_path_missing", "local_bundle_invalid_or_oversize", "provider_content_missing_or_unsupported",
    "worker_configuration_identity_mismatch","production_tracing_must_remain_disabled",
    "independent_build_artifacts_not_distinct","reproduced_build_bytes_mismatch",
    "provider_content_digest_mismatch","independent_bundle_evidence_missing",
    "owner_receipt_missing","owner_receipt_claim_mismatch","owner_receipt_signature_invalid",
    "wrangler_dryrun_failed","nondeterministic_worker_build","missing_source_or_wrangler"]);
   const code=known.has(error?.message)?error.message:"provider_or_build_verification_failed";
   problems.push(code);
  }
 }
 if(!opts.signedReceipt||!opts.receiptKey)
  problems.push("trusted_source_bundle_receipt_missing");
 const state=problems.length?"HOLD":"PROVIDER_SOURCE_VERIFIED";
 return {schema:"clawsweeper-source-deployment-gate/v2",
  checkedAt:new Date().toISOString(),state,expectedSource,healths,provider,attestation,
  problems:[...new Set(problems)],
  caution:"Read-only gate only. No independent provider tracing/privacy approval or activation is implied."};
}

const self=process.argv[1]&&path.resolve(process.argv[1])===fileURLToPath(import.meta.url);
if(self){
 const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),"..");
 const source=process.env.CLAWSWEEPER_EXPECTED_SOURCE_SHA||
   execFileSync("git",["-C",root,"rev-parse","HEAD"],{encoding:"utf8"}).trim();
 let receipt=null;
 try{if(process.env.CLAWSWEEPER_DEPLOY_SOURCE_RECEIPT)
   receipt=JSON.parse(fs.readFileSync(process.env.CLAWSWEEPER_DEPLOY_SOURCE_RECEIPT,"utf8"))}catch{}
 const report=await checkProductionTracing({
  expectedSource:source,apiToken:process.env.OPENCLAW_CLOUDFLARE_API_TOKEN||"",
  signedReceipt:receipt,receiptKey:process.env.CLAWSWEEPER_DEPLOY_SOURCE_RECEIPT_KEY_HEX||"",
  sourceRoot:root,
  productionConfigFile:process.env.CLAWSWEEPER_PRODUCTION_WRANGLER_CONFIG||
    path.join(root,"dashboard/wrangler.toml"),
  wranglerExecutable:process.env.CLAWSWEEPER_PINNED_WRANGLER||"",
 });
 const output=process.env.CLAWSWEEPER_TRACE_GATE_OUTPUT||
   path.join(root,".tracing-admission-readback.json");
 fs.writeFileSync(output,JSON.stringify(report,null,2)+"\n",{mode:0o600});
 console.log(JSON.stringify({state:report.state,expectedSource:report.expectedSource,
   problems:report.problems,healths:report.healths,provider:report.provider,
   evidencePath:output},null,2));
 if(report.state!=="PROVIDER_SOURCE_VERIFIED")process.exitCode=2;
}