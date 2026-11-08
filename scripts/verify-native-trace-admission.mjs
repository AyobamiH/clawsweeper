#!/usr/bin/env node
/**
 * Read-only correct-account Cloudflare Worker source-deployment gate.
 *
 * Outputs a non-sensitive status receipt. It never deploys a Worker, invokes a
 * webhook, accesses secret bindings, or enables tracing.
 *
 * Workers REST endpoints:
 * GET /accounts/{account_id}/workers/scripts/{script}/deployments
 * GET /accounts/{account_id}/workers/scripts/{script}/versions/{version_id}
 */
import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import { fileURLToPath } from "node:url";
import { execFileSync } from "node:child_process";

export const EXPECTED_ACCOUNT = "91b59577e757131d68d55a471fe32aca";
export const EXPECTED_WORKER = "clawsweeper-status";
export const PRODUCTION_HEALTH = "https://clawsweeper.openclaw.ai/api/health";
export const FALLBACK_HEALTH = "https://clawsweeper-status.services-91b.workers.dev/api/health";
const API = "https://api.cloudflare.com/client/v4";
const shaPattern = /^[a-f0-9]{40}$/;
const uuidPattern = /^[a-f0-9-]{36}$/i;

export function validateDeployment(deployments) {
  const rows = deployments?.result?.deployments;
  if (!deployments?.success || !Array.isArray(rows) || !rows.length) {
    throw Error("provider_deployments_unavailable");
  }
  // Cloudflare documents the first deployment as the currently active one.
  const current = rows[0];
  if (!uuidPattern.test(current?.id||"") || !Array.isArray(current?.versions)) {
    throw Error("provider_deployments_invalid");
  }
  const live = current.versions.filter(x=>x?.percentage>0);
  if (live.length!==1 || live[0]?.percentage!==100 || !uuidPattern.test(live[0]?.version_id||"")) {
    throw Error("gradual_or_uncertain_deployment");
  }
  return {deploymentId:current.id,versionId:live[0].version_id,createdAt:current.created_on};
}

export function verifySignedSourceAttestation(
  receipt,
  keyHex,
  expectedSource,
  versionId,
  providerScriptEtag,
  deploymentId,
) {
  if (!receipt || !/^[a-f0-9]{64,128}$/i.test(keyHex||"")) throw Error("owner_receipt_missing");
  const claims = receipt.claims;
  if (!claims || claims.schema!=="clawsweeper-production-source/v1" ||
    claims.account_id!==EXPECTED_ACCOUNT || claims.script_name!==EXPECTED_WORKER ||
    claims.source_sha!==expectedSource || claims.version_id!==versionId ||
    claims.deployment_id!==deploymentId ||
    typeof claims.bundle_sha256!=="string" || !/^[a-f0-9]{64}$/.test(claims.bundle_sha256) ||
    !providerScriptEtag || claims.provider_script_etag!==providerScriptEtag
  ) throw Error("owner_receipt_claim_mismatch");
  if (!/^[a-f0-9]{64}$/i.test(receipt.signature||"")) throw Error("owner_receipt_signature_invalid");
  const expected=crypto.createHmac("sha256",Buffer.from(keyHex,"hex")).update(JSON.stringify(claims)).digest();
  const provided=Buffer.from(receipt.signature,"hex");
  if (expected.length!==provided.length || !crypto.timingSafeEqual(expected,provided))
    throw Error("owner_receipt_signature_invalid");
  return {sourceSha:claims.source_sha,bundleSha256:claims.bundle_sha256,
    versionId:claims.version_id,providerScriptEtag:claims.provider_script_etag,
    provenance:"owner-HMAC validated and Cloudflare version metadata matched"};
}

export async function checkProductionTracing(opts={}) {
  const expectedSource=opts.expectedSource;
  const problems=[];
  if (!shaPattern.test(expectedSource||""))throw Error("missing_exact_expected_source_sha");
  const transport=opts.transport||fetch;
  const safeGet=async (url,headers={})=>{
    const controller=new AbortController();
    const timeout=setTimeout(()=>controller.abort(),8000);
    try{
      const response=await transport(url,{method:"GET",headers,signal:controller.signal,redirect:"error"});
      if (!response.ok)throw Error("http_"+response.status);
      const body=await response.text();
      if(body.length>131072)throw Error("overlarge_provider_response");
      return JSON.parse(body);
    }finally{clearTimeout(timeout)}
  };
  const healths=[];
  for (const url of [PRODUCTION_HEALTH,FALLBACK_HEALTH]){
    try{
      const health=await safeGet(url);
      const claim=health?.deployment_sha;
      if(health?.ok!==true||health?.service!==EXPECTED_WORKER||!shaPattern.test(claim||""))
        problems.push("health_invalid");
      else if(claim!==expectedSource)problems.push("live_source_sha_mismatch");
      healths.push({url,service:health?.service||null,deploymentSha:typeof claim==="string"?claim:null});
    }catch(error){problems.push("health_readback_failed");healths.push({url,error:String(error?.message||"unknown").slice(0,90)})}
  }
  if(healths.length===2&&healths[0].deploymentSha&&healths[1].deploymentSha&&healths[0].deploymentSha!==healths[1].deploymentSha)
    problems.push("public_domain_source_mismatch");
  const token=opts.apiToken||"";
  let provider=null;
  if (!token)problems.push("correct_account_api_credential_missing");
  else{
    try{
      const headers={Authorization:"Bearer "+token,Accept:"application/json"};
      const list=await safeGet(`${API}/accounts/${EXPECTED_ACCOUNT}/workers/scripts/${EXPECTED_WORKER}/deployments?per_page=3`,headers);
      const current=validateDeployment(list);
      const version=await safeGet(`${API}/accounts/${EXPECTED_ACCOUNT}/workers/scripts/${EXPECTED_WORKER}/versions/${current.versionId}`,headers);
      const etag=version?.result?.resources?.script?.etag;
      if(!version.success || version.result?.id!==current.versionId || typeof etag!=="string"||!etag){
        throw Error("provider_version_details_missing");
      }
      provider={accountId:EXPECTED_ACCOUNT,workerName:EXPECTED_WORKER,...current,
        scriptEtag:etag,versionUploadSource:version?.result?.metadata?.source||null};
    }catch(error){problems.push("provider_readback_failed");provider={error:String(error?.message||"unknown").slice(0,120)}}
  }
  let attestation=null;
  if(!opts.signedReceipt||!opts.receiptKey)problems.push("trusted_source_bundle_receipt_missing");
  else if(provider?.versionId&&provider.scriptEtag){
    try{attestation=verifySignedSourceAttestation(opts.signedReceipt,opts.receiptKey,
      expectedSource,provider.versionId,provider.scriptEtag,provider.deploymentId)}
    catch(error){problems.push(String(error?.message||"owner_receipt_validation_failed"))}
  }
  const state=problems.length?"HOLD":"PROVIDER_SOURCE_VERIFIED";
  return {schema:"clawsweeper-source-deployment-gate/v1",checkedAt:new Date().toISOString(),
    state,expectedSource,healths,provider,attestation,
    problems:[...new Set(problems)],
    caution:"Read-only identity and provenance gate only; does not independently establish a sampled runtime trace or authorise activation."};
}

const isEntry=process.argv[1]&&path.resolve(process.argv[1])===fileURLToPath(import.meta.url);
if(isEntry){
  const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),"..");
  const expectedSource=process.env.CLAWSWEEPER_EXPECTED_SOURCE_SHA||
    execFileSync("git",["-C",root,"rev-parse","HEAD"],{encoding:"utf8"}).trim();
  const file=process.env.CLAWSWEEPER_DEPLOY_SOURCE_RECEIPT;
  let signedReceipt=null;
  if(file){try{signedReceipt=JSON.parse(fs.readFileSync(file,"utf8"))}catch{ /* fail closed */}}
  const result=await checkProductionTracing({
    expectedSource,apiToken:process.env.OPENCLAW_CLOUDFLARE_API_TOKEN,
    signedReceipt,receiptKey:process.env.CLAWSWEEPER_DEPLOY_SOURCE_RECEIPT_KEY_HEX,
  });
  const out=process.env.CLAWSWEEPER_TRACE_GATE_OUTPUT||
    path.join(root,".tracing-admission-readback.json");
  fs.writeFileSync(out,JSON.stringify(result,null,2)+"\n",{mode:0o600});
  console.log(JSON.stringify({state:result.state,expectedSource:result.expectedSource,
    problems:result.problems,healths:result.healths,provider:result.provider,
    evidencePath:out},null,2));
  if(result.state!=="PROVIDER_SOURCE_VERIFIED")process.exitCode=2;
}
