import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import {execFileSync} from "node:child_process";
import {
 checkProductionTracing,EXPECTED_ACCOUNT,EXPECTED_WORKER,
 validateDeployment,verifySignedSourceAttestation,
} from "../scripts/verify-native-trace-admission.mjs";

const DEPLOY="bd34742b-9fee-4e8c-a84f-917d5fdc8323";
const VERSION="a450a008-cfcf-431b-b6ab-4f182e9d84a9";
const ETAG="provider-generated-script-etag-example";
const KEY="a9".repeat(32);
const KNOWN_OLD_SHA="2ea8790a6c7c455a7f0291857337d58840d0464f";
const md5="0000000000000000000000000000000000000000";

type Fixture={
 root:string;sha:string;bundle:Buffer;config:string;wrangler:string;
 dispose:()=>void;
};
function repoFixture(options:{scriptName?:string;redact?:boolean;tracingEnabled?:boolean}={}):Fixture {
 const top=fs.mkdtempSync(path.join(os.tmpdir(),"clawsweeper-source-proof-"));
 const root=path.join(top,"source");fs.mkdirSync(root);
 fs.mkdirSync(path.join(root,"dashboard"));
 const source='export default {fetch:()=>new Response("verified-source-fixture")};\n';
 fs.writeFileSync(path.join(root,"worker.ts"),source);
 const config=path.join(root,"dashboard/wrangler.toml");
 fs.writeFileSync(config,`name = "${options.scriptName??"clawsweeper-status"}"\nmain = "../worker.ts"\n[observability]\nredact_query_string = ${options.redact===false?"false":"true"}\n[observability.traces]\nenabled = ${options.tracingEnabled?"true":"false"}\n`);
 execFileSync("git",["-C",root,"init","-q"]);
 execFileSync("git",["-C",root,"add","-A"]);
 execFileSync("git",["-C",root,"-c","commit.gpgsign=false","-c","user.name=Test","-c","user.email=fixture@example.test","commit","-qm","unsigned-isolated-test-repository"]);
 const sha=execFileSync("git",["-C",root,"rev-parse","HEAD"],{encoding:"utf8"}).trim();
 const wrangler=path.join(top,"wrangler-fixture");
 fs.writeFileSync(wrangler,`#!/usr/bin/env node
const fs=require("node:fs"),path=require("node:path");
if(process.argv.includes("--version")){console.log("wrangler 4.151.2");process.exit(0);}
const args=process.argv.slice(2);
if(!args.includes("--dry-run")||!args.includes("--outdir"))process.exit(2);
const output=args[args.indexOf("--outdir")+1];
fs.mkdirSync(output,{recursive:true});
fs.writeFileSync(path.join(output,"worker.js"),fs.readFileSync(path.join(process.cwd(),"worker.ts")));
`, {mode:0o700});
 return {root,sha,bundle:Buffer.from(source),config,wrangler,dispose:()=>fs.rmSync(top,{recursive:true,force:true})};
}

const metadata=()=>({
 success:true,result:{deployments:[{id:DEPLOY,created_on:"2026-11-08T09:00:00Z",
  versions:[{percentage:100,version_id:VERSION}]}]},
});
const version=()=>({success:true,result:{id:VERSION,resources:{script:{etag:ETAG}},
 metadata:{source:"wrangler"}}});
function receipt(sha:string,bundle:Buffer,config:string,options={}) {
 const claims={
  schema:"clawsweeper-production-source/v1",
  account_id:EXPECTED_ACCOUNT,script_name:EXPECTED_WORKER,
  source_sha:sha,deployment_id:DEPLOY,version_id:VERSION,
  provider_script_etag:ETAG,
  bundle_sha256:crypto.createHash("sha256").update(bundle).digest("hex"),
  production_config_sha256:crypto.createHash("sha256").update(fs.readFileSync(config)).digest("hex"),
  wrangler_version:"4.151.2",...options,
 };
 return {claims,signature:crypto.createHmac("sha256",Buffer.from(KEY,"hex")).update(JSON.stringify(claims)).digest("hex")};
}
function wire(sha:string,bytes:Buffer,opt:{
 before?:unknown;after?:unknown;beforeVersion?:unknown;afterVersion?:unknown;
 contentType?:string;contentEtag?:string; content?:Buffer;
}={}) {
 const calls:string[]=[];
 let dc=0,vc=0;
 const transport=async(url:string)=>{
  calls.push(url);
  if(url.includes("/deployments?"))return Response.json((++dc>1?opt.after:opt.before)??metadata());
  if(url.includes("/versions/"))return Response.json((++vc>1?opt.afterVersion:opt.beforeVersion)??version());
  if(url.includes("/content/v2")){
   return new Response(opt.content??bytes,{status:200,headers:{
    "content-type":opt.contentType??"application/javascript",
    "etag":opt.contentEtag??ETAG}});
  }
  return Response.json({ok:true,service:EXPECTED_WORKER,deployment_sha:sha});
 };
 return {transport,calls};
}

test("active Worker versions with split traffic are refused",()=>{
 const split=metadata();
 split.result.deployments[0].versions=[
  {percentage:50,version_id:VERSION},
  {percentage:50,version_id:"e8206590-a4f1-4994-b245-e32bc5c59e82"}];
 assert.throws(()=>validateDeployment(split),/gradual_or_uncertain_deployment/);
});

test("missing correct-account credential fails closed even with agreeing health endpoints",async()=>{
 const {transport,calls}=wire(KNOWN_OLD_SHA,Buffer.from("fixture"));
 const result=await checkProductionTracing({expectedSource:KNOWN_OLD_SHA,transport});
 assert.equal(result.state,"HOLD");
 assert.ok(result.problems.includes("correct_account_api_credential_missing"));
 assert.ok(result.problems.includes("trusted_source_bundle_receipt_missing"));
 assert.equal(calls.length,2);
});

test("old live production SHA never passes candidate source admission",async()=>{
 const {transport}=wire(KNOWN_OLD_SHA,Buffer.from("fixture"));
 const result=await checkProductionTracing({expectedSource:md5,transport});
 assert.equal(result.state,"HOLD");
 assert.ok(result.problems.includes("live_source_sha_mismatch"));
});

test("an owner-signed arbitrary hash cannot authenticate provider bytes",async()=>{
 const f=repoFixture();
 try{
  const {transport}=wire(f.sha,f.bundle);
  const forged=receipt(f.sha,f.bundle,f.config,{bundle_sha256:"f".repeat(64)});
  const result=await checkProductionTracing({
   expectedSource:f.sha,apiToken:"SYNTHETIC_TOKEN",signedReceipt:forged,receiptKey:KEY,
   sourceRoot:f.root,productionConfigFile:f.config,wranglerExecutable:f.wrangler,transport,
  });
  assert.equal(result.state,"HOLD");
  assert.ok(result.problems.includes("owner_receipt_claim_mismatch"));
  assert.equal(result.attestation,null);
 }finally{f.dispose()}
});

test("synthetic provider byte readback and two independent dry-runs are bound to one version",async()=>{
 const f=repoFixture();
 try{
  const {transport,calls}=wire(f.sha,f.bundle);
  const result=await checkProductionTracing({
   expectedSource:f.sha,apiToken:"SYNTHETIC_TOKEN",signedReceipt:receipt(f.sha,f.bundle,f.config),receiptKey:KEY,
   sourceRoot:f.root,productionConfigFile:f.config,wranglerExecutable:f.wrangler,transport,
  });
  assert.equal(result.state,"PROVIDER_SOURCE_VERIFIED",JSON.stringify(result.problems));
  assert.equal(result.provider.accountId,EXPECTED_ACCOUNT);
  assert.equal(result.provider.workerName,EXPECTED_WORKER);
  assert.equal(result.provider.versionId,VERSION);
  assert.equal(result.provider.deploymentId,DEPLOY);
  assert.equal(result.attestation.sourceBytesVerified,true);
  assert.equal(result.attestation.wranglerVersion,"4.151.2");
  assert.equal(calls.length,7);
  assert.equal(calls.filter(x=>x.includes("/content/v2")).length,1);
  assert.ok(!JSON.stringify(result).includes("SYNTHETIC_TOKEN"));
  assert.ok(!JSON.stringify(result).includes(KEY));
 }finally{f.dispose()}
});

test("provider bytes differing from the independently reproducible source fail closed",async()=>{
 const f=repoFixture();
 try{
  const {transport}=wire(f.sha,f.bundle,{content:Buffer.from("evil-unrelated-provider-content")});
  const result=await checkProductionTracing({
   expectedSource:f.sha,apiToken:"SYNTHETIC_TOKEN",signedReceipt:receipt(f.sha,f.bundle,f.config),receiptKey:KEY,
   sourceRoot:f.root,productionConfigFile:f.config,wranglerExecutable:f.wrangler,transport,
  });
  assert.equal(result.state,"HOLD");
  assert.ok(result.problems.includes("provider_content_digest_mismatch"));
 }finally{f.dispose()}
});

test("multipart content cannot be falsely treated as a verified single-script bundle",async()=>{
 const f=repoFixture();
 try{
  const {transport}=wire(f.sha,f.bundle,{contentType:"multipart/form-data"});
  const result=await checkProductionTracing({
   expectedSource:f.sha,apiToken:"SYNTHETIC_TOKEN",signedReceipt:receipt(f.sha,f.bundle,f.config),receiptKey:KEY,
   sourceRoot:f.root,productionConfigFile:f.config,wranglerExecutable:f.wrangler,transport,
  });
  assert.equal(result.state,"HOLD");
  assert.ok(result.problems.includes("provider_content_format_unverifiable"));
 }finally{f.dispose()}
});

test("version/etag race across provider-byte download is rejected",async()=>{
 const f=repoFixture();
 try{
  const altered=metadata();altered.result.deployments[0].id="12345678-1234-4234-a234-123456789abc";
  const {transport}=wire(f.sha,f.bundle,{after:altered});
  const result=await checkProductionTracing({
   expectedSource:f.sha,apiToken:"SYNTHETIC_TOKEN",signedReceipt:receipt(f.sha,f.bundle,f.config),receiptKey:KEY,
   sourceRoot:f.root,productionConfigFile:f.config,wranglerExecutable:f.wrangler,transport,
  });
  assert.equal(result.state,"HOLD");
  assert.ok(result.problems.includes("provider_version_changed_during_readback"));
 }finally{f.dispose()}
});

test("wrong script ETag cannot be substituted for metadata version etag",async()=>{
 const f=repoFixture();
 try{
  const {transport}=wire(f.sha,f.bundle,{contentEtag:"unrelated-bundle-etag"});
  const result=await checkProductionTracing({
   expectedSource:f.sha,apiToken:"SYNTHETIC_TOKEN",signedReceipt:receipt(f.sha,f.bundle,f.config),receiptKey:KEY,
   sourceRoot:f.root,productionConfigFile:f.config,wranglerExecutable:f.wrangler,transport,
  });
  assert.equal(result.state,"HOLD");
  assert.ok(result.problems.includes("provider_content_etag_version_mismatch"));
 }finally{f.dispose()}
});

test("incorrect production identity or tracing-enabled configuration fail closed",async()=>{
 const f=repoFixture();
 try{
  const production=path.join(f.root,"dashboard/wrangler.toml");
  fs.writeFileSync(production,'name = "ayobamih-clawsweeper-status"\n[observability]\nredact_query_string = true\n[observability.traces]\nenabled = false\n');
  const {transport}=wire(f.sha,f.bundle);
  const result=await checkProductionTracing({
   expectedSource:f.sha,apiToken:"SYNTHETIC_TOKEN",signedReceipt:receipt(f.sha,f.bundle,f.config),receiptKey:KEY,
   sourceRoot:f.root,productionConfigFile:f.config,wranglerExecutable:f.wrangler,transport,
  });
  assert.equal(result.state,"HOLD");
  assert.ok(result.problems.includes("source_checkout_not_clean")||result.problems.includes("worker_configuration_identity_mismatch"));
 }finally{f.dispose()}
});

test("missing signed receipt cannot become approved even with valid provider metadata",async()=>{
 const f=repoFixture();
 try{
  const {transport,calls}=wire(f.sha,f.bundle);
  const result=await checkProductionTracing({expectedSource:f.sha,apiToken:"SYNTHETIC_TOKEN",transport});
  assert.equal(result.state,"HOLD");
  assert.ok(result.problems.includes("trusted_source_bundle_receipt_missing"));
  assert.equal(calls.filter(x=>x.includes("/content/v2")).length,0);
 }finally{f.dispose()}
});

test("tampered version, SHA or owner signature are refused",()=>{
 const f=repoFixture();try{
  const actual=crypto.createHash("sha256").update(f.bundle).digest("hex");
  const bundle={sourceRevision:f.sha,bundleSha256:actual,providerContentSha256:actual,
   independentlyHashedProviderContent:true,twoIndependentLocalBuilds:true,wranglerDryRunsVerified:true,
   verifiedIdentity:EXPECTED_WORKER,configSha256:crypto.createHash("sha256").update(fs.readFileSync(f.config)).digest("hex"),wranglerVersion:"4.151.2"};
  const valid=receipt(f.sha,f.bundle,f.config);
  assert.ok(verifySignedSourceAttestation(valid,KEY,f.sha,VERSION,ETAG,DEPLOY,bundle));
  assert.throws(()=>verifySignedSourceAttestation({...valid,signature:"0".repeat(64)},KEY,f.sha,VERSION,ETAG,DEPLOY,bundle),/owner_receipt_signature_invalid/);
  assert.throws(()=>verifySignedSourceAttestation(valid,KEY,f.sha,VERSION,"WRONG",DEPLOY,bundle),/owner_receipt_claim_mismatch/);
  assert.throws(()=>verifySignedSourceAttestation(valid,KEY,f.sha,VERSION,ETAG,"WRONG",bundle),/owner_receipt_claim_mismatch/);
 }finally{f.dispose()}
});

test("the actual separate Ayobami Worker name cannot be substituted for the OpenClaw Worker",async()=>{
 const f=repoFixture({scriptName:"ayobamih-clawsweeper-status"});
 try{
  const {transport}=wire(f.sha,f.bundle);
  const result=await checkProductionTracing({
   expectedSource:f.sha,apiToken:"SYNTHETIC_TOKEN",
   signedReceipt:receipt(f.sha,f.bundle,f.config),receiptKey:KEY,
   sourceRoot:f.root,productionConfigFile:f.config,wranglerExecutable:f.wrangler,transport,
  });
  assert.equal(result.state,"HOLD");
  assert.ok(result.problems.includes("worker_configuration_identity_mismatch"));
 }finally{f.dispose()}
});

test("a clean config lacking query redaction fails source provenance",async()=>{
 const f=repoFixture({redact:false});
 try{
  const {transport}=wire(f.sha,f.bundle);
  const result=await checkProductionTracing({
   expectedSource:f.sha,apiToken:"SYNTHETIC_TOKEN",
   signedReceipt:receipt(f.sha,f.bundle,f.config),receiptKey:KEY,
   sourceRoot:f.root,productionConfigFile:f.config,wranglerExecutable:f.wrangler,transport,
  });
  assert.equal(result.state,"HOLD");
  assert.ok(result.problems.includes("production_query_redaction_missing"));
 }finally{f.dispose()}
});

test("a clean Worker config that already enables tracing fails release admission",async()=>{
 const f=repoFixture({tracingEnabled:true});
 try{
  const {transport}=wire(f.sha,f.bundle);
  const result=await checkProductionTracing({
   expectedSource:f.sha,apiToken:"SYNTHETIC_TOKEN",
   signedReceipt:receipt(f.sha,f.bundle,f.config),receiptKey:KEY,
   sourceRoot:f.root,productionConfigFile:f.config,wranglerExecutable:f.wrangler,transport,
  });
  assert.equal(result.state,"HOLD");
  assert.ok(result.problems.includes("production_tracing_must_remain_disabled"));
 }finally{f.dispose()}
});

test("caller-supplied verifier cannot bypass independent content hashing", async()=>{
 const f=repoFixture();
 try{
  const {transport}=wire(f.sha,f.bundle,{content:Buffer.from("provider-bytes-do-not-match-clean-source")});
  let injectedCalls=0;
  const actual=await checkProductionTracing({
   expectedSource:f.sha,apiToken:"SYNTHETIC_TOKEN",
   signedReceipt:receipt(f.sha,f.bundle,f.config),receiptKey:KEY,
   sourceRoot:f.root,productionConfigFile:f.config,wranglerExecutable:f.wrangler,
   transport,
   buildVerifier:()=>{injectedCalls++;return {independentlyHashedProviderContent:true}},
  });
  assert.equal(actual.state,"HOLD");
  assert.ok(actual.problems.includes("provider_content_digest_mismatch"));
  assert.equal(injectedCalls,0);
 }finally{f.dispose()}
});

test("Wrangler 4.107.0 cannot attest redaction it ignores at runtime",async()=>{
 const f=repoFixture();
 try{
  const legacy=fs.readFileSync(f.wrangler,"utf8").replace("wrangler 4.151.2","wrangler 4.107.0");
  fs.writeFileSync(f.wrangler,legacy,{mode:0o700});
  const {transport}=wire(f.sha,f.bundle);
  const report=await checkProductionTracing({
   expectedSource:f.sha,apiToken:"SYNTHETIC_TOKEN",
   signedReceipt:receipt(f.sha,f.bundle,f.config),receiptKey:KEY,
   sourceRoot:f.root,productionConfigFile:f.config,wranglerExecutable:f.wrangler,transport,
  });
  assert.equal(report.state,"HOLD");
  assert.ok(report.problems.includes("unpinned_wrangler_version"));
  assert.equal(report.attestation,null);
 }finally{f.dispose()}
});
