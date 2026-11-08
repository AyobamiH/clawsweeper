import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import {
  checkProductionTracing,
  EXPECTED_ACCOUNT,
  EXPECTED_WORKER,
  validateDeployment,
  verifySignedSourceAttestation,
} from "../scripts/verify-native-trace-admission.mjs";

const SOURCE = "03d32fb784758d2a3770aaa9721f1212ac061096";
const LIVE_STALE = "2ea8790a6c7c455a7f0291857337d58840d0464f";
const DEPLOY = "bd34742b-9fee-4e8c-a84f-917d5fdc8323";
const VERSION = "a450a008-cfcf-431b-b6ab-4f182e9d84a9";
const ETAG = "provider-generated-etag-example";
const KEY = "a9".repeat(32);

const health = (sha: string) => ({
  ok: true,
  service: EXPECTED_WORKER,
  deployment_sha: sha,
});

const apiDeployments = {
  success: true,
  result: {
    deployments: [{
      id: DEPLOY,
      created_on: "2026-11-08T09:00:00Z",
      versions: [{ percentage: 100, version_id: VERSION }],
    }],
  },
};
const apiVersion = {
  success: true,
  result: {
    id: VERSION,
    resources: {script: {etag: ETAG}},
    metadata: {source: "wrangler"},
  },
};

function fakeTransport(sha: string, options: {
  deployments?: unknown;
  version?: unknown;
} = {}) {
  const requests: Array<{ url: string; headers: object }> = [];
  const transport = async (url: string, init: { headers?: object }) => {
    requests.push({url,headers:init.headers||{}});
    const payload = url.includes("/deployments?")
      ? (options.deployments??apiDeployments)
      : url.includes("/versions/")
        ? (options.version??apiVersion)
        : health(sha);
    return new Response(JSON.stringify(payload), {
      status: 200,headers: {"content-type":"application/json"},
    });
  };
  return {transport, requests};
}

function signedReceipt() {
  const claims = {
    schema: "clawsweeper-production-source/v1",
    account_id: EXPECTED_ACCOUNT,
    script_name: EXPECTED_WORKER,
    source_sha: SOURCE,
    deployment_id: DEPLOY,
    version_id: VERSION,
    provider_script_etag: ETAG,
    bundle_sha256: "2c".repeat(32),
  };
  return {claims,signature:crypto.createHmac("sha256",Buffer.from(KEY,"hex"))
    .update(JSON.stringify(claims)).digest("hex")};
}

test("Cloudflare deployment readback rejects ambiguous 50/50 traffic split", () => {
  const split = JSON.parse(JSON.stringify(apiDeployments));
  split.result.deployments[0].versions = [
    {percentage:50,version_id:VERSION},
    {percentage:50,version_id:"e8206590-a4f1-4994-b245-e32bc5c59e82"},
  ];
  assert.throws(()=>validateDeployment(split),/gradual_or_uncertain_deployment/);
});

test("missing correct-account credential fails closed even when both health endpoints agree", async () => {
  const {transport,requests}=fakeTransport(SOURCE);
  const result=await checkProductionTracing({expectedSource:SOURCE,transport});
  assert.equal(result.state,"HOLD");
  assert.ok(result.problems.includes("correct_account_api_credential_missing"));
  assert.ok(result.problems.includes("trusted_source_bundle_receipt_missing"));
  assert.equal(requests.length,2);
  assert.equal(requests.every(x=>!x.url.includes("api.cloudflare.com")),true);
});

test("real observed stale production SHA is treated as mismatch, never as current source", async () => {
  const {transport}=fakeTransport(LIVE_STALE);
  const result=await checkProductionTracing({expectedSource:SOURCE,transport});
  assert.equal(result.state,"HOLD");
  assert.ok(result.problems.includes("live_source_sha_mismatch"));
  assert.ok(result.healths.every(x=>x.deploymentSha===LIVE_STALE));
});

test("signed owner bundle alone is insufficient when provider readback is absent", async () => {
  const {transport}=fakeTransport(SOURCE);
  const receipt=signedReceipt();
  const result=await checkProductionTracing({
    expectedSource:SOURCE,transport,signedReceipt:receipt,receiptKey:KEY,
  });
  assert.equal(result.state,"HOLD");
  assert.ok(result.problems.includes("correct_account_api_credential_missing"));
  assert.equal(result.attestation,null);
});

test("valid source-bound provider deployment, version, etag and signed receipt pass a read-only gate", async () => {
  const {transport,requests}=fakeTransport(SOURCE);
  const result=await checkProductionTracing({
    expectedSource:SOURCE,apiToken:"TEST_CLOUDFLARE_TOKEN_NOT_REAL",
    signedReceipt:signedReceipt(),receiptKey:KEY,transport,
  });
  assert.equal(result.state,"PROVIDER_SOURCE_VERIFIED");
  assert.equal(result.problems.length,0);
  assert.equal(result.provider.accountId,EXPECTED_ACCOUNT);
  assert.equal(result.provider.workerName,EXPECTED_WORKER);
  assert.equal(result.provider.versionId,VERSION);
  assert.equal(result.provider.deploymentId,DEPLOY);
  assert.equal(result.attestation.sourceSha,SOURCE);
  assert.equal(requests.length,4);
  assert.ok(requests.slice(2).every(x=>x.url.includes("/accounts/"+EXPECTED_ACCOUNT+"/workers/scripts/"+EXPECTED_WORKER+"/")));
  assert.ok(!JSON.stringify(result).includes("TEST_CLOUDFLARE_TOKEN_NOT_REAL"));
  assert.ok(!JSON.stringify(result).includes(KEY));
});

test("provider version and signed claim disagreements cannot be admitted", async () => {
  const receipt=signedReceipt();
  const tampered=structuredClone(receipt);
  tampered.claims.source_sha=LIVE_STALE;
  assert.throws(
    ()=>verifySignedSourceAttestation(tampered,KEY,SOURCE,VERSION,ETAG,DEPLOY),
    /owner_receipt_claim_mismatch/,
  );
  assert.throws(
    ()=>verifySignedSourceAttestation({...receipt,signature:"0".repeat(64)},KEY,SOURCE,VERSION,ETAG,DEPLOY),
    /owner_receipt_signature_invalid/,
  );
  assert.throws(
    ()=>verifySignedSourceAttestation(receipt,KEY,SOURCE,VERSION,"other-provider-etag",DEPLOY),
    /owner_receipt_claim_mismatch/,
  );
  assert.throws(
    ()=>verifySignedSourceAttestation(receipt,KEY,SOURCE,VERSION,ETAG,"wrong-deployment-id"),
    /owner_receipt_claim_mismatch/,
  );
});

test("unsigned or mismatched provider version results hold and do not leak token", async () => {
  const {transport}=fakeTransport(SOURCE,{version:{success:true,result:{id:VERSION,resources:{}}}});
  const result=await checkProductionTracing({
    expectedSource:SOURCE,apiToken:"READ_ONLY_FAKE_TOKEN",signedReceipt:signedReceipt(),
    receiptKey:KEY,transport,
  });
  assert.equal(result.state,"HOLD");
  assert.ok(result.problems.includes("provider_readback_failed"));
  assert.ok(!JSON.stringify(result).includes("READ_ONLY_FAKE_TOKEN"));
});
