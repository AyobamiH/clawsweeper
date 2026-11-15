#!/usr/bin/env node
// Trusted release launcher must independently pin this builtins-only bootstrap
// and exact signed source. Verification runs BEFORE any application import.
import {createHash} from "node:crypto";
import {execFileSync} from "node:child_process";
import {lstatSync,readFileSync,realpathSync} from "node:fs";
import {isBuiltin} from "node:module";
import {dirname,isAbsolute,join,relative,resolve,sep} from "node:path";
import {fileURLToPath,pathToFileURL} from "node:url";
const root=resolve(dirname(fileURLToPath(import.meta.url)),"../..");
const roots=["ci-triage-runtime","ci-triage-evidence","ci-triage-ledger","ci-triage",
"notify-github-activity","observe-ci-triage","openclaw-hook"].map(n=>"dist/repair/"+n+".js");
function fail(reason){throw new Error("preimport_"+reason);}
const importRe=/^\s*import\s+(?:(?:[A-Za-z0-9_$*{},\s]+)\s+from\s+)?["']([^"']+)["']\s*;\s*$/;
const exportRe=/^\s*export\s+(?:\*|\*\s+as\s+[A-Za-z_$][\w$]*|\{[^}]*\})\s+from\s+["']([^"']+)["']\s*;\s*$/;
function imports(code){
 if(/\bimport(?:\s|\/\*[\s\S]{0,64}?\*\/)*\(/.test(code)||/\bcreateRequire\s*\(/.test(code))fail("dynamic_import");
 const out=[];
 for(const line of code.split("\n")){
  if(/^\s*import\s+/.test(line)){
   const m=importRe.exec(line);if(!m?.[1]){fail("import");}out.push(m[1]);
  }else if(/^\s*export\s+(?:\*|\{)/.test(line)){
   const m=exportRe.exec(line);
   if(m?.[1])out.push(m[1]);
   else if(!/^\s*export\s+\{[^}]*\}\s*;\s*$/.test(line))fail("export");
  }
 }
 return out;
}
function hashes(){
 const dist=join(root,"dist"),pending=[...roots],seen=new Set(),files={};
 while(pending.length){
  const name=pending.pop();if(seen.has(name))continue;
  if(seen.size>=96)fail("closure_limit");
  const full=resolve(root,name);
  if(!full.startsWith(dist+sep)||!name.endsWith(".js"))fail("path");
  const st=lstatSync(full);
  if(!st.isFile()||st.isSymbolicLink()||st.nlink!==1||st.size>1048576||realpathSync(full)!==full)fail("file");
  const data=readFileSync(full);
  files[name]=createHash("sha256").update(data).digest("hex");seen.add(name);
  for(const dep of imports(data.toString("utf8"))){
   if(dep.startsWith("node:")&&isBuiltin(dep))continue;
   if(!/^\.\.?\//.test(dep)||!dep.endsWith(".js"))fail("package");
   const next=resolve(dirname(full),dep);if(!next.startsWith(dist+sep))fail("traversal");
   const rel=relative(root,next).split(sep).join("/");if(!seen.has(rel))pending.push(rel);
  }
 }
 return Object.fromEntries(Object.entries(files).sort(([a],[b])=>a.localeCompare(b)));
}
function verify(){
 const sha=process.env.CLAWSWEEPER_CI_TRIAGE_SOURCE_SHA;
 const pin=process.env.CLAWSWEEPER_CI_TRIAGE_BOOTSTRAP_SHA256;
 const manifestPath=process.env.CLAWSWEEPER_CI_TRIAGE_RUNTIME_MANIFEST;
 if(!/^[a-f0-9]{40}$/.test(sha??"")||!/^[a-f0-9]{64}$/.test(pin??""))fail("pin_required");
 if(createHash("sha256").update(readFileSync(fileURLToPath(import.meta.url))).digest("hex")!==pin)fail("bootstrap_changed");
 if(!manifestPath||!isAbsolute(manifestPath))fail("manifest_required");
 const st=lstatSync(manifestPath);
 if(!st.isFile()||st.isSymbolicLink()||st.nlink!==1||st.size>16384||
    (st.mode&0o077)||realpathSync(manifestPath)!==resolve(manifestPath)||
    (process.getuid&&st.uid!==process.getuid()))fail("manifest_unsafe");
 const manifest=JSON.parse(readFileSync(manifestPath,"utf8"));
 const env={PATH:process.env.PATH,HOME:process.env.HOME,GIT_OPTIONAL_LOCKS:"0"};
 execFileSync("git",["-C",root,"diff","--quiet","HEAD","--"],{env,stdio:"pipe",timeout:5000});
 const current=execFileSync("git",["-C",root,"rev-parse","HEAD"],{env,encoding:"utf8",timeout:5000}).trim();
 if(current!==sha||manifest?.schema!=="clawsweeper.ci-triage-runtime.v2"||
    manifest?.implementationSha!==sha)fail("source_mismatch");
 if(!manifest.files||typeof manifest.files!=="object"||Array.isArray(manifest.files))fail("files");
 const actual=hashes(),names=Object.keys(actual);
 if(Object.keys(manifest.files).sort().join()!==names.join()||
    names.some(n=>actual[n]!==manifest.files[n]))fail("runtime_changed");
}
async function run(){
 const mode=process.argv[2];if(mode!=="observer"&&mode!=="notifier")fail("mode");
 verify();
 // No application dependencies are imported until every check above passed.
 const path=join(root,"dist/repair",mode==="observer"?"observe-ci-triage.js":"notify-github-activity.js");
 const app=await import(pathToFileURL(path).href);
 if(mode==="observer")await app.runCiTriageObserverCli(process.argv.slice(3));
 else await app.runCiTriageNotifierCli(process.argv.slice(3));
}
run().catch(e=>{const reason=/^preimport_[a-z_]+$/.test(e?.message??"")?e.message:"preimport_unavailable";
 console.error(JSON.stringify({state:"held",reason}));process.exitCode=1;});
