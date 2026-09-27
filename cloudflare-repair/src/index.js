import { getSandbox } from '@cloudflare/sandbox';
export { Sandbox } from '@cloudflare/sandbox';

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (url.pathname === '/health' && request.method === 'GET') {
      return Response.json({service:'clawsweeper-compute', repairEnabled:false});
    }
    if (!env.PROBE_TOKEN || request.headers.get('Authorization') !== `Bearer ${env.PROBE_TOKEN}`) {
      return new Response('Unauthorized', {status:401});
    }
    if (url.pathname === '/runner' && request.method === 'DELETE') {
      const body = await request.json();
      if (!/^csw-[a-f0-9]{16}-(plan|execute)$/.test(body.name ?? '')) return new Response('Invalid request', {status:400});
      await getSandbox(env.Sandbox, body.name).destroy();
      return Response.json({stopped:true});
    }
    if (url.pathname === '/runner-progress' && request.method === 'POST') {
      const body = await request.json();
      if (!/^csw-[a-f0-9]{16}-(plan|execute)$/.test(body.name ?? '')) return new Response('Invalid request', {status:400});
      const runner = getSandbox(env.Sandbox, body.name, {sleepAfter:'3h'});
      const result = await runner.exec("python3 -c 'import glob,json,os,time\nrows=[]\nfor p in glob.glob('\"'\"'/opt/actions-runner/_work/clawsweeper/clawsweeper/.clawsweeper-repair/runs/*/fix-execution/*'\"'\"')[:80]:\n if not os.path.isfile(p) or not p.endswith(('\"'\"'.jsonl'\"'\"','\"'\"'.stderr.log'\"'\"')): continue\n stat=os.stat(p)\n row={'\"'\"'file'\"'\"':os.path.basename(p),'\"'\"'bytes'\"'\"':stat.st_size,'\"'\"'ageSeconds'\"'\"':round(time.time()-stat.st_mtime)}\n with open(p,'\"'\"'rb'\"'\"') as f:\n  f.seek(max(0,stat.st_size-65536)); tail=f.read(65536).decode('\"'\"'utf-8'\"'\"','\"'\"'replace'\"'\"')\n if p.endswith('\"'\"'.jsonl'\"'\"'):\n  events=[]\n  for line in tail.splitlines()[-30:]:\n   try:\n    e=json.loads(line); t=e.get('\"'\"'type'\"'\"','\"'\"''\"'\"'); item=e.get('\"'\"'item'\"'\"',{}).get('\"'\"'type'\"'\"','\"'\"''\"'\"')\n    if t in ['\"'\"'thread.started'\"'\"','\"'\"'turn.started'\"'\"','\"'\"'turn.completed'\"'\"','\"'\"'turn.failed'\"'\"','\"'\"'item.started'\"'\"','\"'\"'item.completed'\"'\"','\"'\"'error'\"'\"']: events.append({'\"'\"'type'\"'\"':t,'\"'\"'itemType'\"'\"':item if item in ['\"'\"'command_execution'\"'\"','\"'\"'agent_message'\"'\"','\"'\"'reasoning'\"'\"','\"'\"'file_change'\"'\"','\"'\"'mcp_tool_call'\"'\"','\"'\"'web_search'\"'\"','\"'\"'todo_list'\"'\"','\"'\"'error'\"'\"'] else '\"'\"'other'\"'\"'})\n   except Exception: pass\n  row['\"'\"'events'\"'\"']=events[-8:]\n row['\"'\"'usageLimitSignal'\"'\"']='\"'\"'usage limit'\"'\"' in tail.lower() or '\"'\"'usage_limit_reached'\"'\"' in tail.lower()\n row['\"'\"'authErrorSignal'\"'\"']='\"'\"'unauthorized'\"'\"' in tail.lower() or '\"'\"'401 unauthorized'\"'\"' in tail.lower()\n row['\"'\"'networkErrorSignal'\"'\"']='\"'\"'connection refused'\"'\"' in tail.lower() or '\"'\"'stream disconnected'\"'\"' in tail.lower()\n rows.append(row)\nprocesses=[]\nfor p in glob.glob('\"'\"'/proc/[0-9]*/stat'\"'\"'):\n try:\n  raw=open(p).read(); a=raw.index('\"'\"'('\"'\"'); b=raw.rindex('\"'\"')'\"'\"'); fields=raw[b+2:].split(); name=raw[a+1:b]\n  if name in ['\"'\"'node'\"'\"','\"'\"'npm'\"'\"','\"'\"'pnpm'\"'\"','\"'\"'git'\"'\"','\"'\"'codex'\"'\"','\"'\"'bun'\"'\"','\"'\"'python3'\"'\"','\"'\"'bash'\"'\"','\"'\"'curl'\"'\"','\"'\"'bwrap'\"'\"','\"'\"'unshare'\"'\"','\"'\"'trufflehog'\"'\"']:\n   processes.append({'\"'\"'name'\"'\"':name,'\"'\"'state'\"'\"':fields[0],'\"'\"'cpuTicks'\"'\"':int(fields[11])+int(fields[12])})\n except Exception: pass\nprint(json.dumps({'\"'\"'files'\"'\"':rows,'\"'\"'processes'\"'\"':processes[:60]}))\n'", {timeout:15000});
      return Response.json({exitCode:result.exitCode, progress:result.stdout});
    }
    if (url.pathname === '/runner-status' && request.method === 'POST') {
      const body = await request.json();
      if (!/^csw-[a-f0-9]{16}-(plan|execute)$/.test(body.name ?? '')) return new Response('Invalid request', {status:400});
      const runner = getSandbox(env.Sandbox, body.name, {sleepAfter:'3h'});
      const logs = await runner.exec('tail -c 4000 /tmp/runner.log 2>/dev/null || true');
      return Response.json({stdout:logs.stdout, stderr:logs.stderr});
    }
    if (url.pathname === '/runner' && request.method === 'POST') {
      const body = await request.json();
      if (!/^csw-[a-f0-9]{16}-(plan|execute)$/.test(body.name ?? '') || !/^[A-Za-z0-9+/=]{100,50000}$/.test(body.jit ?? '')) return new Response('Invalid request', {status:400});
      const runner = getSandbox(env.Sandbox, body.name, {sleepAfter:'3h'});
      const tools = await runner.exec('command -v gh && command -v rg && command -v bwrap');
      if (tools.exitCode !== 0) return Response.json({error:'Container repair tools are not ready'}, {status:503});
      await runner.writeFile('/tmp/runner-jit', body.jit);
      await runner.startProcess('/opt/start-runner.sh', {processId:'github-runner',autoCleanup:false});
      return Response.json({started:true,name:body.name});
    }
    if (url.pathname !== '/probe' || request.method !== 'POST') {
      return new Response('Not found', {status:404});
    }
    const sandbox = getSandbox(env.Sandbox, 'capability-proof', {sleepAfter:'2m'});
    try {
      const result = await sandbox.exec('node /opt/clawsweeper/dist/repair/containment-preflight.js', {timeout:60000});
      return Response.json({exitCode:result.exitCode, stdout:result.stdout, stderr:result.stderr, repairEnabled:false});
    } finally {
      await sandbox.destroy();
    }
  }
};
