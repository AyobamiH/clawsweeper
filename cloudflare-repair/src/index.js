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
