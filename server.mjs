import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import * as E from './engine.mjs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const cfg = E.getConfig();
const PORT = cfg.port || 8787;
const clients = new Set();

E.setEmitter((type, data) => {
  const msg = `data: ${JSON.stringify({ type, ...data })}\n\n`;
  for (const c of clients) { try { c.write(msg); } catch(e){} }
});

const MIME = { '.html':'text/html', '.js':'text/javascript', '.css':'text/css' };

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, 'http://x');
  const p = url.pathname;

  if (p === '/api/events') {
    res.writeHead(200, { 'Content-Type':'text/event-stream', 'Cache-Control':'no-cache', 'Connection':'keep-alive' });
    res.write(`data: ${JSON.stringify({type:'state', ...E.getState()})}\n\n`);
    clients.add(res);
    req.on('close', () => clients.delete(res));
    return;
  }

  const json = (o, code=200) => { res.writeHead(code, {'Content-Type':'application/json'}); res.end(JSON.stringify(o)); };
  const body = () => new Promise(r => { let b=''; req.on('data', c => b+=c); req.on('end', () => { try { r(JSON.parse(b||'{}')); } catch(e){ r({}); } }); });

  if (p === '/api/state') return json(E.getState());
  if (p === '/api/config' && req.method === 'GET') return json(E.getConfig());
  if (p === '/api/config' && req.method === 'POST') return json(E.saveConfig(await body()));
  if (p === '/api/start' && req.method === 'POST') { E.startScan(await body()); return json({ok:true}); }
  if (p === '/api/stop' && req.method === 'POST') { E.stopScan(); return json({ok:true}); }
  if (p === '/api/bloom' && req.method === 'POST') { const b = await body(); E.buildBloom(b.file); return json({ok:true}); }
  if (p === '/api/bloom/load' && req.method === 'POST') { E.loadBloom(); return json({ok:true}); }

  let file = p === '/' ? '/public/index.html' : p;
  const fp = path.join(__dirname, file);
  if (fs.existsSync(fp) && fs.statSync(fp).isFile()) {
    res.writeHead(200, { 'Content-Type': MIME[path.extname(fp)] || 'application/octet-stream' });
    return fs.createReadStream(fp).pipe(res);
  }
  res.writeHead(404); res.end('404');
});

E.loadBloom();
server.listen(PORT, () => {
  console.log('');
  console.log('  ======================================');
  console.log('   BTC OMEGA AGENT - DASHBOARD');
  console.log('   http://localhost:' + PORT);
  console.log('  ======================================');
  console.log('');
});