import { parentPort, workerData } from 'node:worker_threads';
import { randomBytes } from 'node:crypto';
import { secp256k1 } from '@noble/curves/secp256k1';
import { sha256, hash160, enc, MT19937, bip32Master, bip32Derive, big32, toHex } from './lib.mjs';

const { mode, start, end, base, count, sab, mask, k, words } = workerData;
const bloom = new Uint8Array(sab);

function hit(key) {
  if (key.length < 8) return false;
  const h1 = key.readUInt32LE(0);
  const h2 = key.readUInt32LE(4) | 1;
  for (let j = 0; j < k; j++) {
    const idx = ((h1 + Math.imul(j, h2)) >>> 0) & mask;
    if (!(bloom[idx >> 3] & (1 << (idx & 7)))) return false;
  }
  return true;
}

let n = 0;
function* gen() {
  if (mode === 'milk') {
    for (let s = start; s < end; s++) yield { priv: new MT19937(s >>> 0).bytes32LE(), tag: `milk:${s}` };
  } else if (mode === 'milkHD') {
    for (let s = start; s < end; s++) {
      const m = bip32Master(new MT19937(s >>> 0).bytes32LE());
      yield { priv: bip32Derive(m, [0, 0]).key, tag: `milkHD:${s}` };
    }
  } else if (mode === 'brain') {
    for (let i = start; i < end; i++) {
      const w = words[i % words.length];
      const round = Math.floor(i / words.length);
      let p = w;
      if (round === 1) p = w.toLowerCase();
      if (round === 2) p = w + '123';
      if (round === 3) p = w + '1';
      if (round === 4) p = w + '!';
      if (round === 5) p = w.charAt(0).toUpperCase() + w.slice(1);
      let h = sha256(enc.encode(p));
      if (round >= 6) h = sha256(h);
      yield { priv: h, tag: `brain:"${p}"` };
    }
  } else if (mode === 'seq') {
    const b = BigInt(base);
    for (let i = 0; i < count; i++) yield { priv: big32(b + BigInt(i)), tag: `seq:${b + BigInt(i)}` };
  } else {
    for (let i = 0; i < count; i++) yield { priv: randomBytes(32), tag: 'random' };
  }
}

for (const item of gen()) {
  n++;
  if (n % 250000 === 0) parentPort.postMessage({ type: 'progress', n: 250000 });
  let h;
  try { h = hash160(secp256k1.getPublicKey(item.priv, true)); } catch (e) { continue; }
  if (hit(Buffer.from(h))) parentPort.postMessage({ type: 'hit', priv: toHex(item.priv), tag: item.tag });
}
parentPort.postMessage({ type: 'progress', n: n % 250000 });
parentPort.postMessage({ type: 'done' });