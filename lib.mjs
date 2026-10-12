import { secp256k1 } from '@noble/curves/secp256k1';
import { sha256 } from '@noble/hashes/sha256';
import { sha512 } from '@noble/hashes/sha512';
import { ripemd160 } from '@noble/hashes/ripemd160';
import { hmac } from '@noble/hashes/hmac';
import { bech32, bech32m, convertBits } from '@scure/base';

export { sha256, sha512 };
export const enc = new TextEncoder();
export const concat = (...a) => { const t=a.reduce((s,x)=>s+x.length,0),o=new Uint8Array(t); let p=0; for(const x of a){o.set(x,p);p+=x.length} return o; };
secp256k1.etc.hmacSha256Sync = (k, ...m) => hmac(sha256, k, concat(...m));

export const toHex = b => Buffer.from(b).toString('hex');
export const hexToBytes = h => Uint8Array.from(Buffer.from(h, 'hex'));
export const hash160 = b => ripemd160(sha256(b));
export const N = secp256k1.CURVE.n;
export const big32 = n => hexToBytes(n.toString(16).padStart(64, '0'));

const B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
export function b58decode(s) {
  let n = 0n;
  for (const c of s) { const i = B58.indexOf(c); if (i < 0) return null; n = n * 58n + BigInt(i); }
  let h = n.toString(16); if (h.length % 2) h = '0' + h;
  let z = 0; for (const c of s) { if (c === '1') z++; else break; }
  return Buffer.concat([Buffer.alloc(z), Buffer.from(h, 'hex')]);
}
export const b58encode = buf => {
  let n = 0n; for (const b of buf) n = n * 256n + BigInt(b);
  let s = ''; while (n > 0n) { s = B58[Number(n % 58n)] + s; n /= 58n; }
  for (const b of buf) { if (b === 0) s = '1' + s; else break; }
  return s;
};
export const b58check = p => b58encode(concat(p, sha256(sha256(p)).subarray(0, 4)));

export function addrToKey(addr) {
  try {
    if (addr.startsWith('bc1') || addr.startsWith('tb1')) {
      const tap = addr[2] === '1' && addr[3] === 'p';
      const d = tap ? bech32m.decode(addr) : bech32.decode(addr);
      return Buffer.from(convertBits(d.words.slice(1), 5, 8, false));
    }
    const raw = b58decode(addr);
    if (!raw || raw.length !== 25) return null;
    return raw.subarray(1, 21);
  } catch (e) { return null; }
}

export function keyToAddrs(priv) {
  let pub; try { pub = secp256k1.getPublicKey(priv, true); } catch (e) { return null; }
  const h = hash160(pub);
  return {
    pub, h160: Buffer.from(h),
    segwit: bech32.encode('bc', [0, ...convertBits(h, 8, 5)]),
    legacy: b58check(concat(new Uint8Array([0]), h)),
    wif: b58check(concat(new Uint8Array([0x80]), priv, new Uint8Array([1]))),
  };
}

export class MT19937 {
  constructor(seed) {
    this.mt = new Uint32Array(624); this.i = 624; this.mt[0] = seed >>> 0;
    for (let k = 1; k < 624; k++) {
      const s = (this.mt[k-1] ^ (this.mt[k-1] >>> 30)) >>> 0;
      this.mt[k] = (Math.imul(s, 1812433253) + k) >>> 0;
    }
  }
  u32() {
    if (this.i >= 624) {
      for (let k = 0; k < 624; k++) {
        const y = ((this.mt[k] & 0x80000000) | (this.mt[(k+1)%624] & 0x7fffffff)) >>> 0;
        this.mt[k] = (this.mt[(k+397)%624] ^ (y >>> 1) ^ ((y & 1) ? 0x9908b0df : 0)) >>> 0;
      }
      this.i = 0;
    }
    let y = this.mt[this.i++];
    y ^= y >>> 11; y ^= (y << 7) & 0x9d2c5680; y ^= (y << 15) & 0xefc60000; y ^= y >>> 18;
    return y >>> 0;
  }
  bytes32LE() { const o = new Uint8Array(32), dv = new DataView(o.buffer); for (let k=0;k<8;k++) dv.setUint32(k*4,this.u32(),true); return o; }
}

const ckd = (node, idx) => {
  const d = new Uint8Array(37);
  if (idx >= 0x80000000) { d[0] = 0; d.set(node.key, 1); } else d.set(secp256k1.getPublicKey(node.key, true), 0);
  new DataView(d.buffer).setUint32(33, idx, false);
  const I = hmac(sha512, node.chain, d);
  return { key: big32((BigInt('0x'+toHex(I.subarray(0,32))) + BigInt('0x'+toHex(node.key))) % N), chain: I.subarray(32,64) };
};
export const bip32Master = seed => { const I = hmac(sha512, enc.encode('Bitcoin seed'), seed); return { key: I.subarray(0,32), chain: I.subarray(32,64) }; };
export const bip32Derive = (node, path) => { let n = node; for (const i of path) n = ckd(n, i); return n; };