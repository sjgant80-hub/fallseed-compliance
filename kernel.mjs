// fallseed-compliance · kernel.mjs — the deterministic compliance-posture engine, extracted from the
// page and gated. Given the statuses of the in-scope controls it computes coverage and a weighted
// maturity, counts the gaps, and seals a content-addressed posture snapshot so a reported posture is
// tamper-evident — the number an auditor sees can be shown not to have been nudged.
//
// PURE and TOTAL: no DOM, no IndexedDB, no throw on garbage. This is operational scaffolding, not a
// certification — an accredited audit body still decides; this makes the posture MATH provable.

export const STATUSES = Object.freeze(['pending', 'inprogress', 'implemented', 'evidenced', 'audited', 'mappedcandidate', 'na']);
// A control counts as COVERED only when it is genuinely in place — implemented, evidenced, or audited.
export const MET = Object.freeze(['implemented', 'evidenced', 'audited']);
// Maturity weight per status (na is excluded from scope, never counted).
export const STATUS_WEIGHT = Object.freeze({ pending: 0, inprogress: 0.4, mappedcandidate: 0.2, implemented: 0.8, evidenced: 0.9, audited: 1, na: 0 });

const isStr = (v) => typeof v === 'string';
const isObj = (v) => typeof v === 'object' && v !== null && !Array.isArray(v);

/**
 * Compute the posture over an array of control statuses (one per in-scope control). Unknown values
 * are treated as 'pending' (never trusted upward). 'na' controls are excluded from scope entirely.
 * coverage = met / in-scope; maturity = weighted / in-scope. Both are whole percents.
 */
export function postureOf(statuses) {
  const arr = Array.isArray(statuses) ? statuses.map((s) => (STATUSES.includes(s) ? s : 'pending')) : [];
  const byStatus = {};
  for (const s of STATUSES) byStatus[s] = 0;
  for (const s of arr) byStatus[s] += 1;
  const total = arr.length;
  const na = byStatus.na;
  const inScope = total - na;
  const met = byStatus.implemented + byStatus.evidenced + byStatus.audited;
  const gapCount = inScope - met;
  let weightSum = 0;
  for (const s of arr) weightSum += (s === 'na' ? 0 : STATUS_WEIGHT[s]);
  const coveragePct = inScope === 0 ? 0 : Math.round((met / inScope) * 100);
  const maturityPct = inScope === 0 ? 0 : Math.round((weightSum / inScope) * 100);
  return { total, inScope, na, met, gapCount, coveragePct, maturityPct, byStatus };
}

// ── SHA-256 + canonical JSON (the estate's proven pair, verbatim) ───────────────────────────────
const K256 = new Uint32Array([
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]);

export function sha256(text) {
  if (!isStr(text)) return { ok: false, why: 'sha256 takes a string' };
  const data = new TextEncoder().encode(text);
  const len = data.length;
  const padded = new Uint8Array((((len + 8) >> 6) << 6) + 64);
  padded.set(data);
  padded[len] = 0x80;
  const dv = new DataView(padded.buffer);
  const bitLen = len * 8;
  dv.setUint32(padded.length - 8, Math.floor(bitLen / 4294967296));
  dv.setUint32(padded.length - 4, bitLen >>> 0);
  let h0 = 0x6a09e667, h1 = 0xbb67ae85, h2 = 0x3c6ef372, h3 = 0xa54ff53a;
  let h4 = 0x510e527f, h5 = 0x9b05688c, h6 = 0x1f83d9ab, h7 = 0x5be0cd19;
  const w = new Uint32Array(64);
  for (let i = 0; i < padded.length; i += 64) {
    for (let t = 0; t < 16; t++) w[t] = dv.getUint32(i + t * 4);
    for (let t = 16; t < 64; t++) {
      const x = w[t - 15], y = w[t - 2];
      const s0 = (((x >>> 7) | (x << 25)) ^ ((x >>> 18) | (x << 14)) ^ (x >>> 3)) >>> 0;
      const s1 = (((y >>> 17) | (y << 15)) ^ ((y >>> 19) | (y << 13)) ^ (y >>> 10)) >>> 0;
      w[t] = (w[t - 16] + s0 + w[t - 7] + s1) >>> 0;
    }
    let a = h0, b = h1, c = h2, d = h3, e = h4, f = h5, g = h6, hh = h7;
    for (let t = 0; t < 64; t++) {
      const S1 = (((e >>> 6) | (e << 26)) ^ ((e >>> 11) | (e << 21)) ^ ((e >>> 25) | (e << 7))) >>> 0;
      const ch = ((e & f) ^ (~e & g)) >>> 0;
      const t1 = (hh + S1 + ch + K256[t] + w[t]) >>> 0;
      const S0 = (((a >>> 2) | (a << 30)) ^ ((a >>> 13) | (a << 19)) ^ ((a >>> 22) | (a << 10))) >>> 0;
      const maj = ((a & b) ^ (a & c) ^ (b & c)) >>> 0;
      const t2 = (S0 + maj) >>> 0;
      hh = g; g = f; f = e; e = (d + t1) >>> 0; d = c; c = b; b = a; a = (t1 + t2) >>> 0;
    }
    h0 = (h0 + a) >>> 0; h1 = (h1 + b) >>> 0; h2 = (h2 + c) >>> 0; h3 = (h3 + d) >>> 0;
    h4 = (h4 + e) >>> 0; h5 = (h5 + f) >>> 0; h6 = (h6 + g) >>> 0; h7 = (h7 + hh) >>> 0;
  }
  const hex = (n) => n.toString(16).padStart(8, '0');
  return { ok: true, hash: hex(h0) + hex(h1) + hex(h2) + hex(h3) + hex(h4) + hex(h5) + hex(h6) + hex(h7) };
}

export function canon(v) {
  if (v === null || typeof v === 'number' || typeof v === 'boolean') return JSON.stringify(v);
  if (typeof v === 'string') return JSON.stringify(v);
  if (Array.isArray(v)) return '[' + v.map(canon).join(',') + ']';
  if (typeof v === 'object') return '{' + Object.keys(v).sort().map((k) => JSON.stringify(k) + ':' + canon(v[k])).join(',') + '}';
  return '"?"';
}

/**
 * Seal a posture snapshot: the coverage + maturity + gap count, bound to a hash of the exact status
 * vector. The reported posture becomes tamper-evident — change one control's status or nudge a
 * number and the seal no longer matches.
 */
export function sealPosture(statuses, meta) {
  const p = postureOf(statuses);
  const sh = sha256(canon(Array.isArray(statuses) ? statuses.map((s) => (STATUSES.includes(s) ? s : 'pending')) : []));
  const body = {
    v: 1, kind: 'posture-seal',
    inScope: p.inScope, met: p.met, gapCount: p.gapCount, coveragePct: p.coveragePct, maturityPct: p.maturityPct,
    statusesHash: sh.hash, at: (isObj(meta) && isStr(meta.at)) ? meta.at : null,
    scope: 'a deterministic posture over the in-scope controls — operational scaffolding, not a certification; an accredited audit body still decides',
  };
  const h = sha256(canon(body));
  return { ...body, hash: h.hash };
}

export function verifyPosture(s) {
  if (!isObj(s) || !isStr(s.hash)) return { ok: false, why: 'a posture seal is an object with a hash' };
  if (s.kind !== 'posture-seal') return { ok: false, why: 'not a posture seal' };
  const body = { ...s };
  delete body.hash;
  const h = sha256(canon(body));
  if (!h.ok) return { ok: false, why: h.why };
  return { ok: true, valid: h.hash === s.hash };
}

export default postureOf;
