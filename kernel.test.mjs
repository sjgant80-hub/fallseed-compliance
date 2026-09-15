import { test } from 'node:test';
import assert from 'node:assert/strict';
import { STATUSES, MET, STATUS_WEIGHT, postureOf, sha256, canon, sealPosture, verifyPosture } from './kernel.mjs';

test('sha256 + canon are the proven pair', () => {
  assert.equal(sha256('abc').hash, 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
  assert.equal(canon({ b: 1, a: 2 }), '{"a":2,"b":1}');
});

test('the vocabularies are frozen', () => {
  assert.deepEqual([...STATUSES], ['pending', 'inprogress', 'implemented', 'evidenced', 'audited', 'mappedcandidate', 'na']);
  assert.deepEqual([...MET], ['implemented', 'evidenced', 'audited']);
  assert.throws(() => { STATUSES.push('x'); });
  assert.throws(() => { STATUS_WEIGHT.audited = 0; });
});

test('posture over a mixed control set — exact coverage, maturity, gaps', () => {
  const p = postureOf(['audited', 'evidenced', 'implemented', 'inprogress', 'mappedcandidate', 'pending', 'na']);
  assert.equal(p.total, 7);
  assert.equal(p.na, 1);
  assert.equal(p.inScope, 6);          // na excluded from scope
  assert.equal(p.met, 3);              // audited + evidenced + implemented
  assert.equal(p.gapCount, 3);         // in-scope minus met
  assert.equal(p.coveragePct, 50);     // 3 / 6
  assert.equal(p.maturityPct, 55);     // (1 + .9 + .8 + .4 + .2 + 0) / 6 = .55
});

test('kill: only implemented/evidenced/audited count as MET (not inprogress/mappedcandidate)', () => {
  const p = postureOf(['inprogress', 'mappedcandidate']);
  assert.equal(p.met, 0);              // neither is "met"
  assert.equal(p.coveragePct, 0);      // coverage counts MET only
  assert.equal(p.maturityPct, 30);     // but maturity is weighted: (.4 + .2) / 2 = .30
});

test('kill: na is excluded from scope, not counted as a gap or a met', () => {
  const p = postureOf(['implemented', 'na', 'na']);
  assert.equal(p.inScope, 1);          // two na removed from scope
  assert.equal(p.met, 1);
  assert.equal(p.gapCount, 0);
  assert.equal(p.coveragePct, 100);    // 1 met of 1 in-scope
});

test('kill: an unknown status is treated as pending (never trusted upward)', () => {
  const p = postureOf(['whatever', 'implemented']);
  assert.equal(p.inScope, 2);
  assert.equal(p.met, 1);
  assert.equal(p.coveragePct, 50);     // the unknown does NOT count as met
  assert.equal(p.byStatus.pending, 1); // it landed in pending
});

test('kill: an empty or all-na scope is 0%, never a divide-by-zero', () => {
  assert.equal(postureOf([]).coveragePct, 0);
  assert.equal(postureOf([]).maturityPct, 0);
  assert.equal(postureOf(['na', 'na']).coveragePct, 0);
  assert.equal(postureOf(['na', 'na']).inScope, 0);
});

test('kill: coverage rounds the exact fraction (2/3 → 67)', () => {
  const p = postureOf(['implemented', 'evidenced', 'pending']);
  assert.equal(p.coveragePct, 67);     // Math.round(2/3*100) = 67, not 66
});

test('byStatus counts every bucket', () => {
  const p = postureOf(['pending', 'pending', 'audited']);
  assert.equal(p.byStatus.pending, 2);
  assert.equal(p.byStatus.audited, 1);
  assert.equal(p.byStatus.implemented, 0);
});

test('postureOf is total on garbage (minimal posture, no throw)', () => {
  for (const junk of [null, undefined, 42, {}, 'nope', NaN]) {
    const p = postureOf(junk);
    assert.equal(p.inScope, 0);
    assert.equal(p.coveragePct, 0);
  }
});

test('sealPosture seals a tamper-evident snapshot; verifyPosture confirms it', () => {
  const s = sealPosture(['implemented', 'evidenced', 'pending'], { at: '2026-09-15T00:00:00Z' });
  assert.equal(s.kind, 'posture-seal');
  assert.equal(s.coveragePct, 67);
  assert.equal(verifyPosture(s).valid, true);
});

test('sealPosture: a nudged coverage number breaks the seal', () => {
  const s = sealPosture(['implemented', 'pending'], {});
  const tampered = { ...s, coveragePct: 100 };   // pretend posture was inflated 50 → 100
  assert.equal(verifyPosture(tampered).valid, false);
  assert.equal(verifyPosture({ hash: 'x' }).ok, false);
  assert.equal(verifyPosture({ kind: 'posture-seal' }).ok, false);
});

test('sealPosture: the statusesHash binds the seal to the exact status vector', () => {
  const a = sealPosture(['implemented', 'pending'], {});
  const b = sealPosture(['pending', 'implemented'], {});   // same posture, different order
  assert.notEqual(a.statusesHash, b.statusesHash);         // order is part of what was sealed
});

test('fuzz: pure and total — garbage never throws', () => {
  const junk = [null, undefined, 0, '', [], {}, NaN, true, ['na', 5, {}], Symbol.for('x')];
  for (const a of junk) {
    assert.doesNotThrow(() => { postureOf(a); sealPosture(a, a); verifyPosture(a); });
  }
});
