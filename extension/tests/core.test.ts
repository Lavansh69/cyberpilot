/**
 * Core security invariant tests (minimal set).
 * Full coverage grows incrementally — keeping files small and clean.
 */

import { describe, expect, it } from 'vitest';
import { validateDomain, validateIp, validatePort, validateString, validateUrl } from '../src/core/validators.ts';
import { checkScope } from '../src/core/scope.ts';
import { ApprovalMachine } from '../src/core/approval.ts';
import type { AuthorizationRecord, TargetProfile } from '../src/core/types.ts';

const labTarget: TargetProfile = {
  id: 'lab-1',
  name: 'My Lab Host',
  targetType: 'ip',
  value: '10.0.0.5',
  os: 'linux',
  shell: 'bash',
  scopeEntries: [{ kind: 'single-ip', value: '10.0.0.5' }],
  installedTools: {},
  authorizationRecordIds: ['auth-1'],
  createdAt: 0,
  updatedAt: 0,
};

const validAuth: AuthorizationRecord = {
  id: 'auth-1',
  targetId: 'lab-1',
  scopeEntries: [{ kind: 'single-ip', value: '10.0.0.5' }],
  maxRiskLevel: 2,
  grantedAt: 0,
  expiresAt: Number.MAX_SAFE_INTEGER,
};

describe('validators (deny by default)', () => {
  it('accepts valid values', () => {
    expect(validateDomain('example.com').ok).toBe(true);
    expect(validateIp('10.0.0.5').ok).toBe(true);
    expect(validatePort('8080').ok).toBe(true);
    expect(validateUrl('https://example.com').ok).toBe(true);
  });

  it('rejects invalid and dangerous values', () => {
    expect(validateDomain('example').ok).toBe(false);
    expect(validateIp('256.1.1.1').ok).toBe(false);
    expect(validatePort('0').ok).toBe(false);
    expect(validateUrl('file:///etc/passwd').ok).toBe(false);
    expect(validateString('$(whoami)').ok).toBe(false);
  });
});

describe('scope (authorization enforced)', () => {
  it('rejects active testing with no authorization', () => {
    expect(checkScope(labTarget, '10.0.0.5', 2, []).decision).toBe('reject');
  });

  it('allows active testing with valid authorization', () => {
    expect(checkScope(labTarget, '10.0.0.5', 2, [validAuth]).decision).toBe('allow');
  });

  it('allows risk 0 without authorization', () => {
    expect(checkScope(labTarget, '10.0.0.5', 0, []).decision).toBe('allow');
  });

  it('rejects expired authorization', () => {
    const expired = { ...validAuth, expiresAt: 1 };
    expect(checkScope(labTarget, '10.0.0.5', 2, [expired], 1000).decision).toBe('reject');
  });

  it('rejects authorization below the risk level', () => {
    const low = { ...validAuth, maxRiskLevel: 1 as const };
    expect(checkScope(labTarget, '10.0.0.5', 2, [low]).decision).toBe('reject');
  });
});

describe('approval machine (hash binding)', () => {
  it('rejects approval for a different command hash', () => {
    const m = new ApprovalMachine();
    const fakeCandidate = {
      command: 'nmap -sV 10.0.0.5',
      template: {} as never,
      tool: 'nmap',
      riskLevel: 2 as const,
      commandHash: 'aaaa',
      targetId: 'lab-1',
    };
    m.offer(fakeCandidate);
    expect(m.approveCopy('bbbb', 0, async () => {}, fakeCandidate).ok).toBe(false);
  });

  it('rejects approval for a different command hash', () => {
    const m = new ApprovalMachine();
    const fakeCandidate = {
      command: 'nmap -sV 10.0.0.5',
      template: {} as never,
      tool: 'nmap',
      riskLevel: 2 as const,
      commandHash: 'aaaa',
      targetId: 'lab-1',
    };
    m.offer(fakeCandidate);
    expect(m.approveCopy('bbbb', 0, async () => {}, fakeCandidate).ok).toBe(false);
  });

  it('accepts approval for the exact same command hash', () => {
    const m = new ApprovalMachine();
    const fakeCandidate = {
      command: 'nmap -sV 10.0.0.5',
      template: {} as never,
      tool: 'nmap',
      riskLevel: 2 as const,
      commandHash: 'aaaa',
      targetId: 'lab-1',
    };
    m.offer(fakeCandidate);
    expect(m.approveCopy('aaaa', 0, async () => {}, fakeCandidate).ok).toBe(true);
  });

  it('expires approvals after the TTL', () => {
    const m = new ApprovalMachine();
    const fakeCandidate = {
      command: 'nmap -sV 10.0.0.5',
      template: {} as never,
      tool: 'nmap',
      riskLevel: 2 as const,
      commandHash: 'aaaa',
      targetId: 'lab-1',
    };
    m.offer(fakeCandidate, 0);
    expect(m.approveCopy('aaaa', 10_000_000, async () => {}, fakeCandidate).ok).toBe(false);
  });
});
