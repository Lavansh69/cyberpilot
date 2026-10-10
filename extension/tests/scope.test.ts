/** Scope & authorization engine tests — deny-by-default enforcement. */

import { describe, expect, it } from 'vitest';
import type { AuthorizationRecord, TargetProfile } from '../src/core/types.ts';
import { checkScope, validateScopeEntry } from '../src/core/scope.ts';

const NOW = 1_700_000_000_000;

function makeTarget(): TargetProfile {
  return {
    id: 'target-1',
    name: 'Lab host',
    targetType: 'ip',
    value: '10.0.0.5',
    scopeEntries: [],
    installedTools: { nmap: '7.94' },
    authorizationRecordIds: ['auth-1'],
    createdAt: NOW,
    updatedAt: NOW,
  };
}

function makeAuth(overrides: Partial<AuthorizationRecord> = {}): AuthorizationRecord {
  return {
    id: 'auth-1',
    targetId: 'target-1',
    scopeEntries: [{ kind: 'single-ip', value: '10.0.0.5' }],
    maxRiskLevel: 2,
    grantedAt: NOW - 1000,
    expiresAt: NOW + 3600_000,
    ...overrides,
  };
}

describe('validateScopeEntry', () => {
  it('accepts a single IP', () => {
    expect(validateScopeEntry({ kind: 'single-ip', value: '10.0.0.5' }).ok).toBe(true);
  });
  it('rejects oversized CIDR (max 1024 hosts)', () => {
    expect(validateScopeEntry({ kind: 'approved-cidr', value: '10.0.0.0/8' }).ok).toBe(false);
  });
  it('rejects wildcards', () => {
    expect(validateScopeEntry({ kind: 'approved-subdomain', value: '*.example.com' }).ok).toBe(false);
  });
});

describe('checkScope', () => {
  it('allows risk-0 without authorization', () => {
    const d = checkScope(makeTarget(), '10.0.0.5', 0, [], NOW);
    expect(d.decision).toBe('allow');
  });

  it('rejects risk-2 with no authorization', () => {
    const d = checkScope(makeTarget(), '10.0.0.5', 2, [], NOW);
    expect(d.decision).toBe('reject');
  });

  it('allows risk-2 when a valid authorization covers it', () => {
    const d = checkScope(makeTarget(), '10.0.0.5', 2, [makeAuth()], NOW);
    expect(d.decision).toBe('allow');
  });

  it('rejects when authorization is expired', () => {
    const d = checkScope(makeTarget(), '10.0.0.5', 2, [makeAuth({ expiresAt: NOW - 1 })], NOW);
    expect(d.decision).toBe('reject');
  });

  it('rejects when risk level exceeds the record max', () => {
    const d = checkScope(makeTarget(), '10.0.0.5', 3, [makeAuth({ maxRiskLevel: 2 })], NOW);
    expect(d.decision).toBe('reject');
  });

  it('rejects sensitive targets without explicit entry', () => {
    const t = { ...makeTarget(), value: '127.0.0.1' };
    const d = checkScope(t, '127.0.0.1', 2, [], NOW);
    expect(d.decision).toBe('reject');
  });

  it('rejects a target not covered by the record scope', () => {
    const d = checkScope(makeTarget(), '10.0.0.99', 2, [makeAuth()], NOW);
    expect(d.decision).toBe('reject');
  });
});
