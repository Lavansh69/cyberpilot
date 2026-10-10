/** Engine tests: template rendering + generation pipeline + fixtures. */

import { beforeAll, describe, expect, it } from 'vitest';
import { generateCommand, registry, renderTemplate } from '../src/core/engine.ts';
import { registerBuiltinTemplates } from '../src/data/templates.ts';
import type { AuthorizationRecord, TargetProfile } from '../src/core/types.ts';

const NOW = 1_700_000_000_000;

beforeAll(() => {
  registerBuiltinTemplates();
});

function makeTarget(): TargetProfile {
  return {
    id: 'target-1',
    name: 'Lab host',
    targetType: 'ip',
    value: '10.0.0.5',
    scopeEntries: [],
    installedTools: { nmap: '7.94', curl: '8.5', git: '2.45' },
    authorizationRecordIds: ['auth-1'],
    createdAt: NOW,
    updatedAt: NOW,
  };
}

function makeAuth(): AuthorizationRecord {
  return {
    id: 'auth-1',
    targetId: 'target-1',
    scopeEntries: [{ kind: 'single-ip', value: '10.0.0.5' }],
    maxRiskLevel: 2,
    grantedAt: NOW - 1000,
    expiresAt: NOW + 3600_000,
  };
}

describe('renderTemplate', () => {
  it('substitutes validated params', () => {
    const t = registry.getTemplate('nmap.service-detect.v1')!;
    const r = renderTemplate(t, { target: '10.0.0.5' });
    expect(r.ok).toBe(true);
    if (r.ok) expect(r.command).toBe('nmap -sV 10.0.0.5');
  });

  it('rejects unresolved tokens', () => param-less check...
  it('rejects values containing tokens', () => {
    const t = registry.getTemplate('nmap.service-detect.v1')!;
    const r = renderTemplate(t, { target: '{{other}}' });
    expect(r.ok && r.command.includes('{{')).toBe(false);
  });
});
