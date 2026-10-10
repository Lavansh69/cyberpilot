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

  it('rejects a value that injects a token', () => {
    const t = registry.getTemplate('nmap.service-detect.v1')!;
    const r = renderTemplate(t, { target: '{{other}}' });
    expect(r.ok).toBe(false);
  });
});

describe('generateCommand pipeline', () => {
  it('generates an authorized nmap command', async () => {
    const t = registry.getTemplate('nmap.service-detect.v1')!;
    const res = await generateCommand({
      template: t,
      target: makeTarget(),
      suppliedParams: {},
      authorizations: [makeAuth()],
      now: NOW,
    });
    expect(res.ok).toBe(true);
    if (res.ok) {
      expect(res.candidate.command).toBe('nmap -sV 10.0.0.5');
      expect(res.candidate.riskLevel).toBe(2);
      expect(res.candidate.commandHash).toHaveLength(64);
    }
  });

  it('blocks generation without authorization', async () => {
    const t = registry.getTemplate('nmap.service-detect.v1')!;
    const res = await generateCommand({
      template: t,
      target: makeTarget(),
      suppliedParams: {},
      authorizations: [],
      now: NOW,
    });
    expect(res.ok).toBe(false);
    if (!res.ok) expect(res.type).toBe('out-of-scope');
  });

  it('blocks when the tool is not installed', async () => {
    const t = registry.getTemplate('gobuster.dir.v1')!;
    const res = await generateCommand({
      template: t,
      target: makeTarget(),
      suppliedParams: { url: 'https://example.com', wordlist: '/usr/share/wordlists/common.txt' },
      authorizations: [makeAuth()],
      now: NOW,
    });
    expect(res.ok).toBe(false);
    if (!res.ok) expect(res.type).toBe('tool-not-installed');
  });

  it('generates a risk-0 git command with no authorization', async () => {
    const t = registry.getTemplate('git.status.v1')!;
    const res = await generateCommand({
      template: t,
      target: makeTarget(),
      suppliedParams: {},
      authorizations: [],
      now: NOW,
    });
    expect(res.ok).toBe(true);
  });

  it('validates registered fixtures for all templates', async () => {
    for (const t of registry.allTemplates()) {
      for (const fx of registry.fixturesFor(t.id)) {
        const res = await generateCommand({
          template: t,
          target: makeTarget(),
          suppliedParams: fx.inputs,
          authorizations: [makeAuth()],
          now: NOW,
        });
        expect(res.ok, `${t.id}: expected fixture to generate`).toBe(true);
        if (res.ok) expect(res.candidate.command).toBe(fx.expectedCommand);
      }
    }
  });
});
