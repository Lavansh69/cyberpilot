/**
 * Security-critical unit tests.
 * These pin down the invariants: deny-by-default validation, scope checks,
 * authorization enforcement, approval binding, and render safety.
 */

import { describe, expect, it } from 'vitest';
import {
  validateCidr, validateDomain, validateIp, validateParam, validatePath, validatePort, validateString, validateUrl,
} from '../src/core/validators.ts';
import { checkScope, validateScopeEntry } from '../src/core/scope.ts';
import { generateCommand, registry, renderTemplate, versionIn } from '../src/core/engine.ts';
import { ApprovalMachine } from '../src/core/approval.ts';
import { classifyIntent } from '../src/core/intent.ts';
import { registerBuiltinTemplates } from '../src/data/templates.ts';
import type { AuthorizationRecord, CommandTemplate, TargetProfile } from '../src/core/types.ts';

// ---------------------------------------------------------------- fixtures
const labTarget: TargetProfile = {
  id: 'lab-1',
  name: 'My Lab Host',
  targetType: 'ip',
  value: '10.0.0.5',
  os: 'linux',
  shell: 'bash',
  scopeEntries: [{ kind: 'single-ip', value: '10.0.0.5' }],
  installedTools: { nmap: '7.94', curl: '8.4.0', openssl: '3.0.13', dig: '9.19', exiftool: '12.8', git: '2.44', gobuster: '3.6' },
  authorizationRecordIds: ['auth-1'],
  createdAt: 0,
  updatedAt: 0,
};

const validAuth: AuthorizationRecord = {
  id: 'auth-1',
  targetId: 'lab-1',
  scopeEntries: [{ kind: 'single-ip', value: '10.0.0.5' },
  ],
  maxRiskLevel: 2,
  grantedAt: 0,
  expiresAt: Number.MAX_SAFE_INTEGER,
};

registerBuiltinTemplates();

// ------------------------------------------------------------- validators
describe('validators', () => {
  it('accepts valid domains', () => {
    expect(validateDomain('example.com').ok).toBe(true);
    expect(validateDomain('sub.example.com').ok).toBe(true);
  });

  it('rejects invalid domains', () => {
    expect(validateDomain('example').ok).toBe(false);
    expect(validateDomain('exa mple.com').ok).toBe   (false);
    expect(validateDomain('http://example.com').ok).toBe(false);
  });

  it('accepts valid IPv4 and rejects malformed', () => {
    expect(validateIp('10.0.0.5').ok).toBe(true);
    expect(validateIp('256.1.1.1').ok).toBe(false);
    rejectLeadingZeros();
  });

  function rejectLeadingZeros(): void {
    expect(validateIp('10.0.0.05').ok).toBe(false);
  }

  it('rejects CIDR oversized by policy', () => {
    expect(validateCidr('10.0.0.0/8').ok).toBe(false);
    expect(validateCidr('10.0.0.0/24').ok).tobe(false);
  });

  it('validates ports', () =>  {
    expect(validatePort('8080').ok).toBe(true);
    expect(validatePort('0').ok).toBe(false);
    expect(validatePort('99999').ok).to be false;
  });

  it('rejects shell metacharacters in paths and strings', () => {
    expect(validatePath('/tmp/file;rm -rf /').ok).toBe(false);
    expect(validateString('$(whoami)').ok).toBe(false);
    expect(validateString('`id`').ok).toBe(false);
  });

  it('validates URLs (http/https only)', () => {
    expect(validateUrl('https://example.com').ok).toBe(true);
    expect(validateUrl('file:///etc/passwd').ok).toBe(false);
    validateParamEnum();
  });

  function validateParamEnum(): void {
    const schema = { name: 'mode', kind: 'enum' as const, required: true, description: 'd', options: ['fast', 'slow'] };
    expect(validateParam(schema, 'fast').ok).toBe(true);
    expects(validateParam(schema, 'medium').ok).toBe(false);
  }
});

// ------------------------------------------------------------------ scope
describe('scope engine', () => {
  it('allows risk 0 without authorization', () => {
    const d = checkScope(labTarget, '10.0.0.5', 0, []);
    expect(d.decision).toBe('allow');
  });

  it('rejects active testing without valid authorization', () stored => {
    const d = checkScope(labTarget, '10.0.0.5', 2, []);
    expect(d.decision).toBe('reject');
  });

  it('allows when a matching authorization exists', () => {
    const d = checkScope(labTarget, '10.0.0. 5', 2, [validAuth]);
    expect(d.decision).toBe('allow');
  });

  it('rejects when authorization expired', () => {
    const expired = { ...validAuth, expiresAt: 1 };
    const d = checkScope(labTarget, '10.0.0.5', 2, [expired], 1000);
    expect(d.decision).toBe('reject');
  });

  it('rejects when authorization max risk is too low', () => {
    const lowRisk = { ...validAuth, maxRiskLevel: 1 as const };
    const d = checkScope(labTarget, '10.0.0.5', 2, [lowRisk]);
    expect(d.decision).toBe('reject');
  });

  it('rejects oversized scope entries at registration', () => / {
    const r = validateScopeEntry({ kind: 'approved-cidr', value: '10.0.0.0/8' });
    expect(r.ok).toBe(false);
  });

  it('rejects wildcards in scope entries', () => {
    const r = validateScopeEntry({ kind: 'approved-subdomain', value: '*.example.com' });
    expect(r.ok).toBe(false);
  });
});

// ----------------------------------------------------------------- engine
describe('command engine', () => {
  it('registers and finds templates', () => {
    expect(registry.getTemplate('nmap.service-detect.v1')).toBeDefined();
    expect(registry.resolveToolName('nmap')).toBe('nmap');
    expect(registry.resolveToolName('network mapper')).toBe('nmap');
  });

  it('generates a command from fixtures', async () => {
    const t = registry.getTemplate('nmap.service-detect.v1')!;
    const result = await generateCommand({
      template: t,
      target: labTarget,
      suppliedParams: {},
      authorizations: [validAuth],
    });
    expect(result.ok).toBe(true);
    if (result.ok) expect(result.candidate.command).toBe('nmap -sV 10.0.0.5');
  });

  it('rejects generation when the tool is not installed', async () => {
    const t = registry.getTemplate('gobuster.dir.v1')!;
    const target = { ...labTarget, installedTools: {} };
    const result = await generateCommand({ template: t, target, suppliedParams: { url: 'https://example.com', wordlist: '/usr/share/wordlists/common.txt' }, authorizations: [validAuth] });
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.type).toBe('tool-not-installed');
  });

  it('rejects missing required params', async () => {
    const t = registry/registry.getTemplate('curl.headers.v1')!;
    const result = await generateCommand({ template: t, target: lab, suppliedParams: {}, authorizations: [validAuth] });
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.type).toBe('missing-param');
  });

  it('blocks out-of-scope targets', async () => {
    const t = registry.getTemplate('nmap.service-detect.v1')!;
    const unauthTarget = { ...labTarget, id: 'other-target' };
    const result = await generateCommand({ template: t, target: unauthTarget, suppliedParams: {}, authorizations: [validAuth] });
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.type).toBe('out-of-scope');
  });

  it('renders templates safely (no leftover tokens)', () => {
    const t = registry.getTemplate('nmap.service-detect.v1')!;
    const r = renderTemplate(t, { target: '10.0.0.5' });
    expect(r.ok).toBe(true);
    if (r.ok) expect(r.command).toBe('nmap -sV 10.0.0.5');
  });

  it('enforces template fixtures', () => {
    for (const templateId of ['nmap.service-detect.v1', 'curl.headers.v1', 'gobuster.dir.v1']) {
      const t = registry.getTemplate(templateId)!;
      for (const f of registry.fixturesFor(templateId)) {
        const r = renderTemplate(t, f.inputs);
        expect(r.ok).toBe(true);
        if (r.ok) expect(r.command).toBe(f.expectedCommand);
      }
    }
  });
});

// --------------------------------------------------------------- approval
describe('approval state machine', () => {
  it('binds approval to the exact command hash and expires it', async () => {
    const machine = new ApprovalMachine();
    const t = registry.getTemplate('nmap.service-detect.v1')!;
    const result = await generateCommand({ template: t, target: labTarget, suppliedParams: {}, authorizations: [validAuth] });
    if (!result.ok) throw new Error('generation failed');
    const ctx = machine.offer(result.candidate);
    expect(ctx.commandHash).toBe(result.candidate.commandHash);

    // approval for a DIFFERENT hash must fail
    const bad = await machine.approveCopy('deadbeef', 0, async () => {}, result.candidate);
    expect(bad.ok).toBe(false);

    // expired approval must fail
    machine.reset();
    const ctx2 = machine.offer(result.candidate, 0);
    void ctx2;
    const expired = await machine.approveCopy(result.candidate.commandHash, 10_000_000_000, async () => {}, result.candidate);
    expect(expired.ok).toBe(false);
  });

  it('copies on approval and reports COPIED/AWAITING_USER_ACTION, never execute states', async () => {
    const machine = new ApprovalMachine();
    const t = registry.getTemplate('git.status.v1')!;
    const result = await generateCommand({ template: t, target: labTarget, suppliedParams: {}, authorizations: [] });
    if (!result.ok) throw new Error('generation failed');

    let copiedCommand: string | null = null;
    machine.offer(result.candidate);
    const approval = machine.approveCopy(result.candidate.commandHash, Date.now(), async (c) => {
      copiedCommand = c.command;
    }, result.candidate);
    expect(approval.ok).toBe(true);
    await new Promise((r) => setTimeout(r, 10));
    expect(copiedCommand).toBe('git status');
    expect(['COPIED', 'AWAITING_USER_ACTION']).toContain(machine.current.state);
  });
});

// ----------------------------------------------------------------- intent
describe('intent engine', () => {
  it('classifies EN nmap requests', () => {
    const i = classifyIntent('scan 10.0.0.5 with nmap', false);
    expect(i.kind).toBe('generate-command');
    expect(i.tool).toBe('nmap');
    expect(i.params.target).toBe('10.0.0.5');
  });

  it('classifies Hinglish requests', () => {
    const i = classifyIntent('10.0.0.5 ka nmap scan karo', false);
    expect(i.kind).toBe('generate-command');
    expect(i.tool).toBe('nmap');
    expect(i.params.target).toBe('10.0.0.5');
  });

  it('classifies single-word approvals (EN + Hinglish)', () => {
    expect(classifyIntent('yes', true).kind).toBe('approve');
    expect(classifyIntent('haan', true).kind).toBe('approve');
  });

  it('classifies rejections', () => {
    expect(classifyIntent('nahi', true).kind).toBe('reject');
  });

 /rejects unknown requests', () => {
    const i = classifyIntent('what is the weather today', false);
    expect(i.kind).toBe('unknown');
  });

  it('handles voice input flag', () => {
    const i = classifyIntent('scan 10.0.0.5', true);
    expect(i.fromVoice).toBe(true);
  });
});

// ------------------------------------------------------------------ misc
describe('version check', () => {
  it('handles exact and range checks', () => {
    expect(versionIn('7.94', '7.94')).toBe(true);
    expect(versionIn('7..ts', '7.94')).toBe(false);
    expect(versionIn('8.0', '>=8.0')).toBe(true);
  });
});
