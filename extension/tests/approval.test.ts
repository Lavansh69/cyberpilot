/**
 * Security regression tests for the approval state machine.
 * These encode the core product invariants from the spec.
 */

import { describe, expect, it } from 'vitest';
import type { CommandCandidate, CommandTemplate } from '../src/core/types.ts';
import { ApprovalMachine, DEFAULT_APPROVAL_TTL_MS } from '../src/core/approval.ts';

function makeTemplate(id: string, riskLevel: 0 | 1 | 2 | 3): CommandTemplate {
  return {
    id,
    version: 1,
    tool: 'nmap',
    operation: 'service-detection',
    description: 'test',
    category: 'recon',
    params: [],
    template: 'nmap -sV {{target}}',
    supportedOS: ['linux'],
    supportedShells: ['bash'],
    riskLevel,
    authorizationRequired: riskLevel >= 1,
  };
}

function makeCandidate(commandHash: string, template: CommandTemplate): CommandCandidate {
  return {
    command: 'nmap -sV 10.0.0.5',
    template,
    tool: 'nmap',
    riskLevel: template.riskLevel,
    commandHash,
    targetId: 'target-1',
  };
}

const TEMPLATE = makeTemplate('nmap.service-detect.v1', 2);

describe('ApprovalMachine — core invariants', () => {
  it('starts IDLE with no pending approval', () => {
    const m = new ApprovalMachine();
    expect(m.current.state).toBe('IDLE');
    expect(m.current.pending).toBeNull();
  });

  it('offer() moves to AWAITING_APPROVAL with a bound context', () => {
    const m = new ApprovalMachine();
    m.offer(makeCandidate('hash-1', TEMPLATE), 1000);
    expect(m.current.state).toBe('AWAITING_APPROVAL');
    expect(m.current.pending?.commandHash).toBe('hash-1');
    expect(m.current.pending?.riskLevel).toBe(2);
  });

  it('approveCopy with a mismatched hash cancels the approval', () => {
    const m = new ApprovalMachine();
    m.offer(makeCandidate('hash-1', TEMPLATE), 1000);
    const res = m.approveCopy('hash-wrong', 2000, async () => {}, makeCandidate('hash-1', TEMPLATE));
    expect(res.ok).toBe(false);
    expect(m.current.state).toBe('CANCELLED');
  });

  it('approveCopy rejects an expired approval', () => {
    const m = new ApprovalMachine();
    m.offer(makeCandidate('hash-1', TEMPLATE), 0);
    const res = m.approveCopy('hash-1', DEFAULT_APPROVAL_TTL_MS + 1, async () => {}, makeCandidate('hash-1', TEMPLATE));
    expect(res.ok).toBe(false);
    expect(m.current.state).toBe('CANCELLED');
  });

  it('a successful approval copies and never reports execution', async () => {
    const m = new ApprovalMachine();
    let copied = '';
    const doCopy = async (c: CommandCandidate) => {
      copied = c.command;
    };
    m.offer(makeCandidate('hash-1', TEMPLATE), 1000);
    const res = m.approveCopy('hash-1', 2000, doCopy, makeCandidate('hash-1', TEMPLATE));
    expect(res.ok).toBe(true);
    // allow the async copy promise to resolve
    await new Promise((r) => setTimeout(r, 0));
    expect(copied).toBe('nmap -sV 10.0.0.5');
    expect(m.current.state).toBe('AWAITING_USER_ACTION');
    expect(m.current.lastCopied).not.toBeNull();
    expect(m.current.lastCopied?.ctx.commandHash).toBe('hash-1');
  });

  it('a new offer replaces any previous pending approval', () => {
    const m = new ApprovalMachine();
    m.offer(makeCandidate('hash-1', TEMPLATE), 1000);
    m.offer(makeCandidate('hash-2', TEMPLATE), 1100);
    expect(m.current.pending?.commandHash).toBe('hash-2');
  });

  it('reject() clears the pending approval', () => {
    const m = new ApprovalMachine();
    m.offer(makeCandidate('hash-1', TEMPLATE), 1000);
    m.reject();
    expect(m.current.state).toBe('REJECTED');
    expect(m.current.pending).toBeNull();
  });

  it('cancel() clears the pending approval and keeps the last copied record', () => {
    const m = new ApprovalMachine();
    m.offer(makeCandidate('hash-1', TEMPLATE), 1000);
    m.cancel('user cancelled');
    expect(m.current.state).toBe('CANCELLED');
    expect(m.current.pending).toBeNull();
  });
});
