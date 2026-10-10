/** Intent engine tests — EN + Hinglish classification. */

import { beforeAll, describe, expect, it } from 'vitest';
import { classifyIntent } from '../src/core/intent.ts';
import { registerBuiltinTemplates } from '../src/data/templates.ts';

beforeAll(() => {
  registerBuiltinTemplates();
});

describe('approval/rejection commands', () => {
  it('recognizes English approve', () => {
    expect(classifyIntent('yes', false).kind).toBe('approve');
  });
  it('recognizes Hinglish approve', () => {
    expect(classifyIntent('haan', false).kind).toBe('approve');
  });
  it('recognizes Hinglish reject', () => {
    expect(classifyIntent('nahi karo', false).kind).toBe('reject');
  });
});

describe('command requests', () => {
  it('resolves EN scan request to nmap', () => {
    const i = classifyIntent('nmap scan 10.0.0.5', false);
    expect(i.kind).toBe('generate-command');
    expect(i.tool).toBe('nmap');
    expect(i.params.target).toBe('10.0.0.5');
  });

  it('resolves Hinglish scan request', () => {
    const i = classifyIntent('nmap scan karo 10.0.0.5', false);
    expect(i.kind).toBe('generate-command');
    expect(i.tool).toBe('nmap');
  });

  it('resolves curl headers request with URL', () => {
    const i = classifyIntent('get headers for https://example.com', false);
    expect(i.tool).toBe('curl');
    expect(i.params.url).toBe('https://example.com');
  });

  it('suggests nmap for a bare scan request', () => {
    const i = classifyIntent('scan kar', false);
    expect(i.tool).toBe('nmap');
  });

  it('returns unknown for unrelated text', () => {
    expect(classifyIntent('what is the weather', false).kind).toBe('unknown');
  });
});
