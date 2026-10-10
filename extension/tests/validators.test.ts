/** Validator security regression tests — deny-by-default behavior. */

import { describe, expect, it } from 'vitest';
import {
  validateCidr, validateDomain, validateIp, validatePath, validatePort, validateUrl,
} from '../src/core/validators.ts';

describe('domain validation', () => {
  it.each(['example.com', 'sub.example.com', 'example.co.uk'])('accepts %s', (i) => {
    expect(validateDomain(i).ok).toBe(true);
  });
  it.each(['', 'example', 'example.com/', 'http://example.com', 'exa_mple.com'])('rejects %s', (i) => {
    expect(validateDomain(i).ok).toBe(false);
  });
});

describe('IP validation', () => {
  it.each(['10.0.0.5', '192.168.1.1', '172.16.0.1'])('accepts %s', (i) => {
    expect(validateIp(i).ok).toBe(true);
  });
  it.each(['', '10.0.0', '256.1.1.1', '10.0.0.5;ls', '01.2.3.4'])('rejects %s', (i) => {
    expect(validateIp(i).ok).toBe(false);
  });
});

describe('CIDR validation', () => {
  it('accepts a valid CIDR', () => {
    expect(validateCidr('10.0.0.0/24').ok).toBe(true);
  });
  it('rejects oversized prefix', () => {
    expect(validateCidr('10.0.0.0/33').ok).toBe(false);
  });
  it('requires a prefix', () => {
    expect(validateCidr('10.0.0.5').ok).toBe(false);
  });
});

describe('port validation', () => {
  it.each(['80', '443', '8080'])('accepts %s', (i) => {
    expect(validatePort(i).ok).toBe(true);
  });
  it.each(['0', '65536', 'abc', '22;ls'])('rejects %s', (i) => {
    expect(validatePort(i).ok).toBe(false);
  });
});

describe('path validation — shell metachar rejection', () => {
  it.each(['; rm -rf /', '`id`', '$(id)', 'a && b', 'a | b', 'a\nb'])('rejects injection in %s', (i) => {
    expect(validatePath(i).ok).toBe(false);
  });
  it('accepts a normal path', () => {
    expect(validatePath('/usr/share/wordlists/common.txt').ok).toBe(true);
  });
});

describe('URL validation', () => {
  it('accepts http/https URLs', () => {
    expect(validateUrl('https://example.com').ok).toBe(true);
  });
  it('rejects other schemes', () => {
    expect(validateUrl('ftp://example.com').ok).toBe(false);
    expect(validateUrl('file:///etc/passwd').ok).toBe(false);
  });
});
