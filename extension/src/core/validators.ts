/**
 * Parameter validators. Every value that enters a command template passes
 * through one of these BEFORE rendering. Validation is deny-by-default.
 *
 * Security notes:
 * - Shell metacharacters are rejected unless a schema explicitly allows them.
 * - Validation is the primary defense; escaping is secondary (see render.ts).
 */

import type { ParamKind, ParamSchema } from './types.ts';

export type ValidationOk = { readonly ok: true; readonly value: string };
export type ValidationErr = { readonly ok: false; readonly reason: string };
export type ValidationResult = ValidationOk | ValidationErr;

/** Characters that alter shell parsing. Denied unless a schema opts in. */
const SHELL_METACHARS = new Set([
  ';', '&', '|', '$', '`', '(', ')', '{', '}', '[', ']',
  '<', '>', '\n', '\r', '\\', '"', "'", '!', '*',
]);

const DOMAIN_LABEL = /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/i;

export function validateDomain(input: string): ValidationResult {
  const v = input.trim().toLowerCase().replace(/\.$/, '');
  if (v.length === 0) return { ok: false, reason: 'empty domain' };
  if (v.length > 253) return { ok: false, reason: 'domain too long' };
  if (v.includes('://') || v.includes('/')) return { ok: false, reason: 'domain must not include scheme or path' };
  const labels = v.split('.');
  if (labels.length < 2) return { ok: false, reason: 'domain must have at least two labels' };
  for (const label of labels) {
    if (!DOMAIN_LABEL.test(label)) {
      return { ok: false, reason: `invalid label "${label}"` };
    }
  }
  return { ok: true, value: v };
}

function ipToLong(ip: string): number | null {
  const parts = ip.split('.');
  if (parts.length !== 4) return null;
  let n = 0;
  for (const part of parts) {
    if (!/^\d{1,3}$/.test(part)) return null;
    const octet = Number(part);
    if (octet > 255) return null;
    if (part.length > 1 && part[0] === '0') return null; // reject leading zeros
    n = n * 256 + octet;
  }
  return n;
}

export function validateIp(input: string): ValidationResult {
  const v = input.trim();
  const n = ipToLong(v);
  if (n === null) return { ok: false, reason: 'invalid IPv4 address' };
  return { ok: true, value: v };
}

export function isPrivateIp(input: string): boolean {
  const n = ipToLong(input);
  if (n === null) return false;
  // 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 127.0.0.0/8
  return (
    (n >= 0x0A000000 && n <= 0x0AFFFFFF) ||
    (n >= 0xAC100000 && n <= 0xAC1FFFFF) ||
    (n >= 0xC0A80000 && n <= 0xC0A8FFFF) ||
    (n >= 0x7F000000 && n <= 0x7FFFFFFF) ||
    n === 0
  );
}

export function validateCidr(input: string): ValidationResult {
  const v = input.trim();
  const slash = v.indexOf('/');
  if (slash === -1) return { ok: false, reason: 'CIDR must include prefix length' };
  const ip = v.slice(0, slash);
  const prefixStr = v.slice(slash + 1);
  if (!/^\d{1,2}$/.test(prefixStr)) return { ok: false, reason: 'invalid prefix length' };
  const prefix = Number(prefixStr);
  if (prefix < 0 || prefix > 32) return { ok: false, reason: 'prefix must be 0-32' };
  const ipOk = validateIp(ip);
  if (!ipOk.ok) return ipOk;
  return { ok: true, value: `${ipOk.value}/${prefix}` };
}

export function cidrPrefixToSize(prefix: number): number {
  return 2 ** (32 - prefix);
}

export function validatePort(input: string): ValidationResult {
  const v = input.trim();
  if (!/^\d{1,5}$/.test(v)) return { ok: false, reason: 'port must be numeric' };
  const n = Number(v);
  if (n < 1 || n > 65535) return { ok: false, reason: 'port must be 1-65535' };
  return { ok: true, value: String(n) };
}

export function validatePortRange(input: string): ValidationResult {
  const v = input.trim();
  if (v.includes('-')) {
    const [a, b] = v.split('-');
    const lo = validatePort(a!);
    if (!lo.ok) return lo;
    const hi = validatePort(b!);
    if (!hi.ok) return hi;
    if (Number(lo.value) > Number(hi.value)) return { ok: false, reason: 'range start exceeds end' };
    return { ok: true, value: `${lo.value}-${hi.value}` };
  }
  return validatePort(v);
}

/** Path validation: deny shell metacharacters, control chars, NUL. */
export function validatePath(input: string): ValidationResult {
  const v = input.trim();
  if (v.length === 0) return { ok: false, reason: 'empty path' };
  if (v.length > 4096) return { ok: false, reason: 'path too long' };
  for (const ch of v) {
    if (SHELL_METACHARS.has(ch)) return { ok: false, reason: `shell metacharacter "${ch}" rejected` };
    const code = ch.charCodeAt(0);
    if (code < 0x20) return { ok: false, reason: 'control character rejected' };
  }
  // Windows reserved device names
  if (/^(con|prn|aux|nul|com[1-9]|lpt[1-9])(\.|$)/i.test(v.split(/[\\\/]/).pop() ?? '')) {
    return { ok: false, reason: 'reserved device name rejected' };
  }
  return { ok: true, value: v };
}

export function validateEnum(input: string, options: readonly string[]): ValidationResult {
  const v = input.trim();
  const match = options.find((o) => o === v);
  if (match === undefined) return { ok: false, reason: `must be one of: ${options.join(', ')}` };
  return { ok: true, value: match };
}

export function validateString(input: string): ValidationResult {
  const v = input.trim();
  if (v.length === 0) return { ok: false, reason: 'empty value' };
  for (const ch of v) {
    if (SHELL_METACHARS.has(ch)) return { ok: false, reason: `shell metacharacter "${ch}" rejected` };
    if (ch.charCodeAt(0) < 0x20) return { ok: false, reason: 'control character rejected' };
  }
  return { ok: true, value: v };
}

export function validateUrl(input: string): ValidationResult {
  const v = input.trim();
  let parsed: URL;
  try {
    parsed = new URL(v);
  } catch {
    return { ok: false, reason: 'invalid URL' };
  }
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    return { ok: false, reason: 'only http/https URLs allowed' };
  }
  const hostOk = validateDomain(parsed.hostname) ;
  if (!hostOk.ok) return hostOk;
  return { ok: true, value: parsed.toString() };
}

export function validateWordlist(input: string): ValidationResult {
  return validatePath(input);
}

/** Validate a value against a declared param schema. */
export function validateParam(schema: ParamSchema, raw: string): ValidationResult {
  switch (schema.kind) {
    case 'domain': return validateDomain(raw);
    case 'ip': return validateIp(raw);
    case 'cidr': return validateCidr(raw);
    case 'port': return validatePort(raw);
    case 'path': case 'wordlist': return validatePath(raw);
    case 'enum':
      if (!schema.options || schema.options.length === 0) return { ok: false, reason: 'enum has no options' };
      return validateEnum(raw, schema.options);
    case 'url': return validateUrl(raw);
    case 'string': default: return validateString(raw);
  }
}

export function paramKindLabel(kind: ParamKind): string {
  switch (kind) {
    case 'domain': return 'domain name (e.g. example.com)';
    case 'ip': return 'IPv4 address (e.g. 10.0.0.5)';
    case 'cidr': return 'CIDR range (e.g. 10.0.0.0/24)';
    case 'port': return 'port number (1-65535)';
    case 'path': return 'file/directory path';
    case 'wordlist': return 'wordlist file path';
    case 'enum': return 'one of the listed options';
    case 'url': return 'http/https URL';
    case 'string': default: return 'plain value';
  }
}
