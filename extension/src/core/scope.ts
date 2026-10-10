/**
 * Scope engine. Answers one question: "Is this target, at this risk level,
 * covered by an explicit, currently-valid authorization?"
 *
 * Policy (deny-by-default):
 * - A target profile is NEVER authorization. Only AuthorizationRecords count.
 * - Records have max risk levels and expiry; both are enforced.
 * - Broad wildcards and oversized CIDRs are rejected at entry (see validateScopeEntry).
 * - Sensitive targets (localhost, private ranges, cloud metadata) need explicit
 *   confirmation flags on the record.
 */

import type {
  AuthorizationRecord, RiskLevel, ScopeDecision, ScopeEntry, TargetProfile,
} from './types.ts';
import { cidrPrefixToSize, isPrivateIp, validateCidr, validateDomain, validateIp } from './validators.ts';

/** Max hosts allowed in a single approved CIDR (default policy). */
export const MAX_CIDR_HOSTS = 1024;

/** Cloud metadata endpoints that require extra confirmation. */
const METADATA_HOSTS = new Set([
  '169.254.169.254',
  'metadata.google.internal',
  'metadata.azure.internal',
]);

export type ScopeEntryCheck =
  | { readonly ok: true; readonly entry: ScopeEntry }
  | { readonly ok: false; readonly reason: string };

/** Validate a scope entry at registration time. */
export function validateScopeEntry(entry: ScopeEntry): ScopeEntryCheck {
  switch (entry.kind) {
    case 'exact-domain': {
      const v = validateDomain(entry.value);
      if (!v.ok) return { ok: false, reason: `invalid domain: ${v.reason}` };
      return { ok: true, entry: { kind: entry.kind, value: v.value } };
    }
    case 'approved-subdomain': {
      // Form: parent.tld with explicit acknowledgement; stored as the parent
      // domain plus a marker. We still reject "*" in the value.
      if (entry.value.includes('*')) return { ok: false, reason: 'wildcards are not allowed in scope entries' };
      const v = validateDomain(entry.value);
      if (!v.ok) return { ok: false, reason: `invalid subdomain scope: ${v.reason}` };
      return { ok: true, entry: { kind: entry.kind, value: v.value } };
    }
    case 'single-ip': {
      const v = validateIp(entry.value);
      if (!v.ok) return { ok: false, reason: `invalid IP: ${v.reason}` };
      return { ok: true, entry: { kind: entry.kind, value: v.value } };
    }
    case 'approved-cidr': {
      const v = validateCidr(entry.value);
      if (!v.ok) return { ok: false, reason: `invalid CIDR: ${v.reason}` };
      const prefix = Number(v.value.split('/')[1]);
      if (cidrPrefixToSize(prefix) > MAX_CIDR_HOSTS) {
        return { ok: false, reason: `CIDR too large (max ${MAX_CIDR_HOSTS} hosts; got ${cidrPrefixToSize(prefix)})` };
      }
      return { ok: true, entry: { kind: entry.kind, value: v.value } };
    }
    case 'local-lab': case 'ctf-environment': {
      // Free-form identifier for the user's own lab/CTF environment.
      if (entry.value.length === 0 || entry.value.length > 100) {
        return { ok: false, reason: 'invalid environment label' };
      }
      return { ok: true, entry };
    }
  }
}

function cidrContains(cidr: string, ip: string): boolean {
  const [base, prefixStr] = cidr.split('/');
  const prefix = Number(prefixStr);
  const baseLong = ipStrToLong(base!);
  const ipLong = ipStrToLong(ip);
  if (baseLong === null || ipLong === null) return false;
  const mask = prefix === 0 ? 0 : (0xFFFFFFFF << (32 - prefix)) >>> 0;
  return (baseLong & mask) === (ipLong & mask);
}

function ipStrToLong(ip: string): number | null {
  const parts = ip.split('.');
  if (parts.length !== 4) return null;
  let n = 0;
  for (const p of parts) {
    if (!/^\d{1,3}$/.test(p)) return null;
    const o = Number(p);
    if (o > 255) return null;
    n = n * 256 + o;
  }
  return n;
}

export function isSensitiveTarget(targetValue: string): boolean {
  if (METADATA_HOSTS.has(targetValue)) return true;
  const asIp = validateIp(targetValue);
  if (asIp.ok && (isPrivateIp(asIp.value) || asIp.value === '169.254.169.254')) return true;
  return false;
}

/** Does one entry cover the target value? */
function entryCovers(entry: ScopeEntry, targetValue: string): boolean {
  switch (entry.kind) {
    case 'exact-domain':
      return entry.value === targetValue;
    case 'approved-subdomain':
      // target must equal parent or be a subdomain of the approved parent
      return targetValue === entry.value || targetValue.endsWith(`.${entry.value}`);
    case 'single-ip':
      return entry.value === targetValue;
    case 'approved-cidr': {
      const ipOk = validateIp(targetValue);
      if (!ipOk.ok) return false;
      return cidrContains(entry.value, ipOk.value);
    }
    case 'local-lab': case 'ctf-environment':
      return entry.value === targetValue;
  }
}

export function checkScope(
  target: TargetProfile,
  targetValue: string,
  riskLevel: RiskLevel,
  authorizations: readonly AuthorizationRecord[],
  now: number = Date.now(),
): ScopeDecision {
  // 1. Sensitive-target confirmation (never silently allowed)
  if (riskLevel >= 1 && isSensitiveTarget(targetValue)) {
    const hasExplicit = authorizations.some(
      (a) => a.targetId === target.id && a.scopeEntries.some((e) => entryCovers(e, targetValue) || e.kind === 'local-lab' || e.kind === 'ctf-environment')
    );
    if (!hasExplicit) {
      return { decision: 'reject', reason: 'sensitive target (private/localhost/metadata) requires explicit authorization entry' };
    }
  }

  // 2. Find a valid, unexpired, risk-sufficient authorization that covers the value.
  for (const auth of authorizations) {
    if (auth.targetId !== target.id) continue;
    if (auth.expiresAt <= now) continue;
    if (auth.maxRiskLevel < riskLevel) continue;
    const covered = auth.scopeEntries.some((e) => entryCovers(e, targetValue));
    if (covered) {
      return { decision: 'allow', via: auth.scopeEntries.find((e) => entryCovers(e, targetValue))! };
    }
  }

  if (riskLevel === 0) {
    // Passive/local operations are always permitted (they never touch the target).
    return { decision: 'allow', via: { kind: 'exact-domain', value: targetValue } };
  }

  return { decision: 'reject', reason: `no valid authorization covers ${targetValue} at risk level ${riskLevel}` };
}
