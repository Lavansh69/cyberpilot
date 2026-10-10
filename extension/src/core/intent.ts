/**
 * Intent engine. Converts natural language (English + common Hinglish) into a
 * structured Intent — fully local and deterministic, no AI call required.
 *
 * Design:
 * - Normalizes input (lowercase, trim, collapse whitespace).
 * - Hinglish keyword variants are mapped alongside English keywords.
 * - Tool resolution goes through the registry (name or alias).
 * - Numbers, IPs, domains, ports, and quoted paths are extracted as params.
 * - Confidence is derived from how much of the request was resolved.
 */

import type { Intent } from './types.ts';
import { registry } from './engine.ts';

/** Normalize: lowercase, collapse whitespace, strip punctuation noise. */
function normalize(input: string): string {
  return input
    .toLowerCase()
    .replace(/[\u2018\u2019]/g, "'")
    .replace(/[.,!?;]+/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();
}

/** Hinglish → English tool phrase mapping (matched anywhere in input). */
const HINGLISH_TOOL_PHRASES: ReadonlyArray<readonly [string, string]> = [
  ['nmap karo', 'nmap scan'],
  ['scan karo', 'scan'],
  ['scan kar', 'scan'],
  ['nikalo', 'lookup'],
  ['dikhao', 'show'],
  ['dikhado', 'show'],
  ['batao', 'lookup'],
  ['chalu karo', 'run'],
  ['kholo', 'open'],
  ['header dekho', 'fetch headers'],
  ['metadata nikalo', 'extract metadata'],
  ['certificate check karo', 'inspect certificate'],
  ['certificate dekho', 'inspect certificate'],
  ['directory brute force karo', 'directory enumeration'],
  ['dirs nikalo', 'directory enumeration'],
  ['subdomain nikalo', 'subdomain enumeration'],
];

/** Approval words (voice "yes"). */
const APPROVE_WORDS = new Set(['yes', 'haan', 'han', 'ha', 'yep', 'yeah', 'sure', 'ok', 'okay', 'confirm', 'done', 'copy']);
const REJECT_WORDS = new Set(['no', 'nahi', 'nahin', 'na', 'nope', 'cancel', 'reject', 'abort', 'band karo']);
const CANCEL_WORDS = new Set(['cancel', 'stop', 'ruk jao', 'ruko', 'band karo', 'khatam karo', 'abort']);

/** Extract an IPv4 from text. */
function extractIp(text: string): string | null {
  const m = /\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b/.exec(text);
  return m ? m[1]! : null;
}

/** Extract a domain (not part of a URL, not an IP). */
function extractDomain(text: string): string | null {
  const m = /\b((?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,})\b/.exec(text);
  if (!m) return null;
  const d = m[1]!;
  // avoid matching version-like strings e.g. "tool 1.2.3"
  if (/^\d/.test(d)) return null;
  return d;
}

/** Extract a URL. */
function extractUrl(text: string): string | null {
  const m = /\b(https?:\/\/[^\s]+)\b/.exec(text);
  return m ? m[1]! : null;
}

/** Extract a port number. */
function extractPort(text: string): string | null {
  const m = /\b(?:port\s*|:)(\d{1,5})\b/.exec(text);
  return m ? m[1]! : null;
}

/** Extract a quoted or token-looking file path. */
function extractPath(text: string): string | null {
  const quoted = /['"]([^'"]+)['"]/.exec(text);
  if (quoted) return quoted[1]!;
  const m = /(^|\s)((?:\/|~\/|\w:[\\/])[^\s]+)/.exec(text);
  return m ? m[2]! : null;
}

/** Extract a wordlist filename (common list names). */
function extractWordlist(text: string): string | null {
  const m = /\b([a-z0-9_-]+\.txt)\b/.exec(text);
  return m ? m[1]! : null;
}

export function classifyIntent(rawInput: string, fromVoice: boolean): Intent {
  let text = normalize(rawInput);

  // Apply Hinglish phrase mapping (longest first).
  const phrases = [...HINGLISH_TOOL_PHRASES].sort((a, b) => b[0].length - a[0].length);
  for (const [hinglish, english] of phrases) {
    if (text.includes(hinglish)) {
      text = text.replace(hinglish, english);
    }
  }

  // Single-word responses: approve / reject / cancel.
  const firstWord = text.split(' ')[0] ?? '';
  if (APPROVE_WORDS.has(text)) {
    return { kind: 'approve', confidence: 1, tool: null, category: null, operation: null, params: {}, invalidParams: [], fromVoice };
  }
  if (REJECT_WORDS.has(text)) {
    return { kind: 'reject', confidence: 1, tool: null, category: null, operation: null, params: {}, invalidParams: [], fromVoice };
  }
  if (CANCEL_WORDS.has(text)) {
    return { kind: 'cancel', confidence: 1, tool: null, category: null, operation: null, params: {}, invalidParams: [], fromVoice };
  }

  // Resolve tool via registry (name or alias appears in the input).
  let tool: string | null = null;
  for (const t of registry.allTools()) {
    if (text.includes(t.name.toLowerCase())) { tool = t.name; break; }
    if (t.aliases.some((a) => text.includes(a))) { tool = t.name; break; }
  }

  // Resolve operation hints.
  let operation: string | null = null;
  if (tool === 'nmap') {
    if (text.includes('service') || text.includes('version')) operation = 'service-detection';
    else if (text.includes('top')) operation = 'port-scan-top';
    else operation = 'service-detection'; // default nmap intent
  } else if (tool === 'curl') {
    operation = 'fetch-headers';
  } else if (tool === 'openssl') {
    operation = 'cert-inspect';
  } else if (tool === 'dig') {
    operation = 'dns-lookup';
  } else if (tool === 'exiftool') {
    operation = 'metadata-extract';
  } else if (tool === 'git') {
    if (text.includes('status')) operation = 'status';
  } else if (tool === 'gobuster') {
    operation = 'directory-enumeration';
  }

  // If no tool but user explicitly asked for a scan, suggest nmap.
  const wantsScan = /\bscan|scan karo|port scan|scan kar\b/.test(text);
  if (!tool && wantsScan) {
    tool = 'nmap';
    operation = operation ?? (text.includes('top') ? 'port-scan-top' : 'service-detection');
  }

  // Extract params.
  const params: Record<string, string> = {};
  const url = extractUrl(text);
  if (url) params.url = url;
  const ip = extractIp(text);
  if (ip) params.target = ip;
  const domain = extractDomain(text);
  if (domain && !ip) params.domain = domain;
  if (domain && !ip) params.target = domain; // target fallback for domain targets
  const port = extractPort(text);
  if (port) params.port = port;
  const path = extractPath(text);
  if (path) params.file = path;
  const wordlist = extractWordlist(text);
  if (wordlist) params.wordlist = wordlist;

  // Explain requests.
  if (/\b(explain|kya hai|what is|kya karta|samjhao|samjha)\b/.test(text) && tool) {
    return { kind: 'explain-command', confidence: 0.9, tool, category: null, operation, params, invalidParams: [], fromVoice };
  }

  if (!tool) {
    return { kind: 'unknown', confidence: 0, tool: null, category: null, operation: null, params, invalidParams: [], fromVoice };
  }

  // Confidence: base on how specific the request was.
  let confidence = 0.6;
  if (operation) confidence += 0.2;
  if (Object.keys(params).length > 0) confidence += 0.1;

  return {
    kind: 'generate-command',
    confidence: Math.min(confidence, 0.95),
    tool,
    category: null,
    operation,
    params,
    invalidParams: [],
    fromVoice,
  };
}
