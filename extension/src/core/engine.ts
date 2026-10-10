/**
 * Command engine: template registry + deterministic renderer + generation pipeline.
 *
 * SECURITY MODEL
 * - Only registered templates can produce commands. There is no code path that
 *   turns an arbitrary string into an executable command.
 * - Every parameter is validated (validators.ts) before rendering.
 * - Rendering is token-substitution with NO shell evaluation. Tokens are
 *   `{{param}}` or `{{param|modifier}}`. After substitution the finished command
 *   is re-scanned: if any `{{`/`}}` remains, or a substituted value introduced
 *   forbidden characters, generation fails.
 * - The command hash (SHA-256) binds approvals to the exact command string.
 */

import type {
  CommandTemplate, GenerationResult, ParamSchema, TargetProfile, TemplateFixture,
} from './types.ts';
import { validateParam } from './validators.ts';
import { checkScope } from './scope.ts';

// ---------------------------------------------------------------------------
// Registry
// ---------------------------------------------------------------------------

export interface ToolDefinition {
  readonly name: string;
  readonly aliases: readonly string[];
  readonly platforms: readonly ('linux' | 'windows' | 'macos')[];
  readonly homepage?: string;
}

class TemplateRegistry {
  private templatesById = new Map<string, CommandTemplate>();
  private tools = new Map<string, ToolDefinition>();
  private fixtures = new Map<string, TemplateFixture[]>();

  registerTool(tool: ToolDefinition): void {
    this.tools.set(tool.name.toLowerCase(), tool);
  }

  registerTemplate(t: CommandTemplate): void {
    if (this.templatesById.has(t.id)) {
      throw new Error(`duplicate template id: ${t.id}`);
    }
    this.templatesById.set(t.id, t);
  }

  registerFixtures(templateId: string, fixtures: readonly TemplateFixture[]): void {
    if (!this.templatesById.has(templateId)) {
      throw new Error(`fixtures for unknown template: ${templateId}`);
    }
    this.fixtures.set(templateId, [...fixtures]);
  }

  getTemplate(id: string): CommandTemplate | undefined {
    return this.templatesById.get(id);
  }

  findTemplatesByTool(toolName: string): CommandTemplate[] {
    const key = toolName.toLowerCase();
    return [...this.templatesById.values()].filter((t) => t.tool.toLowerCase() === key);
  }

  findTemplatesByCategory(category: string): CommandTemplate[] {
    return [...this.templatesById.values()].filter((t) => t.category === category);
  }

  allTemplates(): CommandTemplate[] {
    return [...this.templatesById.values()];
  }

  allTools(): ToolDefinition[] {
    return [...this.tools.values()];
  }

  /** Resolve a spoken/typed tool name or alias to the canonical tool name. */
  resolveToolName(input: string): string | null {
    const key = input.trim().toLowerCase();
    if (this.tools.has(key)) return this.tools.get(key)!.name;
    for (const tool of this.tools.values()) {
      if (tool.aliases.includes(key)) return tool.name;
    }
    return null;
  }

  fixturesFor(templateId: string): readonly TemplateFixture[] {
    return this.fixtures.get(templateId) ?? [];
  }
}

export const registry = new TemplateRegistry();

// ---------------------------------------------------------------------------
// Template rendering
// ---------------------------------------------------------------------------

/** Modifiers applied at render time. Kept intentionally minimal. */
type Modifier = 'upper' | 'lower' | 'quote' | 'raw';

function parseModifier(spec: string): Modifier {
  switch (spec) {
    case 'upper': case 'lower': case 'quote': case 'raw': return spec;
    default: throw new Error(`unknown template modifier: ${spec}`);
  }
}

export type RenderResult =
  | { readonly ok: true; readonly command: string }
  | { readonly ok: false; readonly reason: string };

export function renderTemplate(
  template: CommandTemplate,
  values: Readonly<Record<string, string>>,
): RenderResult {
  const substituted = template.template.replace(
    /\{\{\s*([a-zA-Z0-9_]+)(?:\|([a-zA-Z0-9_]+))?\s*\}\}/g,
    (whole, name: string, mod?: string) => {
      const key = name as string;
      const has = Object.prototype.hasOwnProperty.call(values, key);
      if (!has) throw new RenderError(`missing value for token "${key}"`);
      let v = values[key]!;
      if (mod !== undefined) {
        switch (parseModifier(mod)) {
          case 'upper': v = v.toUpperCase(); break;
          case 'lower': v = v.toLowerCase(); break;
          case 'quote': v = `'${v.replace(/'/g, "'\\''")}'`; break;
          case 'raw': break;
        }
      }
      return v;
    },
  );
  // Post-substitution safety net: no leftover tokens allowed.
  if (/\{\{|\}\}/.test(substituted)) {
    return { ok: false, reason: 'command contains unresolved tokens after substitution' };
  }
  return { ok: true, command: substituted.trim() };
}

/** Thrown inside the replace callback so we can convert to a typed failure. */
class RenderError extends Error {}

// ---------------------------------------------------------------------------
// SHA-256 command hash (Web Crypto, async)
// ---------------------------------------------------------------------------

export async function hashCommand(command: string): Promise<string> {
  const data = new TextEncoder().encode(command);
  const digest = await crypto.subtle.digest('SHA-256', data);
  return Array.from(new Uint8Array(digest)).map((b) => b.toString(16).padStart(2, '0')).join('');
}

// ---------------------------------------------------------------------------
// Generation pipeline
// ---------------------------------------------------------------------------

export interface GenerateOptions {
  readonly template: CommandTemplate;
  readonly target: TargetProfile;
  readonly suppliedParams: Readonly<Record<string, string>>;
  readonly authorizations: readonly import('./types.ts').AuthorizationRecord[];
  readonly now?: number;
}

/**
 * Resolve a parameter value: user-supplied first, then schema defaults from
 * the target profile. Returns null when neither exists (caller asks user).
 */
function resolveParam(
  schema: ParamSchema,
  supplied: Readonly<Record<string, string>>,
  target: TargetProfile,
): string | null {
  if (Object.prototype.hasOwnProperty.call(supplied, schema.name)) {
    return supplied[schema.name]!;
  }
  switch (schema.defaultFrom) {
    case 'target.value': return target.value;
    case 'target.os': return target.os ?? null;
    case 'target.shell': return target.shell ?? null;
    default: return null;
  }
}

export async function generateCommand(opts: GenerateOptions): Promise<GenerationResult> {
  const { template, target, suppliedParams, authorizations } = opts;
  const now = opts.now ?? Date.now();

  // 1. Scope & authorization check FIRST — before any work.
  const scope = checkScope(target, target.value, template.riskLevel, authorizations, now);
  if (scope.decision === 'reject') {
    return { type: 'out-of-scope', reason: scope.reason };
  }

  // 2. Tool installed + version compatibility.
  const installed = target.installedTools[template.tool.toLowerCase()]
    ?? target.installedTools[template.tool];
  if (installed === undefined) {
    return { type: 'tool-not-installed', tool: template.tool };
  }
  if (template.toolVersionRange && installed && !versionIn(installed, template.toolVersionRange)) {
    return { type: 'version-unsupported', tool: template.tool, installed, required: template.toolVersionRange };
  }

  //  installed can be null (known-present, unknown version) — treat as compatible.
  if (installed === undefined) {
    return { type: 'tool-not-installed', tool: template.tool };
  }

  // 3. Resolve + validate every parameter.
  const values: Record<string, string> = {};
  for (const schema of template.params) {
    const raw = resolveParam(schema, suppliedParams, target);
    if (raw === null) {
      if (schema.required) {
        return { type: 'missing-param', param: schema.name, paramDescription: schema.description };
      }
      continue;
    }
    const v = validateParam(schema, raw);
    if (!v.ok) {
      return { type: 'invalid-param', param: schema.name, reason: v.reason };
    }
    values[schema.name] = v.value;
  }

  // 4. Render.
  let command: string;
  try {
    const rendered = renderTemplate(template, values);
    if (!rendered.ok) return { type: 'invalid-param', param: '__template__', reason: rendered.reason };
    command = rendered.command;
  } catch (e) {
    return { type: 'invalid-param', param: '__template__', reason: `render failed: ${String(e)}` };
  }

  // 5. Hash + candidate.
  const commandHash = await hashCommand(command);
  return {
    ok: true,
    candidate: {
      command,
      template,
      tool: template.tool,
      riskLevel: template.riskLevel,
      commandHash,
      targetId: target.id,
    },
  };
}

/** Very small semver range check: ">=1.0.0 <2.0.0" or exact "x.y.z". */
export function versionIn(version: string, range: string): boolean {
  const parts = range.trim().split(/\s+/);
  if (parts.length === 1 && /^\d+(\.\d+)*$/.test(parts[0]!)) {
    return parts[0] === version;
  }
  const toTuple = (s: string): number[] => s.split('.').map((x) => Number(x) || 0);
  const v = toTuple(version);
  for (const part of parts) {
    const m = /^(>=|<=|>|<)?(\d+(?:\.\d+)*|\*)$/.exec(part);
    if (!m) continue;
    const [, op, rhs] = m;
    if (rhs === '*') continue;
    const r = toTuple(rhs!);
    const cmp = compareTuples(v, r);
    if (op === '>' && !(cmp > 0)) return false;
    if (op === '<' && !(cmp < 0)) return false;
    if (op === '>=' && !(cmp >= 0)) return false;
    if (op === '<=' && !(cmp <= 0)) return false;
    if (!op && cmp !== 0) return false;
  }
  return true;
}

function compareTuples(a: number[], b: number[]): number {
  const len = Math.max(a.length, b.length);
  for (let i = 0; i < len; i++) {
    const x = a[i] ?? 0;
    const y = b[i] ?? 0;
    if (x !== y) return x - y;
  }
  return 0;
}
