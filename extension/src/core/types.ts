/**
 * CyberPilot core domain types.
 * These types are the contract between the intent engine, command engine,
 * registry, validation, authorization, and the approval state machine.
 */

// ---------------------------------------------------------------------------
// Risk & authorization
// ---------------------------------------------------------------------------

/**
 * Risk levels. Level 3 is never auto-executed and never included in batch runs.
 */
export type RiskLevel = 0 | 1 | 2 | 3;

/**
 * Authorization state for a target scope. NEVER treated as proof of authorization;
 * active testing requires a fresh acknowledgement record.
 */
export interface AuthorizationRecord {
  readonly id: string;
  readonly targetId: string;
  /** Scope entries this authorization covers. */
  readonly scopeEntries: readonly ScopeEntry[];
  /** Max risk level permitted by this record. */
  readonly maxRiskLevel: RiskLevel;
  readonly grantedAt: number;
  readonly expiresAt: number;
  /** Reference to the document/consent that backs this record (opaque string, no secrets). */
  readonly reference?: string;
}

// ---------------------------------------------------------------------------
// Scope
// ---------------------------------------------------------------------------

export type ScopeKind =
  | 'exact-domain'
  | 'approved-subdomain'
  | 'single-ip'
  | 'approved-cidr'
  | 'local-lab'
  | 'ctf-environment';

export interface ScopeEntry {
  readonly kind: ScopeKind;
  readonly value: string;
}

export type ScopeDecision =
  | { readonly decision: 'allow'; readonly via: ScopeEntry }
  | { readonly decision: 'reject'; readonly reason: string };

// ---------------------------------------------------------------------------
// Target profiles
// ---------------------------------------------------------------------------

export type TargetType = 'domain' | 'ip' | 'cidr' | 'local-lab' | 'ctf';

export interface TargetProfile {
  readonly id: string;
  readonly name: string;
  readonly targetType: TargetType;
  readonly value: string;
  readonly os?: 'linux' | 'windows' | 'macos';
  readonly shell?: 'bash' | 'zsh' | 'powershell' | 'cmd' | 'sh';
  readonly scopeEntries: readonly ScopeEntry[];
  /** Installed tool names -> versions. */
  readonly installedTools: Readonly<Record<string, string>>;
  readonly authorizationRecordIds: readonly string[];
  readonly createdAt: number;
  readonly updatedAt: number;
}

// ---------------------------------------------------------------------------
// Command templates
// ---------------------------------------------------------------------------

export type ParamKind =
  | 'domain'
  | 'ip'
  | 'cidr'
  | 'port'
  | 'path'
  | 'enum'
  | 'string'
  | 'wordlist'
  | 'flag'
  | 'url';

export interface ParamSchema {
  readonly name: string;
  readonly kind: ParamKind;
  readonly required: boolean;
  readonly description: string;
  /** For enum kinds. */
  readonly options?: readonly string[];
  /** For numeric kinds. */
  readonly min?: number;
  readonly max?: number;
  /** Where the value comes from when the user doesn't supply it. */
  readonly defaultFrom?: 'target.value' | 'target.os' | 'target.shell';
  /** For wordlist params: well-known directory names resolvable via agent detection. */
  readonly wordlistDirs?: readonly string[];
}

export interface CommandTemplate {
  readonly id: string;
  readonly version: number;
  readonly tool: string;
  readonly operation: string;
  readonly description: string;
  readonly category: string;
  readonly params: readonly ParamSchema[];
  /** Render tokens; see core/render.ts. */
  readonly template: string;
  readonly supportedOS: readonly ('linux' | 'windows' | 'macos')[];
  readonly supportedShells: readonly ('bash' | 'zsh' | 'powershell' | 'cmd' | 'sh')[];
  /** Tool version compatibility, semver-ish inclusive ranges. */
  readonly toolVersionRange?: string;
  readonly riskLevel: RiskLevel;
  /** Authorization category enforced before generation/copy for risk >= 1. */
  readonly authorizationRequired: boolean;
  readonly timeoutMs?: number;
  readonly outputParser?: string;
  readonly docsUrl?: string;
}

export interface TemplateFixture {
  readonly templateId: string;
  readonly inputs: Readonly<Record<string, string>>;
  readonly expectedCommand: string;
}

// ---------------------------------------------------------------------------
// Intent & generation
// ---------------------------------------------------------------------------

export type IntentKind =
  | 'generate-command'
  | 'explain-command'
  | 'suggest-tool'
  | 'approve'
  | 'reject'
  | 'cancel'
  | 'copy'
  | 'execute'
  | 'unknown';

export interface Intent {
  readonly kind: IntentKind;
  readonly confidence: number;
  /** Requested tool name if resolved, else null. */
  readonly tool: string | null;
  readonly category: string | null;
  readonly operation: string | null;
  readonly params: Readonly<Record<string, string>>;
  /** Required params that were mentioned but failed validation. */
  readonly invalidParams: readonly string[];
  /** True when intent came from voice input. */
  readonly fromVoice: boolean;
}

// ---------------------------------------------------------------------------
// Generation result
// ---------------------------------------------------------------------------

export type GenerationFailure =
  | { readonly type: 'tool-not-found' }
  | { readonly type: 'tool-not-installed'; readonly tool: string }
  | { readonly type: 'missing-param'; readonly param: string; readonly paramDescription: string }
  | { readonly type: 'invalid-param'; readonly param: string; readonly reason: string }
  | { readonly type: 'out-of-scope'; readonly reason: string }
  | { readonly type: 'unauthorized'; readonly reason: string }
  | { readonly type: 'risk-blocked'; readonly reason: string }
  | { readonly type: 'version-unsupported'; readonly tool: string; readonly installed: string; readonly required: string }
  | { readonly type: 'ambiguous-target' };

export interface CommandCandidate {
  readonly command: string;
  readonly template: CommandTemplate;
  readonly tool: string;
  readonly riskLevel: RiskLevel;
  /** SHA-256 of the exact command string, used for approval binding. */
  readonly commandHash: string;
  readonly targetId: string | null;
}

export type GenerationResult =
  | { readonly ok: true; readonly candidate: CommandCandidate }
  | GenerationFailure;

// ---------------------------------------------------------------------------
// Approval state machine
// ---------------------------------------------------------------------------

export type ApprovalState =
  | 'IDLE'
  | 'COMMAND_GENERATED'
  | 'VALIDATION'
  | 'AWAITING_APPROVAL'
  | 'COPYING'
  | 'COPIED'
  | 'AWAITING_USER_ACTION'
  | 'CANCELLED'
  | 'REJECTED';

export interface ApprovalContext {
  readonly commandHash: string;
  readonly templateId: string;
  readonly templateVersion: number;
  readonly targetId: string | null;
  readonly riskLevel: RiskLevel;
  readonly requestedAt: number;
  readonly approvalTtlMs: number;
}

export type ApprovalTransition =
  | { readonly to: 'AWAITING_APPROVAL'; readonly ctx: ApprovalContext }
  | { readonly to: 'COPYING'; readonly ctx: ApprovalContext; readonly at: number }
  | { readonly to: 'COPIED'; readonly ctx: ApprovalContext; readonly at: number }
  | { readonly to: 'CANCELLED'; readonly reason: string }
  | { readonly to: 'REJECTED'; readonly reason: string };

// ---------------------------------------------------------------------------
// Audit
// ---------------------------------------------------------------------------

export interface AuditEntry {
  readonly id: string;
  readonly ts: number;
  readonly kind:
    | 'generated'
    | 'approved'
    | 'copy'
    | 'execute-request'
    | 'execute-rejected'
    | 'scope-block'
    | 'auth-block';
  readonly targetId: string | null;
  readonly templateId: string | null;
  readonly templateVersion?: number;
  readonly riskLevel?: RiskLevel;
  readonly commandHash?: string;
  readonly reason?: string;
}
