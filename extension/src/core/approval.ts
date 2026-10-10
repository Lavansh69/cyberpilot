/**
 * Approval state machine. Enforces the strict separation between generating,
 * approving, copying, and (separately) executing a command.
 *
 * INVARIANTS (tested in state machine tests):
 * 1. Copying never triggers execution. There is no transition from COPIED to
 *    any execution state. Execution requires a separate, explicitly-granted
 *    agent execution approval — clipboard approval does NOT count.
 * 2. Every approval is bound to the EXACT command hash. A changed command
 *    invalidates the pending approval.
 * 3. Approvals expire (default 60s). Expired approvals are rejected.
 * 4. A command that reached COPIED is reported as "copied", never "executed".
 * 5. Changing the target cancels any pending approval.
 */

import type { ApprovalContext, ApprovalState, CommandCandidate } from './types.ts';

export const DEFAULT_APPROVAL_TTL_MS = 60_000;

export interface ApprovalSnapshot {
  readonly state: ApprovalState;
  readonly pending: ApprovalContext | null;
  readonly lastCopied: { readonly ctx: ApprovalContext; readonly at: number } | null;
}

export function initialApprovalSnapshot(): ApprovalSnapshot {
  return { state: 'IDLE', pending: null, lastCopied: null };
}

export class ApprovalMachine {
  private snapshot: ApprovalSnapshot = initialApprovalSnapshot();
  private readonly onTransition?: (s: ApprovalSnapshot) => void;

  constructor(onTransition?: (s: ApprovalSnapshot) => void) {
    this.onTransition = onTransition;
  }

  get current(): ApprovalSnapshot {
    return this.snapshot;
  }

  private set(next: ApprovalSnapshot): void {
    this.snapshot = next;
    this.onTransition?.(next);
  }

  /** A new command was generated and validated. Begin approval flow. */
  offer(candidate: CommandCandidate, requestedAt: number = Date.now()): ApprovalContext {
    const ctx: ApprovalContext = {
      commandHash: candidate.commandHash,
      templateId: candidate.template.id,
      templateVersion: candidate.template.version,
      targetId: candidate.targetId,
      riskLevel: candidate.riskLevel,
      requestedAt,
      approvalTtlMs: DEFAULT_APPROVAL_TTL_MS,
    };
    this.set({ ...this.snapshot, state: 'AWAITING_APPROVAL', pending: ctx });
    return ctx;
  }

  /**
   * User approved copying (voice "yes" or Enter key). The approval is only
   * accepted if it matches the EXACT pending command hash and is unexpired.
   * This transitions to COPYING and performs the clipboard write via the
   * provided callback — never an execution.
   */
  approveCopy(
    commandHash: string,
    now: number = Date.now(),
    doCopy: (candidate: CommandCandidate) => Promise<void>,
    candidate: CommandCandidate,
  ): { ok: true; ctx: ApprovalContext } | { ok: false; reason: string } {
    const pending = this.snapshot.pending;
    if (!pending) return { ok: false, reason: 'no pending command' };
    if (pending.commandHash !== commandHash) {
      this.cancel('command changed since approval');
      return { ok: false, reason: 'command changed since approval' };
    }
    if (now - pending.requestedAt > pending.approvalTtlMs) {
      this.cancel('approval expired');
      return { ok: false, reason: 'approval expired' };
    }
    this.set({ ...this.snapshot, state: 'COPYING', pending });
    void doCopy(candidate)
      .then(() => {
        this.set({
          state: 'COPIED',
          pending: null,
          lastCopied: { ctx: pending, at: Date.now() },
        });
        // COPIED → AWAITING_USER_ACTION is the terminal clipboard state.
        // There is NO transition to any execution state from here.
        this.set({ ...this.snapshot, state: 'AWAITING_USER_ACTION' });
      })
      .catch(() => {
        this.cancel('clipboard write failed');
      });
    return { ok: true, ctx: pending };
  }

  /** User rejected the copy. */
  reject(reason = 'user rejected'): void {
    this.set({ state: 'REJECTED', pending: null, lastCopied: this.snapshot.lastCopied });
  }

  /** Cancel pending approval (command changed, target changed, explicit cancel). */
  cancel(reason: string): void {
    this.set({ state: 'CANCELLED', pending: null, lastCopied: this.snapshot.lastCopied });
  }

  /** Explicit reset to IDLE (e.g., user starts a new request). */
  reset(): void {
    this.set(initialApprovalSnapshot());
  }
}
