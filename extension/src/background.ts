/**
 * Background service worker (MV3, module type).
 * Responsibilities:
 * - Registers built-in templates once at startup.
 * - Bridges popup UI to the core engine (message passing).
 * - Owns the ApprovalMachine instance (survives popup close).
 */

import { generateCommand, registry } from './core/engine.ts';
import { classifyIntent } from './core/intent.ts';
import { ApprovalMachine } from './core/approval.ts';
import { registerBuiltinTemplates } from './data/templates.ts';
import type { AuthorizationRecord, CommandCandidate, TargetProfile } from './core/types.ts';

let approvalMachine = new ApprovalMachine();

registerBuiltinTemplates();

type Message =
  | { type: 'classify'; text: string; fromVoice: boolean }
  | { type: 'generate'; intentTool: string | null; intentOperation: string | null; params: Record<string, string> }
  | { type: 'approve-copy'; commandHash: string }
  | { type: 'cancel' }
  | { type: 'reject' };

// In-memory state for the current session. Persistence (IndexedDB) is a later phase.
let currentCandidate: CommandCandidate | null = null;
let currentTarget: TargetProfile | null = null;
let currentAuthorizations: AuthorizationRecord[] = [];

chrome.runtime.onMessage.addListener((msg: Message, _sender, sendResponse) => {
  (async () => {
    switch (msg.type) {
      case 'classify': {
        const intent = classifyIntent(msg.text, msg.fromVoice);
        sendResponse({ ok: true, intent });
        break;
      }
      case 'generate': {
        if (!currentTarget) {
          sendResponse({ ok: false, error: 'no active target profile' });
          break;
        }
        const templates = registry.findTemplatesByTool(msg.intentTool ?? '');
        const template = templates.find((t) => t.operation === msg.intentOperation) ?? templates[0];
        if (!template) {
          sendResponse({ ok: false, error: 'no matching template' });
          break;
        }
        const result = await generateCommand({
          template,
          target: currentTarget,
          suppliedParams: msg.params,
          authorizations: currentAuthorizations,
        });
        if (result.ok) {
          currentCandidate = result.candidate;
          approvalMachine.offer(result.candidate);
        } else {
          currentCandidate = null;
        }
        sendResponse({ ok: true, result });
        break;
      }
      case 'approve-copy': {
        if (!currentCandidate) {
          sendResponse({ ok: false, error: 'no pending candidate' });
          break;
        }
        const approval = approvalMachine.approveCopy(
          msg.commandHash,
          Date.now(),
          async (candidate) => {
            await writeClipboard(candidate.command);
          },
          currentCandidate,
        );
        sendResponse({ ok: approval.ok, error: approval.ok ? undefined : approval.reason });
        break;
      }
      case 'cancel': {
        approvalMachine.cancel('user cancel');
        currentCandidate = null;
        sendResponse({ ok: true });
        break;
      }
      case 'reject': {
        approvalMachine.reject('user reject');
        currentCandidate = null;
        sendResponse({ ok: true });
        break;
      }
    }
  })();
  return true; // async sendResponse
});

async function writeClipboard(command: string): Promise<void> {
  await navigator.clipboard.writeText(command);
}

export {};
