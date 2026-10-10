/**
 * Popup controller: sends the user's typed request to the background worker,
 * renders the generated command, and handles approve/reject/copy flow.
 * Voice input (Web Speech API) is a later phase — text input works now.
 */

const input = document.querySelector<HTMLInputElement>('#input')!;
const out = document.querySelector<HTMLDivElement>('#out')!;
const status = document.querySelector<HTMLDivElement>('#status')!;

let pendingHash: string | null = null;

function send(msg: unknown): Promise<any> {
  return new Promise((resolve) => {
    chrome.runtime.sendMessage(msg, (res) => resolve(res));
  });
}

async function handleSubmit(): Promise<void> {
  const text = input.value.trim();
  if (!text) return;
  status.textContent = 'Processing…';

  const cls = await send({ type: 'classify', text, fromVoice: false });
  const intent = cls?.intent;
  if (!intent || intent.kind === 'unknown') {
    out.textContent = 'Could not map that to a command. Try e.g. "nmap scan karo 10.0.0.5".';
    status.textContent = '';
    return;
  }
  if (intent.kind === 'approve' || intent.kind === 'reject' || intent.kind === 'cancel') {
    await send({ type: intent.kind === 'approve' ? 'approve-copy' : intent.kind });
    status.textContent = intent.kind === 'approve' ? 'Copied. Paste in your terminal.' : 'Cancelled.';
    return;
  }

  const gen = await send({
    type: 'generate',
    intentTool: intent.tool,
    intentOperation: intent.operation,
    params: intent.params,
  });
  const result = gen?.result;
  if (!gen?.ok) {
    out.textContent = gen?.error ?? 'Generation failed.';
    status.textContent = '';
    return;
  }
  if (result?.ok) {
    pendingHash = result.candidate.commandHash;
    out.textContent = result.candidate.command;
    status.textContent = `Risk ${result.candidate.riskLevel} — say/type "yes" to copy to clipboard.`;
  } else {
    const map: Record<string, string> = {
      'out-of-scope': 'Target not authorized for this operation. Add authorization in the dashboard.',
      'tool-not-installed': 'Tool not marked installed on the target profile.',
      'missing-param': `Missing parameter: ${result.paramDescription ?? result.param}`,
      'version-unsupported': 'Tool version on target is outside the supported range.',
    };
    out.textContent = map[result.type] ?? `Blocked: ${result.type}`;
    status.textContent = '';
  }
}

async function handleKey(e: KeyboardEvent): Promise<void> {
  if (e.key !== 'Enter' || !pendingHash) return;
  const res = await send({ type: 'approve-copy', commandHash: pendingHash });
  status.textContent = res?.ok ? 'Copied — paste in your terminal and press Enter.' : (res?.error ?? 'Not copied.');
}

input.addEventListener('keydown', (e) => {
  if (e.key === 'Enter') {
    if (pendingHash) void handleKey(e);
    else void handleSubmit();
  }
});
input.addEventListener('change', () => void handleSubmit());
