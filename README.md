# CyberPilot

**AI-Powered Cybersecurity Assistant — Voice-to-Command Engine, Chrome Extension, and Secure Terminal Integration**

CyberPilot helps security professionals and students describe a technical task naturally (by voice or text) and get the **correct, validated command** almost instantly — without memorizing syntax, flags, or wordlist paths.

## Core philosophy

1. **Local-first**: Common commands generate deterministically, offline, with no AI call.
2. **Security first**: Scope + authorization + risk checks run before any active-testing command. Security is never bypassed for performance.
3. **Copy ≠ Execute**: The user approves a *clipboard copy*. The user then pastes into their own terminal and presses Enter themselves. CyberPilot never simulates keystrokes and never auto-executes.

## Monorepo layout

```
extension/          Chrome Extension (Manifest V3, TypeScript, React, Vite)
  src/
    core/           Command engine, tool registry, intent engine, validators
    state/          Approval state machine, caches, persistence (IndexedDB)
    ui/             Popup, dashboard panels, voice panel
agent/              Python local terminal agent (loopback-only, registered operations)
docs/               Architecture and security documentation
```

## Key state separation

CyberPilot keeps these as strictly separate states, never confused:

- **Generate** — build a command from a template + validated parameters
- **Approve (copy)** — user explicitly approves clipboard copy; bound to a command hash, target, and risk level
- **Copy** — clipboard contains the validated command
- **Paste + Enter** — done by the human, in their own terminal. CyberPilot has no visibility or control here
- **Execute** — only via the local agent, with separate authorization; clipboard approval never implies execution approval
- **Analyze** — results only when execution is confirmed or output is pasted/imported

## Command generation pipeline

```
User input (voice/text)
   → Intent classification (local, deterministic)
   → Tool registry lookup
   → Target resolution (from profile)
   → Parameter validation (schema-enforced)
   → Scope + risk validation
   → Template rendering
   → Command preview → Approve → Copy → (user's manual terminal)
```

## Risk classification

| Level | Meaning | Examples | Auto-execute |
|---|---|---|---|
| 0 | Passive / local | Local system info, file metadata, docs | N/A (local) |
| 1 | Low-impact active diagnostics | Single HTTP request, TLS diagnostics | Never |
| 2 | Active testing | Port scanning, directory enumeration | Never |
| 3 | Intrusive / potentially disruptive | Service modification, destructive testing | **Never — explicitly excluded from batch execution** |

## Authorization model

- A stored target profile is **never** proof of authorization.
- Explicit authorization acknowledgement is required before active testing.
- Broad wildcards and oversized CIDR ranges are rejected by default.
- Public websites are not automatically authorized targets.
- High-risk operations require fresh approval every time.

## Development

### Extension
```bash
cd extension
npm install
npm run build      # outputs dist/ for chrome://extensions "Load unpacked"
npm test           # Vitest unit + template + validation tests
```

### Agent
```bash
cd agent
python -m venv .venv && source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -r requirements.txt
pytest             # agent unit + security regression tests
```

## Status

See `docs/IMPLEMENTATION_STATUS.md` for an honest, always-current report of what is implemented, tested, known limitations, and next steps.
