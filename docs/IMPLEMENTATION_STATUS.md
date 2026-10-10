# Implementation Status

Honest, always-current report. Last updated: 2026-10-10.

## Implemented (on `feature/foundation-scaffold`)

| Component | Files | State |
|---|---|---|
| Core type contract | `extension/src/core/types.ts` | Committed. Risk levels, scope, targets, templates, intents, approval states, audit |
| Parameter validators | `extension/src/core/validators.ts` | Committed. Deny-by-default; shell metachar + control-char rejection; domain/IP/CIDR/port/path/URL/enum |
| Scope & authorization engine | `extension/src/core/scope.ts` | Committed. Deny-by-default; expiry + risk-level enforcement; CIDR size cap (1024 hosts); wildcard rejection; sensitive-target confirmation |
| Command engine + registry | `extension/src/core/engine.ts` | Committed. Template registry, safe token rendering (no shell eval), generation pipeline (scope → tool/version → params → render → hash), SHA-256 command hashing |
| Approval state machine | `extension/src/core/approval.ts` | Committed. Hash binding, 60s TTL, COPIED ≠ EXECUTED (no transition to execution) |
| Built-in templates | `extension/src/data/templates.ts` | Committed. 7 tools, 8 templates, fixtures for 3 templates |
| Intent engine (EN + Hinglish) | `extension/src/core/intent.ts` | Committed. Deterministic, local, no AI call |
| Core invariant tests | `extension/tests/core.test.ts` | Committed. Validators, scope, approval binding + expiry |
| Background service worker | `extension/src/background.ts` | Committed. Message bridge; owns ApprovalMachine |
| Build config | `package.json`, `tsconfig.json`, `vite.config.ts`, `public/manifest.json` | Committed. MV3, least-privilege permissions |

## Not yet implemented (next phases)

- Popup / dashboard UI (popup.html is referenced but not written yet)
- IndexedDB persistence layer (target profiles, authorization records, audit log)
- Local Python agent (Native Messaging, loopback-only)
- AI explanation / result analysis (provider-independent)
- Firefox build
- Voice capture (Web Speech API) wiring
- Template pack expansions (recon, web, privesc, post-exploitation)

## Known limitations

1. **Tests are written but not executed in this environment.** The maintainers' test runner was unavailable during initial development. Run locally:
   `cd extension && npm install && npm test && npm run typecheck`
   No test result should be treated as passing until executed.
2. Background worker state is in-memory; service worker restart clears `currentTarget`/`currentCandidate` (persistence phase fixes this).
3. Intent engine handles common phrasings; exotic phrasing falls to `unknown` (by design — never guess a command).
4. Manifest currently requests `storage` + `clipboardWrite` only. `nativeMessaging` is optional and only enabled when the agent phase lands.

## Verification steps (local)

```bash
cd extension
npm install
npm run typecheck   # must pass with zero errors
npm test            # must pass all core invariant tests
npm run build       # produces dist/ loadable via chrome://extensions
```
