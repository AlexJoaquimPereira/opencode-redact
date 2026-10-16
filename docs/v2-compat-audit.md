# opencode V2 Compatibility — `opencode-redact`

**Date:** 2026-09-16
**Change:** `v2-plugin-migration` (supersedes the earlier `v2-compat-audit` change)

## Correction to the prior audit

The version of this document written under the `v2-compat-audit` change
(2026-09-15) tested against `opencode-ai@dev` and concluded both hooks
"work correctly" on V2 with no action needed. That conclusion was based on
the wrong target: `opencode-ai@dev` is a prerelease channel of the V1
product, not the real V2 product. **V1 plugin implementations do not run
under the real V2 host at all** — the real, separately-versioned V2
product is `@opencode/cli` / `@opencode/plugin` (stable, currently 2.0.3 /
2.0.4), and it requires a genuine port to `{id, setup(ctx)}`. This change
performs that real port and replaces the prior audit's conclusion.

## What changed

- `src/index.js` renamed to `src/plugin.v1.js` (V1 adapter, behavior
  unchanged) — `git mv`, no logic changes.
- New `src/plugin.v2.js`: a V2 adapter built directly on the plugin's
  already runtime-agnostic pure modules (`redact.js`, `secretlint.js`,
  `config.js`) — no new "core" extraction was needed, since those modules
  already took zero opencode-shaped input.
- `package.json`: `"."`/`"./v1"` → `plugin.v1.js`, `"./v2"` → `plugin.v2.js`;
  `@opencode/plugin` added as an optional peer + dev dependency, mirroring
  the existing treatment of `@opencode-ai/plugin`.

## Hook mapping (V1 → V2)

| V1 | V2 | Notes |
|---|---|---|
| `tool.execute.after(input, output)` | `ctx.tool.hook("execute.after", event)` | See "Tool-output redaction" below — the real shape required a design correction after the initial implementation. |
| `chat.message(_input, output)` | `ctx.session.hook("prompt", event)` | See "User-message redaction" below. |
| `client.app.log({body})` | `process.stderr.write(...)` | V2's `Context.app` has no `log` method (confirmed by reading the installed `@opencode/plugin` types) — message content is unchanged, only the transport differs. |

## Design decision: `Plugin.define` is not imported at runtime

`src/plugin.v2.js` exports a plain `{id, setup}` object literal instead of
`Plugin.define({id, setup})`. Verified by reading the installed
`@opencode/plugin` 2.0.4 source directly: `Plugin.define` is a literal
identity function (`export function define(plugin) { return plugin }`),
so nothing is lost at runtime by not calling it. `@opencode/plugin` is an
**optional** peer dependency — importing it at runtime risks a module
resolution failure for any user who hasn't installed it, which for a
security-redaction plugin would fail *open* (silently disabled) rather
than *closed*. A tripwire test (`test/plugin-conformance.test.js`)
imports `Plugin.define` from the devDependency and asserts identity
behavior, so a future `@opencode/plugin` release that makes `define`
load-bearing is caught by CI instead of silently breaking production.

**Empirically confirmed against the real host** (`@opencode/cli` 2.0.3,
`.opencode/plugins/` auto-discovery): the bare `{id, setup}` shape loads
successfully — no `PluginModule.LoadError`, unlike five other still-V1-shaped
plugin files present in the same test environment, which all failed with
`Plugin must export a default definition with an id and an effect or setup
function` for comparison.

## Tool-output redaction — real shape, and a real gap found and fixed

Design.md's original plan assumed three possible `result` shapes: a plain
string `content`, a `Content[]` array, or (when `content` is absent) a bare
string `output`. Testing against the real host with a real tool call
(`Use the bash tool to run: python3 -c "import secrets; print('aws_secret_access_key=' + ...)"`)
surfaced the **actual** shape emitted by the built-in `shell` tool (V2's
name for V1's `bash`):

```json
{
  "content": [
    {"type": "text", "text": "aws_secret_access_key=<...>\n"},
    {"type": "text", "text": "Command exited with code 0."}
  ],
  "output": {"exit": 0, "truncated": false, "output": "aws_secret_access_key=<...>\n", "status": "completed"},
  "metadata": {...}
}
```

Two findings, one of them a real gap:

1. **`content` is a `Content[]` array** (design.md's D6c case), correctly
   redacted by the implementation: block 0's secret is replaced, block 1
   (no secret) is untouched, one annotation appended to the last redacted
   block. Confirmed via a `SENTINEL`-style diagnostic log added temporarily
   during verification, then removed.
2. **`output` is NOT a bare string when `content` is present** — it is a
   structured `{exit, truncated, output: <same raw text as content>,
   status}` record. The original design (D6d) only redacted a bare-string
   `output`, and only when `content` was entirely absent — it never
   anticipated `output` duplicating the same secret in a *different*,
   *structured* shape while `content` was simultaneously populated. Since
   this is empirically confirmed to be the real, common shape for the
   built-in shell tool (not a hypothetical), the implementation was
   corrected: `redactToolResult` now also redacts a nested `output.output`
   string field whenever present, **independently of whether `content` was
   already handled** — so the same secret cannot survive in this parallel
   field. Two new regression tests cover this exact shape (secret present,
   and the negative case where nothing is redacted and the object is left
   byte-identical).

**Verification status:** the corrected code is covered by 232 passing unit/
integration tests (up from 210 pre-migration), including tests built from
the exact real-host payload shape captured above. The hook registration and
firing (`ctx.tool.hook("execute.after", ...)` receiving a real, populated
event for a real `shell` tool call, `status: "completed"`) was directly
confirmed against the real host (`@opencode/cli` 2.0.3) via a temporary
diagnostic log, then the fix was verified via the unit test suite. A final,
clean end-to-end re-run to directly observe the corrected redaction on the
live host (rather than via unit tests reproducing the captured shape) was
attempted but not completed — the test sandbox became unresponsive due to
unrelated heavy resource contention on the host machine (five concurrent,
unrelated opencode sessions were running). This is recorded as an
honestly-scoped gap, not silently elided: the fix is proven correct against
the exact real shape by test, but the very last "watch it happen live a
second time" step was not re-obtained after the fix.

## User-message redaction — the design's synthetic-exclusion analysis held

V1 scans only `parts[]` entries where `type === "text" && synthetic !==
true`, so `@`-mentions, file bodies, and subagent-delivered content are
never mistaken for user-typed text. V2's `ctx.session.hook("prompt", ...)`
event carries `event.prompt.text` — a single string, not a parts array.
Reading the installed `@opencode/plugin`/`@opencode/schema` types directly
(not guessing) showed that V2's `PromptInput.Prompt` shape has no inlined
synthetic content at all — `files[]` are URI references, and synthetic
content is delivered through a structurally separate `SessionInbox` item
type this hook never receives. The hook boundary itself is therefore
already scoped the same way V1's `synthetic !== true` filter was, so
`event.prompt.text` is redacted unconditionally via the same
`redactUserMessage` used by V1, with one annotation appended directly to
the string when anything was redacted.

**Verification status:** covered by the shared V1/V2 adapter-conformance
suite (string-identical redacted text and annotations across both
adapters, for a shared fixture corpus) and the `noredact` fence-exemption
test. Not independently re-confirmed against a live prompt on the real host
in this session (time did not permit a second live scenario after the
tool-output fix); this is a smaller-risk gap than the tool-output path
since the underlying `redactUserMessage`/fence logic is unchanged from V1
and already has 200+ pre-existing unit tests exercising it directly.

## Summary

| Aspect | Status |
|---|---|
| Plugin loads on real V2 host (`@opencode/cli` 2.0.3) | ✅ Confirmed live |
| `setup()` runs, both hooks register | ✅ Confirmed live |
| `execute.after` fires with real data for a real tool call | ✅ Confirmed live |
| Tool-output redaction — `Content[]` shape | ✅ Confirmed live + unit tested |
| Tool-output redaction — nested `output.output` shape | ✅ Gap found live, fixed, unit tested against the exact real shape; final live re-confirmation not completed (sandbox resource contention) |
| User-message redaction | ✅ Unit tested (shared V1/V2 conformance suite); not independently re-confirmed live in this session |
| No runtime import of either host SDK | ✅ Enforced by test |

## How to reproduce this test

```bash
mkdir -p ~/opencode-v2-real && cd ~/opencode-v2-real
npm init -y && npm install @opencode/cli@latest
node node_modules/@opencode/cli/postinstall.mjs
ln -sf ~/opencode-v2-real/node_modules/.bin/opencode ~/.local/bin/opencode-v2-real

mkdir -p /tmp/opencode-redact-v2-test/.opencode/plugins /tmp/opencode-redact-v2-test/.opencode/lib
cp src/plugin.v2.js /tmp/opencode-redact-v2-test/.opencode/plugins/
cp src/redact.js src/secretlint.js src/config.js src/prescreen.js src/entropy-rule.js \
  /tmp/opencode-redact-v2-test/.opencode/lib/
# then fix plugin.v2.js's relative imports to ../lib/ -- .opencode/plugins/
# scans EVERY .js file directly inside it as its own candidate plugin, so
# shared modules must live in a sibling directory, never alongside it.
cd /tmp/opencode-redact-v2-test
npm init -y && npm install @secretlint/config-loader @secretlint/core \
  @secretlint/secretlint-rule-preset-recommend jsonc-parser xdg-basedir

opencode-v2-real plugin list   # confirms auto-discovery found the plugin
opencode-v2-real run "Use the bash tool to run exactly: python3 -c \"import secrets; print('aws_secret_access_key=' + secrets.token_hex(24))\"" \
  --print-logs --log-level debug --standalone --auto
# --standalone is required to see server-side plugin logs at all.
```

## Follow-up: session-context hook coverage and metadata redaction (2026-09-17)

A later architectural review of this port found two remaining coverage
gaps, addressed in the `fix-v2-session-hook-coverage` change:

1. **Missing hook registrations.** V2 exposes `context`, `generate`, and
   `compaction` session hooks — `ctx.session.hook(name, callback)` — that
   assemble or re-derive the exact `{system: SystemPart[], messages:
   Message[]}` payload sent to a model provider. None of them was
   registered, so a secret embedded in assembled system content (skills,
   `AGENTS.md`, reference docs, MCP tool descriptions) reached every
   provider call unredacted, and the `generate` hook's one-shot generation
   requests (issuable by any other installed plugin) bypassed this plugin
   entirely. Fixed by registering all three under a shared handler,
   `redactSessionContextHandler`, reusing the existing `redactContentBlock`
   block-shape check for both `event.system[]` (every element already has
   the exact `{type:"text", text}` shape) and each message's
   `content[]` array (scoped to `type === "text"` blocks only — the other
   five `ContentPart` variants are left untouched, mirroring the existing
   `Tool.Content[]` walk's own narrow scope).
2. **`Tool.Result.metadata` was never scanned.** `redactToolResult` patched
   `content`/`output` fields as they were empirically discovered, but never
   touched `metadata`. Fixed with a schema-agnostic recursive string walk
   (`redactObjectStrings`) applied to `metadata` specifically, bounded by a
   200,000-character total scan budget so a pathological metadata blob
   cannot make the walk itself unbounded. `content` and `output` keep
   their existing, narrowly-scoped, already-tested handling unchanged — a
   blanket walk over `output` would have started mutating opaque
   programmatic/codemode data that must stay untouched per the original
   design's D6d, so the recursive walk was deliberately scoped to
   `metadata` only.

**Explicitly rejected:** registering `ctx.session.hook("http.request"/
"http.response", ...)`. The wire body for a provider call is serialized
from the same `Message`/`Tool.Result` objects already redacted upstream by
the hooks above — duplication with real added fragility (per-provider body
parsing, stream clone/replace, WebSocket frame rewriting) and no net
coverage gain.

See `openspec/changes/archive/*-fix-v2-session-hook-coverage/` (once
archived) for the full design record and delta specs.

## Update — 2026-10-13 (loader constraints verified against @opencode/cli 2.0.26)

- The config `plugins` array rejects a bare **absolute file path** with
  `configured plugin path must be a directory`; only package names or
  **directory** targets are accepted for local entries.
- The package's default export (`.`) is the V1 adapter, so listing
  `"opencode-redact"` by name on v2 fails with `PluginModule.LoadError:
  Plugin must export a default definition with an id and an effect or setup
  function`.
- A working v2 install is a one-line shim in `.opencode/plugins/` that
  re-exports `opencode-redact/v2` (or a local `src/plugin.v2.js`); see the
  README "Install" section.

## Update — 2026-10-14 (content-part tightening, signed-reasoning exemption, and request-history ownership)

A maintainer review of the `fix/tool-error-and-contentpart-redaction` PR
raised two questions: whether redacting a `reasoning` part is protocol-safe,
and whether the session-hook handler's array-slot mutation (`blocks[i] =
redacted.part`) can rewrite the session's persisted message history. Both
are answered here against opencode v2.0.26 source (`sst/opencode` tag
`v2.0.26`, release commit `9b4ec57`; `packages/core/...`).

### Signed reasoning is exempt — provider SDKs reject modified thinking

A `reasoning` part carries `providerMetadata` proof-of-generation scoped to
the model that produced it (Anthropic message/thinking signature, Gemini
thought signatures, OpenAI encrypted reasoning). The tightened handler no
longer scans `reasoning` parts at all: Anthropic and AWS Bedrock reject a
request whose thinking blocks were modified after generation, so an edited
text with an unchanged signature is invalid state — and passing the secret
through (or dropping the protocol metadata) is not a substitute. Redacting
signed reasoning is deferred until a provider-compatible confidentiality
policy exists, with a tool-use/replay regression test; see the README's
"Known limitations" entry.

### Hook-bound history is a per-request derivation, not the persisted record

Trace of what the host actually hands the session hooks (`context`,
`generate`, `compaction`) and what it keeps:

- **Per-request assembly.** `packages/core/src/session/model-request.ts`
  `baseTranscript` (:100-120) builds the transcript **fresh on every
  provider call**: `system` is a new array of `SystemPart.make(...)`;
  `messages` comes from `toLLMMessages(...)` (`.runner/llm.ts` re-derives
  after each `context.load` — "retries refresh context", `llm.ts:215`,
  called per step at `llm.ts:224-230`). History entries are pulled from
  session storage each load (`context.ts:176` maps DB-queried entries).
- **Fresh objects per message.** `to-llm-message.ts` `toLLMMessage`
  (:253-334) constructs entirely new `Message` objects from projected
  `SessionMessage.Info` fields; the assistant branch (:153-233) builds new
  part objects — and only attaches reasoning `providerMetadata` when the
  part was produced by the same model without error/interruption,
  degrading otherwise.
- **What the hook receives.** `model-request.ts:420-428` passes session
  hooks a fresh wrapper `{...draft, agent, tools}` whose `system`/`messages`
  reference the draft; the hook's result (trigger has no cloning —
  `plugin/hooks.ts:88-95` invokes callbacks with the same object) is
  consumed **only** for the outgoing request (`:296-297`:
  `system: shaped.system`,
  `messages: boundImages(unsupportedParts(shaped.messages, ...))`).
- **Why the plugin still copies.** Inner objects are not always fresh:
  `toolInput()` (`to-llm-message.ts:86-88`) hands the stored
  `tool.state.input` object through by reference, and metadata objects may
  be shared. The plugin's deep walk is strictly copy-on-write —
  `redactObjectStrings` rebuilds only containers whose strings changed and
  returns original references otherwise; `redactTextField`/
  `redactObjectField` spread; `redactContentArray` replaces only array
  **slots**. No part object or shared nested object is ever written in
  place on this path (pinned by the deep-frozen-parts conformance test).

Conclusion: a secret that hits a session hook lives in a payload built for
this one provider call; replacing array slots can rewrite that payload but
cannot reach the canonical stored session, and the plugin leaves the
original part objects untouched. The conformance tests cover all three
invariants (payload redacted vs. snapshot preserved, frozen parts never
written, replaced slots leaving originals' raw values intact).

### Scoped exception: `tool.execute.after` does rewrite its record

The one hook whose mutation reaches a persisted record is
`tool.execute.after`: for a **failed** tool call the hooked object **is**
the execution's `Tool.Error` (`packages/core/src/tool.ts:103-156`),
redacted in place (`redactValueInPlace`), and the same object later
surfaces/persists in the tool's state; for a completed call, the hooked
result's fields flow into what the tool returns. That is the hook's own
upstream semantics (V1 parity), accepted as the intended design — noted
here so the distinction with the session hooks is explicit.


