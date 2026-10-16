# opencode-redact

An [opencode](https://github.com/anomalyco/opencode) plugin that scans the
text returned by every successful tool call for secrets and redacts them in
place — before that output is appended to the LLM's context.

## What it does

This plugin registers two hooks. **Tool output** (`tool.execute.after`,
described here) is scanned unconditionally; **user messages** are scanned by
a separate hook with a narrower scope and its own exemption mechanism — see
"User message redaction" below.

- Registers the `tool.execute.after` hook.
- Scans `output.output` using [secretlint](https://github.com/secretlint/secretlint)'s
  recommend rule preset (with the `filter-comments` rule disabled — see
  "Known limitations" below).
- Replaces each detected secret with a `***REDACTED:<rule>***` placeholder,
  merging overlapping findings and expanding to whitespace boundaries so a
  finding whose reported range only partially covers its secret doesn't leave
  a fragment of it in the output.
- Appends a short note telling the model a redaction occurred and that it must
  never write a placeholder back into a file, command, or message.
- Logs a warning (tool name, redaction count, rule ids only — never the
  matched secret text or scanner message) when a redaction happens.
- **Fails open** on a scanner error or timeout — the original output passes
  through unmodified rather than being blocked or corrupted.
- **Fails loud** at plugin startup if the secretlint rule configuration cannot
  load — this is the one point where a failure is not silent.

<img width="1453" height="657" alt="image" src="https://github.com/user-attachments/assets/ad1235e2-dfd8-4c25-9f6a-db7fc8ec1182" />

See `openspec/specs/tool-output-redaction/spec.md` for the full tool-output
behavior contract and `openspec/specs/user-message-redaction/spec.md` for the
user-message contract; see each change's `design.md` for implementation
rationale.

## User message redaction

- Registers the `chat.message` hook, which fires when a new message is
  received — before it reaches the LLM.
- **Scope: non-synthetic text parts only.** Only parts where
  `type === "text" && synthetic !== true` are scanned. This deliberately
  excludes `@`-mentioned file bodies, directory listings, decoded pastes, and
  subagent/task-tool prompts — all of these arrive as *synthetic* parts, not
  text the user typed into the composer themselves. Scanning that content is
  out of scope for v1 (see "Known limitations"); it is unscanned today too, so
  this is not a regression.
- Each qualifying part is redacted independently using the same detect →
  merge → splice pipeline as tool output (`***REDACTED:<rule>***`
  placeholders, merged overlapping findings, token-boundary expansion).
- **The ` ```noredact ` fence** lets you exempt part of your own message from
  scanning — useful for sending a checksum, hash, or other string that only
  *looks* like a secret. Wrap it in a fenced code block whose info string is
  exactly `noredact` (case-insensitive):

  ````
  ```noredact
  0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcd
  ```
  ````

  Rules of this fence (this plugin's own grammar — not full Markdown, and not
  CommonMark-conformant in every respect):
  - The opening line is 0–3 leading spaces, 3 or more backticks, then the word
    `noredact` (case-insensitive) and nothing else besides surrounding
    whitespace.
  - The closing line must have **exactly** the same number of backticks as
    the opener — not "at least", as CommonMark specifies. A 4-backtick opener
    closed by a 3- or 5-backtick line is **not** closed.
  - Only backticks are recognised; a `~~~noredact` block is ordinary text and
    **is** scanned.
  - **No nesting.** The first line with a matching bare backtick run of the
    right length closes the block — so a plain ` ``` ` line *inside* a
    3-backtick `noredact` block ends it early, and everything after that is
    scanned normally. If your content itself contains a bare ` ``` ` line,
    wrap it with a **longer** fence instead (e.g. ` ````noredact ` … ` ```` `),
    which is exempt from the nesting problem precisely because the closer
    must match the opener's exact length.
  - A malformed or unterminated fence is **not** exempt — see "Known
    limitations".
  - This fence is honored **only** in user messages, never in tool output.
    In V2, the exemption persists through `context`, `generate`, and
    `compaction` request rescans for messages whose role is exactly `user`.
    System-prompt segments and messages with any other or missing role remain
    scanned, including inside fences. Each text block is parsed independently;
    a fence cannot span blocks or messages.
  - **V2 role is not proof of human authorship.** Synthetic messages, expanded
    file text, and compaction summaries represented as user-role text also
    receive the exemption. A real secret inside a valid fence in that text
    can reach the model provider; no provenance check is performed.
- Exactly **one** annotation is appended per message (to the last part that
  was actually redacted), aggregating the count and rule ids across every
  redacted part — not one annotation per part. The wording is deliberately
  different from the tool-output annotation: it tells the model the
  redaction happened in the user's own message and instructs it to say so and
  stop rather than try to recover the value (unlike the tool-output note,
  which says to ask the user for it — here the user already supplied it, and
  it was redacted on purpose). **The annotation never mentions the
  `noredact` fence or how it works** — this is intentional: `chat.message`
  also fires for subagent/task-tool turns, where the "user message" is
  authored by the parent model, so teaching the fence to the model would
  teach it a documented way to bypass this security control.
- Logs a warning (redaction count, rule ids only — never message text) when a
  redaction happens.
- **Fails open**, and **never rejects**, even on an unexpected internal
  error — a rejection from this hook would abort the user's entire turn, not
  just skip redaction, so failures here are always swallowed and logged
  rather than propagated.

## High-entropy secret detection

All of the rules above are vendor-pattern based — each requires a literal
prefix or format (`sk-ant-`, `ghp_`, `-----BEGIN`, etc.). A credential with no
recognizable format — an internal API key, a bespoke session token — passes
through every one of them undetected. This plugin additionally runs a
Shannon-entropy check that flags secret-*shaped* substrings regardless of
vendor, alongside (not instead of) the pattern-based rules.

- **How it works**: candidate substrings (runs of base64/hex/base64url
  characters) are scored for randomness. A run is flagged when its entropy
  exceeds **4.5 bits/character** (base64-shaped) or **3.0 bits/character**
  (hex-shaped) — the same thresholds [detect-secrets](https://github.com/Yelp/detect-secrets)
  uses. Below a minimum length (23 for base64, 9 for hex — the shortest
  length at which each threshold is even mathematically reachable) nothing
  is scored at all.
- **Always runs, unlike every other rule.** The existing prescreen only
  works because every anchored rule requires a literal token; an
  entropy-based secret has no such anchor; this check runs on every scanned
  message, tool output and user message alike, at the cost of the extra
  scan.
- **Built-in allowlist** — never flagged, regardless of measured entropy:
  - a git commit id or common hash digest, in **one consistent letter
    case** (lowercase or uppercase, never mixed): 7–12 hex characters (an
    abbreviated commit id) or exactly 32/40/64/128 (md5/sha1/sha256/sha512
    digest lengths);
  - a canonical UUID (`8-4-4-4-12` hyphenated hex, any case);
  - a Subresource Integrity / lockfile hash (`sha256-<base64>`,
    `sha1-`/`sha384-`/`sha512-` likewise) — this is specifically what keeps
    `npm install`'s own `package-lock.json` from tripping this plugin on
    every dependency.
- **JWTs are handled specially.** A JWT's header and payload are not scored
  (they're expected to be readable claims, not secret material); its
  signature segment — the part that actually makes the token usable — is
  flagged unconditionally, with no entropy check at all, since even a short
  signature must never survive. In the current version this still redacts
  the **entire token** as one placeholder (not just the signature) — see
  "Known limitations" below for why.

**Short, password-shaped secrets.** The check above only fires at 23+
characters (base64-shaped) or 9+ characters (hex-shaped) — a typed or
generated password is often shorter, and frequently contains punctuation
the check above doesn't even scan (`!`, `@`, `#`, etc. immediately split a
run into fragments it never sees). A second, independent check
specifically targets this case:

- **Length: 14–22 characters.** An 8-character floor was the original
  target, but it isn't mathematically deliverable together with a
  false-positive-safe threshold — see below.
- **Character set**: letters (upper + lower), digits, and exactly these
  ten punctuation characters: `! # $ % ^ + - _ ~ @`. Common punctuation
  such as `. , = & * ? / \ < > ( ) [ ] { } | " '` and the backtick is
  deliberately excluded — each is a top contributor to false positives in
  ordinary text (sentence punctuation, `key:value`/`.env`/query-string
  shapes, Markdown emphasis, paths, quoting) when measured against this
  project's own source and dependencies.
- **A candidate must clear all three of the following** — none is
  sufficient alone:
  1. contains at least one lowercase **and** at least one uppercase
     letter (digits and symbols are optional bonus signals, not
     required);
  2. contains **no run of 4 or more consecutive characters from the same
     class** (lowercase, uppercase, digit, or symbol);
  3. its Shannon entropy strictly exceeds **3.75 bits/character** — a
     threshold calibrated specifically for this character set and length
     range, not reused from the 4.5/3.0 thresholds above.
- **How the thresholds were chosen.** Shannon entropy over a string's own
  character distribution cannot, by itself, distinguish a random password
  from an ordinary all-distinct-character identifier of the same length —
  both reach the same `log2(length)` ceiling. Measured directly against
  real identifiers in this project's own dependencies (`Configurable`,
  `rightHandSymbols`, `$ZodBase64URL`, and others), several reach or
  exceed the entropy of an equal-length random password. The
  character-class-run cap (condition 2 above) is what restores the
  separation: `rightHandSymbols` clears the entropy threshold but is
  rejected by the run cap (`right` is five consecutive lowercase
  characters); a genuine password with the same entropy but no such run
  survives. With that cap in place, the lowest defensible threshold pushes
  the floor to 14 characters — below that, an all-distinct ordinary
  identifier and an all-distinct random password become mathematically
  indistinguishable by entropy alone. This favors precision over recall,
  deliberately: some real short passwords (especially word-based ones,
  e.g. `Hunter2024!`) will still not be caught — see "Known limitations".
- **Excludes JWT and existing-allowlist content.** A candidate inside a
  JWT-shaped span, or inside an existing-path allowlisted run (e.g. a
  Subresource Integrity hash's digest), is never independently evaluated
  by this check — it defers entirely to the existing handling for that
  content.

## Install

Both opencode V1 (`@opencode-ai/plugin`) and V2 (`@opencode/cli` /
`@opencode/plugin`) are supported, via separate entrypoint files.

```bash
npm install
```

**V1:** symlink the V1 entry file into opencode's plugin directory:

```bash
ln -s "$(pwd)/src/plugin.v1.js" ~/.config/opencode/plugins/opencode-redact.js
```

**V2:** OpenCode v2 requires a plugin whose default export is `{ id, setup }`.
This package's own default export (`.`) is the **V1** adapter, so listing
`"opencode-redact"` directly in the plugin list does **not** work on v2 — the
loader rejects the V1 entry with a `PluginModule.LoadError`. Load the `/v2`
entrypoint explicitly through a one-line shim in an `.opencode/plugins/`
directory (project or global):

```js
// .opencode/plugins/opencode-redact.ts
export { default } from "opencode-redact/v2";             // package in node_modules
// or, from a local checkout:
// export { default } from "/abs/path/opencode-redact/src/plugin.v2.js";
```

The shim re-exports the real adapter, so its sibling modules (`redact.js`,
`secretlint.js`, `config.js`) and the `@secretlint/*` dependencies resolve
from the package's own `node_modules` — do not copy those files next to the
shim. If you use the config `plugins` array instead, note it accepts package
names or **directory** targets only; a bare absolute *file* path is rejected
with `configured plugin path must be a directory`.

Restart opencode. No further configuration is needed — the only setting
(high-entropy on/off) lives in `redact.jsonc` (see "Configuration").

Unlike some other plugins with a peer dependency on `@opencode-ai/plugin`,
this plugin needs no additional symlink step for its own dependencies — a
plain `npm install` inside this repo is sufficient. Neither `@opencode-ai/plugin`
nor `@opencode/plugin` is ever imported at runtime by either entrypoint —
see `docs/v2-compat-audit.md` for why.

## Configuration

This plugin has exactly one setting, in v1: whether high-entropy detection
is on. Everything else — which vendor rules run, thresholds, the allowlist —
is fixed and not configurable.

Create `redact.jsonc` (JSON with comments; trailing commas are fine) in
opencode's own configuration directory — the same directory the `plugins/`
folder above lives in (`$XDG_CONFIG_HOME/opencode/redact.jsonc`, i.e.
`~/.config/opencode/redact.jsonc` by default):

```jsonc
{
  // Turn off the high-entropy check; every other rule keeps running.
  "disableHighEntropy": true
}
```

- The file is entirely optional — no file means every default applies
  (high-entropy detection **on**).
- **Fails open on every problem**, exactly like the rest of this plugin:
  a missing file is silent; a file that can't be read, doesn't parse as
  valid JSONC, or has the wrong shape falls back to every default and logs
  a warning (never the file's actual contents — only key names and error
  categories are ever logged). This is deliberately the opposite failure
  direction from the secretlint rule bundle itself, which still fails
  loud on startup if it can't load — a broken settings file should never
  cost you detection coverage, but a broken rule bundle should never run
  silently unprotected.
- Restart opencode after changing this file — it's read once at plugin
  startup, not watched for changes.

## Rollback / disabling

There is still no way to turn off vendor-pattern detection (the
`tool.execute.after`/`chat.message` hooks themselves) in v1 — the only
partial control is `disableHighEntropy` in `redact.jsonc` (see
"Configuration" above), which turns off just the entropy check. The fast
"turn everything off" path remains removing the symlink and restarting
opencode:

```bash
rm ~/.config/opencode/plugins/opencode-redact.js
```

## Known limitations (v1, documented — not oversights)

- **Failed tool calls are not scanned.** `tool.execute.after` only fires
  after a tool call succeeds; error output (e.g. a command's stderr, a stack
  trace) can still carry a secret to the model unredacted.
- **Truncated output can spill an unredacted secret to disk.** opencode
  truncates very large tool output to a managed on-disk retention path
  *before* this hook runs; redacting the in-context string does not redact
  that spill file.
- **`output.attachments` is not scanned.** Tool-result `metadata` IS scanned
  (a V1-parity fix in this plugin); `attachments` carries references/URLs,
  not inline text, so it is left untouched by the redactor.
- **Provider-signed reasoning is not redacted.** In the V2 session hooks, a
  `reasoning` part is left completely untouched — its text and its
  `providerMetadata` (proof-of-generation: Anthropic signature, Gemini
  thought signature, OpenAI encrypted content) travel as generated, because
  Anthropic and AWS Bedrock reject requests whose thinking blocks were
  modified after generation. A secret inside such a part is intentionally
  not replaced; redacting signed reasoning needs a provider-compatible
  confidentiality policy and a tool-use/replay regression test, tracked as
  a follow-up. Refs:
  [Anthropic — extended thinking](https://platform.claude.com/docs/en/build-with-claude/thinking),
  [AWS Bedrock — conversation inference](https://docs.aws.amazon.com/bedrock/latest/userguide/conversation-inference.html).
- **The GCP p12 (binary) check never fires.** The GCP rule only runs when
  the scanned content's extension is `.json` or `.p12`; this plugin detects
  JSON-shaped text automatically and scans it as `.json`, but `.p12` is a
  binary format with no text-based fixture that could route a text-only
  pipeline into that branch.
- **AWS access-key-id and account-id detection is not active.** Those two
  checks in the AWS rule are gated behind an `enableIDScanRule` option that
  defaults to `false` and is not set by this plugin — only the AWS
  secret-access-key check is reachable. (Access key IDs alone are not
  secrets, so this is by design, not a gap.)
- **Detection is heuristic, not a guarantee.** The recommend preset is
  vendor-pattern-based and will not catch bespoke or opaque secret formats
  — mitigated, but not eliminated, by high-entropy detection (see above).
- **Over-redaction is still possible**, though narrower in scope, on dense
  content with no whitespace at all between tokens. Redaction range
  expansion (`expandToTokenBoundaries` in `src/redact.js`) stops at
  whitespace or a structural delimiter (`" ' \` , { } [ ]`), so a finding
  inside minified JSON expands only to its enclosing value — up to the
  surrounding quote, comma, or bracket — not the entire document. Content
  that is dense in some *other* way (e.g. a long path or query string with
  no whitespace and none of those delimiter characters) can still expand
  further than the exact secret. This is the safe direction for a security
  control, and the annotation warns the model not to write the placeholder
  back.
- **Configuration is limited to one setting** (`disableHighEntropy` in
  `redact.jsonc` — see "Configuration" above); no per-rule enable/disable
  beyond that, no custom allowlist, no threshold tuning.
- **Hook ordering relative to other `tool.execute.after` plugins is
  undefined** — opencode runs hooks sequentially in registration order.
- **Live streaming preview is not redacted.** opencode's `bash` tool
  (`src/tool/shell.ts`) streams stdout chunk-by-chunk into a live preview
  field (`ctx.metadata({ metadata: { output: ... } })`) as the command runs,
  and this is what a human watching the TUI in real time sees — entirely
  separate from, and populated *before*, the final `tool.execute.after`
  hook this plugin uses. Confirmed by direct testing (2026-09-04): a
  previously-unseen randomly generated secret, read back through `cat`,
  never reached the model (only `***REDACTED:aws***` was ever visible in
  the conversation/tool-result history — the value the LLM provider
  actually receives), but the live terminal-style rendering in the TUI can
  still show raw output while a command is executing. **This is a
  human-visible-only gap, not a model/provider leak** — the redaction
  guarantee this plugin makes (secrets don't reach the LLM or persist in
  replayed conversation history) still holds; only a live-updating visual
  preview during execution is unaffected.
- **Synthetic content in a user turn is not scanned.** `@`-mentioned file
  bodies, directory listings, decoded pastes, and subagent/task-tool prompts
  all arrive as *synthetic* parts and are out of scope for the
  `chat.message` hook (see "User message redaction" above) — a secret
  pasted via one of those paths is not redacted. This is unscanned today
  too (no regression); scanning it is deferred to a future change.
- **A malformed or unterminated `noredact` fence fails safe by being
  scanned, not exempted.** If you open a fence and never close it, or close
  it with the wrong number of backticks, that content is treated as
  ordinary text and scanned like anything else — it is never silently
  dropped from scanning by a broken fence.
- **Segment-splitting can suppress the GCP JSON-key detection.** The GCP
  rule only fires when the *scanned segment* parses as JSON
  (`JSON.parse` succeeds). If a `noredact` fence splits a pasted JSON blob
  into multiple segments, no single segment may parse as valid JSON on its
  own, and the GCP rule then never fires on that message — even though the
  same content pasted as tool output, or as a user message with no fence in
  it, would be caught. This is a narrower case of a pre-existing gap: any
  prose+JSON mix already fails to parse as JSON today.
- **Possible TUI optimistic-render gap for user messages, analogous to the
  tool-output streaming-preview limitation above.** Some TUI clients may
  render the user's just-typed message optimistically before this hook's
  redacted version returns over the session event stream, similar to the
  bash live-preview gap. This has not yet been empirically confirmed (unlike
  the tool-output case, which was directly tested) — treat it as a
  suspected, not verified, human-visible-only gap until confirmed.
- **The high-entropy allowlist can be reused to smuggle a real secret.**
  Any string shaped like an allowlisted form — a git commit id, a UUID, a
  common hash-digest length, an SRI hash — is never flagged, even if it is
  reused as an actual credential rather than what it appears to be. This is
  an accepted trade-off to keep the false-positive rate bounded; it is not
  possible to distinguish "looks like a git SHA" from "is a git SHA" by
  content alone.
- **A JWT's claims are not preserved, despite signature-only targeting.**
  The entropy rule reports only the JWT's signature segment as a finding,
  but the existing token-boundary-expansion logic (unchanged, shared with
  every other rule) widens any finding to the surrounding whitespace — and
  a JWT has none internally — so the entire token is replaced by one
  placeholder in this version. The security goal (the token becomes
  unusable) is achieved in full; only the debugging convenience of keeping
  the claims readable is not.
- **An unsigned JWT (`alg: none`, empty signature) is not redacted at
  all.** Its header and payload are exempt from generic scoring by design
  (they're expected to be readable claims), and with no signature segment
  to unconditionally flag, nothing is reported. An unsigned token is not a
  bearer credential, so this is the intended outcome, but it does mean its
  claims pass through completely unprotected if they happen to contain
  something sensitive.
- **Case-uniform git-object-id/hash-digest lengths outside {7-12, 32, 40,
  64, 128} are not exempt** and are scored normally — this is deliberate
  (those are the lengths git and common hash algorithms actually produce),
  but a hex string of some other length that happens to *look* like a
  digest is not specially treated.
- **The short password-shaped check catches modest recall, by design.**
  Many real short passwords — especially word-based ones such as
  `Hunter2024!` — will not be flagged: the character-class-run cap that
  keeps ordinary identifiers from flooding the results also rejects any
  password built from dictionary words with few internal case/class
  transitions. This is the accepted precision-over-recall trade-off (see
  "High-entropy secret detection" above); it is not a bug.
- **Short password-shaped secrets under 14 characters are never caught,
  by any means.** Below that length, Shannon entropy alone cannot
  distinguish a random password from an ordinary all-distinct-character
  identifier — there is no threshold, with or without the run cap, that
  would separate them, so shorter candidates are excluded entirely rather
  than accepted at a degraded precision.
- **A password containing punctuation outside the short check's 10-symbol
  set (`. , = & * ? / \ < > ( ) [ ] { } | " '` and the backtick) is
  invisible to that check** even within the 14–22 character window,
  because such punctuation splits the candidate into shorter fragments the
  same way it always has. A password built entirely from the 10 included
  symbols plus letters and digits is unaffected.

## History and request ownership

Every path this plugin writes is either a provider-bound payload or a record
the host explicitly surfaces through a hook — and it is deliberately one or
the other, never both by accident:

- **Session hooks (`context` / `generate` / `compaction`).** The host
  derives the hook-bound `system`/`messages` fresh on every provider call
  and consumes the hook's result only for the outgoing request; the
  session's persisted message history is re-derived from storage on the
  next call and is not reachable through the hook event. The handler
  therefore replaces array *slots* copy-on-write: no part object or shared
  nested object is written in place (pinned by deep-frozen-parts,
  identity, and untouched-original tests in
  `test/plugin-conformance.test.js`). The full trace against v2.0.26
  source is in `docs/v2-compat-audit.md`, "Update — 2026-10-14".
- **`tool.execute.after`.** By upstream hook semantics (V1 parity), the
  object this hook receives backs the tool's visible result (and, for an
  error, the execution's `Tool.Error` the host persists). Redacting it
  therefore rewrites both the provider-bound payload and the tool record —
  intended: the placeholder the provider sees is the one the record keeps,
  and the plugin's annotation tells any later reader why.
- **Provider-signed reasoning is untouched on every path.** See
  "Known limitations" above; scanning it requires a provider-compatible
  confidentiality policy and is tracked as a follow-up.

## Development

```bash
npm test
```

Tests use [vitest](https://vitest.dev). `test/fixtures.js` contains one
verified-real fixture per reachable secretlint rule, derived empirically by
probing the installed rule bundle rather than invented from documentation —
see `design.md` D2 for why the fixture list, not hand-derivation, is the
source of truth.
