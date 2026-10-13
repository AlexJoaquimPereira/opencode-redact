// src/plugin.v2.js — opencode-redact, V2 plugin entrypoint
//
// Thin adapter over the runtime-agnostic redaction core (src/redact.js,
// src/secretlint.js, src/config.js), mapping the same detect/redact/annotate
// logic onto opencode's real V2 plugin SDK (`@opencode/plugin`,
// `{id, setup(ctx)}`). See design.md for the full decision record (D1-D9).
//
//   V1                                     V2
//   tool.execute.after(input, output)      ctx.tool.hook("execute.after", event)
//   chat.message(_input, output)           ctx.session.hook("prompt", event)
//   client.app.log                         process.stderr (design.md D3)
//
// Deliberately does NOT import `@opencode/plugin` at runtime (design.md D1):
// `Plugin.define` is a verified identity function, and the package is an
// OPTIONAL peer dependency that end users may not have installed — a
// runtime import would fail this security plugin CLOSED (load error)
// instead of open. This file exports a plain object literal with the same
// shape `Plugin.define({...})` would produce.
//
// @typedef {import("@opencode/plugin").Plugin} Plugin

import { createSecretlintConfig, createCompositeLinter } from "./secretlint.js";
import { loadPluginConfig } from "./config.js";
import { createLogger } from "./log.js";
import { redactSecrets, redactUserMessage, buildAnnotation, buildUserMessageAnnotation, scanAndRedact } from "./redact.js";

const PLUGIN_NAME = "opencode-redact";

// D4 (design.md): total character budget for the recursive metadata walk,
// shared across every string leaf scanned in one redactToolResult call.
// Consistent with secretlint.js's per-scan DEFAULT_TIMEOUT_MS -- this is a
// count/size cap, not a new timeout: each scanAndRedact call still races its
// own per-call timeout unchanged; this only bounds how many such calls one
// metadata walk can issue.
const METADATA_SCAN_BUDGET_CHARS = 200_000;

/**
 * Redacts a single V2 `Tool.Content` block in place. Returns
 * `{content, redactionCount, ruleIds}` — `content` unchanged when nothing
 * was redacted or the block is not a `type:"text"` block (design.md D6c:
 * `type:"file"` blocks are URI references with no inline body, and are
 * left completely untouched).
 */
async function redactContentBlock(block, { lint }) {
  if (!block || block.type !== "text" || typeof block.text !== "string") {
    return { block, redactionCount: 0, ruleIds: [] };
  }
  const scanned = await scanAndRedact(block.text, { lint });
  if (scanned.redactionCount === 0) {
    return { block, redactionCount: 0, ruleIds: [] };
  }
  return {
    block: { ...block, text: scanned.text },
    redactionCount: scanned.redactionCount,
    ruleIds: scanned.ruleIds,
  };
}

/**
 * Recursively walks an arbitrary JSON-like value, scanning and redacting
 * every string leaf via `scanAndRedact` (design.md D4). Rebuilds arrays and
 * plain objects only when a descendant actually changed; returns the
 * original reference unchanged otherwise. Non-string, non-array,
 * non-object values (numbers, booleans, null, undefined) pass through
 * as-is.
 *
 * `budget.remaining` is a shared, mutable character counter: before
 * scanning a string leaf, its length is checked against the remaining
 * budget. A leaf that would exceed the remaining budget is left
 * unscanned entirely (not truncated) -- fail-open, matching this
 * plugin's existing scanner-error/timeout behavior -- and the walk
 * continues over the rest of the tree with whatever budget remains.
 *
 * Scoped to `Tool.Result.metadata` only (design.md D4's implementation-time
 * correction) -- `content` and `output` keep their existing, narrowly
 * targeted handling in `redactToolResult`.
 */
async function redactObjectStrings(value, { lint }, budget) {
  if (typeof value === "string") {
    if (value.length === 0 || value.length > budget.remaining) {
      return { value, redactionCount: 0, ruleIds: [] };
    }
    budget.remaining -= value.length;
    const scanned = await scanAndRedact(value, { lint });
    return { value: scanned.text, redactionCount: scanned.redactionCount, ruleIds: scanned.ruleIds };
  }

  if (Array.isArray(value)) {
    let changed = false;
    let totalCount = 0;
    const ruleIdSet = new Set();
    const items = [];
    for (const item of value) {
      const walked = await redactObjectStrings(item, { lint }, budget);
      items.push(walked.value);
      if (walked.redactionCount > 0) {
        changed = true;
        totalCount += walked.redactionCount;
        for (const ruleId of walked.ruleIds) ruleIdSet.add(ruleId);
      }
    }
    return { value: changed ? items : value, redactionCount: totalCount, ruleIds: [...ruleIdSet] };
  }

  if (value && typeof value === "object") {
    let changed = false;
    let totalCount = 0;
    const ruleIdSet = new Set();
    const walkedObject = {};
    // `getOwnPropertyNames` (not `Object.keys`) so non-enumerable own fields
    // are scanned too — e.g. a host Error's `message`/`stack`, which are
    // non-enumerable and would otherwise leak through a tool-result value.
    for (const key of Object.getOwnPropertyNames(value)) {
      let item;
      try {
        item = value[key];
      } catch {
        continue; // throwing getter; fail-open
      }
      const walked = await redactObjectStrings(item, { lint }, budget);
      walkedObject[key] = walked.value;
      if (walked.redactionCount > 0) {
        changed = true;
        totalCount += walked.redactionCount;
        for (const ruleId of walked.ruleIds) ruleIdSet.add(ruleId);
      }
    }
    return { value: changed ? walkedObject : value, redactionCount: totalCount, ruleIds: [...ruleIdSet] };
  }

  return { value, redactionCount: 0, ruleIds: [] };
}

/**
 * Scans a single string leaf against a shared budget. Returns the redacted
 * text, or `undefined` when the value is not a string, is empty, exceeds the
 * remaining budget, or has no finding. Fail-open, like the rest of the plugin.
 */
async function scanLeaf(text, budget, lint) {
  if (typeof text !== "string" || text.length === 0) return undefined;
  if (text.length > budget.remaining) return undefined;
  budget.remaining -= text.length;
  const scanned = await scanAndRedact(text, { lint });
  return scanned.redactionCount > 0 ? scanned.text : undefined;
}

/**
 * Recursively redacts string leaves of an arbitrary value IN PLACE, preserving
 * object identity and prototype. Used for host class instances (e.g. a tool
 * error, a `Tool.Error` Schema.Class) where replacing the value with a plain
 * clone could break the host. Read-only/frozen fields that throw on assignment
 * are skipped (fail-open). Returns the number of leaves redacted.
 */
async function redactValueInPlace(value, { lint }, budget) {
  let total = 0;
  const seen = new WeakSet();
  const walk = async (v) => {
    if (!v || typeof v !== "object" || seen.has(v)) return;
    seen.add(v);
    if (Array.isArray(v)) {
      for (let i = 0; i < v.length; i += 1) {
        const item = v[i];
        const next = await scanLeaf(item, budget, lint);
        if (next !== undefined) {
          try {
            v[i] = next;
            total += 1;
          } catch {
            // read-only entry; skip
          }
        } else if (item && typeof item === "object") {
          await walk(item);
        }
      }
      return;
    }
    // `getOwnPropertyNames` (not `Object.keys`): a host Error's `message` and
    // `stack` are non-enumerable own properties, and `message` is the most
    // likely carrier of a secret in a failed tool call.
    for (const key of Object.getOwnPropertyNames(v)) {
      let item;
      try {
        item = v[key];
      } catch {
        continue; // throwing getter; fail-open
      }
      const next = await scanLeaf(item, budget, lint);
      if (next !== undefined) {
        try {
          v[key] = next;
          total += 1;
        } catch {
          // read-only field; skip
        }
      } else if (item && typeof item === "object") {
        await walk(item);
      }
    }
  };
  await walk(value);
  return total;
}

/** Deep-redacts an arbitrary JSON-like value, returning a new value + aggregate count. */
async function redactDeepValue(value, { lint }) {
  const budget = { remaining: METADATA_SCAN_BUDGET_CHARS };
  const walked = await redactObjectStrings(value, { lint }, budget);
  return { value: walked.value, count: walked.redactionCount, ruleIds: walked.ruleIds };
}

/** Redacts a string field of a plain object, returning a new object only when changed. */
async function redactTextField(obj, key, { lint }) {
  const current = obj?.[key];
  if (typeof current !== "string" || current.length === 0) {
    return { part: obj, count: 0, ruleIds: [] };
  }
  const scanned = await scanAndRedact(current, { lint });
  if (scanned.redactionCount === 0) {
    return { part: obj, count: 0, ruleIds: [] };
  }
  return { part: { ...obj, [key]: scanned.text }, count: scanned.redactionCount, ruleIds: scanned.ruleIds };
}

/** Deep-redacts a maybe-string/maybe-object field of a plain object, returning a new object only when changed. */
async function redactObjectField(obj, key, { lint }) {
  const current = obj?.[key];
  if (current === undefined || current === null) {
    return { part: obj, count: 0, ruleIds: [] };
  }
  if (typeof current === "string") {
    return redactTextField(obj, key, { lint });
  }
  if (typeof current !== "object") {
    return { part: obj, count: 0, ruleIds: [] };
  }
  const r = await redactDeepValue(current, { lint });
  if (r.count === 0) {
    return { part: obj, count: 0, ruleIds: [] };
  }
  return { part: { ...obj, [key]: r.value }, count: r.count, ruleIds: r.ruleIds };
}

/**
 * Redacts a `ToolResultValue` union (`{type, value}`). For `type:"content"`
 * only the inline `text` blocks are scanned (URI `file` blocks are left
 * untouched); for `json`/`text`/`error` the whole `value` is deep-scanned
 * (the `error` variant is how a tool failure reaches the model).
 */
async function redactResultValue(result, { lint }) {
  if (!result || typeof result !== "object") {
    return { result, count: 0, ruleIds: [] };
  }
  if (result.type === "content" && Array.isArray(result.value)) {
    let total = 0;
    const ruleIdSet = new Set();
    const blocks = [];
    for (const block of result.value) {
      if (block && block.type === "text" && typeof block.text === "string") {
        const scanned = await scanAndRedact(block.text, { lint });
        if (scanned.redactionCount > 0) {
          blocks.push({ ...block, text: scanned.text });
          total += scanned.redactionCount;
          for (const id of scanned.ruleIds) ruleIdSet.add(id);
          continue;
        }
      }
      blocks.push(block);
    }
    if (total === 0) return { result, count: 0, ruleIds: [] };
    return { result: { ...result, value: blocks }, count: total, ruleIds: [...ruleIdSet] };
  }
  const r = await redactDeepValue(result.value, { lint });
  if (r.count === 0) return { result, count: 0, ruleIds: [] };
  return { result: { ...result, value: r.value }, count: r.count, ruleIds: r.ruleIds };
}

/**
 * Redacts any one `ContentPart` variant, returning a new part only when
 * changed. Media parts (binary/base64/url/ref) and effort parts are never
 * touched; tool-call inputs and tool-result values are deep-scanned; text
 * and compaction parts scan their `.text`; reasoning parts are left
 * completely untouched (see the `case "reasoning"` note below).
 *
 * Note: redacting `tool-call.input` rewrites the model's own prior tool-call
 * arguments in the replayed request payload. That is intentional for
 * confidentiality, but it means the model sees a placeholder where it
 * previously emitted a real value.
 */
async function redactContentPart(part, { lint }) {
  if (!part || typeof part !== "object") {
    return { part, count: 0, ruleIds: [] };
  }
  switch (part.type) {
    case "text":
      return redactTextField(part, "text", { lint });
    case "reasoning":
      // Provider-signed: a reasoning part's providerMetadata carries proof of
      // generation (Anthropic signature, Gemini thought signature, OpenAI
      // encrypted content). Anthropic and AWS Bedrock reject requests whose
      // thinking blocks were modified after generation, so scanning this
      // part's text and returning an edited part while keeping the signature
      // is invalid protocol state — the part is exempted entirely. Redacting
      // signed reasoning is out of scope until a provider-compatible
      // confidentiality policy exists (docs/v2-compat-audit.md).
      return { part, count: 0, ruleIds: [] };
    case "compaction":
      if (typeof part.text !== "string") return { part, count: 0, ruleIds: [] };
      return redactTextField(part, "text", { lint });
    case "tool-call":
      return redactObjectField(part, "input", { lint });
    case "tool-result": {
      const r = await redactResultValue(part.result, { lint });
      if (r.count === 0) return { part, count: 0, ruleIds: [] };
      return { part: { ...part, result: r.result }, count: r.count, ruleIds: r.ruleIds };
    }
    case "media":
    case "effort":
      return { part, count: 0, ruleIds: [] };
    default:
      // Unknown future variant: best-effort scan a string `.text`.
      return redactTextField(part, "text", { lint });
  }
}

/**
 * Redacts a V2 tool result (design.md D6): only `status === "completed"` is
 * ever scanned (D6a — a tool error's `error: Tool.Error` is left alone,
 * both because V1 never saw this branch either and because handling it
 * would require a runtime import of that schema class, reintroducing the
 * dependency D1 removes). Returns a NEW result object when anything was
 * redacted (`Tool.Result`'s fields are readonly), or the original `result`
 * reference unchanged otherwise.
 */
async function redactToolResult(result, { lint }) {
  let workingResult = result;
  let totalRedactionCount = 0;
  let annotated = false;
  const ruleIdSet = new Set();

  if (typeof workingResult.content === "string") {
    const scanned = await redactSecrets(workingResult.content, { lint });
    if (scanned.redactionCount > 0) {
      workingResult = { ...workingResult, content: scanned.text };
      totalRedactionCount += scanned.redactionCount;
      for (const ruleId of scanned.ruleIds) ruleIdSet.add(ruleId);
      annotated = true;
    }
  } else if (Array.isArray(workingResult.content)) {
    const blocks = [];
    let blockTotal = 0;
    const blockRuleIds = new Set();
    let lastRedactedIndex = -1;

    for (const block of workingResult.content) {
      const redacted = await redactContentBlock(block, { lint });
      blocks.push(redacted.block);
      if (redacted.redactionCount > 0) {
        blockTotal += redacted.redactionCount;
        for (const ruleId of redacted.ruleIds) blockRuleIds.add(ruleId);
        lastRedactedIndex = blocks.length - 1;
      }
    }

    if (blockTotal > 0) {
      // Design.md D6c: exactly one annotation, on the last redacted block.
      const sortedRuleIds = [...blockRuleIds].sort();
      blocks[lastRedactedIndex] = {
        ...blocks[lastRedactedIndex],
        text: `${blocks[lastRedactedIndex].text}\n\n${buildAnnotation(blockTotal, sortedRuleIds)}`,
      };
      workingResult = { ...workingResult, content: blocks };
      totalRedactionCount += blockTotal;
      for (const ruleId of blockRuleIds) ruleIdSet.add(ruleId);
      annotated = true;
    }
  } else if (typeof workingResult.content === "undefined" && typeof workingResult.output === "string") {
    // design.md D6d: `content` absent entirely and `output` is a bare
    // string -- the only shape the original design anticipated.
    const scanned = await redactSecrets(workingResult.output, { lint });
    if (scanned.redactionCount > 0) {
      workingResult = { ...workingResult, output: scanned.text };
      totalRedactionCount += scanned.redactionCount;
      for (const ruleId of scanned.ruleIds) ruleIdSet.add(ruleId);
      annotated = true;
    }
  }

  // Empirically confirmed against the real host (@opencode/cli 2.0.4): the
  // built-in `shell` tool's `result.output` is NOT a bare string even when
  // `result.content` IS present -- it is a structured
  // `{exit, truncated, output: <same raw text as content>, status}` record.
  // This is a duplicate carrier of the same text `content` already covers,
  // not the "arbitrary programmatic data, never model-facing" case D6d's
  // original bare-string branch above was written for. Redact this nested
  // string field independently of whether `content` was already handled,
  // so the same secret can never survive in this parallel field.
  if (
    workingResult.output &&
    typeof workingResult.output === "object" &&
    !Array.isArray(workingResult.output) &&
    typeof workingResult.output.output === "string"
  ) {
    const scanned = await scanAndRedact(workingResult.output.output, { lint });
    if (scanned.redactionCount > 0) {
      // When `content` was absent, this structured field is the only carrier
      // of the redacted text, so attach the model-facing annotation here too —
      // otherwise a redaction would occur with no note. When `content` was
      // present it already carries the note, so the duplicate field stays bare.
      const nextText = annotated
        ? scanned.text
        : `${scanned.text}\n\n${buildAnnotation(scanned.redactionCount, [...scanned.ruleIds].sort())}`;
      workingResult = { ...workingResult, output: { ...workingResult.output, output: nextText } };
      totalRedactionCount += scanned.redactionCount;
      for (const ruleId of scanned.ruleIds) ruleIdSet.add(ruleId);
      annotated = true;
    }
  }

  // design.md D4: metadata is scanned unconditionally, independent of
  // content/output handling above -- it had zero prior scanning behavior,
  // so there is no existing test to regress here (unlike output, whose
  // arbitrary-structured-data case must stay untouched -- see D4's
  // implementation-time correction).
  if (workingResult.metadata && typeof workingResult.metadata === "object" && !Array.isArray(workingResult.metadata)) {
    const budget = { remaining: METADATA_SCAN_BUDGET_CHARS };
    const walked = await redactObjectStrings(workingResult.metadata, { lint }, budget);
    if (walked.redactionCount > 0) {
      workingResult = { ...workingResult, metadata: walked.value };
      totalRedactionCount += walked.redactionCount;
      for (const ruleId of walked.ruleIds) ruleIdSet.add(ruleId);
    }
  }

  if (totalRedactionCount === 0) {
    return { result, redactionCount: 0, ruleIds: [] };
  }
  return { result: workingResult, redactionCount: totalRedactionCount, ruleIds: [...ruleIdSet].sort() };
}

/**
 * Redacts an array of ContentPart variants (text, reasoning, compaction,
 * tool-call, tool-result, media, effort) by replacing changed slots via
 * `redactContentPart` (copy-on-write; nothing is written in place and
 * untouched parts keep their identity). When anything was redacted, exactly
 * one `buildAnnotation` note is appended to the last redacted part that
 * carries a string `.text` (text/compaction) — the aggregate-then-
 * annotate-once shape shared by `Tool.Content[]`, `event.system[]`, and each
 * message's `content[]`. Parts with no redacted text (tool-call/tool-result)
 * are redacted without an annotation. Returns `{redactionCount, ruleIds}`
 * for the caller's logging.
 */
async function redactContentArray(blocks, { lint }) {
  let total = 0;
  const ruleIdSet = new Set();
  let lastTextIndex = -1;

  for (let i = 0; i < blocks.length; i += 1) {
    const redacted = await redactContentPart(blocks[i], { lint });
    if (redacted.count > 0) {
      blocks[i] = redacted.part;
      total += redacted.count;
      for (const ruleId of redacted.ruleIds) ruleIdSet.add(ruleId);
      // Annotate only `type:"text"` parts (system prompt + message text):
      // injecting the tool-output-worded note into reasoning/compaction
      // content would be semantically wrong.
      if (redacted.part?.type === "text" && typeof redacted.part.text === "string") lastTextIndex = i;
    }
  }

  if (total === 0) {
    return { redactionCount: 0, ruleIds: [] };
  }

  const sortedRuleIds = [...ruleIdSet].sort();
  if (lastTextIndex >= 0) {
    blocks[lastTextIndex] = {
      ...blocks[lastTextIndex],
      text: `${blocks[lastTextIndex].text}\n\n${buildAnnotation(total, sortedRuleIds)}`,
    };
  }
  return { redactionCount: total, ruleIds: sortedRuleIds };
}

/**
 * Redacts the request payload assembled/re-derived for a provider call
 * (design.md D1-D3): shared by the `context`, `generate`, and `compaction`
 * session hooks, since all three extend `SessionContext`
 * (`{system: SystemPart[], messages: Message[], ...}`, both mutable).
 *
 * `event.system[]` elements always have the exact `{type:"text", text}`
 * shape `redactContentBlock` expects (verified: `SystemPart` is not a
 * union), so it is reused unchanged. `event.messages[].content[]` is a
 * six-member tagged union (`Message.content: ContentPart[]`); text,
 * compaction, tool-call, and tool-result parts are scanned (the latter two
 * deep-walked copy-on-write), while media and effort parts and provider-
 * signed reasoning parts are left completely untouched: reasoning parts
 * carry providerMetadata proof-of-generation (Anthropic signature, Gemini
 * thought signature, OpenAI encrypted content) that loses validity if the
 * text is edited, and both Anthropic and AWS Bedrock reject modified
 * thinking blocks (D3, mirrors the archived design's D6c precedent of
 * scanning only verified-safe union members).
 *
 * Ownership: the host derives `system`/`messages` fresh per provider call
 * and consumes the hook-modified arrays only for the outgoing request —
 * array-slot replacement never reaches the session's persisted message
 * history (traced with file:line references in docs/v2-compat-audit.md).
 *
 * Annotation is aggregated once per container (D2: the whole `system[]`
 * array; D3: each message's own `content[]` independently) via
 * `redactTextBlockArray` -- the same aggregate-then-annotate-once shape
 * the archived design already applies to `Tool.Content[]`.
 */
async function redactSessionContextHandler(event, { lint }, log) {
  try {
    if (Array.isArray(event.system) && event.system.length > 0) {
      const { redactionCount, ruleIds } = await redactContentArray(event.system, { lint });
      if (redactionCount > 0) {
        log("warn", `redacted ${redactionCount} secret(s) in assembled system prompt (rules: ${ruleIds.join("+")})`, {
          source: "system-prompt",
          count: redactionCount,
          ruleIds,
        });
      }
    }

    if (Array.isArray(event.messages)) {
      for (const message of event.messages) {
        if (!Array.isArray(message?.content) || message.content.length === 0) {
          continue;
        }
        const { redactionCount, ruleIds } = await redactContentArray(message.content, { lint });
        if (redactionCount > 0) {
          log("warn", `redacted ${redactionCount} secret(s) in a message's content (rules: ${ruleIds.join("+")})`, {
            source: "message-history",
            count: redactionCount,
            ruleIds,
          });
        }
      }
    }
  } catch (err) {
    log("error", `session-context redaction handler failed: ${err?.message ?? err}`);
  }
}

export default {
  id: PLUGIN_NAME,

  /**
   * `testOverrides` (design.md D2) is a second parameter, never a named
   * export — the real V2 host only ever calls `setup(ctx)`, so the default
   * `{}` is always what production sees; the shape stays exactly
   * `{id, setup}`. Mirrors V1's `_loadPluginConfigOverride` /
   * `_createSecretlintConfigOverride` / `_createLinterOverride` seam.
   *
   * @param {{
   *   _createSecretlintConfigOverride?: () => Promise<unknown>,
   *   _createLinterOverride?: (config: unknown, options?: unknown) => (text: string, opts?: unknown) => Promise<unknown>,
   *   _loadPluginConfigOverride?: (params?: unknown) => Promise<{ disableHighEntropy: boolean }>,
   * }} [testOverrides]
   */
  async setup(ctx, testOverrides = {}) {
    const loadPlugConfig = testOverrides._loadPluginConfigOverride ?? loadPluginConfig;
    const loadConfig = testOverrides._createSecretlintConfigOverride ?? createSecretlintConfig;
    const buildLinter = testOverrides._createLinterOverride ?? createCompositeLinter;

    // Bootstrap logger with defaults so configuration-load warnings have a
    // sink before the configured logger exists; the configured logger is
    // built immediately after and used for everything else.
    const bootstrapLog = createLogger();
    const pluginConfig = await loadPlugConfig({
      log: (level, message) => bootstrapLog.log(level, message),
    });

    const logger = createLogger(pluginConfig.log ?? {});
    const log = (level, message, fields) => logger.log(level, message, fields);

    // Step 2: the secretlint rule bundle itself. May throw — fail loud,
    // unchanged from V1's behavior.

    let config;
    try {
      config = await loadConfig();
    } catch (err) {
      log("error", `failed to load secretlint rule configuration: ${err?.message ?? err}`);
      throw err;
    }

    const lint = buildLinter(config, { disableHighEntropy: pluginConfig.disableHighEntropy });

    const registrations = await Promise.all([
      ctx.tool.hook("execute.after", async (event) => {
        try {
          if (event.status === "error") {
            // Tightened: a tool failure's error payload is exactly where
            // secrets surface (stack traces, env dumps, connection strings).
            // `Tool.Error` is a host Schema.Class, so redact its string leaves
            // IN PLACE to preserve identity/prototype (a plain clone could
            // break host serialization).
            if (event.error && typeof event.error === "object") {
              const budget = { remaining: METADATA_SCAN_BUDGET_CHARS };
              const count = await redactValueInPlace(event.error, { lint }, budget);
              if (count > 0) {
                log("warn", `redacted ${count} secret(s) in tool '${event.tool}' error`, {
                  source: "tool-error",
                  tool: event.tool,
                  count,
                });
              }
            }
            return;
          }

          if (event.status !== "completed") {
            return;
          }

          const { result, redactionCount, ruleIds } = await redactToolResult(event.result, { lint });
          if (redactionCount === 0) {
            return;
          }

          event.result = result;
          log("warn", `redacted ${redactionCount} secret(s) in tool '${event.tool}' output (rules: ${ruleIds.join("+")})`, {
            source: "tool-output",
            tool: event.tool,
            count: redactionCount,
            ruleIds,
          });
        } catch (err) {
          log("error", `redaction handler failed for tool '${event?.tool}': ${err?.message}`);
        }
      }),

      ctx.session.hook("prompt", async (event) => {
        try {
          const text = event?.prompt?.text;
          if (typeof text !== "string" || text.length === 0) {
            return;
          }

          // design.md D4: the V2 prompt hook boundary already excludes
          // synthetic/file-body content structurally (they are delivered
          // through a separate SessionInbox item shape this hook never
          // receives) — so the whole string is scanned unconditionally,
          // matching V1's effective (non-synthetic-parts-only) scope.
          const { text: redacted, redactionCount, ruleIds } = await redactUserMessage(text, { lint });
          if (redactionCount === 0) {
            return;
          }

          // Write the redaction first, the annotation second, as two
          // separate steps (design.md D5) — matching V1's tested guarantee
          // that a redaction survives even if the annotation-append itself
          // throws. A single combined assignment would lose an
          // already-computed redaction if that one write ever failed.
          event.prompt.text = redacted;
          try {
            event.prompt.text += `\n\n${buildUserMessageAnnotation(redactionCount, ruleIds)}`;
          } catch (err) {
            log("error", `failed to append user-message redaction annotation: ${err?.message ?? err}`);
          }
          log("warn", `redacted ${redactionCount} secret(s) in user message (rules: ${ruleIds.join("+")})`, {
            source: "prompt",
            count: redactionCount,
            ruleIds,
          });
        } catch (err) {
          log("error", `user-message redaction handler failed: ${err?.message ?? err}`);
        }
      }),

      ctx.session.hook("context", (event) => redactSessionContextHandler(event, { lint }, log)),
      ctx.session.hook("generate", (event) => redactSessionContextHandler(event, { lint }, log)),
      ctx.session.hook("compaction", (event) => redactSessionContextHandler(event, { lint }, log)),
      // `SessionTitle` is a distinct auxiliary provider request
      // (SessionRequestKind includes "title") carrying system[] + messages[],
      // so it must be redacted independently — the context hook does not fire
      // for it.
      ctx.session.hook("title", (event) => redactSessionContextHandler(event, { lint }, log)),
    ]);

    return async () => {
      await Promise.allSettled(registrations.map((registration) => registration.dispose()));
    };
  },
};
