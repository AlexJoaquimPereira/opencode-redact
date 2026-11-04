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
import { redactSecrets, redactUserMessage, buildAnnotation, buildUserMessageAnnotation, scanAndRedact } from "./redact.js";

const PLUGIN_NAME = "opencode-redact";

// Per-traversal limits complement the scanner's per-call timeout.
const METADATA_SCAN_BUDGET_CHARS = 200_000;
const STRUCTURED_SCAN_MAX_DEPTH = 128;
const STRUCTURED_SCAN_MAX_VISITS = 10_000;

/** Returns a logger function; V2's Context.app has no log method (design.md D3), so this is stderr-only. */
function makeLogger() {
  return (level, message) => {
    try {
      process.stderr.write(`[${PLUGIN_NAME}] [${level}] ${message}\n`);
    } catch { /* Diagnostics must not interrupt redaction. */ }
  };
}

function createScanState(log) {
  return { remaining: METADATA_SCAN_BUDGET_CHARS, visits: STRUCTURED_SCAN_MAX_VISITS, ancestors: new WeakSet(), skipped: new Set(), log };
}

function warnSkipped(state, reason) {
  if (state.skipped.has(reason)) return;
  state.skipped.add(reason);
  state.log("warn", `structured redaction skipped (${reason})`);
}

function visitValue(state) {
  if (state.visits === 0) {
    warnSkipped(state, "visits");
    return false;
  }
  state.visits -= 1;
  return true;
}

function enterContainer(value, state, depth) {
  const reason = state.ancestors.has(value) ? "cycle" : depth >= STRUCTURED_SCAN_MAX_DEPTH ? "depth" : null;
  if (reason) {
    warnSkipped(state, reason);
    return false;
  }
  state.ancestors.add(value);
  return true;
}

/**
 * Recursively walks an arbitrary JSON-like value, scanning and redacting
 * every string leaf within the traversal limits. Rebuilds arrays and
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
 * Cyclic back-edges and over-depth branches remain untouched. Tracking the
 * current path, rather than all visited objects, lets shared siblings each
 * receive their own redacted clone without mutating their common source.
 */
async function redactObjectStrings(value, { lint }, budget, depth = 0) {
  if (!visitValue(budget)) return { value, redactionCount: 0, ruleIds: [] };
  if (typeof value === "string") {
    const scanned = await scanLeaf(value, budget, lint);
    return scanned
      ? { value: scanned.text, redactionCount: scanned.redactionCount, ruleIds: scanned.ruleIds }
      : { value, redactionCount: 0, ruleIds: [] };
  }

  if (value && typeof value === "object" && !Array.isArray(value)) {
    const prototype = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null) {
      return { value, redactionCount: 0, ruleIds: [] };
    }
  }

  if (!value || typeof value !== "object" || !enterContainer(value, budget, depth)) {
    return { value, redactionCount: 0, ruleIds: [] };
  }

  try {
    let totalCount = 0;
    const ruleIdSet = new Set();
    const descriptors = Object.getOwnPropertyDescriptors(value);
    for (const key of Object.getOwnPropertyNames(descriptors)) {
      if (Array.isArray(value) && key === "length") continue;
      if (budget.visits === 0) {
        warnSkipped(budget, "visits");
        break;
      }
      let item;
      try {
        item = value[key];
      } catch {
        visitValue(budget);
        continue; // throwing getter; fail-open
      }
      const walked = await redactObjectStrings(item, { lint }, budget, depth + 1);
      const descriptor = descriptors[key];
      if ("value" in descriptor) descriptor.value = walked.value;
      else if (walked.redactionCount > 0) {
        descriptors[key] = { value: walked.value, enumerable: descriptor.enumerable, configurable: descriptor.configurable, writable: true };
      }
      totalCount += walked.redactionCount;
      for (const ruleId of walked.ruleIds) ruleIdSet.add(ruleId);
    }
    const clone = totalCount === 0 ? value : Array.isArray(value)
      ? Object.defineProperties([], descriptors)
      : Object.create(Object.getPrototypeOf(value), descriptors);
    return { value: clone, redactionCount: totalCount, ruleIds: [...ruleIdSet] };
  } finally {
    budget.ancestors.delete(value);
  }
}

/**
 * Scans a single string leaf against a shared budget. Returns the redacted
 * scan result, or `undefined` when the value is not a string, is empty, exceeds the
 * remaining budget, or has no finding. Fail-open, like the rest of the plugin.
 */
async function scanLeaf(text, budget, lint) {
  if (typeof text !== "string" || text.length === 0) return undefined;
  if (text.length > budget.remaining) {
    warnSkipped(budget, "budget");
    return undefined;
  }
  budget.remaining -= text.length;
  const scanned = await scanAndRedact(text, { lint });
  return scanned.redactionCount > 0 ? scanned : undefined;
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
  const walk = async (v, depth) => {
    if (!visitValue(budget) || !v || typeof v !== "object" || !enterContainer(v, budget, depth)) return;
    try {
      for (const key of Object.getOwnPropertyNames(v)) {
        if (Array.isArray(v) && key === "length") continue;
        if (budget.visits === 0) {
          warnSkipped(budget, "visits");
          break;
        }
        let item;
        try {
          item = v[key];
        } catch {
          visitValue(budget);
          continue; // throwing getter; fail-open
        }
        if (item && typeof item === "object") {
          await walk(item, depth + 1);
          continue;
        }
        if (!visitValue(budget)) break;
        const scanned = await scanLeaf(item, budget, lint);
        if (scanned) {
          try {
            v[key] = scanned.text;
            total += 1;
          } catch {
            // Host fields can be read-only; preserve the host object.
            continue;
          }
        }
      }
    } finally {
      budget.ancestors.delete(v);
    }
  };
  await walk(value, 0);
  return total;
}

/** Deep-redacts an arbitrary JSON-like value, returning a new value + aggregate count. */
async function redactDeepValue(value, { lint, log, budget = createScanState(log) }) {
  const walked = await redactObjectStrings(value, { lint }, budget);
  return { value: walked.value, count: walked.redactionCount, ruleIds: walked.ruleIds };
}

/** Redacts a string field of a plain object, returning a new object only when changed. */
async function redactTextField(obj, key, { lint, honorNoRedact = false }) {
  const current = obj?.[key];
  if (typeof current !== "string" || current.length === 0) {
    return { part: obj, count: 0, ruleIds: [] };
  }
  const scanned = honorNoRedact
    ? await redactUserMessage(current, { lint })
    : await scanAndRedact(current, { lint });
  if (scanned.redactionCount === 0) {
    return { part: obj, count: 0, ruleIds: [] };
  }
  return { part: { ...obj, [key]: scanned.text }, count: scanned.redactionCount, ruleIds: scanned.ruleIds };
}

/** Deep-redacts a maybe-string/maybe-object field of a plain object, returning a new object only when changed. */
async function redactObjectField(obj, key, { lint, log, budget }) {
  const current = obj?.[key];
  if (current === undefined || current === null) {
    return { part: obj, count: 0, ruleIds: [] };
  }
  if (typeof current !== "object" && typeof current !== "string") {
    return { part: obj, count: 0, ruleIds: [] };
  }
  const r = await redactDeepValue(current, { lint, log, budget });
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
async function redactResultValue(result, { lint, log, budget }) {
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
  const r = await redactDeepValue(result.value, { lint, log, budget });
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
 * emitted a real value. Call identity, signature metadata and order are retained.
 */
async function redactContentPart(part, { lint, log, budget, honorNoRedact = false }) {
  if (!part || typeof part !== "object") {
    return { part, count: 0, ruleIds: [] };
  }
  switch (part.type) {
    case "text":
      return redactTextField(part, "text", { lint, honorNoRedact });
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
      return redactObjectField(part, "input", { lint, log, budget });
    case "tool-result": {
      const r = await redactResultValue(part.result, { lint, log, budget });
      if (r.count === 0) return { part, count: 0, ruleIds: [] };
      return { part: { ...part, result: r.result }, count: r.count, ruleIds: r.ruleIds };
    }
    case "media":
    case "effort":
      return { part, count: 0, ruleIds: [] };
    default:
      // Unknown future variant: best-effort scan a string `.text`, honoring a
      // user-role `noredact` fence exactly as a `text` part would.
      return redactTextField(part, "text", { lint, honorNoRedact });
  }
}

/**
 * Redacts a completed V2 tool result by replacing changed fields on a new
 * result object (`Tool.Result`'s fields are readonly). Tool errors use the
 * separate in-place walker to retain host class identity and prototype.
 */
async function redactToolResult(result, { lint, log }) {
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
      const redacted = block?.type === "text"
        ? await redactTextField(block, "text", { lint })
        : { part: block, count: 0, ruleIds: [] };
      blocks.push(redacted.part);
      if (redacted.count > 0) {
        blockTotal += redacted.count;
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
    const scanned = await redactSecrets(workingResult.output, { lint });
    if (scanned.redactionCount > 0) {
      workingResult = { ...workingResult, output: scanned.text };
      totalRedactionCount += scanned.redactionCount;
      for (const ruleId of scanned.ruleIds) ruleIdSet.add(ruleId);
      annotated = true;
    }
  }

  // The host's shell result duplicates content in a structured output.output
  // field. Scan both carriers independently without rewriting other fields.
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

  // Metadata is independent of the narrowly targeted output fields.
  if (workingResult.metadata && typeof workingResult.metadata === "object" && !Array.isArray(workingResult.metadata)) {
    const budget = createScanState(log);
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
async function redactContentArray(blocks, { lint, log, budget, honorNoRedact = false }) {
  let total = 0;
  const ruleIdSet = new Set();
  let lastAnnotatableIndex = -1;

  for (let i = 0; i < blocks.length; i += 1) {
    const redacted = await redactContentPart(blocks[i], { lint, log, budget, honorNoRedact });
    if (redacted.count > 0) {
      blocks[i] = redacted.part;
      total += redacted.count;
      for (const ruleId of redacted.ruleIds) ruleIdSet.add(ruleId);
      // Annotate the last redacted part that carries model-facing text (a
      // `text` block, a `compaction` summary, or any future text-bearing
      // variant). Parts with no `.text` (tool-call inputs, tool-result
      // values) cannot carry the note; a container whose redactions are all
      // there is still counted and logged, just without an annotation.
      if (typeof redacted.part?.text === "string") lastAnnotatableIndex = i;
    }
  }

  if (total === 0) {
    return { redactionCount: 0, ruleIds: [] };
  }

  const sortedRuleIds = [...ruleIdSet].sort();
  if (lastAnnotatableIndex >= 0) {
    blocks[lastAnnotatableIndex] = {
      ...blocks[lastAnnotatableIndex],
      text: `${blocks[lastAnnotatableIndex].text}\n\n${buildAnnotation(total, sortedRuleIds)}`,
    };
  }
  return { redactionCount: total, ruleIds: sortedRuleIds };
}

/**
 * Scans derived provider requests without mutating shared history objects.
 * Structured inputs/results share one budget across the hook invocation.
 * User-role text alone honors fences; signed reasoning stays untouched.
 * Each container fails independently and carries at most one annotation;
 * tool-call inputs and tool-result values never carry annotations.
 */
async function redactSessionContextHandler(event, { lint }, log) {
  const budget = createScanState(log);
  try {
    if (Array.isArray(event.system) && event.system.length > 0) {
      const { redactionCount, ruleIds } = await redactContentArray(event.system, { lint, log, budget });
      if (redactionCount > 0) {
        log("warn", `redacted ${redactionCount} secret(s) in assembled system prompt (rules: ${ruleIds.join("+")})`);
      }
    }

  } catch {
    log("error", "system-prompt redaction handler failed");
  }

  if (Array.isArray(event.messages)) {
    for (const message of event.messages) {
      try {
        if (!Array.isArray(message?.content) || message.content.length === 0) {
          continue;
        }
        // User role is the exemption boundary, not proof of human authorship:
        // a noredact fence in a user-role text block is exempt from rescan.
        const { redactionCount, ruleIds } = await redactContentArray(message.content, {
          lint,
          log,
          budget,
          honorNoRedact: message.role === "user",
        });
        if (redactionCount > 0) {
          log("warn", `redacted ${redactionCount} secret(s) in a message's content (rules: ${ruleIds.join("+")})`);
        }
      } catch {
        log("error", "message-content redaction handler failed");
      }
    }
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

    const log = makeLogger();

    // Step 1 (design.md D2): the plugin's own optional settings file. Never
    // throws, by loadPluginConfig's own contract — no try/catch needed, and
    // this step MUST NOT share a try block with step 2, so a config-file
    // problem can never be reported inside, or mistaken for, the fail-loud
    // secretlint-config failure.
    const pluginConfig = await loadPlugConfig({
      log: (level, message) => log(level, message),
    });

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
            // `Tool.Error` is a host Schema.Class, so redact its string leaves
            // IN PLACE to preserve identity/prototype (a plain clone could
            // break host serialization).
            if (event.error && typeof event.error === "object") {
              const budget = createScanState(log);
              const count = await redactValueInPlace(event.error, { lint }, budget);
              if (count > 0) {
                log("warn", `redacted ${count} secret(s) in tool '${event.tool}' error`);
              }
            }
            return;
          }

          if (event.status !== "completed") {
            return;
          }

          const { result, redactionCount, ruleIds } = await redactToolResult(event.result, { lint, log });
          if (redactionCount === 0) {
            return;
          }

          event.result = result;
          log("warn", `redacted ${redactionCount} secret(s) in tool '${event.tool}' output (rules: ${ruleIds.join("+")})`);
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
          log("warn", `redacted ${redactionCount} secret(s) in user message (rules: ${ruleIds.join("+")})`);
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
