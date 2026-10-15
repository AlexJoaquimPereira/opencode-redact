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

// D4 (design.md): total character budget for the recursive metadata walk,
// shared across every string leaf scanned in one redactToolResult call.
// Consistent with secretlint.js's per-scan DEFAULT_TIMEOUT_MS -- this is a
// count/size cap, not a new timeout: each scanAndRedact call still races its
// own per-call timeout unchanged; this only bounds how many such calls one
// metadata walk can issue.
const METADATA_SCAN_BUDGET_CHARS = 200_000;

/** Returns a logger function; V2's Context.app has no log method (design.md D3), so this is stderr-only. */
function makeLogger() {
  return (level, message) => {
    process.stderr.write(`[${PLUGIN_NAME}] [${level}] ${message}\n`);
  };
}

/**
 * Redacts a single V2 `Tool.Content` block in place. Returns
 * `{content, redactionCount, ruleIds}` — `content` unchanged when nothing
 * was redacted or the block is not a `type:"text"` block (design.md D6c:
 * `type:"file"` blocks are URI references with no inline body, and are
 * left completely untouched).
 */
async function redactContentBlock(block, { lint, honorNoRedact = false }) {
  if (!block || block.type !== "text" || typeof block.text !== "string") {
    return { block, redactionCount: 0, ruleIds: [] };
  }
  const scanned = honorNoRedact
    ? await redactUserMessage(block.text, { lint })
    : await scanAndRedact(block.text, { lint });
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
    for (const key of Object.keys(value)) {
      const walked = await redactObjectStrings(value[key], { lint }, budget);
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
  const ruleIdSet = new Set();

  if (typeof workingResult.content === "string") {
    const scanned = await redactSecrets(workingResult.content, { lint });
    if (scanned.redactionCount > 0) {
      workingResult = { ...workingResult, content: scanned.text };
      totalRedactionCount += scanned.redactionCount;
      for (const ruleId of scanned.ruleIds) ruleIdSet.add(ruleId);
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
    }
  } else if (typeof workingResult.content === "undefined" && typeof workingResult.output === "string") {
    // design.md D6d: `content` absent entirely and `output` is a bare
    // string -- the only shape the original design anticipated.
    const scanned = await redactSecrets(workingResult.output, { lint });
    if (scanned.redactionCount > 0) {
      workingResult = { ...workingResult, output: scanned.text };
      totalRedactionCount += scanned.redactionCount;
      for (const ruleId of scanned.ruleIds) ruleIdSet.add(ruleId);
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
      workingResult = { ...workingResult, output: { ...workingResult.output, output: scanned.text } };
      totalRedactionCount += scanned.redactionCount;
      for (const ruleId of scanned.ruleIds) ruleIdSet.add(ruleId);
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
 * Walks an array of `{type:"text", text}`-shaped blocks, redacting each via
 * `redactContentBlock` and mutating the array in place. When anything was
 * redacted, exactly one `buildAnnotation` note is appended to the last
 * redacted block's `.text` (the aggregate-then-annotate-once shape shared
 * by `Tool.Content[]`, `event.system[]`, and each message's `content[]`).
 * Returns `{redactionCount, ruleIds}` for the caller's own logging.
 */
async function redactTextBlockArray(blocks, { lint, honorNoRedact = false }) {
  let total = 0;
  const ruleIdSet = new Set();
  let lastRedactedIndex = -1;

  for (let i = 0; i < blocks.length; i += 1) {
    const redacted = await redactContentBlock(blocks[i], { lint, honorNoRedact });
    if (redacted.redactionCount > 0) {
      blocks[i] = redacted.block;
      total += redacted.redactionCount;
      for (const ruleId of redacted.ruleIds) ruleIdSet.add(ruleId);
      lastRedactedIndex = i;
    }
  }

  if (total === 0) {
    return { redactionCount: 0, ruleIds: [] };
  }

  const sortedRuleIds = [...ruleIdSet].sort();
  blocks[lastRedactedIndex] = {
    ...blocks[lastRedactedIndex],
    text: `${blocks[lastRedactedIndex].text}\n\n${buildAnnotation(total, sortedRuleIds)}`,
  };
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
 * six-member tagged union (`Message.content: ContentPart[]`); only
 * `type === "text"` blocks share that same shape and are redacted --
 * every other variant (media, tool-call, tool-result, reasoning,
 * compaction, effort) is left untouched (D3, mirrors the archived design's
 * D6c precedent of scanning only a verified-safe union member).
 *
 * Annotation is aggregated once per container (D2: the whole `system[]`
 * array; D3: each message's own `content[]` independently) via
 * `redactTextBlockArray` -- the same aggregate-then-annotate-once shape
 * the archived design already applies to `Tool.Content[]`.
 */
async function redactSessionContextHandler(event, { lint }, log) {
  try {
    if (Array.isArray(event.system) && event.system.length > 0) {
      const { redactionCount, ruleIds } = await redactTextBlockArray(event.system, { lint });
      if (redactionCount > 0) {
        log("warn", `redacted ${redactionCount} secret(s) in assembled system prompt (rules: ${ruleIds.join("+")})`);
      }
    }

    if (Array.isArray(event.messages)) {
      for (const message of event.messages) {
        if (!Array.isArray(message?.content) || message.content.length === 0) {
          continue;
        }
        // User role is the exemption boundary, not proof of human authorship.
        const { redactionCount, ruleIds } = await redactTextBlockArray(message.content, {
          lint,
          honorNoRedact: message.role === "user",
        });
        if (redactionCount > 0) {
          log("warn", `redacted ${redactionCount} secret(s) in a message's content (rules: ${ruleIds.join("+")})`);
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
          if (event.status !== "completed") {
            // design.md D6a: a tool error is never scanned here.
            return;
          }

          const { result, redactionCount, ruleIds } = await redactToolResult(event.result, { lint });
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
    ]);

    return async () => {
      await Promise.allSettled(registrations.map((registration) => registration.dispose()));
    };
  },
};
