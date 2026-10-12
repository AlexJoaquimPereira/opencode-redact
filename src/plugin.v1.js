import { createSecretlintConfig, createCompositeLinter } from "./secretlint.js";
import { loadPluginConfig } from "./config.js";
import { redactSecrets, redactUserMessage, buildUserMessageAnnotation, scanAndRedact } from "./redact.js";

// Total character budget for one recursive metadata walk (parity with the V2
// adapter's METADATA_SCAN_BUDGET_CHARS).
const METADATA_SCAN_BUDGET_CHARS = 200_000;

/**
 * Recursively redacts string leaves of an arbitrary value IN PLACE using
 * `scanAndRedact`, preserving identity. Non-enumerable own fields are scanned
 * (a host error's `message`/`stack` are non-enumerable). Read-only fields are
 * skipped (fail-open). Returns the number of leaves redacted.
 */
async function redactValueInPlace(value, lint, budget) {
  let total = 0;
  const seen = new WeakSet();
  const scanLeaf = async (text) => {
    if (typeof text !== "string" || text.length === 0 || text.length > budget.remaining) return undefined;
    budget.remaining -= text.length;
    const scanned = await scanAndRedact(text, { lint });
    return scanned.redactionCount > 0 ? scanned.text : undefined;
  };
  const walk = async (v) => {
    if (!v || typeof v !== "object" || seen.has(v)) return;
    seen.add(v);
    const keys = Array.isArray(v) ? v.map((_, i) => i) : Object.getOwnPropertyNames(v);
    for (const key of keys) {
      let item;
      try {
        item = v[key];
      } catch {
        continue;
      }
      const next = await scanLeaf(item);
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

/**
 * opencode plugin that redacts secrets from tool output before it reaches
 * the LLM. Registers the `tool.execute.after` hook. See proposal.md and
 * design.md for the full behavior contract.
 *
 * `@opencode-ai/plugin` is referenced only through erased JSDoc types below
 * (never a runtime import) — see design.md D7 for why no peer-dependency
 * symlink is needed for this plugin, unlike opencode-use.
 *
 * @param {{ client: import("@opencode-ai/plugin").PluginInput["client"] }} input
 * @param {{
 *   _createSecretlintConfigOverride?: () => Promise<unknown>,
 *   _createLinterOverride?: (config: unknown, options?: unknown) => (text: string, opts?: unknown) => Promise<unknown>,
 *   _loadPluginConfigOverride?: (params?: unknown) => Promise<{ disableHighEntropy: boolean }>,
 * }} [testOverrides]
 *   Internal test seam only — never used by opencode itself.
 */
export default async function OpencodeRedact({ client }, testOverrides = {}) {
  const loadPlugConfig = testOverrides._loadPluginConfigOverride ?? loadPluginConfig;
  const loadConfig = testOverrides._createSecretlintConfigOverride ?? createSecretlintConfig;
  const buildLinter = testOverrides._createLinterOverride ?? createCompositeLinter;

  // Step 1 (design.md D8): the plugin's own optional settings file. Never
  // throws or rejects, by loadPluginConfig's own contract — no try/catch
  // needed, and this step MUST NOT share a try block with step 2 below, so
  // a config-file problem can never be reported inside, or mistaken for,
  // the fail-loud secretlint-config failure.
  const pluginConfig = await loadPlugConfig({
    log: (level, message) => logSafely(client, level, message),
  });

  // Step 2: the secretlint rule bundle itself. May throw — fail loud,
  // unchanged from before this change.
  let config;
  try {
    config = await loadConfig();
  } catch (err) {
    await logSafely(client, "error", `failed to load secretlint rule configuration: ${err?.message ?? err}`);
    throw err;
  }

  // Step 3: compose the anchored and high-entropy bundles into one linter.
  const lint = buildLinter(config, { disableHighEntropy: pluginConfig.disableHighEntropy });

  return {
    "tool.execute.after": async (input, output) => {
      try {
        const original = output?.output;
        if (typeof original === "string" && original.length > 0) {
          const { text, redactionCount, ruleIds } = await redactSecrets(original, { lint });
          if (redactionCount > 0) {
            output.output = text;
            await logSafely(
              client,
              "warn",
              `redacted ${redactionCount} secret(s) in tool '${input.tool}' output (rules: ${ruleIds.join("+")})`,
            );
          }
        }

        // Parity with the V2 adapter: also scan the tool result's metadata.
        if (output && typeof output.metadata === "object" && output.metadata !== null) {
          const budget = { remaining: METADATA_SCAN_BUDGET_CHARS };
          const metaCount = await redactValueInPlace(output.metadata, lint, budget);
          if (metaCount > 0) {
            await logSafely(client, "warn", `redacted ${metaCount} secret(s) in tool '${input.tool}' metadata`);
          }
        }
      } catch (err) {
        await logSafely(client, "error", `redaction handler failed for tool '${input?.tool}': ${err?.message}`);
      }
    },

    /**
     * Scans every non-synthetic text part of a newly received user message
     * for secrets and redacts them in place, honoring a `noredact` fenced
     * block as a per-segment exemption. Scans only parts where
     * `type === "text" && synthetic !== true` — this deliberately excludes
     * `@`-mentioned file bodies, directory listings, decoded pastes, and
     * subagent/task-tool prompts (all delivered as synthetic parts), so the
     * fence can never be honored on content the user did not type
     * themselves into the composer (design.md D2/D3).
     *
     * Never rejects, by design (design.md D7): `chat.message` hooks run
     * through `Effect.promise`, so a rejection here would abort the user's
     * entire turn, not just skip redaction. Three try/catch layers bound
     * the blast radius of any unexpected failure: the whole handler, each
     * part individually (so one poisoned part cannot suppress redaction of
     * its siblings), and the final annotation-append step.
     */
    "chat.message": async (_input, output) => {
      try {
        const parts = output?.parts;
        if (!Array.isArray(parts)) {
          return;
        }

        let total = 0;
        const unionedRuleIds = new Set();
        let lastRedactedPart = null;

        for (const part of parts) {
          try {
            if (
              !part ||
              part.type !== "text" ||
              part.synthetic === true ||
              typeof part.text !== "string" ||
              part.text.length === 0
            ) {
              continue;
            }

            const { text, redactionCount, ruleIds } = await redactUserMessage(part.text, { lint });
            if (redactionCount === 0) {
              continue;
            }

            part.text = text;
            total += redactionCount;
            for (const ruleId of ruleIds) {
              unionedRuleIds.add(ruleId);
            }
            lastRedactedPart = part;
          } catch (err) {
            await logSafely(client, "error", `user-message redaction failed for one part: ${err?.message ?? err}`);
          }
        }

        if (total === 0 || lastRedactedPart === null) {
          return;
        }

        const sortedRuleIds = [...unionedRuleIds].sort();
        let annotationAppended = false;

        try {
          lastRedactedPart.text += `\n\n${buildUserMessageAnnotation(total, sortedRuleIds)}`;
          annotationAppended = true;
        } catch (err) {
          await logSafely(
            client,
            "error",
            `failed to append user-message redaction annotation: ${err?.message ?? err}`,
          );
        }

        await logSafely(
          client,
          "warn",
          `redacted ${total} secret(s) across user message parts (rules: ${sortedRuleIds.join("+")})` +
            (annotationAppended ? "" : " — annotation append failed, see preceding error log"),
        );
      } catch (err) {
        await logSafely(client, "error", `chat.message redaction handler failed: ${err?.message ?? err}`);
      }
    },
  };
}

async function logSafely(client, level, message) {
  try {
    await client.app.log({ body: { service: "opencode-redact", level, message } });
  } catch {
    // Logging is best-effort; never let a logging failure escalate.
  }
}
