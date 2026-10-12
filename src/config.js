// Loads the plugin's own optional settings file, redact.jsonc, from the
// host application's (opencode's) configuration directory. See
// design.md D7 for the full failure-ladder rationale.
//
// This is deliberately separate from src/secretlint.js's
// createSecretlintConfig(), which loads the SECRET-DETECTION ENGINE's own
// rule bundle and fails loud on error. This file governs the PLUGIN'S OWN
// settings and fails open on every error path — a malformed or unreadable
// redact.jsonc must never block the plugin from starting, and must never
// silently expand what it disables beyond the one problem key.

import { readFileSync } from "node:fs";
import { join } from "node:path";
import { parse } from "jsonc-parser";
import { xdgConfig } from "xdg-basedir";

export const CONFIG_FILE_NAME = "redact.jsonc";

/**
 * The only setting in v1. Defaults to enabled (`false` = do not disable).
 */
export const DEFAULT_PLUGIN_CONFIG = Object.freeze({ disableHighEntropy: false });

const KEY_VALIDATORS = {
  disableHighEntropy: (value) => typeof value === "boolean",
};

/**
 * Resolves the absolute path to redact.jsonc under opencode's own config
 * directory (the same `<xdgConfig>/opencode` directory and `.jsonc` format
 * opencode itself uses — see design.md D7). Returns `null` when the
 * underlying XDG config directory itself cannot be resolved (e.g. no
 * resolvable home directory) — callers must treat `null` the same as a
 * missing file: silent defaults, never an error.
 */
export function resolveConfigPath() {
  const override = process.env.OPENCODE_CONFIG_DIR;
  if (typeof override === "string" && override.length > 0) {
    return join(override, CONFIG_FILE_NAME);
  }
  if (!xdgConfig) {
    return null;
  }
  return join(xdgConfig, "opencode", CONFIG_FILE_NAME);
}

/**
 * Loads and validates the plugin configuration. Never throws and never
 * rejects, for any input — every failure path falls back to a default
 * value and, except for a simply-missing file or an unresolvable path,
 * logs a warning naming only the problem (never a configuration value).
 *
 * @param {{ configPath?: string | null, log?: (level: string, message: string) => void | Promise<void> }} [params]
 *   `configPath` defaults to `resolveConfigPath()`; inject an explicit path
 *   (or `null`) in tests. `log` defaults to a no-op; each adapter
 *   (`src/plugin.v1.js`, `src/plugin.v2.js`) wires this to its own logging
 *   transport.
 */
export async function loadPluginConfig({ configPath = resolveConfigPath(), log = () => {} } = {}) {
  if (!configPath) {
    return { ...DEFAULT_PLUGIN_CONFIG };
  }

  let raw;
  try {
    raw = readFileSync(configPath, "utf8");
  } catch (err) {
    if (err?.code === "ENOENT") {
      return { ...DEFAULT_PLUGIN_CONFIG };
    }
    await log("warn", `could not read plugin configuration file (${err?.code ?? "unknown error"}); using defaults`);
    return { ...DEFAULT_PLUGIN_CONFIG };
  }

  const errors = [];
  const parsed = parse(raw, errors, { allowTrailingComma: true });
  if (errors.length > 0) {
    await log("warn", "plugin configuration file contains invalid JSONC syntax; using defaults");
    return { ...DEFAULT_PLUGIN_CONFIG };
  }
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    await log("warn", "plugin configuration file root is not a JSON object; using defaults");
    return { ...DEFAULT_PLUGIN_CONFIG };
  }

  const result = { ...DEFAULT_PLUGIN_CONFIG };
  let hadWarning = false;

  for (const key of Object.keys(parsed)) {
    const validate = KEY_VALIDATORS[key];
    if (!validate) {
      await log("warn", `plugin configuration file contains unknown key '${key}'; ignoring it`);
      hadWarning = true;
      continue;
    }
    if (!validate(parsed[key])) {
      await log("warn", `plugin configuration key '${key}' has the wrong type; using its default`);
      hadWarning = true;
      continue;
    }
    result[key] = parsed[key];
  }

  if (!hadWarning) {
    await log("info", "loaded plugin configuration file");
  }

  return result;
}
