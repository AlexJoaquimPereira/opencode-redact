// Configurable, fail-open logging for the plugin.
//
// The V2 plugin context has no logger (`ctx.app` is `{name, version, channel}`
// only), and `process.stderr` from a managed opencode server is not captured
// in opencode's own log file — so redaction events were effectively invisible
// in normal operation. This module centralizes logging behind a small,
// level-filtered interface with a `stderr` sink (default, back-compatible), a
// JSONL `file` sink (the observability fix), and `none`.
//
// Hard constraint (see openspec/specs/tool-output-redaction and
// plugin-configuration): a log entry MUST NEVER contain a detected secret
// value or a configuration value. Callers pass only safe fields (counts,
// rule ids, source, tool name, key names). This module never inspects or
// redacts message content itself.
//
// Every operation is wrapped so a logging failure can never break a turn
// (fail-open), matching the plugin's existing scanner posture.

import { appendFileSync, existsSync, mkdirSync, renameSync, statSync } from "node:fs";
import { dirname, join } from "node:path";
import { xdgState } from "xdg-basedir";

/** Ordered severities; `silent` disables all output. */
export const LOG_LEVELS = Object.freeze({ silent: 0, error: 1, warn: 2, info: 3, debug: 4 });
export const LOG_SINKS = Object.freeze(["stderr", "file", "none"]);

export const DEFAULT_MAX_BYTES = 1024 * 1024;

/** Default JSONL log path under the XDG state dir, or `null` when unresolvable. */
export function defaultLogFile() {
  if (!xdgState) return null;
  return join(xdgState, "opencode", "opencode-redact.log");
}

export const DEFAULT_LOG_CONFIG = Object.freeze({
  level: "warn",
  sink: "stderr",
  file: null, // resolved lazily to defaultLogFile() when the file sink is used
  maxBytes: DEFAULT_MAX_BYTES,
});

/**
 * Validates and normalizes a raw `log` config object. Never throws; every
 * failure path falls back to the default for that key and reports a warning
 * message (naming only the key), mirroring `loadPluginConfig`'s contract.
 *
 * @param {unknown} raw the value of the `log` key in redact.jsonc
 * @returns {{ value: {level:string,sink:string,file:string|null,maxBytes:number}, warnings: string[] }}
 */
export function normalizeLogConfig(raw) {
  const warnings = [];
  const value = { ...DEFAULT_LOG_CONFIG };
  if (raw === undefined) {
    return { value, warnings };
  }
  if (typeof raw !== "object" || raw === null || Array.isArray(raw)) {
    warnings.push("plugin configuration key 'log' has the wrong type; using its default");
    return { value, warnings };
  }

  if (raw.level !== undefined) {
    if (typeof raw.level === "string" && Object.prototype.hasOwnProperty.call(LOG_LEVELS, raw.level)) {
      value.level = raw.level;
    } else {
      warnings.push("plugin configuration key 'log.level' is invalid; using its default");
    }
  }
  if (raw.sink !== undefined) {
    if (typeof raw.sink === "string" && LOG_SINKS.includes(raw.sink)) {
      value.sink = raw.sink;
    } else {
      warnings.push("plugin configuration key 'log.sink' is invalid; using its default");
    }
  }
  if (raw.file !== undefined) {
    if (typeof raw.file === "string" && raw.file.length > 0) {
      value.file = raw.file;
    } else {
      warnings.push("plugin configuration key 'log.file' is invalid; using its default");
    }
  }
  if (raw.maxBytes !== undefined) {
    if (typeof raw.maxBytes === "number" && Number.isFinite(raw.maxBytes) && raw.maxBytes > 0) {
      value.maxBytes = Math.floor(raw.maxBytes);
    } else {
      warnings.push("plugin configuration key 'log.maxBytes' is invalid; using its default");
    }
  }
  for (const key of Object.keys(raw)) {
    if (!["level", "sink", "file", "maxBytes"].includes(key)) {
      warnings.push(`plugin configuration file contains unknown key 'log.${key}'; ignoring it`);
    }
  }
  return { value, warnings };
}

/**
 * Creates a logger. Returns `{ log, level, sink }`.
 *
 * `log(level, message, fields?)`:
 *  - drops the record when `level` is below the configured threshold (or the
 *    sink is `none`);
 *  - `stderr` sink writes `[opencode-redact] [level] message` (unchanged from
 *    the plugin's original format);
 *  - `file` sink appends one JSON line `{ts, level, message, ...fields}` to the
 *    configured path (0600, size-capped with a single `.1` rotation).
 *
 * @param {{
 *   level?: string, sink?: string, file?: string|null, maxBytes?: number,
 *   stderrWrite?: (line: string) => void, now?: () => string,
 * }} [options]
 */
export function createLogger(options = {}) {
  const level = Object.prototype.hasOwnProperty.call(LOG_LEVELS, options.level) ? options.level : "warn";
  const threshold = LOG_LEVELS[level];
  const sink = LOG_SINKS.includes(options.sink) ? options.sink : "stderr";
  const configuredFile = typeof options.file === "string" && options.file.length > 0 ? options.file : null;
  const file = configuredFile ?? defaultLogFile();
  const maxBytes = Number.isFinite(options.maxBytes) && options.maxBytes > 0 ? options.maxBytes : DEFAULT_MAX_BYTES;
  const now = typeof options.now === "function" ? options.now : () => new Date().toISOString();
  const stderrWrite =
    typeof options.stderrWrite === "function" ? options.stderrWrite : (line) => process.stderr.write(line);

  const enabled = (lvl) => threshold !== LOG_LEVELS.silent && LOG_LEVELS[lvl] > 0 && LOG_LEVELS[lvl] <= threshold;

  function toStderr(lvl, message) {
    stderrWrite(`[opencode-redact] [${lvl}] ${message}\n`);
  }

  function writeFile(lvl, message, fields) {
    if (!file) {
      // No resolvable path -> degrade to stderr rather than dropping silently.
      toStderr(lvl, message);
      return;
    }
    mkdirSync(dirname(file), { recursive: true });
    try {
      if (existsSync(file) && statSync(file).size >= maxBytes) {
        renameSync(file, `${file}.1`);
      }
    } catch {
      // rotation is best-effort
    }
    let record;
    try {
      record = JSON.stringify({
        ts: now(),
        level: lvl,
        message,
        ...(fields && typeof fields === "object" ? fields : {}),
      });
    } catch {
      return; // non-serializable fields; drop rather than risk a raw dump
    }
    appendFileSync(file, `${record}\n`, { mode: 0o600 });
  }

  return {
    level,
    sink,
    log(lvl, message, fields) {
      try {
        if (!enabled(lvl)) return;
        if (sink === "none") return;
        if (sink === "file") {
          writeFile(lvl, message, fields);
          return;
        }
        toStderr(lvl, message);
      } catch {
        // Fail-open: logging must never break the plugin or a turn.
      }
    },
  };
}
