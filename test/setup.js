// Test isolation: point XDG config/state/cache at a throwaway temp directory so
// a developer's real ~/.config/opencode/redact.jsonc (or state) can never
// change test outcomes. Runs before any test module imports src/config.js or
// src/log.js, which resolve their XDG paths at module-evaluation time.

import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const iso = mkdtempSync(join(tmpdir(), "opencode-redact-test-iso-"));
process.env.XDG_CONFIG_HOME = join(iso, "config");
process.env.XDG_STATE_HOME = join(iso, "state");
process.env.XDG_CACHE_HOME = join(iso, "cache");
delete process.env.OPENCODE_CONFIG_DIR;
