// script-jail — src/cli/parse-args.ts
//
// Argv parser for the CLI.  Split out from index.ts so the CLI entry stays
// small and the parsing logic can be unit-tested in isolation.
//
// Subcommands: init | update | check  (positional, optional).
// Flags: --config, --lock, --spoof-platform, --spoof-arch, --help, --version.
//
// We hand-roll the parser rather than pull in commander/yargs because:
//   - The flag surface is tiny and frozen.
//   - script-jail already ships zero runtime deps for the CLI bundle; an
//     extra dependency would inflate dist/cli.cjs by a non-trivial amount.
//   - Errors are accumulated (not thrown) so the CLI can print every problem
//     before exiting, which is friendlier than failing on the first bad arg.

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

export type Subcommand = 'init' | 'update' | 'check';
export type SpoofPlatform = 'linux' | 'darwin' | 'win32';
export type SpoofArch = 'x64' | 'arm64';

export interface ParsedArgs {
  subcommand: Subcommand | null;
  configPath: string;
  lockPath: string;
  spoofPlatform: SpoofPlatform;
  spoofArch: SpoofArch;
  help: boolean;
  version: boolean;
  errors: string[];
}

const VALID_SUBCOMMANDS: ReadonlySet<Subcommand> = new Set<Subcommand>(['init', 'update', 'check']);
const VALID_PLATFORMS: ReadonlySet<SpoofPlatform> = new Set<SpoofPlatform>(['linux', 'darwin', 'win32']);
const VALID_ARCHES: ReadonlySet<SpoofArch> = new Set<SpoofArch>(['x64', 'arm64']);

// ---------------------------------------------------------------------------
// parseArgs
// ---------------------------------------------------------------------------

export function parseArgs(argv: string[]): ParsedArgs {
  const out: ParsedArgs = {
    subcommand: null,
    configPath: '.script-jail.yml',
    lockPath: '.script-jail.lock.yml',
    spoofPlatform: 'linux',
    // `src/cli/index.ts` replaces this with the detected host arch when the
    // user did not pass --spoof-arch.  Keeping a concrete parser default
    // preserves the stable ParsedArgs shape.
    spoofArch: 'x64',
    help: false,
    version: false,
    errors: [],
  };

  // peekValue: look at argv[i+1] without consuming.  Returns the value when
  // it exists AND does not look like another flag (no leading `-`).
  // Otherwise records a "requires a value" error and returns null; the
  // caller's `continue` then falls through to the next loop iteration,
  // leaving `i` unchanged so the next token is parsed normally (e.g.
  // `parseArgs(['--config', '--help'])` accumulates BOTH the missing-value
  // error for `--config` AND records `--help`).  Matches the parser's
  // "accumulate every error" design.
  const peekValue = (name: string, next: string | undefined): string | null => {
    if (next === undefined || next.startsWith('-')) {
      out.errors.push(`--${name} requires a value`);
      return null;
    }
    return next;
  };

  // Only the FIRST non-flag argument is treated as the subcommand; any
  // additional positional args are an error so we don't silently swallow
  // typos (e.g. `script-jail init --check` written as `script-jail init check`).
  let positionalSeen = 0;
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i] ?? '';
    if (a === '--help' || a === '-h') { out.help = true; continue; }
    if (a === '--version' || a === '-V') { out.version = true; continue; }
    if (a === '--config') {
      const v = peekValue('config', argv[i + 1]);
      if (v === null) continue;
      i++;
      out.configPath = v;
      continue;
    }
    if (a === '--lock') {
      const v = peekValue('lock', argv[i + 1]);
      if (v === null) continue;
      i++;
      out.lockPath = v;
      continue;
    }
    if (a === '--spoof-platform') {
      const v = peekValue('spoof-platform', argv[i + 1]);
      if (v === null) continue;
      i++;
      if (!VALID_PLATFORMS.has(v as SpoofPlatform)) {
        out.errors.push(`--spoof-platform must be one of: linux, darwin, win32 (got '${v}')`);
        continue;
      }
      out.spoofPlatform = v as SpoofPlatform;
      continue;
    }
    if (a === '--spoof-arch') {
      const v = peekValue('spoof-arch', argv[i + 1]);
      if (v === null) continue;
      i++;
      if (!VALID_ARCHES.has(v as SpoofArch)) {
        out.errors.push(`--spoof-arch must be one of: x64, arm64 (got '${v}')`);
        continue;
      }
      out.spoofArch = v as SpoofArch;
      continue;
    }
    if (a.startsWith('-')) {
      out.errors.push(`unknown flag: ${a}`);
      continue;
    }
    // Positional argument.
    positionalSeen++;
    if (positionalSeen > 1) {
      out.errors.push(`unexpected positional argument: '${a}'`);
      continue;
    }
    if (!VALID_SUBCOMMANDS.has(a as Subcommand)) {
      out.errors.push(`unknown subcommand: '${a}' (expected: init, update, check)`);
      continue;
    }
    out.subcommand = a as Subcommand;
  }

  return out;
}
