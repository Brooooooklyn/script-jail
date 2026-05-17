// script-jail — src/action/log.ts
//
// One-function logging helper that emits a GitHub Actions `::warning::`
// annotation to stdout.  Centralised so every part of the action surfaces
// runtime warnings the same way (instead of mixing `console.warn` with
// `process.stdout.write('::warning::…')`).
//
// We intentionally keep this as a single function — not a logger — because
// `::error::` is emitted only from `main.ts`'s catch path and is short
// enough to inline there.

/**
 * Emit `msg` as a GitHub Actions `::warning::` annotation followed by `\n`.
 *
 * Production code calls this with no second argument; tests inject a sink
 * to intercept the write without touching the real process stdout.
 */
export function warn(
  msg: string,
  write: (s: string) => void = (s) => { process.stdout.write(s); },
): void {
  write(`::warning::${msg}\n`);
}
