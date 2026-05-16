// strace-ff output parser -- pure functions, no I/O, no globals.
//
// Intended use: the guest VM agent runs `strace -ff -e trace=...` and pipes
// each per-process file through parseStraceStream. The host never touches this
// module directly, but it can be unit-tested in vitest on the host.
//
// LIMITATIONS (v1):
//   - Only handles `openat(AT_FDCWD, ...)` -- openat with a numeric dir-fd is
//     dropped with null (the relative-path base is unknowable without fd table
//     tracking).
//   - Unfinished/resumed pairs (<unfinished ...> / <... foo resumed>) are both
//     dropped; we lose those syscall outcomes entirely in v1.
//   - We expect `strace -ff` WITHOUT `-t`/`-tt`. Timestamp prefixes are
//     tolerated (stripped) if present, but the ts field is a monotonic counter
//     owned by parseStraceStream, not a wall-clock value.
//   - AF_UNIX connect calls are dropped -- we only track AF_INET/AF_INET6.
//
// ASYMMETRY (failure handling):
//   - openat: ENOENT and EACCES are EMITTED with an `errno` field. The
//     downstream protected-paths policy filter decides whether to drop the
//     event (unprotected ENOENT) or surface it as <HIDDEN> (protected path,
//     whether ENOENT or EACCES). This preserves the audit promise that a
//     probe for `~/.ssh/id_rsa` shows up under external_reads even when the
//     file doesn't exist in the sandbox.
//   - statx / faccessat2 / readlinkat: ENOENT is DROPPED at parse time. These
//     are info-query syscalls (does the path exist? what mode? where does the
//     symlink point?) rather than real reads; the audit only cares about
//     actual fs accesses. A path under `~/.ssh/**` that produces a statx miss
//     does not flow through the hidden-marking pipeline.
//   - unlinkat / renameat2: errors emit nothing (no kernel state change).

import type { RawEvent } from '../lock/schema.js';

// -- string-escaping ---------------------------------------------------------

/**
 * Decode strace-style C string escapes inside a quoted string body
 * (everything between the opening and closing double-quote).
 * Handles: \\ \" \n \t \r \a \b \f \v \0NN (octal) \xNN (hex).
 * Unrecognised escapes are left as-is (the backslash is kept).
 */
function unescape(s: string): string {
  return s.replace(/\\(\\|"|n|t|r|a|b|f|v|x[0-9a-fA-F]{1,2}|[0-7]{1,3})/g, (_, esc: string) => {
    switch (esc[0]) {
      case '\\': return '\\';
      case '"':  return '"';
      case 'n':  return '\n';
      case 't':  return '\t';
      case 'r':  return '\r';
      case 'a':  return '\x07';
      case 'b':  return '\x08';
      case 'f':  return '\x0C';
      case 'v':  return '\x0B';
      case 'x':  return String.fromCharCode(parseInt(esc.slice(1), 16));
      default:   return String.fromCharCode(parseInt(esc, 8)); // octal
    }
  });
}

// -- low-level tokenising helpers ---------------------------------------------

/**
 * Extract the body of the first "..." token starting at the given position.
 * Handles strace truncated strings ("longstr"...) -- we keep the visible body.
 * Returns [unescapedContent, indexAfterClosingQuote] or null if not a string.
 */
function extractQuotedString(s: string, pos: number): [string, number] | null {
  if (s[pos] !== '"') return null;
  let i = pos + 1;
  let raw = '';
  while (i < s.length) {
    const ch = s[i];
    if (ch === '\\') {
      // consume one escape sequence
      raw += s[i];
      i++;
      if (i < s.length) { raw += s[i]; i++; }
    } else if (ch === '"') {
      i++; // past the closing quote
      // consume optional `...` for truncated strings
      if (s.slice(i, i + 3) === '...') i += 3;
      return [unescape(raw), i];
    } else {
      raw += ch;
      i++;
    }
  }
  return null; // unterminated
}

/**
 * Parse the argument list of a syscall: the text between the outer parens,
 * already stripped of the syscall name. Returns tokens as strings; complex
 * strace sub-structures (like argv arrays or connect structs) are returned as
 * a single raw token string so callers can further parse them.
 *
 * This is intentionally very simple -- it splits on top-level commas only.
 */
function splitArgs(s: string): string[] {
  const args: string[] = [];
  let depth = 0;
  let cur = '';
  let i = 0;
  while (i < s.length) {
    const ch = s[i];
    if (ch === '"') {
      // consume quoted string whole
      const r = extractQuotedString(s, i);
      if (r !== null) {
        const [, end] = r;
        cur += s.slice(i, end);
        i = end;
        continue;
      }
    }
    if (ch === '(' || ch === '[' || ch === '{') { depth++; cur += ch; i++; continue; }
    if (ch === ')' || ch === ']' || ch === '}') { depth--; cur += ch; i++; continue; }
    if (ch === ',' && depth === 0) {
      args.push(cur.trim());
      cur = '';
      i++;
      continue;
    }
    cur += ch;
    i++;
  }
  if (cur.trim().length > 0) args.push(cur.trim());
  return args;
}

// -- return-value parsing ------------------------------------------------------

interface RetVal {
  /** The numeric return value as a string (e.g. "3", "-1", "0x7ffd1234"). */
  raw: string;
  /** True when the return is -1 (failure). */
  isError: boolean;
  /** Errno symbol, e.g. "ENOENT", "EACCES". Only set when isError is true. */
  errno?: string;
}

/**
 * Parse the trailing "= <retval>" portion of a strace line.
 * Returns null if no return-value clause is found (unfinished etc.).
 */
function parseRetVal(line: string): RetVal | null {
  // Match "= -1 ERRNO (...)" or "= 0" or "= 0x..." at end of line.
  // Tolerates strace -T duration suffix like "<0.000042>".
  const m = line.match(/=\s+(-?\d[\w]*)\s*(?:(\w+)\s*\([^)]*\))?\s*(?:<[^>]*>)?\s*$/);
  if (!m) return null;
  const raw = m[1] ?? '';
  const errno = m[2]; // may be undefined
  const isError = raw === '-1';
  if (isError && errno !== undefined) {
    return { raw, isError, errno };
  }
  return { raw, isError };
}

// -- openat flags ------------------------------------------------------------

const WRITE_FLAGS = ['O_WRONLY', 'O_RDWR', 'O_CREAT', 'O_TRUNC', 'O_APPEND'];

/**
 * Determine if a strace flags token implies a write.
 * When both read and write flags are present we classify as write -- the more
 * restrictive event, because a write implies a read of the same path in terms
 * of policy impact.
 */
function flagsImplyWrite(flags: string): boolean {
  for (const f of WRITE_FLAGS) {
    if (flags.includes(f)) return true;
  }
  return false;
}

// -- argv parsing (for execve) -------------------------------------------------

/**
 * Parse strace's argv representation: ["prog", "arg1", "arg2"].
 * Handles escaped strings, ignores slash-star N vars star-slash comments,
 * truncated arrays.
 */
function parseArgvToken(token: string): string[] {
  // token looks like: ["node", "-e", "require(...)"] or ["node", ...]
  const inside = token.replace(/^\[/, '').replace(/\]$/, '').trim();
  // remove /* ... */ comments (lazy match handles * inside comment body)
  const cleaned = inside.replace(/\/\*[\s\S]*?\*\//g, '').trim();
  if (cleaned.length === 0 || cleaned === '...') return [];
  const args: string[] = [];
  let i = 0;
  while (i < cleaned.length) {
    // skip whitespace and commas
    while (i < cleaned.length && (cleaned[i] === ',' || /\s/.test(cleaned[i]!))) i++;
    if (i >= cleaned.length) break;
    if (cleaned[i] === '"') {
      const r = extractQuotedString(cleaned, i);
      if (r !== null) {
        const [val, end] = r;
        args.push(val);
        i = end;
      } else {
        i++;
      }
    } else if (cleaned.slice(i, i + 3) === '...') {
      // truncated -- stop
      break;
    } else {
      // unquoted token (rare)
      let j = i;
      while (j < cleaned.length && cleaned[j] !== ',' && !/\s/.test(cleaned[j]!)) j++;
      args.push(cleaned.slice(i, j));
      i = j;
    }
  }
  return args;
}

// -- connect struct parsing ---------------------------------------------------

interface ConnectAddr {
  family: 'AF_INET' | 'AF_INET6';
  host: string;
  port: number;
}

/**
 * Parse the sockaddr struct token from strace connect(). Returns null for
 * families we don't handle (AF_UNIX etc.).
 */
function parseConnectStruct(token: string): ConnectAddr | null {
  // AF_INET: {sa_family=AF_INET, sin_port=htons(443), sin_addr=inet_addr("1.2.3.4")}
  if (token.includes('AF_INET6')) {
    const portM = token.match(/sin6_port=htons\((\d+)\)/);
    // inet_pton(AF_INET6, "::1", ...) or sin6_addr=inet_pton(AF_INET6, "2001:db8::1")
    const addrM = token.match(/inet_pton\(AF_INET6,\s*"([^"]+)"/);
    if (!portM || !addrM) return null;
    const port = parseInt(portM[1] ?? '0', 10);
    const host = addrM[1] ?? '';
    return { family: 'AF_INET6', host, port };
  }
  if (token.includes('AF_INET')) {
    const portM = token.match(/sin_port=htons\((\d+)\)/);
    const addrM = token.match(/inet_addr\("([^"]+)"\)/);
    if (!portM || !addrM) return null;
    const port = parseInt(portM[1] ?? '0', 10);
    const host = addrM[1] ?? '';
    return { family: 'AF_INET', host, port };
  }
  // AF_UNIX and anything else -- v1 does not track these
  return null;
}

// -- main line parser ---------------------------------------------------------

/**
 * Strip an optional timestamp prefix added by strace -t or -tt.
 * Format: "HH:MM:SS " or "HH:MM:SS.MICROSECS ".
 * We expect strace -ff without -t in v1; this is a tolerance-only path.
 */
function stripTimestamp(line: string): string {
  return line.replace(/^\d{2}:\d{2}:\d{2}(?:\.\d+)?\s+/, '');
}

/**
 * Parse a single strace line. Returns an array of RawEvent (usually 0 or 1
 * element; renameat2 can produce two). Returns null when the line should be
 * dropped entirely (signal, exit, unfinished, resumed, unparseable).
 *
 * Never throws -- all parse failures produce null.
 *
 * @param line   One line of strace -ff output (no trailing newline required).
 * @param pid    The PID of the process that produced this line.
 * @param ts     Monotonic timestamp counter assigned by the caller (parseStraceStream).
 */
export function parseStraceLine(line: string, pid: number, ts: number): RawEvent[] | null {
  try {
    return _parseStraceLine(line, pid, ts);
  } catch {
    return null;
  }
}

function _parseStraceLine(line: string, pid: number, ts: number): RawEvent[] | null {
  line = stripTimestamp(line.trim());

  // Drop signal delivery lines: "--- SIGCHLD {...} ---"
  if (line.startsWith('---') && line.endsWith('---')) return null;
  // Drop exit lines: "+++ exited with N +++"
  if (line.startsWith('+++') && line.endsWith('+++')) return null;
  // Drop unfinished halves: "syscall(...  <unfinished ...>)"
  if (line.includes('<unfinished ...>')) return null;
  // Drop resumed halves: "<... syscall resumed> ...)"
  if (line.startsWith('<...') && line.includes('resumed>')) return null;
  // Drop process-attachment noise
  if (line.startsWith('strace: ')) return null;

  // Extract syscall name and argument body
  const parenIdx = line.indexOf('(');
  if (parenIdx === -1) return null;
  const syscallName = line.slice(0, parenIdx).trim();

  // Find the matching close paren by scanning (handles nested parens).
  // Quote-aware: skip over "..." tokens so that a literal ) or ( inside a
  // quoted path (e.g. "/work/pkg/a)b") does not confuse the depth counter.
  let depth = 0;
  let closeIdx = -1;
  let i = parenIdx;
  while (i < line.length) {
    const ch = line[i];
    if (ch === '"') {
      const r = extractQuotedString(line, i);
      if (r !== null) { i = r[1]; continue; }
    }
    if (ch === '(') depth++;
    else if (ch === ')') { depth--; if (depth === 0) { closeIdx = i; break; } }
    i++;
  }
  if (closeIdx === -1) return null;

  const argBody = line.slice(parenIdx + 1, closeIdx);
  const suffix = line.slice(closeIdx + 1); // " = 3" etc.

  const retVal = parseRetVal(suffix);
  if (retVal === null) return null; // no return value → unfinished or unparseable

  const args = splitArgs(argBody);

  switch (syscallName) {
    case 'openat':      return parseOpenat(args, retVal, pid, ts);
    case 'execve':      return parseExecve(args, retVal, pid, ts);
    case 'connect':     return parseConnect(args, retVal, pid, ts);
    case 'readlinkat':  return parseReadlinkat(args, retVal, pid, ts);
    case 'statx':       return parseStatx(args, retVal, pid, ts);
    case 'renameat2':   return parseRenameat2(args, retVal, pid, ts);
    case 'unlinkat':    return parseUnlinkat(args, retVal, pid, ts);
    case 'faccessat2':  return parseFaccessat2(args, retVal, pid, ts);
    // TODO(v2): add mkdir, mkdirat, symlink, symlinkat, link, linkat, rmdir,
    // truncate, truncate64, chmod, fchmodat; also resolve numeric dir-fds by
    // tracking the open-fd table across syscalls.
    default: return null;
  }
}

// -- per-syscall parsers -------------------------------------------------------

function parseOpenat(args: string[], retVal: RetVal, pid: number, ts: number): RawEvent[] | null {
  // openat(AT_FDCWD, "path", flags[, mode]) = fd
  // v1 limitation: only AT_FDCWD is handled; numeric dir-fds are dropped.
  const dirfdToken = args[0] ?? '';
  if (dirfdToken !== 'AT_FDCWD') return null;

  const pathToken = args[1] ?? '';
  const r = extractQuotedString(pathToken, 0);
  if (r === null) return null;
  const [path] = r;

  const flags = args[2] ?? '';
  const isWrite = flagsImplyWrite(flags);

  // On failure we stamp the event with `errno` and emit it. The downstream
  // protected-paths policy filter (src/guest/protected-paths.ts) decides
  // whether to drop the event or surface it as <HIDDEN>:
  //   - ENOENT, path NOT protected      → policy filter drops (noise filter)
  //   - ENOENT, path IS protected       → policy filter emits as <HIDDEN>
  //   - EACCES, path NOT protected      → policy filter emits (record probe)
  //   - EACCES, path IS protected       → policy filter emits as <HIDDEN>
  // Errors other than ENOENT/EACCES are dropped here (unusual kernel results
  // we have no audit story for).
  let errno: 'ENOENT' | 'EACCES' | undefined;
  if (retVal.isError) {
    if (retVal.errno === 'ENOENT') errno = 'ENOENT';
    else if (retVal.errno === 'EACCES') errno = 'EACCES';
    else return null; // other errors: drop
  }

  if (isWrite) {
    return [errno === undefined
      ? { kind: 'write', path, pid, ts, hidden: false }
      : { kind: 'write', path, pid, ts, hidden: false, errno }];
  }
  return [errno === undefined
    ? { kind: 'read', path, pid, ts, hidden: false }
    : { kind: 'read', path, pid, ts, hidden: false, errno }];
}

function parseExecve(args: string[], retVal: RetVal, pid: number, ts: number): RawEvent[] | null {
  // execve("path", [argv...], envp_or_pointer) = 0
  const pathToken = args[0] ?? '';
  const r = extractQuotedString(pathToken, 0);
  if (r === null) return null;

  // The argv is the second argument (args[1]); the third (envp) is discarded.
  const argvToken = args[1] ?? '';
  const argv = parseArgvToken(argvToken);
  if (argv.length === 0) {
    // Fall back to just the executable path from arg0
    const [path] = r;
    argv.push(path);
  }

  let result: 'ok' | 'enoent' | 'eacces';
  if (!retVal.isError) {
    result = 'ok';
  } else if (retVal.errno === 'ENOENT') {
    result = 'enoent';
  } else if (retVal.errno === 'EACCES') {
    result = 'eacces';
  } else {
    result = 'eacces'; // other exec errors treated as access-denied
  }

  return [{ kind: 'spawn', argv, result, pid, ts }];
}

function parseConnect(args: string[], retVal: RetVal, pid: number, ts: number): RawEvent[] | null {
  // connect(fd, {sa_family=..., ...}, addrlen) = 0
  const structToken = args[1] ?? '';
  const addr = parseConnectStruct(structToken);
  if (addr === null) return null;

  // Success: retVal 0 → ok; any failure → blocked.
  // EINPROGRESS is classified as blocked here even though the connect may
  // eventually succeed; for phase-B audit purposes we only count connections
  // that complete synchronously, which is operationally correct even if
  // semantically imprecise (the caller would need SO_ERROR/getsockopt to
  // confirm completion, which we do not trace in v1).
  // TODO(v2): track SO_ERROR getsockopt results to resolve EINPROGRESS.
  const result = retVal.isError ? 'blocked' : 'ok';

  return [{ kind: 'connect', host: addr.host, port: addr.port, result, pid, ts }];
}

function parseReadlinkat(args: string[], retVal: RetVal, pid: number, ts: number): RawEvent[] | null {
  // readlinkat(AT_FDCWD, "path", "target", bufsize) = len
  const dirfdToken = args[0] ?? '';
  if (dirfdToken !== 'AT_FDCWD') return null;

  if (retVal.isError && retVal.errno === 'ENOENT') return null;
  if (retVal.isError) return null;

  const pathToken = args[1] ?? '';
  const r = extractQuotedString(pathToken, 0);
  if (r === null) return null;
  const [path] = r;

  return [{ kind: 'read', path, pid, ts, hidden: false }];
}

function parseStatx(args: string[], retVal: RetVal, pid: number, ts: number): RawEvent[] | null {
  // statx(AT_FDCWD, "path", flags, mask, statxbuf) = 0
  const dirfdToken = args[0] ?? '';
  if (dirfdToken !== 'AT_FDCWD') return null;

  if (retVal.isError && retVal.errno === 'ENOENT') return null;
  if (retVal.isError) return null;

  const pathToken = args[1] ?? '';
  const r = extractQuotedString(pathToken, 0);
  if (r === null) return null;
  const [path] = r;

  return [{ kind: 'read', path, pid, ts, hidden: false }];
}

function parseRenameat2(args: string[], retVal: RetVal, pid: number, ts: number): RawEvent[] | null {
  // renameat2(AT_FDCWD, "oldpath", AT_FDCWD, "newpath", flags) = 0
  // Normal rename: read(oldpath) + write(newpath).
  // RENAME_EXCHANGE (atomic swap): write(oldpath) + write(newpath) — both
  // paths are mutated; classifying oldpath as a read would silently miss a
  // write to it.
  // On any failure: emit nothing.
  if (retVal.isError) return null;

  const oldDirfd = args[0] ?? '';
  if (oldDirfd !== 'AT_FDCWD') return null;
  const newDirfd = args[2] ?? '';
  if (newDirfd !== 'AT_FDCWD') return null;

  const oldPathToken = args[1] ?? '';
  const newPathToken = args[3] ?? '';
  const flagsToken = args[4] ?? '';

  const rOld = extractQuotedString(oldPathToken, 0);
  const rNew = extractQuotedString(newPathToken, 0);
  if (rOld === null || rNew === null) return null;

  const [oldPath] = rOld;
  const [newPath] = rNew;

  const isExchange = flagsToken.includes('RENAME_EXCHANGE');
  const oldEv: RawEvent = isExchange
    ? { kind: 'write', path: oldPath, pid, ts, hidden: false }
    : { kind: 'read',  path: oldPath, pid, ts, hidden: false };
  const newEv: RawEvent = { kind: 'write', path: newPath, pid, ts, hidden: false };
  return [oldEv, newEv];
}

function parseUnlinkat(args: string[], retVal: RetVal, pid: number, ts: number): RawEvent[] | null {
  // unlinkat(AT_FDCWD, "path", flags) = 0
  if (retVal.isError) return null;

  const dirfdToken = args[0] ?? '';
  if (dirfdToken !== 'AT_FDCWD') return null;

  const pathToken = args[1] ?? '';
  const r = extractQuotedString(pathToken, 0);
  if (r === null) return null;
  const [path] = r;

  return [{ kind: 'write', path, pid, ts, hidden: false }];
}

function parseFaccessat2(args: string[], retVal: RetVal, pid: number, ts: number): RawEvent[] | null {
  // faccessat2(AT_FDCWD, "path", mode, flags) = 0
  const dirfdToken = args[0] ?? '';
  if (dirfdToken !== 'AT_FDCWD') return null;

  if (retVal.isError && retVal.errno === 'ENOENT') return null;
  if (retVal.isError) return null;

  const pathToken = args[1] ?? '';
  const r = extractQuotedString(pathToken, 0);
  if (r === null) return null;
  const [path] = r;

  return [{ kind: 'read', path, pid, ts, hidden: false }];
}

// -- stream wrapper ------------------------------------------------------------

/**
 * Async generator that wraps parseStraceLine over an async iterable of lines.
 * Assigns a monotonic counter (starting from 0) as the ts value for each
 * emitted event. The counter increments for every input line (whether or not
 * it produces events) so events from the same parse round share the same ts.
 */
export async function* parseStraceStream(
  lines: AsyncIterable<string>,
  pid: number,
): AsyncIterable<RawEvent> {
  let ts = 0;
  for await (const line of lines) {
    const events = parseStraceLine(line, pid, ts);
    if (events !== null) {
      for (const ev of events) {
        yield ev;
      }
    }
    ts++;
  }
}
