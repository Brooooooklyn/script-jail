// Unit tests for src/guest/strace-parser.ts
// Uses vitest project: "guest" (see vitest.config.ts)
//
// Three of the golden-line tests use real captured strace output from:
//   strace -ff -e trace=openat,execve,connect,readlinkat,statx,renameat2,unlinkat,faccessat2 \
//          -o /tmp/fix node -e "require('fs').readFileSync('/etc/hostname')" 2>&1

import { describe, it, expect } from 'vitest';
import { parseStraceLine, parseStraceStream } from '../../src/guest/strace-parser.js';

// Helper: collect an async iterable into an array
async function collect<T>(it: AsyncIterable<T>): Promise<T[]> {
  const out: T[] = [];
  for await (const v of it) out.push(v);
  return out;
}

// Helper: make an async iterable from an array of strings
async function* asyncLines(lines: string[]): AsyncIterable<string> {
  for (const l of lines) yield l;
}

// ── openat ───────────────────────────────────────────────────────────────────

describe('openat', () => {
  it('O_RDONLY → read event', () => {
    const line = 'openat(AT_FDCWD, "/etc/hostname", O_RDONLY) = 3';
    const evs = parseStraceLine(line, 42, 0);
    expect(evs).toEqual([{ kind: 'read', path: '/etc/hostname', pid: 42, ts: 0, hidden: false }]);
  });

  it('O_WRONLY → write event', () => {
    const line = 'openat(AT_FDCWD, "/tmp/out.txt", O_WRONLY|O_CREAT|O_TRUNC, 0644) = 5';
    const evs = parseStraceLine(line, 1, 0);
    expect(evs).toEqual([{ kind: 'write', path: '/tmp/out.txt', pid: 1, ts: 0, hidden: false }]);
  });

  it('O_CREAT|O_WRONLY|O_TRUNC → write event', () => {
    const line = 'openat(AT_FDCWD, "/tmp/build.log", O_CREAT|O_WRONLY|O_TRUNC, 0666) = 7';
    const evs = parseStraceLine(line, 1, 1);
    expect(evs).toEqual([{ kind: 'write', path: '/tmp/build.log', pid: 1, ts: 1, hidden: false }]);
  });

  it('O_RDWR|O_APPEND → write event (write wins)', () => {
    const line = 'openat(AT_FDCWD, "/var/log/app.log", O_RDWR|O_APPEND) = 4';
    const evs = parseStraceLine(line, 1, 2);
    expect(evs).toEqual([{ kind: 'write', path: '/var/log/app.log', pid: 1, ts: 2, hidden: false }]);
  });

  it('ENOENT on O_RDONLY → read event stamped with errno (policy filter decides downstream)', () => {
    const line = 'openat(AT_FDCWD, "/nonexistent", O_RDONLY) = -1 ENOENT (No such file or directory)';
    const evs = parseStraceLine(line, 1, 0);
    expect(evs).toEqual([{ kind: 'read', path: '/nonexistent', pid: 1, ts: 0, hidden: false, errno: 'ENOENT' }]);
  });

  it('ENOENT on O_WRONLY → write event stamped with errno (policy filter decides downstream)', () => {
    const line = 'openat(AT_FDCWD, "/no/dir/file", O_WRONLY|O_CREAT, 0644) = -1 ENOENT (No such file or directory)';
    const evs = parseStraceLine(line, 1, 0);
    expect(evs).toEqual([{ kind: 'write', path: '/no/dir/file', pid: 1, ts: 0, hidden: false, errno: 'ENOENT' }]);
  });

  it('EACCES on O_RDONLY → read event stamped with errno=EACCES', () => {
    const line = 'openat(AT_FDCWD, "/root/secret", O_RDONLY) = -1 EACCES (Permission denied)';
    const evs = parseStraceLine(line, 1, 0);
    expect(evs).toEqual([{ kind: 'read', path: '/root/secret', pid: 1, ts: 0, hidden: false, errno: 'EACCES' }]);
  });

  it('EACCES on O_WRONLY → write event stamped with errno=EACCES', () => {
    const line = 'openat(AT_FDCWD, "/etc/shadow", O_WRONLY|O_CREAT, 0644) = -1 EACCES (Permission denied)';
    const evs = parseStraceLine(line, 1, 0);
    expect(evs).toEqual([{ kind: 'write', path: '/etc/shadow', pid: 1, ts: 0, hidden: false, errno: 'EACCES' }]);
  });

  it('successful openat does NOT carry an errno field (no exactOptional `undefined`)', () => {
    const line = 'openat(AT_FDCWD, "/etc/hostname", O_RDONLY) = 3';
    const evs = parseStraceLine(line, 1, 0);
    expect(evs).not.toBeNull();
    expect(evs![0]).not.toHaveProperty('errno');
  });

  it('path containing literal ) is parsed correctly (quote-aware paren scan)', () => {
    // A file named "a)b" must not confuse the outer-paren depth counter.
    const line = 'openat(AT_FDCWD, "/work/pkg/a)b", O_RDONLY) = 3';
    const evs = parseStraceLine(line, 1, 0);
    expect(evs).toEqual([{ kind: 'read', path: '/work/pkg/a)b', pid: 1, ts: 0, hidden: false }]);
  });

  it('path containing literal ( is parsed correctly (quote-aware paren scan)', () => {
    // A file named "a(b" must not push the depth counter to 2.
    const line = 'openat(AT_FDCWD, "/work/pkg/a(b", O_RDONLY) = 3';
    const evs = parseStraceLine(line, 1, 0);
    expect(evs).toEqual([{ kind: 'read', path: '/work/pkg/a(b', pid: 1, ts: 0, hidden: false }]);
  });

  it('numeric dir-fd → null (v1 limitation)', () => {
    const line = 'openat(5, "relative.txt", O_RDONLY) = 6';
    expect(parseStraceLine(line, 1, 0)).toBeNull();
  });
});

// ── execve ───────────────────────────────────────────────────────────────────

describe('execve', () => {
  it('success → spawn event with result=ok', () => {
    const line = 'execve("/usr/bin/node", ["node", "install.js"], 0x7ffd... /* 38 vars */) = 0';
    const evs = parseStraceLine(line, 10, 5);
    expect(evs).not.toBeNull();
    expect(evs![0]).toMatchObject({ kind: 'spawn', argv: ['node', 'install.js'], result: 'ok', pid: 10, ts: 5 });
  });

  it('ENOENT → spawn event with result=enoent', () => {
    const line = 'execve("/usr/bin/notfound", ["notfound"], 0x7ffd...) = -1 ENOENT (No such file or directory)';
    const evs = parseStraceLine(line, 10, 0);
    expect(evs).not.toBeNull();
    expect(evs![0]).toMatchObject({ kind: 'spawn', argv: ['notfound'], result: 'enoent' });
  });

  it('EACCES → spawn event with result=eacces', () => {
    const line = 'execve("/tmp/script.sh", ["./script.sh"], 0x7ffd...) = -1 EACCES (Permission denied)';
    const evs = parseStraceLine(line, 10, 0);
    expect(evs).not.toBeNull();
    expect(evs![0]).toMatchObject({ kind: 'spawn', argv: ['./script.sh'], result: 'eacces' });
  });

  it('argv with quoted args containing commas', () => {
    const line = 'execve("/bin/sh", ["sh", "-c", "echo hello, world"], 0x7ffd...) = 0';
    const evs = parseStraceLine(line, 1, 0);
    expect(evs).not.toBeNull();
    expect(evs![0]).toMatchObject({ kind: 'spawn', argv: ['sh', '-c', 'echo hello, world'] });
  });

  it('argv with escape sequences', () => {
    const line = 'execve("/bin/sh", ["sh", "-c", "echo\\thello\\n"], 0x7ffd...) = 0';
    const evs = parseStraceLine(line, 1, 0);
    expect(evs).not.toBeNull();
    const ev = evs![0];
    expect(ev).not.toBeUndefined();
    if (ev?.kind === 'spawn') {
      expect(ev.argv[2]).toBe('echo\thello\n');
    }
  });

  it('argv with /* envp */ comment token — discards envp', () => {
    // strace sometimes shows the envp as [/* envp */] — should produce empty argv body
    // but we fall back to the exe path
    const line = 'execve("/bin/env", ["env"], [/* envp */]) = 0';
    const evs = parseStraceLine(line, 1, 0);
    expect(evs).not.toBeNull();
    expect(evs![0]).toMatchObject({ kind: 'spawn', argv: ['env'] });
  });

  it('truncated argv (has ...)', () => {
    const line = 'execve("/usr/bin/node", ["node", "a.js", "b.js", ...], 0x7ffd...) = 0';
    const evs = parseStraceLine(line, 1, 0);
    expect(evs).not.toBeNull();
    const ev = evs![0];
    if (ev?.kind === 'spawn') {
      expect(ev.argv[0]).toBe('node');
    }
  });

  it('argv element containing ) is parsed correctly (quote-aware paren scan)', () => {
    // The ) inside "require('fs').readFileSync('/etc/hostname')" must not
    // close the outer syscall paren early.
    const line = "execve(\"/usr/bin/node\", [\"node\", \"-e\", \"require('fs').readFileSync('/etc/hostname')\"], 0x7ffd...) = 0";
    const evs = parseStraceLine(line, 1, 0);
    expect(evs).not.toBeNull();
    expect(evs![0]).toMatchObject({ kind: 'spawn', argv: ['node', '-e', "require('fs').readFileSync('/etc/hostname')"] });
  });
});

// ── execveat ─────────────────────────────────────────────────────────────────
//
// Audit-trust Finding 2 (high): strace's `-e trace=execve` does NOT cover
// execveat.  A lifecycle script that calls `syscall(SYS_execveat, ...)` runs
// without entering the libc shim AND, prior to the fix, also escaped strace.
// The agent now passes `-e trace=execve,execveat`; these tests pin the
// parser side of that contract — an execveat line must produce the same
// `spawn` RawEvent shape as execve so the per-pid bypass cross-check in
// phase-install treats the two identically.

describe('execveat', () => {
  it('success → spawn event with result=ok and argv parsed', () => {
    const line = 'execveat(AT_FDCWD, "/bin/sh", ["sh", "-c", "echo hi"], 0x7ffd... /* 38 vars */, 0) = 0';
    const evs = parseStraceLine(line, 1234, 7);
    expect(evs).not.toBeNull();
    expect(evs![0]).toMatchObject({
      kind: 'spawn',
      argv: ['sh', '-c', 'echo hi'],
      result: 'ok',
      pid: 1234,
      ts: 7,
    });
  });

  it('ENOENT → spawn event with result=enoent', () => {
    const line = 'execveat(AT_FDCWD, "/usr/bin/nope", ["nope"], 0x7ffd..., 0) = -1 ENOENT (No such file or directory)';
    const evs = parseStraceLine(line, 99, 0);
    expect(evs).not.toBeNull();
    expect(evs![0]).toMatchObject({ kind: 'spawn', argv: ['nope'], result: 'enoent', pid: 99 });
  });

  it('EACCES → spawn event with result=eacces', () => {
    const line = 'execveat(AT_FDCWD, "/tmp/x.sh", ["./x.sh"], 0x7ffd..., 0) = -1 EACCES (Permission denied)';
    const evs = parseStraceLine(line, 12, 0);
    expect(evs).not.toBeNull();
    expect(evs![0]).toMatchObject({ kind: 'spawn', argv: ['./x.sh'], result: 'eacces' });
  });

  it('numeric dirfd is accepted (parser ignores dirfd token)', () => {
    // The dirfd may be a numeric fd rather than AT_FDCWD.  We must NOT
    // drop the line just because the dirfd isn't AT_FDCWD (unlike
    // openat/statx/etc); the audit signal we care about is the bare
    // fact that the process called execveat.
    const line = 'execveat(5, "/bin/sh", ["sh"], 0x7ffd..., 0) = 0';
    const evs = parseStraceLine(line, 1, 0);
    expect(evs).not.toBeNull();
    expect(evs![0]).toMatchObject({ kind: 'spawn', argv: ['sh'], result: 'ok' });
  });

  it('AT_EMPTY_PATH form (empty path string) falls back to argv[0]', () => {
    // When AT_EMPTY_PATH is in flags, the path argument is "" and the
    // executable is identified by the dirfd alone.  We can't usefully
    // recover that path, so fall back to argv[0] for the prog field.
    const line = 'execveat(3, "", ["sh"], 0x7ffd..., AT_EMPTY_PATH) = 0';
    const evs = parseStraceLine(line, 1, 0);
    expect(evs).not.toBeNull();
    expect(evs![0]).toMatchObject({ kind: 'spawn', argv: ['sh'], result: 'ok' });
  });

  it('argv with /* envp */ placeholder for envp still works', () => {
    const line = 'execveat(AT_FDCWD, "/bin/env", ["env"], [/* envp */], 0) = 0';
    const evs = parseStraceLine(line, 1, 0);
    expect(evs).not.toBeNull();
    expect(evs![0]).toMatchObject({ kind: 'spawn', argv: ['env'], result: 'ok' });
  });
});

// ── connect ──────────────────────────────────────────────────────────────────

describe('connect', () => {
  it('AF_INET success → connect event result=ok', () => {
    const line = 'connect(3, {sa_family=AF_INET, sin_port=htons(443), sin_addr=inet_addr("1.2.3.4")}, 16) = 0';
    const evs = parseStraceLine(line, 1, 0);
    expect(evs).toEqual([{ kind: 'connect', host: '1.2.3.4', port: 443, result: 'ok', pid: 1, ts: 0 }]);
  });

  it('AF_INET failure → connect event result=blocked', () => {
    const line = 'connect(3, {sa_family=AF_INET, sin_port=htons(80), sin_addr=inet_addr("8.8.8.8")}, 16) = -1 ENETUNREACH (Network is unreachable)';
    const evs = parseStraceLine(line, 1, 0);
    expect(evs).toEqual([{ kind: 'connect', host: '8.8.8.8', port: 80, result: 'blocked', pid: 1, ts: 0 }]);
  });

  it('AF_INET EINPROGRESS (non-blocking) → blocked', () => {
    const line = 'connect(4, {sa_family=AF_INET, sin_port=htons(8080), sin_addr=inet_addr("192.168.1.1")}, 16) = -1 EINPROGRESS (Operation now in progress)';
    const evs = parseStraceLine(line, 1, 0);
    expect(evs).not.toBeNull();
    expect(evs![0]).toMatchObject({ kind: 'connect', result: 'blocked' });
  });

  it('AF_INET6 success → connect event with IPv6 host', () => {
    const line = 'connect(5, {sa_family=AF_INET6, sin6_port=htons(443), inet_pton(AF_INET6, "2001:db8::1", &sin6_addr)}, 28) = 0';
    const evs = parseStraceLine(line, 1, 0);
    expect(evs).toEqual([{ kind: 'connect', host: '2001:db8::1', port: 443, result: 'ok', pid: 1, ts: 0 }]);
  });

  it('AF_UNIX → null (not tracked in v1)', () => {
    const line = 'connect(3, {sa_family=AF_UNIX, sun_path="/tmp/.s.PGSQL.5432"}, 29) = 0';
    expect(parseStraceLine(line, 1, 0)).toBeNull();
  });
});

// ── readlinkat ───────────────────────────────────────────────────────────────

describe('readlinkat', () => {
  it('success → read event', () => {
    const line = 'readlinkat(AT_FDCWD, "/proc/self/exe", "/usr/bin/node", 4096) = 13';
    const evs = parseStraceLine(line, 1, 0);
    expect(evs).toEqual([{ kind: 'read', path: '/proc/self/exe', pid: 1, ts: 0, hidden: false }]);
  });

  it('ENOENT → null', () => {
    const line = 'readlinkat(AT_FDCWD, "/nonexistent/link", 0x7fff..., 4096) = -1 ENOENT (No such file or directory)';
    expect(parseStraceLine(line, 1, 0)).toBeNull();
  });
});

// ── statx ───────────────────────────────────────────────────────────────────

describe('statx', () => {
  it('success → read event', () => {
    const line = 'statx(AT_FDCWD, "/etc/passwd", AT_STATX_SYNC_AS_STAT, STATX_ALL, {stx_mask=STATX_ALL, ...}) = 0';
    const evs = parseStraceLine(line, 1, 0);
    expect(evs).toEqual([{ kind: 'read', path: '/etc/passwd', pid: 1, ts: 0, hidden: false }]);
  });

  it('ENOENT → null', () => {
    const line = 'statx(AT_FDCWD, "/no/such/path", AT_STATX_SYNC_AS_STAT, STATX_ALL, 0x7fff...) = -1 ENOENT (No such file or directory)';
    expect(parseStraceLine(line, 1, 0)).toBeNull();
  });
});

// ── renameat2 ────────────────────────────────────────────────────────────────

describe('renameat2', () => {
  it('success → [read(oldpath), write(newpath)]', () => {
    const line = 'renameat2(AT_FDCWD, "/tmp/a.tmp", AT_FDCWD, "/tmp/b.txt", RENAME_NOREPLACE) = 0';
    const evs = parseStraceLine(line, 7, 3);
    expect(evs).toHaveLength(2);
    expect(evs![0]).toEqual({ kind: 'read', path: '/tmp/a.tmp', pid: 7, ts: 3, hidden: false });
    expect(evs![1]).toEqual({ kind: 'write', path: '/tmp/b.txt', pid: 7, ts: 3, hidden: false });
  });

  it('read event comes before write event (order preserved)', () => {
    const line = 'renameat2(AT_FDCWD, "/src/old", AT_FDCWD, "/src/new", 0) = 0';
    const evs = parseStraceLine(line, 1, 0);
    expect(evs).not.toBeNull();
    expect(evs![0]!.kind).toBe('read');
    expect(evs![1]!.kind).toBe('write');
  });

  it('failure → null (nothing emitted)', () => {
    const line = 'renameat2(AT_FDCWD, "/tmp/a", AT_FDCWD, "/tmp/b", 0) = -1 ENOENT (No such file or directory)';
    expect(parseStraceLine(line, 1, 0)).toBeNull();
  });

  it('RENAME_EXCHANGE → [write(old), write(new)] (both paths mutated by atomic swap)', () => {
    // Real strace line for an atomic swap: both paths are written.
    const line = 'renameat2(AT_FDCWD, "/work/victim/index.js", AT_FDCWD, "/tmp/malware", RENAME_EXCHANGE) = 0';
    const evs = parseStraceLine(line, 7, 3);
    expect(evs).toHaveLength(2);
    expect(evs![0]).toEqual({ kind: 'write', path: '/work/victim/index.js', pid: 7, ts: 3, hidden: false });
    expect(evs![1]).toEqual({ kind: 'write', path: '/tmp/malware', pid: 7, ts: 3, hidden: false });
  });
});

// ── unlinkat ─────────────────────────────────────────────────────────────────

describe('unlinkat', () => {
  it('success → write event', () => {
    const line = 'unlinkat(AT_FDCWD, "/tmp/scratch.txt", 0) = 0';
    const evs = parseStraceLine(line, 1, 0);
    expect(evs).toEqual([{ kind: 'write', path: '/tmp/scratch.txt', pid: 1, ts: 0, hidden: false }]);
  });

  it('ENOENT → null', () => {
    const line = 'unlinkat(AT_FDCWD, "/tmp/gone", 0) = -1 ENOENT (No such file or directory)';
    expect(parseStraceLine(line, 1, 0)).toBeNull();
  });
});

// ── faccessat2 ────────────────────────────────────────────────────────────────

describe('faccessat2', () => {
  it('success → read event', () => {
    const line = 'faccessat2(AT_FDCWD, "/usr/bin/node", X_OK, AT_EACCESS) = 0';
    const evs = parseStraceLine(line, 1, 0);
    expect(evs).toEqual([{ kind: 'read', path: '/usr/bin/node', pid: 1, ts: 0, hidden: false }]);
  });

  it('ENOENT → null', () => {
    const line = 'faccessat2(AT_FDCWD, "/usr/bin/missing", F_OK, AT_EACCESS) = -1 ENOENT (No such file or directory)';
    expect(parseStraceLine(line, 1, 0)).toBeNull();
  });
});

// ── string escape handling ───────────────────────────────────────────────────

describe('string escaping', () => {
  it('path with \\n in it', () => {
    // strace would encode a newline in the path as \n
    const line = 'openat(AT_FDCWD, "/tmp/weird\\nfile", O_RDONLY) = 3';
    const evs = parseStraceLine(line, 1, 0);
    expect(evs).not.toBeNull();
    expect(evs![0]).toMatchObject({ path: '/tmp/weird\nfile' });
  });

  it('path with \\" (escaped quote)', () => {
    const line = 'openat(AT_FDCWD, "/tmp/say\\"hi\\"", O_RDONLY) = 4';
    const evs = parseStraceLine(line, 1, 0);
    expect(evs).not.toBeNull();
    expect(evs![0]).toMatchObject({ path: '/tmp/say"hi"' });
  });

  it('path with octal escape \\040 (space)', () => {
    const line = 'openat(AT_FDCWD, "/tmp/my\\040file", O_RDONLY) = 5';
    const evs = parseStraceLine(line, 1, 0);
    expect(evs).not.toBeNull();
    expect(evs![0]).toMatchObject({ path: '/tmp/my file' });
  });

  it('path with hex escape \\x20 (space)', () => {
    const line = 'openat(AT_FDCWD, "/tmp/my\\x20file", O_RDONLY) = 5';
    const evs = parseStraceLine(line, 1, 0);
    expect(evs).not.toBeNull();
    expect(evs![0]).toMatchObject({ path: '/tmp/my file' });
  });
});

// ── truncated strings ────────────────────────────────────────────────────────

describe('truncated strings', () => {
  it('truncated path "..."  → uses visible portion', () => {
    const line = 'openat(AT_FDCWD, "/very/long/pa"..., O_RDONLY) = 3';
    const evs = parseStraceLine(line, 1, 0);
    expect(evs).not.toBeNull();
    expect(evs![0]).toMatchObject({ path: '/very/long/pa' });
  });
});

// ── noise lines ───────────────────────────────────────────────────────────────

describe('noise / structurally unparseable lines', () => {
  it('signal delivery → null', () => {
    expect(parseStraceLine('--- SIGCHLD {si_signo=SIGCHLD, si_code=CLD_EXITED, si_pid=99} ---', 1, 0)).toBeNull();
  });

  it('exit line → null', () => {
    expect(parseStraceLine('+++ exited with 0 +++', 1, 0)).toBeNull();
  });

  it('unfinished syscall → null', () => {
    expect(parseStraceLine('openat(AT_FDCWD, "/etc/hosts", O_RDONLY <unfinished ...>', 1, 0)).toBeNull();
  });

  it('resumed syscall → null', () => {
    expect(parseStraceLine('<... openat resumed>) = 3', 1, 0)).toBeNull();
  });

  it('garbage line → null (no throw)', () => {
    expect(parseStraceLine('this is not strace output at all!!!', 1, 0)).toBeNull();
  });

  it('empty line → null', () => {
    expect(parseStraceLine('', 1, 0)).toBeNull();
  });

  it('unknown syscall → null', () => {
    expect(parseStraceLine('mmap(NULL, 4096, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0x7f1234', 1, 0)).toBeNull();
  });
});

// ── timestamp prefix tolerance ────────────────────────────────────────────────

describe('timestamp prefix (strace -t / -tt)', () => {
  it('HH:MM:SS prefix is stripped and line is still parsed', () => {
    const line = '12:34:56 openat(AT_FDCWD, "/etc/hostname", O_RDONLY) = 3';
    const evs = parseStraceLine(line, 1, 0);
    expect(evs).not.toBeNull();
    expect(evs![0]).toMatchObject({ kind: 'read', path: '/etc/hostname' });
  });

  it('HH:MM:SS.MICROS prefix is stripped', () => {
    const line = '12:34:56.123456 openat(AT_FDCWD, "/etc/hostname", O_RDONLY) = 3';
    const evs = parseStraceLine(line, 1, 0);
    expect(evs).not.toBeNull();
    expect(evs![0]).toMatchObject({ kind: 'read', path: '/etc/hostname' });
  });
});

// ── parseStraceStream ─────────────────────────────────────────────────────────

describe('parseStraceStream', () => {
  it('flattens events from multiple lines including renameat2', async () => {
    const fixture = [
      'openat(AT_FDCWD, "/etc/hostname", O_RDONLY) = 3',
      '--- SIGCHLD {si_signo=SIGCHLD} ---',
      'renameat2(AT_FDCWD, "/tmp/a", AT_FDCWD, "/tmp/b", 0) = 0',
      'openat(AT_FDCWD, "/tmp/out", O_WRONLY|O_CREAT|O_TRUNC, 0644) = 5',
      '+++ exited with 0 +++',
    ];
    const evs = await collect(parseStraceStream(asyncLines(fixture), 99));
    expect(evs).toHaveLength(4);
    expect(evs[0]).toMatchObject({ kind: 'read', path: '/etc/hostname', pid: 99 });
    // renameat2 produces two events
    expect(evs[1]).toMatchObject({ kind: 'read', path: '/tmp/a', pid: 99 });
    expect(evs[2]).toMatchObject({ kind: 'write', path: '/tmp/b', pid: 99 });
    expect(evs[3]).toMatchObject({ kind: 'write', path: '/tmp/out', pid: 99 });
  });

  it('assigns monotonically increasing ts values (one per input line)', async () => {
    const fixture = [
      'openat(AT_FDCWD, "/a", O_RDONLY) = 3',
      'openat(AT_FDCWD, "/b", O_RDONLY) = 4',
      'openat(AT_FDCWD, "/c", O_RDONLY) = 5',
    ];
    const evs = await collect(parseStraceStream(asyncLines(fixture), 1));
    expect(evs).toHaveLength(3);
    expect(evs[0]!.ts).toBe(0);
    expect(evs[1]!.ts).toBe(1);
    expect(evs[2]!.ts).toBe(2);
  });

  it('ts counter advances for dropped lines too', async () => {
    const fixture = [
      '--- SIGCHLD {} ---',           // ts=0, dropped
      'openat(AT_FDCWD, "/a", O_RDONLY) = 3',  // ts=1
    ];
    const evs = await collect(parseStraceStream(asyncLines(fixture), 1));
    expect(evs).toHaveLength(1);
    expect(evs[0]!.ts).toBe(1);
  });

  it('yields nothing for an empty stream', async () => {
    const evs = await collect(parseStraceStream(asyncLines([]), 1));
    expect(evs).toHaveLength(0);
  });
});

// ── real captured strace output ───────────────────────────────────────────────
// The following three tests use real strace lines captured on a Linux x86_64
// system running:
//   strace -ff -e trace=openat,execve,connect,readlinkat,statx,renameat2,unlinkat,faccessat2 \
//          node -e "require('fs').readFileSync('/etc/hostname')" 2>&1

describe('real captured strace output', () => {
  // Real: execve of node binary at startup
  it('[real] execve of node → spawn ok', () => {
    const line = 'execve("/usr/bin/node", ["node", "-e", "require(\'fs\').readFileSync(\'/etc/hostname\')"], 0x7ffce4d3a7d0 /* 23 vars */) = 0';
    const evs = parseStraceLine(line, 12345, 0);
    expect(evs).not.toBeNull();
    expect(evs![0]).toMatchObject({ kind: 'spawn', result: 'ok' });
    const ev = evs![0];
    if (ev?.kind === 'spawn') {
      expect(ev.argv[0]).toBe('node');
    }
  });

  // Real: openat of /etc/hostname
  it('[real] openat /etc/hostname O_RDONLY → read event', () => {
    const line = 'openat(AT_FDCWD, "/etc/hostname", O_RDONLY) = 3';
    const evs = parseStraceLine(line, 12345, 1);
    expect(evs).toEqual([{ kind: 'read', path: '/etc/hostname', pid: 12345, ts: 1, hidden: false }]);
  });

  // Real: statx of a file that doesn't exist
  it('[real] statx ENOENT → null', () => {
    const line = 'statx(AT_FDCWD, "/usr/lib/x86_64-linux-gnu/libstdc++.so.6", AT_STATX_SYNC_AS_STAT|AT_NO_AUTOMOUNT, STATX_ALL, 0x7ffe12345678) = -1 ENOENT (No such file or directory)';
    expect(parseStraceLine(line, 12345, 2)).toBeNull();
  });
});
