// Real /proc filesystem reader for Linux.
//
// LinuxProcReader reads from a configurable root directory (defaulting to
// '/proc') so tests can inject a fake /proc tree pointing at a fixture
// directory. Both methods use synchronous I/O (readFileSync) — /proc files
// are tiny in-memory pseudo-files; there is no benefit to streaming them.

import { readFileSync } from 'node:fs';
import type { ProcReader } from './attribution.js';

export class LinuxProcReader implements ProcReader {
  private readonly root: string;

  /**
   * @param root  Base directory to read from. Defaults to '/proc'.
   *              Inject a different path in tests to point at a fixture tree.
   */
  constructor(root = '/proc') {
    this.root = root;
  }

  /**
   * Read the PPid field from <root>/<pid>/status.
   * Returns null on ENOENT, EACCES, or any parse failure. Never throws.
   */
  readPpid(pid: number): number | null {
    try {
      const text = readFileSync(`${this.root}/${pid}/status`, 'utf8');
      // The PPid line looks like: "PPid:\t<number>\n"
      const match = text.match(/^PPid:\s*(\d+)/m);
      if (match === null) return null;
      const raw = match[1];
      if (raw === undefined) return null;
      const val = parseInt(raw, 10);
      return isNaN(val) ? null : val;
    } catch {
      // Swallows ENOENT/EACCES/EPERM (the pid may have exited).
      // This also swallows logic bugs; the interface contract is "never throws".
      return null;
    }
  }

  /**
   * Read and parse <root>/<pid>/environ.
   * The file contains NUL-separated KEY=VALUE tokens. Tokens without '=' are
   * silently skipped. When '=' appears in the value (e.g. KEY=foo=bar) only
   * the first '=' is the delimiter, so the value becomes 'foo=bar'.
   * Returns null on ENOENT or EACCES. Never throws.
   */
  readEnviron(pid: number): Map<string, string> | null {
    try {
      // Read as a Buffer so we can split on NUL bytes without any encoding
      // concerns. The individual KEY=VALUE strings are then decoded as UTF-8.
      const buf = readFileSync(`${this.root}/${pid}/environ`);
      const text = buf.toString('utf8');
      const map = new Map<string, string>();
      for (const token of text.split('\0')) {
        if (token.length === 0) continue;
        const eqIdx = token.indexOf('=');
        if (eqIdx === -1) continue; // skip tokens without '='
        const key = token.slice(0, eqIdx);
        const val = token.slice(eqIdx + 1);
        map.set(key, val);
      }
      return map;
    } catch {
      // Swallows ENOENT/EACCES/EPERM (the pid may have exited).
      // This also swallows logic bugs; the interface contract is "never throws".
      return null;
    }
  }
}
