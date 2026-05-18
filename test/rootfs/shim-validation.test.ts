// script-jail — test/rootfs/shim-validation.test.ts
//
// Unit tests for the ELF-header validation that gates accepting an
// `images/libscriptjail.so` artifact during the rootfs build.
//
// Why: the rootfs Dockerfile COPYs that file into the VM at /lib/libscriptjail.so
// and the agent loads it via LD_PRELOAD.  If a stale Mach-O dylib (or any other
// non-ELF blob) slips in, the dynamic linker silently refuses to load it and
// the env-read audit chain disappears without an obvious error.  These tests
// pin the validation contract so that doesn't recur.

import { describe, it, expect } from 'vitest';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';

import {
  validateElfShimHeader,
  validateShimFile,
  expectedShimMachine,
  machineLabel,
  EM_X86_64,
  EM_AARCH64,
} from '../../src/rootfs/build.js';

// ---------------------------------------------------------------------------
// Fixture helpers
// ---------------------------------------------------------------------------

/** Construct a synthetic ELF64 little-endian header.  All we need is the
 *  first 20 bytes — `validateElfShimHeader` ignores anything past that. */
function makeElfHeader(opts: {
  magic?: ReadonlyArray<number>;
  eiClass?: number;
  eiData?: number;
  eType?: number;
  eMachine?: number;
} = {}): Buffer {
  const buf = Buffer.alloc(20, 0);
  const magic = opts.magic ?? [0x7f, 0x45, 0x4c, 0x46];
  buf[0] = magic[0] ?? 0;
  buf[1] = magic[1] ?? 0;
  buf[2] = magic[2] ?? 0;
  buf[3] = magic[3] ?? 0;
  buf[4] = opts.eiClass ?? 2; // ELFCLASS64
  buf[5] = opts.eiData ?? 1;  // ELFDATA2LSB
  const eType = opts.eType ?? 3;       // ET_DYN
  const eMachine = opts.eMachine ?? EM_X86_64;
  buf[16] = eType & 0xff;
  buf[17] = (eType >> 8) & 0xff;
  buf[18] = eMachine & 0xff;
  buf[19] = (eMachine >> 8) & 0xff;
  return buf;
}

// ---------------------------------------------------------------------------
// validateElfShimHeader — happy path
// ---------------------------------------------------------------------------

describe('validateElfShimHeader (happy path)', () => {
  it('accepts a well-formed ELF64 LE shared object for x86-64', () => {
    expect(validateElfShimHeader(makeElfHeader(), EM_X86_64)).toBeNull();
  });

  it('accepts an aarch64 ELF when aarch64 is the expected machine', () => {
    const buf = makeElfHeader({ eMachine: EM_AARCH64 });
    expect(validateElfShimHeader(buf, EM_AARCH64)).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// validateElfShimHeader — rejection paths
// ---------------------------------------------------------------------------

describe('validateElfShimHeader (rejections)', () => {
  it('rejects a buffer shorter than 20 bytes', () => {
    const err = validateElfShimHeader(new Uint8Array(4), EM_X86_64);
    expect(err).toMatch(/header too short/);
  });

  it('rejects an empty buffer', () => {
    const err = validateElfShimHeader(new Uint8Array(0), EM_X86_64);
    expect(err).toMatch(/header too short/);
  });

  it('rejects a Mach-O 64-bit LE binary with a specific message', () => {
    // Mach-O 64-bit LE magic = 0xCFFAEDFE in the byte order observed on disk.
    const buf = Buffer.alloc(20, 0);
    buf[0] = 0xcf;
    buf[1] = 0xfa;
    buf[2] = 0xed;
    buf[3] = 0xfe;
    const err = validateElfShimHeader(buf, EM_X86_64);
    expect(err).toMatch(/Mach-O/i);
  });

  it('rejects a Mach-O universal binary with a specific message', () => {
    const buf = Buffer.alloc(20, 0);
    buf[0] = 0xca;
    buf[1] = 0xfe;
    buf[2] = 0xba;
    buf[3] = 0xbe;
    const err = validateElfShimHeader(buf, EM_X86_64);
    expect(err).toMatch(/Mach-O universal/i);
  });

  it('rejects a shell-script shebang', () => {
    const buf = Buffer.alloc(20, 0);
    buf[0] = 0x23; // '#'
    buf[1] = 0x21; // '!'
    const err = validateElfShimHeader(buf, EM_X86_64);
    expect(err).toMatch(/bad ELF magic/);
  });

  it('rejects ELF32 (EI_CLASS=1)', () => {
    const err = validateElfShimHeader(
      makeElfHeader({ eiClass: 1 }),
      EM_X86_64,
    );
    expect(err).toMatch(/EI_CLASS=1/);
  });

  it('rejects big-endian ELF (EI_DATA=2)', () => {
    const err = validateElfShimHeader(
      makeElfHeader({ eiData: 2 }),
      EM_X86_64,
    );
    expect(err).toMatch(/EI_DATA=2/);
  });

  it('rejects ET_EXEC (e_type=2) — we need a shared object, not an executable', () => {
    const err = validateElfShimHeader(
      makeElfHeader({ eType: 2 }),
      EM_X86_64,
    );
    expect(err).toMatch(/e_type=2/);
  });

  it('rejects ET_REL (e_type=1)', () => {
    const err = validateElfShimHeader(
      makeElfHeader({ eType: 1 }),
      EM_X86_64,
    );
    expect(err).toMatch(/e_type=1/);
  });

  it('rejects an aarch64 ELF when the rootfs target is x86-64', () => {
    const err = validateElfShimHeader(
      makeElfHeader({ eMachine: EM_AARCH64 }),
      EM_X86_64,
    );
    expect(err).toMatch(/wrong architecture/);
    expect(err).toMatch(/aarch64/);
    expect(err).toMatch(/x86-64/);
  });
});

// ---------------------------------------------------------------------------
// validateShimFile — IO wrapper
// ---------------------------------------------------------------------------

describe('validateShimFile', () => {
  it('returns null for a real ELF-shaped file', () => {
    const dir = mkdtempSync(join(tmpdir(), 'shim-elf-'));
    try {
      const p = join(dir, 'libscriptjail.so');
      // Pad to >20 bytes so the file-system read returns a full header.
      const buf = Buffer.concat([makeElfHeader(), Buffer.alloc(64, 0)]);
      writeFileSync(p, buf);
      expect(validateShimFile(p, EM_X86_64)).toBeNull();
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('flags an empty file with a "header too short" error', () => {
    const dir = mkdtempSync(join(tmpdir(), 'shim-empty-'));
    try {
      const p = join(dir, 'libscriptjail.so');
      writeFileSync(p, Buffer.alloc(0));
      expect(validateShimFile(p, EM_X86_64)).toMatch(/header too short/);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('flags a Mach-O file specifically as a Mach-O binary', () => {
    const dir = mkdtempSync(join(tmpdir(), 'shim-macho-'));
    try {
      const p = join(dir, 'libscriptjail.so');
      // First 4 bytes = Mach-O 64-bit LE magic.
      const buf = Buffer.alloc(64, 0);
      buf[0] = 0xcf;
      buf[1] = 0xfa;
      buf[2] = 0xed;
      buf[3] = 0xfe;
      writeFileSync(p, buf);
      const err = validateShimFile(p, EM_X86_64);
      expect(err).toMatch(/Mach-O/i);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('returns a "cannot open" error for a missing file', () => {
    const missing = join(tmpdir(), `definitely-not-here-${Date.now()}.so`);
    const err = validateShimFile(missing, EM_X86_64);
    expect(err).toMatch(/cannot open/);
  });
});

// ---------------------------------------------------------------------------
// expectedShimMachine + machineLabel
// ---------------------------------------------------------------------------

describe('expectedShimMachine', () => {
  it('returns EM_X86_64 for ubuntu-22.04', () => {
    expect(expectedShimMachine({ runnerImage: 'ubuntu-22.04' })).toBe(EM_X86_64);
  });

  it('returns EM_X86_64 for ubuntu-24.04', () => {
    expect(expectedShimMachine({ runnerImage: 'ubuntu-24.04' })).toBe(EM_X86_64);
  });
});

describe('machineLabel', () => {
  it('labels EM_X86_64 as x86-64 with the symbolic name', () => {
    expect(machineLabel(EM_X86_64)).toMatch(/x86-64/);
    expect(machineLabel(EM_X86_64)).toMatch(/EM_X86_64/);
  });

  it('labels EM_AARCH64 as aarch64 with the symbolic name', () => {
    expect(machineLabel(EM_AARCH64)).toMatch(/aarch64/);
    expect(machineLabel(EM_AARCH64)).toMatch(/EM_AARCH64/);
  });

  it('falls back to raw e_machine for unknown values', () => {
    expect(machineLabel(0x1234)).toBe(`e_machine=${0x1234}`);
  });
});
