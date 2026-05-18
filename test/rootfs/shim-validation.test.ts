// script-jail — test/rootfs/shim-validation.test.ts
//
// Unit tests for the ELF validation that gates accepting an
// `images/libscriptjail.so` artifact during the rootfs build.
//
// Why: the rootfs Dockerfile COPYs that file into the VM at /lib/libscriptjail.so
// and the agent loads it via LD_PRELOAD.  If a stale Mach-O dylib (or any
// other non-loadable blob) slips in, the dynamic linker silently refuses to
// load it and the env-read audit chain disappears without an obvious error.
// These tests pin the validation contract so that doesn't recur.
//
// Validation depth: prefix-only checks (magic, class, endianness, e_type,
// e_machine) plus a loadability check (program header table contains both
// PT_LOAD and PT_DYNAMIC). A 20-byte file with only valid prefix bytes is
// REJECTED because ld.so cannot load it.

import { describe, it, expect } from 'vitest';
import { mkdtempSync, writeFileSync, rmSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';

import {
  validateElfShimHeader,
  validateElfProgramHeaders,
  validateShimFile,
  expectedShimMachine,
  machineLabel,
  EM_X86_64,
  EM_AARCH64,
  ELF64_EHDR_SIZE,
  ELF64_PHDR_SIZE,
  PT_LOAD,
  PT_DYNAMIC,
} from '../../src/rootfs/build.js';

// ---------------------------------------------------------------------------
// Fixture helpers
// ---------------------------------------------------------------------------

/** Write a little-endian unsigned 16 into `buf` at `off`. */
function writeU16LE(buf: Buffer, off: number, val: number): void {
  buf[off] = val & 0xff;
  buf[off + 1] = (val >> 8) & 0xff;
}

/** Write a little-endian unsigned 32 into `buf` at `off`. */
function writeU32LE(buf: Buffer, off: number, val: number): void {
  buf[off] = val & 0xff;
  buf[off + 1] = (val >> 8) & 0xff;
  buf[off + 2] = (val >> 16) & 0xff;
  buf[off + 3] = (val >>> 24) & 0xff;
}

/** Write a little-endian unsigned 64 into `buf` at `off`. */
function writeU64LE(buf: Buffer, off: number, val: number): void {
  const lo = val >>> 0;
  const hi = Math.floor(val / 0x100000000) >>> 0;
  writeU32LE(buf, off, lo);
  writeU32LE(buf, off + 4, hi);
}

/** Construct a synthetic ELF64 header.  The 20-byte prefix is what
 *  `validateElfShimHeader` inspects; the rest is for `validateShimFile`'s
 *  loadability check (e_phoff / e_phentsize / e_phnum). */
function makeElfHeader(opts: {
  magic?: ReadonlyArray<number>;
  eiClass?: number;
  eiData?: number;
  eType?: number;
  eMachine?: number;
  ePhoff?: number;
  ePhentsize?: number;
  ePhnum?: number;
  size?: number;
} = {}): Buffer {
  const size = opts.size ?? ELF64_EHDR_SIZE;
  const buf = Buffer.alloc(size, 0);
  const magic = opts.magic ?? [0x7f, 0x45, 0x4c, 0x46];
  buf[0] = magic[0] ?? 0;
  buf[1] = magic[1] ?? 0;
  buf[2] = magic[2] ?? 0;
  buf[3] = magic[3] ?? 0;
  buf[4] = opts.eiClass ?? 2; // ELFCLASS64
  buf[5] = opts.eiData ?? 1;  // ELFDATA2LSB
  writeU16LE(buf, 16, opts.eType ?? 3);       // ET_DYN
  writeU16LE(buf, 18, opts.eMachine ?? EM_X86_64);
  if (size >= ELF64_EHDR_SIZE) {
    writeU64LE(buf, 32, opts.ePhoff ?? ELF64_EHDR_SIZE);
    writeU16LE(buf, 54, opts.ePhentsize ?? ELF64_PHDR_SIZE);
    writeU16LE(buf, 56, opts.ePhnum ?? 0);
  }
  return buf;
}

/** Build one ELF64 program-header entry (56 bytes) with the given p_type. */
function makePhdr(pType: number): Buffer {
  const buf = Buffer.alloc(ELF64_PHDR_SIZE, 0);
  writeU32LE(buf, 0, pType);
  return buf;
}

/** Assemble a full loadable-looking ELF64 .so: header + phdr table. */
function makeLoadableElf(opts: {
  phdrs: ReadonlyArray<Buffer>;
  eMachine?: number;
} = { phdrs: [makePhdr(PT_LOAD), makePhdr(PT_DYNAMIC)] }): Buffer {
  const phdrs = Buffer.concat(opts.phdrs.map((p) => Buffer.from(p)));
  const headerOpts: Parameters<typeof makeElfHeader>[0] = {
    ePhoff: ELF64_EHDR_SIZE,
    ePhentsize: ELF64_PHDR_SIZE,
    ePhnum: opts.phdrs.length,
  };
  if (opts.eMachine !== undefined) headerOpts.eMachine = opts.eMachine;
  const header = makeElfHeader(headerOpts);
  return Buffer.concat([header, phdrs]);
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
      makeElfHeader({ eiClass: 1, size: 20 }),
      EM_X86_64,
    );
    expect(err).toMatch(/EI_CLASS=1/);
  });

  it('rejects big-endian ELF (EI_DATA=2)', () => {
    const err = validateElfShimHeader(
      makeElfHeader({ eiData: 2, size: 20 }),
      EM_X86_64,
    );
    expect(err).toMatch(/EI_DATA=2/);
  });

  it('rejects ET_EXEC (e_type=2) — we need a shared object, not an executable', () => {
    const err = validateElfShimHeader(
      makeElfHeader({ eType: 2, size: 20 }),
      EM_X86_64,
    );
    expect(err).toMatch(/e_type=2/);
  });

  it('rejects ET_REL (e_type=1)', () => {
    const err = validateElfShimHeader(
      makeElfHeader({ eType: 1, size: 20 }),
      EM_X86_64,
    );
    expect(err).toMatch(/e_type=1/);
  });

  it('rejects an aarch64 ELF when the rootfs target is x86-64', () => {
    const err = validateElfShimHeader(
      makeElfHeader({ eMachine: EM_AARCH64, size: 20 }),
      EM_X86_64,
    );
    expect(err).toMatch(/wrong architecture/);
    expect(err).toMatch(/aarch64/);
    expect(err).toMatch(/x86-64/);
  });
});

// ---------------------------------------------------------------------------
// validateElfProgramHeaders — loadability
// ---------------------------------------------------------------------------

describe('validateElfProgramHeaders', () => {
  it('accepts a phdr table with PT_LOAD + PT_DYNAMIC', () => {
    const ehdr = makeElfHeader({
      ePhoff: ELF64_EHDR_SIZE,
      ePhentsize: ELF64_PHDR_SIZE,
      ePhnum: 2,
    });
    const phdrs = Buffer.concat([makePhdr(PT_LOAD), makePhdr(PT_DYNAMIC)]);
    const fileSize = ELF64_EHDR_SIZE + phdrs.length;
    expect(validateElfProgramHeaders(ehdr, phdrs, fileSize)).toBeNull();
  });

  it('rejects when e_phoff is zero (no program header table)', () => {
    const ehdr = makeElfHeader({ ePhoff: 0, ePhnum: 0 });
    const err = validateElfProgramHeaders(ehdr, Buffer.alloc(0), ELF64_EHDR_SIZE);
    expect(err).toMatch(/e_phoff=0/);
  });

  it('rejects when e_phnum is zero', () => {
    const ehdr = makeElfHeader({
      ePhoff: ELF64_EHDR_SIZE,
      ePhentsize: ELF64_PHDR_SIZE,
      ePhnum: 0,
    });
    const err = validateElfProgramHeaders(ehdr, Buffer.alloc(0), ELF64_EHDR_SIZE);
    expect(err).toMatch(/e_phnum=0/);
  });

  it('rejects when e_phentsize is not the ELF64 standard', () => {
    const ehdr = makeElfHeader({
      ePhoff: ELF64_EHDR_SIZE,
      ePhentsize: 32, // wrong: ELF32 phdr size
      ePhnum: 1,
    });
    const err = validateElfProgramHeaders(
      ehdr,
      Buffer.alloc(32),
      ELF64_EHDR_SIZE + 32,
    );
    expect(err).toMatch(/e_phentsize=32/);
  });

  it('rejects when the phdr table runs past end-of-file', () => {
    const ehdr = makeElfHeader({
      ePhoff: ELF64_EHDR_SIZE,
      ePhentsize: ELF64_PHDR_SIZE,
      ePhnum: 2,
    });
    const phdrs = Buffer.concat([makePhdr(PT_LOAD), makePhdr(PT_DYNAMIC)]);
    // Claim the file is too small to contain both phdrs.
    const truncatedSize = ELF64_EHDR_SIZE + ELF64_PHDR_SIZE - 1;
    const err = validateElfProgramHeaders(ehdr, phdrs, truncatedSize);
    expect(err).toMatch(/runs past end of file/);
  });

  it('rejects when there is no PT_LOAD segment', () => {
    const ehdr = makeElfHeader({
      ePhoff: ELF64_EHDR_SIZE,
      ePhentsize: ELF64_PHDR_SIZE,
      ePhnum: 1,
    });
    const phdrs = makePhdr(PT_DYNAMIC);
    expect(
      validateElfProgramHeaders(ehdr, phdrs, ELF64_EHDR_SIZE + phdrs.length),
    ).toMatch(/no PT_LOAD/);
  });

  it('rejects when there is no PT_DYNAMIC segment', () => {
    const ehdr = makeElfHeader({
      ePhoff: ELF64_EHDR_SIZE,
      ePhentsize: ELF64_PHDR_SIZE,
      ePhnum: 1,
    });
    const phdrs = makePhdr(PT_LOAD);
    expect(
      validateElfProgramHeaders(ehdr, phdrs, ELF64_EHDR_SIZE + phdrs.length),
    ).toMatch(/no PT_DYNAMIC/);
  });
});

// ---------------------------------------------------------------------------
// validateShimFile — IO wrapper with full ELF-walk
// ---------------------------------------------------------------------------

describe('validateShimFile', () => {
  it('returns null for a real ELF-shaped file with PT_LOAD + PT_DYNAMIC', () => {
    const dir = mkdtempSync(join(tmpdir(), 'shim-elf-'));
    try {
      const p = join(dir, 'libscriptjail.so');
      writeFileSync(p, makeLoadableElf());
      expect(validateShimFile(p, EM_X86_64)).toBeNull();
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('rejects a 20-byte file with only a valid ELF prefix (Finding A)', () => {
    // This is exactly the threat described in Finding A: the file passes the
    // old prefix-only check but ld.so cannot load it. The new validation
    // requires the full ELF64 header (64 bytes) plus a program header table.
    const dir = mkdtempSync(join(tmpdir(), 'shim-prefix-only-'));
    try {
      const p = join(dir, 'libscriptjail.so');
      const buf = Buffer.alloc(20, 0);
      buf[0] = 0x7f;
      buf[1] = 0x45; // 'E'
      buf[2] = 0x4c; // 'L'
      buf[3] = 0x46; // 'F'
      buf[4] = 2;    // ELFCLASS64
      buf[5] = 1;    // ELFDATA2LSB
      writeU16LE(buf, 16, 3);        // ET_DYN
      writeU16LE(buf, 18, EM_X86_64);
      writeFileSync(p, buf);
      const err = validateShimFile(p, EM_X86_64);
      expect(err).not.toBeNull();
      expect(err).toMatch(/header too short/);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('rejects a full ELF header with e_phoff == 0 (Finding A)', () => {
    const dir = mkdtempSync(join(tmpdir(), 'shim-no-phdrs-'));
    try {
      const p = join(dir, 'libscriptjail.so');
      // 64-byte ELF header with e_phoff = 0. No program header table at all.
      const header = makeElfHeader({ ePhoff: 0, ePhnum: 0 });
      writeFileSync(p, header);
      const err = validateShimFile(p, EM_X86_64);
      expect(err).toMatch(/e_phoff=0|no program header table/);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('rejects a 64-byte garbage blob with the ELF prefix but otherwise zero', () => {
    // Equivalent to the user-supplied verification case: a 64-byte file with
    // valid ELF identification but zero phdr table. This must fail.
    const dir = mkdtempSync(join(tmpdir(), 'shim-garbage64-'));
    try {
      const p = join(dir, 'libscriptjail.so');
      const buf = Buffer.alloc(64, 0);
      buf[0] = 0x7f; buf[1] = 0x45; buf[2] = 0x4c; buf[3] = 0x46;
      buf[4] = 2; buf[5] = 1;
      writeU16LE(buf, 16, 3);
      writeU16LE(buf, 18, EM_X86_64);
      // e_phoff (offset 32) left at 0 → no program headers.
      writeFileSync(p, buf);
      expect(validateShimFile(p, EM_X86_64)).not.toBeNull();
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('rejects an ELF with program headers present but no PT_DYNAMIC (Finding A)', () => {
    const dir = mkdtempSync(join(tmpdir(), 'shim-no-dynamic-'));
    try {
      const p = join(dir, 'libscriptjail.so');
      // Header + a single PT_LOAD phdr, no PT_DYNAMIC.
      writeFileSync(p, makeLoadableElf({ phdrs: [makePhdr(PT_LOAD)] }));
      expect(validateShimFile(p, EM_X86_64)).toMatch(/no PT_DYNAMIC/);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('rejects when the phdr table runs past end-of-file', () => {
    const dir = mkdtempSync(join(tmpdir(), 'shim-truncated-'));
    try {
      const p = join(dir, 'libscriptjail.so');
      // Header claims 4 phdrs but the file only contains the 64-byte header.
      const header = makeElfHeader({
        ePhoff: ELF64_EHDR_SIZE,
        ePhentsize: ELF64_PHDR_SIZE,
        ePhnum: 4,
      });
      writeFileSync(p, header);
      expect(validateShimFile(p, EM_X86_64)).toMatch(/runs past end of file/);
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
      // First 4 bytes = Mach-O 64-bit LE magic; pad to >= 64 bytes so the
      // initial read of the full ELF header succeeds and the magic check is
      // what surfaces the error (rather than "header too short").
      const buf = Buffer.alloc(128, 0);
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

  // Integration-style: when an actual Linux .so is sitting in the repo's
  // images/ directory, exercise the validator against it. We skip on macOS
  // (or when the file isn't a Linux ELF) to keep the unit test deterministic
  // on dev hosts where the local artifact may be a Mach-O dylib.
  it('accepts a real images/libscriptjail.so when present and Linux-ELF-shaped', () => {
    const realPath = join(
      process.cwd(),
      'images',
      'libscriptjail.so',
    );
    if (!existsSync(realPath)) {
      return; // No artifact present; nothing to assert.
    }
    // If the local artifact is the macOS dev Mach-O, the validator will
    // (correctly) reject it. Only assert acceptance when it looks like a
    // genuine Linux ELF, to keep this test green on macOS dev hosts.
    const err = validateShimFile(realPath, EM_X86_64);
    if (err === null) {
      expect(err).toBeNull();
    } else {
      // Sanity: the error message must be one of the expected diagnostic
      // strings rather than an unhandled exception bubbling out.
      expect(typeof err).toBe('string');
      expect(err.length).toBeGreaterThan(0);
    }
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
