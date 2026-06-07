// script-jail — src/rootfs/macho.ts
//
// Mach-O validation for libscriptjail-arm64.dylib (macOS bare backend).
//
// This lives in its OWN module — separate from build.ts — because it is now
// consumed on the RUNTIME path (src/action/backend/mac-bare.ts validates the
// shim before each audit), not just by the build scripts.  build.ts carries a
// top-level `fileURLToPath(import.meta.url)`, which esbuild rewrites to an
// empty value in the CJS `dist/` bundles and would THROW at module load.
// Keeping these helpers in an import.meta-free module lets the bundled CLI
// import them safely.
//
// The macOS `bare` backend injects a Mach-O dylib via DYLD_INSERT_LIBRARIES
// instead of an ELF .so via LD_PRELOAD.  This validator is the Mach-O analog
// of validateShimFile (build.ts): it confirms the file is a 64-bit Mach-O
// dylib for the expected cputype AND — crucially — that it carries a
// `__DATA,__interpose` section.  Without that section dyld has nothing to
// rebind, so the dylib would load (ctor fires) yet silently intercept NOTHING
// — the Mach-O analog of "valid ELF but no PT_DYNAMIC".

import { openSync, statSync, readSync, closeSync } from 'node:fs';

import type { BuildArch } from './build.js';

/** Read a little-endian unsigned 32-bit integer from `buf` at `off`. */
function readU32LE(buf: Uint8Array, off: number): number {
  return (
    (buf[off]! |
      (buf[off + 1]! << 8) |
      (buf[off + 2]! << 16) |
      (buf[off + 3]! << 24)) >>>
    0
  );
}

// Mach-O 64 header (little-endian on arm64/x86_64):
//   bytes 0..3   = magic            (0xFEEDFACF = MH_MAGIC_64, native-endian)
//   bytes 4..7   = cputype          (0x0100000C arm64 / 0x01000007 x86_64)
//   bytes 12..15 = filetype         (0x6 = MH_DYLIB)
//   bytes 16..19 = ncmds
//   bytes 20..23 = sizeofcmds
// Load commands follow the 32-byte header.  We walk them looking for
// LC_SEGMENT_64 (0x19) commands and, within each, its sections, matching
// segname=="__DATA" + sectname=="__interpose".

/** Mach-O 64-bit little-endian magic (cpu native order on arm64/x86_64). */
export const MH_MAGIC_64 = 0xfeedfacf;
/** Mach-O fat/universal magics (we reject — arm64 ships a thin dylib first). */
export const FAT_MAGIC = 0xcafebabe;
export const FAT_MAGIC_CIGAM = 0xbebafeca;
/** MH_DYLIB filetype. */
export const MH_DYLIB = 0x6;
/** LC_SEGMENT_64 load command. */
export const LC_SEGMENT_64 = 0x19;
/** cputype values. */
export const CPU_TYPE_ARM64 = 0x0100000c;
export const CPU_TYPE_X86_64 = 0x01000007;
/** Mach-O 64 header size. */
export const MACHO64_HEADER_SIZE = 32;

/** Map the dylib arch to its expected Mach-O cputype. */
export function expectedMachOCpuType(arch: BuildArch | undefined): number {
  // arm64 is the only published darwin package today (R10); x64 build-from-
  // source still validates against CPU_TYPE_X86_64.
  return arch === 'x64' ? CPU_TYPE_X86_64 : CPU_TYPE_ARM64;
}

/** Human label for a cputype (for error messages). */
export function cpuTypeLabel(cpu: number): string {
  if (cpu === CPU_TYPE_ARM64) return 'arm64 (CPU_TYPE_ARM64)';
  if (cpu === CPU_TYPE_X86_64) return 'x86-64 (CPU_TYPE_X86_64)';
  return `cputype=0x${(cpu >>> 0).toString(16)}`;
}

/**
 * Compare a fixed-width Mach-O name field (NUL-padded, e.g. segname[16] /
 * sectname[16]) against a JS string.  Mach-O name fields are NOT required to
 * be NUL-terminated when they fill the full width, so we compare up to the
 * field width and treat a trailing NUL as the terminator.
 */
function machoNameEquals(buf: Uint8Array, off: number, width: number, name: string): boolean {
  for (let i = 0; i < width; i++) {
    const c = buf[off + i] ?? 0;
    const want = i < name.length ? name.charCodeAt(i) : 0;
    if (c !== want) return false;
    if (c === 0 && i >= name.length) return true;
  }
  return true;
}

/**
 * Read `path` and validate it is a 64-bit Mach-O dylib for `expectedCpuType`
 * that carries a `__DATA,__interpose` section.  Returns `null` on success or a
 * descriptive error string.  Surfaces open/read errors as strings rather than
 * throwing.  Pure-ish (filesystem read only).
 */
export function validateMachOShimFile(path: string, expectedCpuType: number): string | null {
  let fd: number;
  try {
    fd = openSync(path, 'r');
  } catch (err) {
    return `cannot open: ${err instanceof Error ? err.message : String(err)}`;
  }
  try {
    let fileSize: number;
    try {
      fileSize = statSync(path).size;
    } catch (err) {
      return `cannot stat: ${err instanceof Error ? err.message : String(err)}`;
    }

    const hdr = Buffer.alloc(MACHO64_HEADER_SIZE);
    const n = readSync(fd, hdr, 0, MACHO64_HEADER_SIZE, 0);
    if (n < MACHO64_HEADER_SIZE) {
      return `header too short (${n} bytes; need ≥ ${MACHO64_HEADER_SIZE})`;
    }

    const magic = readU32LE(hdr, 0);
    if (magic === FAT_MAGIC || magic === FAT_MAGIC_CIGAM) {
      return 'file is a Mach-O universal (fat) binary; expected a thin arm64 dylib';
    }
    if (magic !== MH_MAGIC_64) {
      // ELF magic is 0x7F 45 4C 46 → readU32LE = 0x464c457f.
      if (magic === 0x464c457f) {
        return 'file is a Linux ELF object, not a macOS Mach-O dylib';
      }
      return `bad Mach-O magic: expected 0x${MH_MAGIC_64.toString(16)}, got 0x${magic.toString(16)}`;
    }

    const cputype = readU32LE(hdr, 4);
    if (cputype !== expectedCpuType) {
      return `wrong architecture: got ${cpuTypeLabel(cputype)}, expected ${cpuTypeLabel(expectedCpuType)}`;
    }

    const filetype = readU32LE(hdr, 12);
    if (filetype !== MH_DYLIB) {
      return `unexpected filetype=0x${filetype.toString(16)} (expected 0x${MH_DYLIB.toString(16)} = MH_DYLIB)`;
    }

    const ncmds = readU32LE(hdr, 16);
    const sizeofcmds = readU32LE(hdr, 20);
    if (ncmds === 0 || sizeofcmds === 0) {
      return 'no load commands; not a loadable dylib';
    }
    if (MACHO64_HEADER_SIZE + sizeofcmds > fileSize) {
      return (
        `load-command region runs past end of file ` +
        `(header ${MACHO64_HEADER_SIZE} + sizeofcmds ${sizeofcmds} > file_size ${fileSize})`
      );
    }

    // Read the whole load-command region and walk it for the interpose section.
    const cmds = Buffer.alloc(sizeofcmds);
    const m = readSync(fd, cmds, 0, sizeofcmds, MACHO64_HEADER_SIZE);
    if (m < sizeofcmds) {
      return `short read of load commands (got ${m}; need ${sizeofcmds})`;
    }

    let off = 0;
    let sawInterpose = false;
    for (let i = 0; i < ncmds; i++) {
      if (off + 8 > sizeofcmds) {
        return `load command ${i} runs past the command region (off=${off})`;
      }
      const cmd = readU32LE(cmds, off);
      const cmdsize = readU32LE(cmds, off + 4);
      if (cmdsize < 8 || off + cmdsize > sizeofcmds) {
        return `load command ${i} has invalid cmdsize=${cmdsize} at off=${off}`;
      }
      if (cmd === LC_SEGMENT_64) {
        // segment_command_64: cmd(4) cmdsize(4) segname[16] vmaddr(8)
        // vmsize(8) fileoff(8) filesize(8) maxprot(4) initprot(4) nsects(4)
        // flags(4) = 72 bytes, then nsects * section_64 (80 bytes each).
        const segnameOff = off + 8;
        const nsects = readU32LE(cmds, off + 64);
        const sectsBase = off + 72;
        for (let s = 0; s < nsects; s++) {
          const secOff = sectsBase + s * 80;
          if (secOff + 32 > off + cmdsize) break;
          // section_64: sectname[16] segname[16] ...
          const sectnameOff = secOff;
          const secSegnameOff = secOff + 16;
          if (
            machoNameEquals(cmds, secSegnameOff, 16, '__DATA') &&
            machoNameEquals(cmds, sectnameOff, 16, '__interpose')
          ) {
            sawInterpose = true;
          }
        }
        // (segnameOff retained for clarity; not otherwise needed.)
        void segnameOff;
      }
      off += cmdsize;
    }

    if (!sawInterpose) {
      return (
        'no __DATA,__interpose section; dyld has nothing to rebind ' +
        '(the dylib would load but intercept nothing)'
      );
    }

    return null;
  } finally {
    try { closeSync(fd); } catch { /* ignore */ }
  }
}
