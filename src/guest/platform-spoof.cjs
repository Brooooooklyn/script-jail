// @ts-check
// npm-jar — platform-spoof.cjs
// NODE_OPTIONS=--require preload: redefines process.platform, process.arch,
// and os.* getters to return spoofed values for cross-platform install audits.
//
// Env vars:
//   NPM_JAR_SPOOF_PLATFORM — one of: linux | darwin | win32  (default: linux)
//   NPM_JAR_SPOOF_ARCH     — one of: x64 | arm64             (default: x64)
//
// This file is deliberately plain CommonJS (no build step needed).

'use strict';

const os = require('os');

const PLATFORM = /** @type {Record<string, string>} */ ({
  linux:   'linux',
  darwin:  'darwin',
  win32:   'win32',
});

/** @type {Record<string, { type: string; release: string; version: string }>} */
const PLATFORM_META = {
  linux:  { type: 'Linux',      release: '4.0.0',  version: '#1 SMP Linux 4.0.0' },
  darwin: { type: 'Darwin',     release: '19.0.0', version: 'Darwin Kernel Version 19.0.0' },
  win32:  { type: 'Windows_NT', release: '10.0.0', version: 'Windows NT 10.0.0' },
};

const rawPlatform = process.env['NPM_JAR_SPOOF_PLATFORM'] ?? 'linux';
const rawArch     = process.env['NPM_JAR_SPOOF_ARCH']     ?? 'x64';

const spoofPlatform = /** @type {NodeJS.Platform} */ (PLATFORM[rawPlatform] ?? 'linux');
const spoofArch     = /** @type {string} */ (rawArch === 'arm64' ? 'arm64' : 'x64');
const meta          = PLATFORM_META[spoofPlatform] ?? PLATFORM_META['linux'];

// Idempotency guard: if already installed (configurable === false), skip re-install.
// This prevents TypeError when a child process requires this preload a second time
// via NODE_OPTIONS after the parent already applied it.
const platformDesc = Object.getOwnPropertyDescriptor(process, 'platform');
if (platformDesc && platformDesc.configurable === false) return;

// Patch process.platform and process.arch
Object.defineProperty(process, 'platform', { value: spoofPlatform, writable: false, configurable: false });
Object.defineProperty(process, 'arch',     { value: spoofArch,     writable: false, configurable: false });

// Patch os module getters
Object.defineProperty(os, 'platform',    { value: () => spoofPlatform,    writable: false, configurable: false });
Object.defineProperty(os, 'arch',        { value: () => spoofArch,        writable: false, configurable: false });
Object.defineProperty(os, 'type',        { value: () => meta.type,        writable: false, configurable: false });
Object.defineProperty(os, 'release',     { value: () => meta.release,     writable: false, configurable: false });
Object.defineProperty(os, 'version',     { value: () => meta.version,     writable: false, configurable: false });
// endianness is architecture-dependent; both x64 and arm64 are little-endian.
Object.defineProperty(os, 'endianness',  { value: () => /** @type {'LE'|'BE'} */ ('LE'), writable: false, configurable: false });

// Self-test: verify one mapping is applied correctly (caught at load time).
/* c8 ignore next 3 */
if (process.platform !== spoofPlatform) {
  throw new Error(`npm-jar platform-spoof: self-test failed (expected ${spoofPlatform}, got ${process.platform})`);
}
