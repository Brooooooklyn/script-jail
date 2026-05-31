#!/usr/bin/env node
// Validate the macOS npm tarball before publish. npm silently omits missing
// `files` entries, so `npm pack --dry-run` alone is not a release gate.

import { spawnSync } from 'node:child_process';

const expectedFiles = [
  'README.md',
  'bin/darwin-arm64/script-jail-vm',
  'dist/cli.cjs',
  'images/libscriptjail-arm64.so',
  'images/rootfs-ubuntu-24.04-arm64.ext4.gz',
  'images/vmlinux-vz-arm64',
  'package.json',
].sort();

const maxPackBytes = Number.parseInt(
  process.env.SCRIPT_JAIL_NPM_MAX_PACK_BYTES ?? String(70 * 1024 * 1024),
  10,
);

if (!Number.isSafeInteger(maxPackBytes) || maxPackBytes <= 0) {
  fail(`invalid SCRIPT_JAIL_NPM_MAX_PACK_BYTES: ${process.env.SCRIPT_JAIL_NPM_MAX_PACK_BYTES}`);
}

const result = spawnSync('npm', ['pack', '--dry-run', '--json'], {
  encoding: 'utf8',
  stdio: ['ignore', 'pipe', 'pipe'],
});

if (result.status !== 0) {
  fail(`npm pack --dry-run failed\n${result.stderr}${result.stdout}`);
}

let packs;
try {
  packs = JSON.parse(result.stdout);
} catch {
  fail(`npm pack --dry-run did not return JSON:\n${result.stdout}`);
}

if (!Array.isArray(packs) || packs.length !== 1) {
  fail(`expected one npm pack result, got ${JSON.stringify(packs)}`);
}

const pack = packs[0];
if (typeof pack !== 'object' || pack === null) {
  fail(`invalid npm pack result: ${JSON.stringify(pack)}`);
}

const files = Array.isArray(pack.files)
  ? pack.files.map((entry) => entry?.path).filter((path) => typeof path === 'string').sort()
  : [];

if (JSON.stringify(files) !== JSON.stringify(expectedFiles)) {
  fail(
    'npm pack file list mismatch\n' +
    `expected:\n${expectedFiles.map((file) => `  ${file}`).join('\n')}\n` +
    `actual:\n${files.map((file) => `  ${file}`).join('\n')}`,
  );
}

const helper = pack.files.find((entry) => entry.path === 'bin/darwin-arm64/script-jail-vm');
if (helper.mode !== 0o755) {
  fail(`bin/darwin-arm64/script-jail-vm must be executable, got mode ${helper.mode}`);
}

if (typeof pack.size !== 'number' || pack.size > maxPackBytes) {
  fail(`npm pack size ${pack.size} exceeds limit ${maxPackBytes}`);
}

console.log(`npm packlist ok: ${files.length} files, ${formatBytes(pack.size)} packed`);

function fail(message) {
  console.error(message);
  process.exit(1);
}

function formatBytes(value) {
  return `${(value / (1024 * 1024)).toFixed(1)} MiB`;
}
