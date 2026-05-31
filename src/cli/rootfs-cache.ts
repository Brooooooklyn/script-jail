// script-jail — src/cli/rootfs-cache.ts
//
// The npm package ships the macOS arm64 rootfs as .ext4.gz. Packing the raw
// sparse ext4 keeps download size small but expands to a real ~1 GB file on
// npm install. We instead materialize a sparse ext4 in the user's cache on
// first run.

import {
  closeSync,
  existsSync,
  ftruncateSync,
  mkdirSync,
  openSync,
  readFileSync,
  renameSync,
  rmSync,
  statSync,
  writeFileSync,
  writeSync,
  createReadStream,
} from 'node:fs';
import { createHash } from 'node:crypto';
import { homedir, tmpdir } from 'node:os';
import { basename, dirname, join } from 'node:path';
import { createGunzip } from 'node:zlib';

export interface EnsureRootfsInput {
  rootfsPath: string;
  compressedRootfsPath: string;
  cacheDir?: string;
}

interface RootfsCacheMeta {
  compressedSha256: string;
  logicalSize: number;
}

export async function ensureRootfs(input: EnsureRootfsInput): Promise<string> {
  if (existsSync(input.rootfsPath)) return input.rootfsPath;
  if (!existsSync(input.compressedRootfsPath)) return input.rootfsPath;

  const cacheDir = input.cacheDir ?? defaultCacheDir();
  mkdirSync(cacheDir, { recursive: true });

  const digest = await sha256File(input.compressedRootfsPath);
  const ext4Name = basename(input.rootfsPath);
  const cached = join(cacheDir, `${stripExt4Suffix(ext4Name)}-${digest.slice(0, 16)}.ext4`);
  const metaPath = `${cached}.json`;
  if (isReusableCachedRootfs(cached, metaPath, digest)) return cached;
  rmSync(cached, { force: true });
  rmSync(metaPath, { force: true });

  const tmp = join(cacheDir, `.${basename(cached)}.${process.pid}.${Date.now()}.tmp`);
  const tmpMeta = `${tmp}.json`;
  try {
    const logicalSize = await sparseGunzip(input.compressedRootfsPath, tmp);
    writeFileSync(
      tmpMeta,
      JSON.stringify({ compressedSha256: digest, logicalSize } satisfies RootfsCacheMeta, null, 2) + '\n',
    );
    renameSync(tmp, cached);
    renameSync(tmpMeta, metaPath);
  } catch (err) {
    rmSync(tmp, { force: true });
    rmSync(tmpMeta, { force: true });
    throw err;
  }
  return cached;
}

function defaultCacheDir(): string {
  const override = process.env['SCRIPT_JAIL_CACHE_DIR'];
  if (override !== undefined && override !== '') return override;
  const home = homedir();
  if (home !== '') return join(home, 'Library', 'Caches', 'script-jail');
  return join(tmpdir(), 'script-jail-cache');
}

async function sha256File(path: string): Promise<string> {
  const hash = createHash('sha256');
  for await (const chunk of createReadStream(path)) {
    hash.update(chunk as Buffer);
  }
  return hash.digest('hex');
}

async function sparseGunzip(source: string, dest: string): Promise<number> {
  mkdirSync(dirname(dest), { recursive: true });
  const fd = openSync(dest, 'w', 0o644);
  let offset = 0;
  try {
    const stream = createReadStream(source, { highWaterMark: 1024 * 1024 }).pipe(createGunzip());
    for await (const chunk of stream) {
      const buf = chunk as Buffer;
      writeNonZeroRanges(fd, buf, offset);
      offset += buf.length;
    }
    ftruncateSync(fd, offset);
  } finally {
    closeSync(fd);
  }
  // Force a stat while the temp path still exists; this catches failed writes
  // before rename and keeps the returned error tied to materialization.
  statSync(dest);
  return offset;
}

function writeNonZeroRanges(fd: number, buf: Buffer, baseOffset: number): void {
  let start = -1;
  for (let i = 0; i < buf.length; i++) {
    if (buf[i] !== 0) {
      if (start === -1) start = i;
      continue;
    }
    if (start !== -1) {
      writeSync(fd, buf, start, i - start, baseOffset + start);
      start = -1;
    }
  }
  if (start !== -1) {
    writeSync(fd, buf, start, buf.length - start, baseOffset + start);
  }
}

function stripExt4Suffix(name: string): string {
  return name.endsWith('.ext4') ? name.slice(0, -'.ext4'.length) : name;
}

function isReusableCachedRootfs(cached: string, metaPath: string, digest: string): boolean {
  if (!existsSync(cached) || !existsSync(metaPath)) return false;
  const meta = readCacheMeta(metaPath);
  if (meta === undefined) return false;
  if (meta.compressedSha256 !== digest) return false;
  if (!Number.isSafeInteger(meta.logicalSize) || meta.logicalSize < 0) return false;
  return statSync(cached).size === meta.logicalSize;
}

function readCacheMeta(path: string): RootfsCacheMeta | undefined {
  try {
    const parsed = JSON.parse(readFileSync(path, 'utf8')) as Record<string, unknown>;
    const { compressedSha256, logicalSize } = parsed;
    if (typeof compressedSha256 !== 'string' || typeof logicalSize !== 'number') return undefined;
    return { compressedSha256, logicalSize };
  } catch {
    return undefined;
  }
}
