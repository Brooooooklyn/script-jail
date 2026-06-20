import type { LauncherResult } from '../../shared/run-audit.js';
import type {
  AuditBackend,
  BackendContext,
  ConcreteBackend,
  RequestedBackend,
} from './types.js';
import { BackendUnavailableError } from './types.js';

export type BackendMap = Readonly<Record<ConcreteBackend, AuditBackend>>;

const AUTO_ORDER: ReadonlyArray<ConcreteBackend> = ['firecracker', 'docker', 'bare'];

/**
 * Backends whose AUDIT runs at the SAME absolute path as the host `repoDir`:
 * Firecracker (`mount --move` the repo disk to repoDir) and Docker (`-v
 * staged:${repoDir}`). `install: true` REQUIRES one of these.
 *
 * SECURITY (Codex re-review, bare-backend staged-symlink escape): the `bare`
 * backend audits in a TEMPORARY staged copy at a path that differs from repoDir.
 * `cpSync(..., dereference:false)` rewrites a committed RELATIVE symlink to an
 * ABSOLUTE target in the ORIGINAL checkout, so the audit resolves it to ENOENT
 * (and the read is dropped) while host part-2 (cwd=repoDir, real checkout, after
 * host part-1 created the target) resolves and EXECUTES it — un-audited code while
 * the lock says trusted. Only repoDir-aligned backends make the staged tree
 * resolve identically to the host. This is an ALLOWLIST (not a `bare` denylist) so
 * a FUTURE backend is fail-closed by default until proven repoDir-aligned.
 */
export const INSTALL_ALIGNED_BACKENDS: ReadonlySet<ConcreteBackend> = new Set<ConcreteBackend>([
  'firecracker',
  'docker',
]);

export async function runSelectedBackend(input: {
  requested: RequestedBackend;
  backends: BackendMap;
  ctx: BackendContext;
  warn: (msg: string) => void;
  /**
   * When true (`install: true`), restrict selection to {@link INSTALL_ALIGNED_BACKENDS}:
   * `auto` drops `bare` from the order, and an explicit non-aligned backend throws.
   * Backstops the pre-audit reject in main.ts so host lifecycle scripts can never
   * run after a non-repoDir-aligned audit.
   */
  requireRepoDirAligned?: boolean;
  /**
   * Invoked with the CONCRETE backend actually selected, immediately before it
   * runs.  `install: true` uses this to make the host re-run's env match the
   * AUDITING backend (e.g. the Firecracker guest exports `TMPDIR=/sjtmp` while
   * Docker exports none — the host TMPDIR-presence must match whichever audited,
   * or a lifecycle script reading `process.env.TMPDIR` becomes a value-blind
   * benign-in-audit / evil-on-host oracle).
   */
  onBackendSelected?: (name: ConcreteBackend) => void;
}): Promise<LauncherResult> {
  const aligned = input.requireRepoDirAligned === true;
  if (
    aligned &&
    input.requested !== 'auto' &&
    !INSTALL_ALIGNED_BACKENDS.has(input.requested)
  ) {
    throw new Error(
      `script-jail: \`install: true\` requires a repoDir-aligned backend ` +
        `(firecracker or docker); the "${input.requested}" backend audits in a ` +
        `temporary staged copy and cannot safely re-run host lifecycle scripts.`,
    );
  }
  const baseOrder = input.requested === 'auto' ? AUTO_ORDER : [input.requested];
  const order = aligned
    ? baseOrder.filter((b) => INSTALL_ALIGNED_BACKENDS.has(b))
    : baseOrder;
  const unavailable: string[] = [];

  for (const name of order) {
    try {
      input.onBackendSelected?.(name);
      return await input.backends[name].run(input.ctx);
    } catch (err) {
      if (err instanceof BackendUnavailableError) {
        if (input.requested !== 'auto') throw err;
        unavailable.push(`${name}: ${err.message}`);
        input.warn(`script-jail backend "${name}" unavailable: ${err.message}`);
        continue;
      }
      throw err;
    }
  }

  throw new Error(
    `script-jail: no audit backend available. Tried ${order.join(', ')}. ` +
      unavailable.join('; '),
  );
}
