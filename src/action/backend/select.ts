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

export async function runSelectedBackend(input: {
  requested: RequestedBackend;
  backends: BackendMap;
  ctx: BackendContext;
  warn: (msg: string) => void;
}): Promise<LauncherResult> {
  const order = input.requested === 'auto'
    ? AUTO_ORDER
    : [input.requested];
  const unavailable: string[] = [];

  for (const name of order) {
    try {
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
