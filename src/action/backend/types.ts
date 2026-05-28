import type { Backend } from '../inputs.js';
import type { RunnerImage } from '../runner-image.js';
import type { ArtifactManifest, ArtifactArch } from '../pre-fetch-artifacts.js';
import type { HttpClient } from '../firecracker/download.js';
import type {
  AuditExecutionInput,
  LauncherResult,
} from '../../shared/run-audit.js';

export type RequestedBackend = Backend;
export type ConcreteBackend = Exclude<Backend, 'auto'>;

export class BackendUnavailableError extends Error {
  readonly backend: ConcreteBackend;

  constructor(backend: ConcreteBackend, message: string) {
    super(message);
    this.name = 'BackendUnavailableError';
    this.backend = backend;
  }
}

export interface BackendContext extends AuditExecutionInput {
  imagesDir: string;
  runnerImage: RunnerImage;
  arch: ArtifactArch;
  manifest: ArtifactManifest;
  http: HttpClient;
  selfTest: boolean;
}

export interface AuditBackend {
  readonly name: ConcreteBackend;
  run(ctx: BackendContext): Promise<LauncherResult>;
}
