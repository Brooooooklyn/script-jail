// Type declarations for the canonical package-manifest spec module
// `scripts/npm-packages.mjs` (PKG-1). The runtime module is plain ESM JS so it
// can be `node`-imported by the release scripts without a build step; this
// declaration file lets the strict-mode TS consumers (the PKG-1 test and the
// Phase 4 filename-contract test) type the result.

/** One artifact copied (or gzipped) into a package's staging dir. */
export interface NpmArtifact {
  /** Source path relative to the assemble `--artifacts` dir. */
  src: string;
  /** Destination basename inside the staged package. */
  dest: string;
  /** When true, stream `src` through gzip into `dest`; otherwise copy. */
  gzip?: boolean;
  /** File mode applied to `dest` (e.g. 0o755 for the VZ helper). */
  mode?: number;
}

/** One published npm package in the cross-platform split. */
export interface NpmPackageSpec {
  /** Published npm name, e.g. `script-jail` or `@script-jail/linux-x64`. */
  name: string;
  /** Sanitized staging-dir name (also the release publish-loop iterand). */
  dir: string;
  /**
   * The exact `package.json` written into the staging dir. Typed loosely
   * because the manifest shape is intentionally dynamic per package.
   */
  packageJson: Record<string, any>;
  /** Artifacts to materialize alongside the manifest. */
  artifacts: NpmArtifact[];
  /** Per-package `npm pack` size cap in bytes. */
  maxPackBytes: number;
}

/**
 * The default preloads shipped by the main package, enumerated explicitly so
 * the packlist gate can detect a missing one. Basenames under `dist/preloads/`.
 */
export const MAIN_PRELOADS: string[];

/**
 * The canonical 4-package source of truth, with `version` threaded into every
 * package's `version` and the main package's `optionalDependencies` ranges.
 */
export function npmPackages(version: string): NpmPackageSpec[];
