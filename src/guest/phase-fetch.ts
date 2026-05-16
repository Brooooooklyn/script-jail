// npm-jar — phase-fetch.ts
// Phase A: fetch packages with network ON.
//
// Per-manager command notes:
//   npm: `npm ci --ignore-scripts`
//     npm has no clean "fetch-only" command. We run `npm ci --ignore-scripts`
//     which downloads packages into node_modules but skips lifecycle scripts.
//     Phase B will then run `npm rebuild --foreground-scripts` to execute
//     scripts against the already-populated node_modules under strace with
//     network disabled. This two-step gymnastics is necessary because:
//       - npm pack/install always merges fetch+install into one command.
//       - --ignore-scripts suppresses scripts in phase A so we can audit
//         them separately in the offline phase B.
//
//   pnpm: `pnpm fetch`
//     Fetches tarballs to the store without linking. Clean separation.
//
//   yarn: `yarn install --immutable --mode=skip-build`
//     Fetches and links packages but skips lifecycle script execution.
//     Phase B runs `yarn install --immutable --offline` which re-links and
//     triggers scripts (or yarn rebuild if needed).

export interface Spawner {
  spawn(
    cmd: string,
    args: string[],
    opts: { env: NodeJS.ProcessEnv; cwd: string },
  ): Promise<{ exitCode: number; stdout: string; stderr: string }>;
}

export interface PhaseFetchInput {
  manager: 'npm' | 'pnpm' | 'yarn';
  cwd: string;
  env: NodeJS.ProcessEnv;
  spawner: Spawner;
}

const FETCH_CMD: Record<'npm' | 'pnpm' | 'yarn', { cmd: string; args: string[] }> = {
  npm:  { cmd: 'npm',  args: ['ci', '--ignore-scripts'] },
  pnpm: { cmd: 'pnpm', args: ['fetch'] },
  yarn: { cmd: 'yarn', args: ['install', '--immutable', '--mode=skip-build'] },
};

export async function runFetchPhase(
  input: PhaseFetchInput,
): Promise<{ ok: boolean; stderr: string }> {
  const { cmd, args } = FETCH_CMD[input.manager];

  const result = await input.spawner.spawn(cmd, args, {
    env: input.env,
    cwd: input.cwd,
  });

  return {
    ok: result.exitCode === 0,
    stderr: result.stderr,
  };
}
