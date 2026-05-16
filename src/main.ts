// Action entry point. Wired in action.yml as `runs.main: dist/main.js`.
// Implementation lands in task #9; this stub keeps `tsc --noEmit` green.

async function main(): Promise<void> {
  throw new Error('npm-jar: not yet implemented');
}

main().catch((err: unknown) => {
  process.stderr.write(`${err instanceof Error ? err.stack ?? err.message : String(err)}\n`);
  process.exit(1);
});
