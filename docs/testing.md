# Testing

## Vitest projects

Configured in `vitest.config.ts`. Each project has its own pattern and timeout.

| Project | Pattern | Timeout | What it covers |
| --- | --- | --- | --- |
| `unit` | `test/**/*.test.ts` (excl. guest/integration/e2e) | default | Host modules: inputs parsing, package-manager detection, diff canonicalization, caching, runner-image detection. |
| `guest` | `test/guest/**/*.test.ts` | long | Guest modules in isolation: `env-spy`, legacy `dlopen-block`, `strace-parser`, `protected-paths`, attribution, agent orchestration, emit, phase fetch/install. Uses fakes for vsock and spawn. |
| `integration` | `test/integration/**/*.test.ts` | long | Pure-JS pipeline: normalize + render against canned event streams from `test/fixtures/`. No VM. |
| `e2e` | `test/e2e/**/*.test.ts` | shortest, but slow | Boots a real Firecracker VM. Asserts attack markers appear, then asserts `mode=check` fails on tampered lockfiles. Requires `/dev/kvm`. |

Run a single project with `pnpm test:guest` / `pnpm test:integration` / `pnpm test:e2e`. `pnpm test` runs unit + guest + integration (no VM); e2e is gated behind its own command and the dedicated CI workflow.

## Fixtures

`test/fixtures/<scenario>/` each pin one attack pattern. Current scenarios:

- `reads-home-ssh/` — install script tries to exfiltrate `~/.ssh/`.
- `reads-secret-env/` — reads protected env vars like `NPM_TOKEN`.
- `spawns-gcc/` — execs a compiler that isn't present in the rootfs.
- `tries-dlopen/` — calls `process.dlopen` at install time; default policy should not block native-addon loading.
- `tries-network-egress/` — opens a TCP connection from the lifecycle script.
- `writes-into-repo/` — modifies files outside the package's own directory.
- `cross-package-tampering/` + `victim-package/` — one package writes into another's `node_modules` tree.

Each fixture has `package.json`, the lifecycle script, and `expected-events.json` (the golden event stream). Goldens are regenerated, not hand-edited:

```bash
oxnode scripts/build-e2e-golden.ts
```

The integration project consumes the goldens through the normalize/render pipeline; the e2e project replays them through a real VM.

## Test harness

`test/e2e/harness.ts` provides `FakeVsockSession` and `FakeSpawner` so guest code can be exercised in unit tests without a VM. When writing new guest modules, prefer adding to `test/guest/` with these fakes before reaching for e2e.

## e2e requirements

The `e2e.yml` workflow sets up the environment locally; reproducing it on a developer machine needs:

- Linux host with `/dev/kvm` accessible.
- A tap interface (`tap0`) and NAT, for Phase A network reachability.
- Firecracker + kernel artifacts (downloaded automatically via the artifact manifest).
- The rootfs built locally (`pnpm build` with the appropriate `--runner-image`).

If you're on macOS, run `pnpm test` only. e2e is CI-only from there.

## Adding a new attack fixture

1. Create `test/fixtures/<name>/` with `package.json` and the lifecycle script.
2. Add a brief description here in the fixtures list.
3. Run the golden generator above.
4. Add an e2e assertion in `test/e2e/generate.test.ts` for any new markers.
