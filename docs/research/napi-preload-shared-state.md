# N-API Addon and LD_PRELOAD Shared State

Date: 2026-05-26

## Question

If `libscriptjail.so` is both loaded by the dynamic linker with
`LD_PRELOAD=/lib/libscriptjail.so` and later loaded by Node as a N-API addon,
can both views of the library share the same in-process static state?

## Temporary Probe

The verification was intentionally kept out of the repo test suite and run from
`/tmp/script-jail-napi-preload-probe`.

The probe builds one shared object that is both:

- an ELF `LD_PRELOAD` library with a constructor.
- a Node N-API addon exporting `getState()`.

The constructor checks `SCRIPT_JAIL_DUAL_PRELOAD_TOKEN=from-preload` and writes
the result into static storage. The Node process deletes that env var before
`require()` and then reads the static state through the addon export.

Commands:

```bash
docker run --rm \
  -v /tmp/script-jail-napi-preload-probe:/probe \
  -w /probe \
  node:24-bookworm \
  /probe/run-probe.sh

docker run --rm --platform linux/amd64 \
  -v /tmp/script-jail-napi-preload-probe:/probe \
  -w /probe \
  node:24-bookworm \
  /probe/run-probe.sh
```

Observed results:

```text
node=v24.16.0 linux arm64
{"constructorRan":1,"sawPreloadToken":true}

node=v24.16.0 linux x64
{"constructorRan":1,"sawPreloadToken":true}
```

## Conclusion

Yes, for the same process and same shared object, Node's addon load can observe
static state that was initialized when the object was loaded through
`LD_PRELOAD`. The constructor ran once, and the N-API export saw the
preload-time value after the JS process had removed the env var.

This test verifies the ELF loader / Node addon behavior with a C N-API addon.
NAPI-RS ultimately emits a native Node addon using the same loader path, so this
is enough to validate the state-sharing premise. A production implementation
should still ensure Node loads the same DSO path/inode that was preloaded.

## Script-jail Caveats

The default sandbox now leaves native addons enabled: `buildChildEnv()` injects
the active `platform-spoof.cjs` and `env-spy.cjs` preloads, but does not add
`--no-addons` and does not load `dlopen-block.cjs`. That makes a production
startup signal through a trusted N-API view of `libscriptjail.so` viable, as
long as Node loads the same shared-object path/inode that the dynamic linker
preloaded.

This does not by itself make arbitrary native code safe. The shim hides
protected names from libc `getenv` / `secure_getenv`, but native addon code can
still inspect or mutate the live `environ` array directly unless a future design
scrubs protected entries out of the process environment or moves the audit
channel behind a stronger isolation boundary.

The current production filter does not skip all startup reads in the shim.
Instead, it records Node's own bootstrap reads and package-manager client reads
as baselines, then drops matching unprotected noise from the rendered lockfile.
Protected env names are still hidden and audited.

Current production control flow:

1. `buildChildEnv()` injects `LD_PRELOAD=/lib/libscriptjail.so`,
   `SCRIPT_JAIL_NODE_OPTIONS`, and `NODE_OPTIONS` with
   `--require=/usr/local/lib/script-jail/platform-spoof.cjs` and
   `--require=/usr/local/lib/script-jail/env-spy.cjs`. It does not inject
   `--no-addons` or `dlopen-block.cjs`.
2. `env-spy.cjs` installs the `process.env` Proxy, emits JS-level env-read
   audit events for unprotected reads, and sets/deletes
   `SCRIPT_JAIL_NODE_STARTUP_DONE` after the preload has finished installing.
3. The shim's `setenv` / `putenv` wrappers consume that marker and emit a
   `node_startup_done` JSONL event without leaving the marker in the child env.
4. The install phase combines the marker with strace file-read markers to learn
   Node bootstrap file/env reads for each spawned Node process.
5. The renderer filters matching unprotected Node bootstrap reads and
   npm/yarn/pnpm client reads before writing the lockfile. Protected reads are
   still rendered, and native lifecycle executable divergence is not hidden.

## Design Implication

A N-API callback from the same `.so` would be a stronger in-process startup
barrier than an env-marker side channel, because it would flip state from inside
the preloaded library's own static storage. The current implementation does not
need that stronger barrier because bootstrap reads are learned and filtered
later, but the N-API approach remains viable if we need a more precise
"Node preload installed" signal. With native addons enabled by default, the
remaining production questions are how to guarantee the addon path matches the
preloaded `.so`, and whether protected env entries should be scrubbed from
`environ` before untrusted native lifecycle code runs.
