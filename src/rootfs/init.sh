#!/bin/sh
# PID 1 inside the microVM (Firecracker on Linux, Apple VZ on macOS).
#
# Two virtio drives are attached by the host (see src/action/firecracker/launch.ts):
#   rootfs       — this filesystem, already mounted by the kernel as /
#   repo disk    — filesystem label `repo`, mounted read-write at /work
#
# The repo drive is looked up by filesystem label via `blkid -L repo`.  The
# kernel may assign different /dev/vd* letters depending on the host's drive
# registration order, so the device path is NOT stable — only the label is.
# `mkfs.ext4 -L repo` is applied at host-side disk build time (see
# src/action/firecracker/overlay.ts).
#
# The Node toolchain is NOT shipped as a drive.  The rootfs bakes the
# standalone `vp` (vite-plus) binary; this script runs `vp env install`
# during Phase A (network on) to download a real Linux Node toolchain, then
# `corepack enable` for pnpm / yarn.  See the toolchain block below.
#
# Responsibilities: mount /proc /sys /tmp /root, mount the repo filesystem,
# copy the user's config into the rootfs's canonical /etc/script-jail/,
# provision the Node toolchain and prepend its bin/ to PATH, then exec the
# agent under that Node.

set -eu

# fatal MESSAGE… — print to stderr and power the VM off cleanly.
#
# A bare `exit 1` from PID 1 makes the kernel `panic ... Attempted to kill
# init`; with `panic=1 reboot=k` on the cmdline that panics-and-reboots in a
# tight loop, drowning the real error in an endless boot spew.  `poweroff -f`
# issues the power-off reboot syscall directly, so the host runner (Firecracker
# or VZ) sees a clean shutdown and the FATAL line stays the last thing printed.
fatal() {
  echo "[init] FATAL: $*" >&2
  busybox poweroff -f 2>/dev/null || true
  # poweroff -f should not return; spin so we never fall through to an
  # implicit `exit`, which would re-arm the panic-reboot path.
  while :; do busybox sleep 1; done
}

mount -t proc proc /proc 2>/dev/null || true
mount -t sysfs sys /sys 2>/dev/null || true
mount -t tmpfs -o size=64m tmpfs /tmp 2>/dev/null || true
mount -t tmpfs -o size=16m tmpfs /root 2>/dev/null || true
# /dev is set up by the kernel device tree.

# --- Wall clock --------------------------------------------------------------
# A fresh microVM has no battery-backed RTC and no NTP sync.  Apple VZ guests
# boot at the Unix epoch (1970-01-01); a 1970 clock makes every TLS handshake
# fail certificate validation ("certificate not yet valid"), so Phase A's
# `vp env install` and `pnpm fetch` HTTPS downloads all fail.  The host bakes
# its own wall-clock time into the kernel cmdline as `sj_epoch=<unix-seconds>`
# (src/cli/index.ts); apply it before the first network fetch.  Firecracker
# does not pass the marker, so absence is normal — degrade silently.
SJ_EPOCH=''
for tok in $(cat /proc/cmdline); do
  case "${tok}" in
    sj_epoch=*) SJ_EPOCH="${tok#sj_epoch=}" ;;
  esac
done
if [ -n "${SJ_EPOCH}" ]; then
  date -s "@${SJ_EPOCH}" >/dev/null 2>&1 || busybox date -s "@${SJ_EPOCH}" >/dev/null 2>&1 || true
  echo "[init] wall clock set from host epoch ${SJ_EPOCH}: $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
fi

# --- Scrub host->guest cmdline markers from the environment ------------------
# The Linux kernel hands any `key=value` boot-cmdline token it does not itself
# recognise to PID 1 as an environment variable (init/main.c collects them
# into envp_init[]).  Our three VZ markers — sj_epoch, sj_net, sj_vsock — are
# therefore present in this script's environment and would otherwise be
# inherited all the way down to the audited lifecycle scripts, where npm/pnpm
# enumerate `process.env` and the env-spy preload records every visible var as
# an `env_read`.  Firecracker's cmdline carries no such markers, so leaving
# them set desyncs the macOS lockfile from the CI one.  init.sh and
# orchestrate.sh read these markers from /proc/cmdline, never from the
# environment, so dropping the env copies is safe.
unset sj_epoch sj_net sj_vsock

# Bring up the loopback interface. The kernel creates `lo` in DOWN state;
# without an explicit `up` here the agent's listener on 127.0.0.1:10243
# binds successfully but no traffic actually flows. socat's TCP forwarder
# inside `orchestrate.sh` then fails with `connect(...): Network is
# unreachable` and the host sees only "vsock session ended without a
# final frame".  We use busybox's `ifconfig` applet since the rootfs
# deliberately omits iproute2 / net-tools (Dockerfile.base) to keep the
# image small.  Failure is fatal — without loopback the agent cannot
# accept its single control connection.
busybox ifconfig lo 127.0.0.1 netmask 255.0.0.0 up
busybox ifconfig lo

# --- eth0 (optional — only present when the host registered a NIC) -----------
# Phase A boots with networking so `vp env install` can fetch the Node
# toolchain; Phase B boots with no NIC at all.  The two host VMMs wire eth0
# up differently, so the guest picks its addressing from a `/proc/cmdline`
# marker the host bakes into the kernel command line:
#
#   sj_net=dhcp   — Apple VZ (src/cli/index.ts).  VZ's `VZNATNetworkDevice`
#                   runs its own DHCP server on a subnet it chooses itself
#                   (typically 192.168.64.0/24); the gateway/DNS are not
#                   knowable ahead of time, so the guest MUST DHCP.
#   (absent)      — Firecracker (the GitHub Action).  The e2e NAT step uses a
#                   fixed 172.16.0.0/24 with the gateway at 172.16.0.1, so the
#                   guest takes the static .2 — matching the 06:00:AC:10:00:02
#                   MAC `setupTapDevice` registers via the Firecracker API.
#
# dhclient isn't in the rootfs (Dockerfile.base ships only busybox/strace/
# dumb-init/socat to keep the image small); busybox's `udhcpc` applet does the
# DHCP handshake instead.  udhcpc has no built-in lease-apply logic — it shells
# out to a `-s` script on every state change — and the rootfs has no
# /usr/share/udhcpc/default.script, so we write a minimal one to /tmp.
#
# /etc/resolv.conf is (re)written unconditionally: the rootfs image's stub may
# point at 127.0.0.53 (systemd-resolved on the build host), meaningless here.
if grep -q 'sj_net=dhcp' /proc/cmdline 2>/dev/null; then
  cat > /tmp/udhcpc.script <<'EOF'
#!/bin/sh
# busybox udhcpc lease-apply hook. $1 is the event; lease fields arrive as env.
case "$1" in
  deconfig)
    busybox ifconfig "$interface" 0.0.0.0
    ;;
  bound|renew)
    busybox ifconfig "$interface" "$ip" netmask "${subnet:-255.255.255.0}"
    if [ -n "${router:-}" ]; then
      busybox route add default gw "$router" dev "$interface" 2>/dev/null || true
    fi
    : > /etc/resolv.conf
    for d in ${dns:-}; do
      printf 'nameserver %s\n' "$d" >> /etc/resolv.conf
    done
    ;;
esac
EOF
  chmod +x /tmp/udhcpc.script
  # -i eth0 iface, -s script, -q quit once a lease is bound, -f foreground (so
  # we block here until eth0 is configured), -n exit if no lease, -t/-T retry
  # budget.  Fatal on failure: Phase A cannot fetch the toolchain without it.
  if ! busybox udhcpc -i eth0 -s /tmp/udhcpc.script -q -f -n -t 10 -T 3; then
    fatal "udhcpc could not obtain a DHCP lease on eth0 (VZ NAT)"
  fi
  # VZ NAT does serve DNS, but append public resolvers as a belt-and-braces
  # fallback in case the lease carried none.
  printf 'nameserver 1.1.1.1\nnameserver 8.8.8.8\n' >> /etc/resolv.conf
else
  # Firecracker: static addressing.  Tolerate failure (`|| true`) — when eth0
  # is absent (Phase B), busybox prints "SIOCGIFFLAGS: No such device" and we
  # continue with lo only; Phase A fails loudly downstream if it needed net.
  busybox ifconfig eth0 172.16.0.2 netmask 255.255.255.0 up 2>/dev/null || true
  busybox route add default gw 172.16.0.1 2>/dev/null || true
  printf 'nameserver 1.1.1.1\nnameserver 8.8.8.8\n' > /etc/resolv.conf
fi
busybox ifconfig eth0 2>/dev/null || true

# --- Repo disk (filesystem label `repo`) --------------------------------------
# The host always registers the repo drive when running through the action.
# Mount it read-only at /work; the guest agent reads the user's repo from here.
#
# We resolve the device by label via `blkid -L` rather than hard-coding
# /dev/vdb: with PID 1 = this script there is no udev to populate
# /dev/disk/by-label/, and the drive-letter assigned by the kernel depends on
# Firecracker's drive registration order (which is not part of the public
# contract).  `/usr/sbin/blkid` ships in the Ubuntu base image as part of
# util-linux; busybox's own `blkid` applet would NOT work here as it does not
# support the `-L` shortcut.
mkdir -p /work
# `blkid -L <label>` exits non-zero when no device matches.  Under `set -e`
# (which we want for every OTHER command in this script), a bare
# `REPO_DEV="$(blkid -L repo)"` would abort the script at the assignment
# itself — before our friendly FATAL line can run — because dash propagates
# the command-substitution's non-zero status to the assignment.  Wrap the
# call in `if; then; else` so the non-zero branch is handled explicitly.
if REPO_DEV="$(blkid -L repo)" && [ -n "${REPO_DEV}" ]; then
  # Mount read-write: Phase A (`npm ci` / `pnpm fetch` / `yarn install`)
  # populates a node_modules tree under /work, and Phase B then runs the
  # lifecycle scripts against it.  A read-only mount makes npm fail with
  # `ENOENT mkdir '/work/node_modules'` — the audit cannot proceed.
  #
  # Modifying the disk in-place is safe: overlay.ts builds a FRESH repo.ext4
  # per VM run and the host destroys it during teardown (see
  # src/action/firecracker/teardown.ts).  Any writes the in-VM tooling makes
  # are scratch — they never touch the user's checkout on the host.
  mount "${REPO_DEV}" /work
else
  fatal "no block device with filesystem label 'repo'"
fi

# --- Scratch disk (filesystem label `scratch`, REQUIRED) ----------------------
# VM backends (Firecracker, Apple VZ) attach a third virtio drive labelled
# `scratch` (empty ext4, 4096 MiB) for the agent's bulk audit artifacts: the
# per-pid `strace -ff` logs and the audit-events JSONL.  Both historically
# lived on the 64 MB /tmp tmpfs above, which a large repo overflows (ENOSPC
# partway through Phase B — a ~1000-package yarn-berry monorepo produces
# hundreds of MB of strace text alone), truncating the audit.
#
# The drive is REQUIRED, exactly like the repo disk above: this init.sh only
# runs inside a VM, and the host that boots this rootfs ships in lock-step
# with it (the action/CLI pins the rootfs by manifest SHA from its own
# release, and every VM launcher in that release attaches the scratch
# drive).  A missing or unmountable scratch device therefore always means a
# bug — and silently degrading to /tmp would reintroduce the exact silent
# ENOSPC truncation this disk exists to prevent (Codex review 2026-06-12,
# round-1 high finding).  The Docker/bare backends never execute init.sh, so
# fail-closed here cannot affect them; their agent falls back to /tmp via the
# unset SCRIPT_JAIL_SCRATCH_DIR.
#
# Resolution mirrors the repo-disk lookup: by label via `blkid -L`, never by
# /dev/vd* letter, with the same `if`-wrapping so `set -e` doesn't swallow
# the diagnostic on the absent-device non-zero exit.
#
# SCRIPT_JAIL_SCRATCH_DIR tells the agent (src/guest/agent.ts,
# scratchBaseDir()) where to put the events file + strace logs.  The variable
# is agent-internal: it is deliberately NOT in the agent's
# LIFECYCLE_ALLOWED_SCRIPT_JAIL_ENV_NAMES allow-list, so it is stripped from
# every audited lifecycle child's env — backends with and without the scratch
# disk present byte-identical child environments.
if SCRATCH_DEV="$(blkid -L scratch)" && [ -n "${SCRATCH_DEV}" ]; then
  mkdir -p /scratch
  mount "${SCRATCH_DEV}" /scratch
  export SCRIPT_JAIL_SCRATCH_DIR=/scratch
  echo "[init] scratch disk mounted at /scratch (${SCRATCH_DEV})"
else
  fatal "no block device with filesystem label 'scratch'"
fi
SCRATCH_BASE=/scratch

# Copy the user's config from the repo disk into the rootfs's canonical
# /etc/script-jail/config.yml so the agent can read it regardless of /work staying
# mounted.  overlay.ts stages the config at /work/etc/script-jail/config.yml.
#
# Fail fast if the host overlay didn't stage it: the agent has no useful
# behaviour without a config, and a clear FATAL line is far easier to debug
# than the downstream YAML/parse errors we'd otherwise see.
mkdir -p /etc/script-jail
if [ ! -f /work/etc/script-jail/config.yml ]; then
  fatal "/work/etc/script-jail/config.yml not staged by host overlay"
fi
cp /work/etc/script-jail/config.yml /etc/script-jail/config.yml

# pm-flags.json is OPTIONAL. The normal same-arch parity path does not stage
# it, so absence is normal — degrade silently and let `loadPmFlags()` in the
# guest default to "no extra args".
if [ -f /work/etc/script-jail/pm-flags.json ]; then
  cp /work/etc/script-jail/pm-flags.json /etc/script-jail/pm-flags.json
fi

# pnpm-arch.json is OPTIONAL. The guest (src/guest/apply-pnpm-arch.ts) merges
# its `supportedArchitectures` block into the repo's root package.json before
# Phase A when present. Absence is normal — degrade silently to "no merge".
if [ -f /work/etc/script-jail/pnpm-arch.json ]; then
  cp /work/etc/script-jail/pnpm-arch.json /etc/script-jail/pnpm-arch.json
fi

# --- Node toolchain (vite-plus) ----------------------------------------------
# The rootfs bakes the standalone `vp` binary (see Dockerfile.base).  While
# Phase A still has network, `vp env install` downloads the pinned Node
# toolchain into VP_HOME; corepack (bundled with that Node) then provides
# pnpm / yarn honouring each repo's `packageManager` field.  Phase B reuses
# the warm VP_HOME + corepack cache offline.
#
# VP_HOME lives on the read-write rootfs at /opt/vp — NOT the 16 MB /root
# tmpfs, and NOT the audited /work repo disk.  The ~200 MB Node download is
# why the rootfs ext4 is sized at 1 GB (see src/rootfs/build.ts).
export VP_HOME=/opt/vp
export COREPACK_HOME=/opt/vp/corepack
export COREPACK_ENABLE_DOWNLOAD_PROMPT=0

if [ ! -f /etc/script-jail/node-version ]; then
  fatal "/etc/script-jail/node-version not baked into rootfs"
fi
NODE_VERSION="$(cat /etc/script-jail/node-version)"
echo "[init] vp env install ${NODE_VERSION}"
if ! vp env install "${NODE_VERSION}"; then
  fatal "'vp env install ${NODE_VERSION}' failed (Phase A network down?)"
fi

# vp lays the toolchain out as the standard Node tarball tree under
# /opt/vp/js_runtime/node/<version>/.  Discover the bin/ directory rather
# than hard-coding the version path (robust against vp version bumps).
NODE_BIN="$(find /opt/vp/js_runtime -maxdepth 4 -type d -name bin 2>/dev/null | head -n1)"
if [ -z "${NODE_BIN}" ] || [ ! -x "${NODE_BIN}/node" ]; then
  fatal "vp produced no Node toolchain under /opt/vp/js_runtime"
fi
export PATH="${NODE_BIN}:${PATH:-/usr/local/bin:/usr/bin:/bin}"

# corepack enable writes pnpm/yarn/npx shims into NODE_BIN (already on PATH),
# so the guest agent's bare `pnpm` / `yarn` invocations resolve transparently
# to the version pinned by each repo's `packageManager` field.
corepack enable

# Strace output directory used by phase B — on the scratch disk when the host
# attached one (see the scratch block above), else the /tmp tmpfs fallback.
# Must match the agent's `${scratchBaseDir()}/script-jail-strace` wiring in
# src/guest/agent.ts main().
mkdir -p "${SCRATCH_BASE}/script-jail-strace"

# Hand off to the orchestrator under dumb-init.  dumb-init becomes PID 1 and
# reaps the two children (the agent and socat); orchestrate.sh is responsible
# for the startup ordering — start agent first, wait until its TCP listener
# is bound, THEN start socat, so the AF_VSOCK port doesn't accept a host
# connection before the agent's TCP target exists (see Task #14).
exec dumb-init /sbin/orchestrate
