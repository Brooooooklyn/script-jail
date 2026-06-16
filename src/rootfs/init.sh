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

# --- Guest-wide TMPDIR on a DEDICATED disk (not /work, not the audit /scratch) -
# yarn Berry's fetch step converts every downloaded tarball into a cache zip
# via a staging file in os.tmpdir() (ZipFS convertToZipWorker).  On the 64 MB
# /tmp tmpfs above, a real monorepo's parallel conversions ENOSPC partway
# through Phase A (napi-rs: ~488 MiB of zips against 64 MB).
#
# TMPDIR points at a SEPARATE 4 GiB ext4 (label `sjtmp`, built per-run by
# overlay.ts) mounted at /sjtmp — distinct from BOTH /work (the repo disk) and
# /scratch (the audit disk).  Why a dedicated disk rather than the earlier
# /work/.sj-tmp scheme (Codex rounds 1-4, 2026-06-12):
#   * NOT /scratch: /scratch holds the AUDIT artifacts (per-pid `strace -ff`
#     logs + the events JSONL, written only by the trusted agent/strace).  A
#     lifecycle script honours TMPDIR, so co-locating would let a malicious
#     script fill the disk and silently STARVE the audit writes (partial
#     capture presented as a clean lockfile).
#   * NOT /work: /work is built from the USER repo, so a committed `.sj-tmp`
#     symlink — or a Phase-A `rm -rf && ln -s` from repo-controlled code (the
#     yarnPath bundle / pnpmfile / Yarn plugins run during `yarn install`) —
#     could redirect TMPDIR onto /scratch (starve) or /work/node_modules (so
#     writes spelled `$TMPDIR/...` tokenize benignly yet land in real repo
#     content, hiding them).  Three rounds of point-in-time guards could not
#     close that TOCTOU because the trusted root itself was repo-mutable.
# A MOUNTPOINT closes it structurally: /sjtmp cannot be symlink-swapped without
# `umount`, and it has no committed repo content to subvert.  We make "no
# lifecycle child can umount" actually TRUE by dropping CAP_SYS_ADMIN from the
# bounding set before the agent hands off (see the setpriv exec at the end of
# this file) — so neither Phase-A nor Phase-B repo code can umount /sjtmp or
# `mount --bind` over it.  A TMPDIR fill on /sjtmp now only fails the install
# honestly with ENOSPC — it touches neither the repo nor the audit channel.
#
# Lockfile parity is preserved: the agent's tmp tokenize root follows
# os.tmpdir() (so /sjtmp renders $TMPDIR) and keeps the literal /tmp as a second
# $TMPDIR alias for tools that ignore TMPDIR (src/guest/agent.ts roots +
# src/lock/tokenize.ts tmpLegacy).
#
# Resolution mirrors the scratch lookup: by label via `blkid -L`, never by
# /dev/vd* letter, with the same `if`-wrapping so `set -e` doesn't swallow the
# diagnostic on the absent-device non-zero exit.  Fail closed when missing — a
# silent /tmp fallback would reintroduce the ENOSPC truncation this disk
# exists to prevent.  The Docker/bare backends never execute init.sh, so this
# cannot affect them; their agent falls back to /tmp (no TMPDIR export).
if SJTMP_DEV="$(blkid -L sjtmp)" && [ -n "${SJTMP_DEV}" ]; then
  mkdir -p /sjtmp
  mount "${SJTMP_DEV}" /sjtmp
  chmod 1777 /sjtmp
  export TMPDIR=/sjtmp
  echo "[init] sjtmp disk mounted at /sjtmp (${SJTMP_DEV}); TMPDIR=/sjtmp"
else
  fatal "no block device with filesystem label 'sjtmp'"
fi

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

# --- install:true cwd parity (relocate the repo mount to the host repoDir) ---
# For `install: true` the host re-runs lifecycle scripts on the UNINSTRUMENTED
# runner at the real checkout path (repoDir), while the audit ran at /work.  A
# dependency script can branch on `process.cwd()` (the getcwd syscall is NOT
# traced) — benign under /work, malicious on the host — and the byte-stable lock
# still matches.  The host pins the config `work_dir` to repoDir for that case;
# relocate the repo mount there so the audited cwd equals the host re-run's.
#
# Runs HERE on purpose: still root with CAP_SYS_ADMIN (the line ~413 setpriv
# drops sys_admin), and AFTER every /work read above (config/pm-flags/pnpm-arch
# are already copied to the fixed /etc paths).  `mount --move` (util-linux; the
# rootfs ships it — see the blkid -L use above) leaves no /work alias, so strace
# can only observe repo opens under repoDir = roots.repo → tokenized to $REPO.
# /scratch and /sjtmp are SIBLING mounts, untouched by moving /work.
#
# No-op for the default /work audit (work_dir absent or == /work).  On any
# relocate failure we FALL BACK to auditing at /work (rewrite work_dir) rather
# than break the run: the audit still happens; only the install:true cwd parity
# (defense-in-depth) is skipped for that run.  Both paths are byte-stable
# ($REPO either way).  The leading-anchor sed only matches a top-level key.
SJ_WD="$(sed -n 's/^work_dir:[[:space:]]*//p' /etc/script-jail/config.yml | head -n1)"
SJ_WD="${SJ_WD%\"}"; SJ_WD="${SJ_WD#\"}"; SJ_WD="${SJ_WD%\'}"; SJ_WD="${SJ_WD#\'}"
if [ -n "$SJ_WD" ] && [ "$SJ_WD" != "/work" ]; then
  case "$SJ_WD" in
    # Never relocate onto the FS root, a /work descendant, or a system mount
    # (would shatter the rootfs).  A real repoDir is always a nested checkout
    # path (e.g. /home/runner/work/x/x or /opt/actions-runner/_work/x/x), never
    # exactly one of these — so this guard never fires on a valid run.
    /|/work/*|/etc|/usr|/bin|/sbin|/lib|/lib64|/proc|/sys|/dev|/run|/var|/tmp|/opt|/root|/home|/scratch|/sjtmp)
      fatal "refusing to relocate repo mount onto unsafe work_dir '$SJ_WD'" ;;
    /*)
      sj_relocated=0
      if mkdir -p "$SJ_WD"; then
        # Clear shared propagation so MS_MOVE is permitted, then move.
        mount --make-private /work 2>/dev/null || true
        if mount --move /work "$SJ_WD" 2>/dev/null; then
          sj_relocated=1
        fi
      fi
      if [ "$sj_relocated" != "1" ]; then
        echo "[init] repo relocate to '$SJ_WD' failed; auditing at /work (install cwd parity skipped)" >&2
        sed -i 's|^work_dir:.*|work_dir: /work|' /etc/script-jail/config.yml \
          || fatal "could not reset work_dir to /work after a failed relocate"
      fi
      ;;
    *)
      fatal "work_dir '$SJ_WD' is not an absolute path" ;;
  esac
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

# --- Drop CAP_SYS_ADMIN before any repo-influenced code runs -----------------
# Everything past this exec — the agent, strace, and (load-bearing) the
# package-manager processes that execute REPO-CONTROLLED code (a repo's
# `yarnPath` bundle, `.pnpmfile.cjs`, Yarn plugins, and lifecycle scripts) —
# runs as root in this microVM.  A root process holding CAP_SYS_ADMIN can
# mount(2)/umount(2); without dropping it, a malicious Phase-A/Phase-B script
# could `umount /sjtmp` and then `mount --bind /scratch /sjtmp` (→ co-locate
# TMPDIR with the audit artifacts and STARVE the strace/event writes) or
# `mount --bind /work/node_modules /sjtmp` (→ make repo/node_modules mutations
# spelled `$TMPDIR/...` tokenize as the benign `$TMPDIR`, HIDING them from the
# audit).  That bind/umount vector is exactly what the dedicated `/sjtmp`
# mountpoint is meant to be immune to — but a mountpoint only resists redirect
# while no one can call umount.  So we make that true: drop CAP_SYS_ADMIN from
# the BOUNDING set here.  The bounding set is inherited by every descendant and
# can never be re-raised, and for a uid-0 process tree a root execve's permitted
# set is capped by the bounding set (capabilities(7)) — so the agent and ALL
# package-manager children lose CAP_SYS_ADMIN from their effective set and
# mount/umount return EPERM.  Every legitimate mount (/work, /scratch, /sjtmp,
# proc/sys) is already established above, and nothing downstream mounts, so this
# is safe.  CAP_SYS_PTRACE is left in place for strace -ff.  (Docker/bare
# backends never run init.sh; their isolation boundary is the container/host,
# and they use /tmp, not /sjtmp.)
#
# Fail closed if the tool is missing: silently skipping the drop would ship the
# false "mountpoint cannot be redirected" premise.  `blkid` (util-linux) is used
# above, so setpriv (also util-linux) is present in a well-formed rootfs.
if ! command -v setpriv >/dev/null 2>&1; then
  fatal "setpriv (util-linux) not found; refusing to hand off without dropping CAP_SYS_ADMIN"
fi

# Dropping CAP_SYS_ADMIN blocks mount(2)/umount(2) for the uid-0 process tree —
# but on a kernel with CONFIG_USER_NS=y (our VZ kernels are built that way, and
# the Firecracker kernel ships it too) repo code can `unshare(CLONE_NEWUSER|
# CLONE_NEWNS)` to gain CAP_SYS_ADMIN INSIDE a fresh namespace and `mount --bind`
# /scratch or /work/node_modules over /sjtmp there.  Bind mounts share the
# underlying superblock, so that namespace-local redirect still starves the
# audit (/scratch) or hides repo writes behind the benign $TMPDIR token —
# verified to survive a bare CAP_SYS_ADMIN drop (Codex round-7, 2026-06-12).
# Clamp new user-namespace creation to zero, for BOTH backends, independent of
# kernel config.  Done while still fully privileged; the matching
# CAP_SYS_RESOURCE drop at the handoff below stops any descendant from raising
# the limit back (a uid-0 child WITH cap_sys_resource can rewrite this knob).
# If the knob is absent the kernel has no user-namespace support, so the escape
# is already impossible — absence is safe, not fatal.
USERNS_MAX=/proc/sys/user/max_user_namespaces
if [ -e "${USERNS_MAX}" ]; then
  echo 0 > "${USERNS_MAX}" || fatal "could not clamp ${USERNS_MAX}"
  if [ "$(cat "${USERNS_MAX}")" != "0" ]; then
    fatal "failed to set ${USERNS_MAX}=0 (user namespaces still creatable)"
  fi
  echo "[init] user namespaces clamped (max_user_namespaces=0)"
fi

# Hand off to the orchestrator under dumb-init.  dumb-init becomes PID 1 and
# reaps the two children (the agent and socat); orchestrate.sh is responsible
# for the startup ordering — start agent first, wait until its TCP listener
# is bound, THEN start socat, so the AF_VSOCK port doesn't accept a host
# connection before the agent's TCP target exists (see Task #14).
# Drop CAP_SYS_ADMIN (blocks mount/umount) AND CAP_SYS_RESOURCE (so the
# max_user_namespaces clamp above cannot be raised back by a uid-0 descendant).
# NB: setpriv (util-linux/libcap-ng) names capabilities WITHOUT the `cap_`
# prefix — `-sys_admin,-sys_resource`, not `-cap_*` (that errors "unknown
# capability" and, being fail-closed, would abort every boot).  Verified against
# ubuntu:24.04: this clears exactly CapBnd/CapEff bits 21+24, retains
# CAP_SYS_PTRACE for strace, and makes mount/umount, `unshare -Urm`, and
# rewriting the userns clamp all fail.
exec setpriv --bounding-set=-sys_admin,-sys_resource dumb-init /sbin/orchestrate
