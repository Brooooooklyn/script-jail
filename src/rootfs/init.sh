#!/bin/sh
# PID 1 inside the Firecracker microVM.
#
# Three virtio drives are attached by the host (see src/action/firecracker/launch.ts):
#   rootfs       — this filesystem, already mounted by the kernel as /
#   repo disk    — filesystem label `repo`,      read-only, mounted at /work
#   host-node    — filesystem label `host-node`, read-only, mounted at /opt/host-node
#
# Drives are looked up by filesystem label via `blkid -L <label>`.  The kernel
# may assign different /dev/vd* letters depending on Firecracker's drive
# registration order (and which drives the caller chose to register), so the
# device path is NOT stable.  Only the labels are.  `mkfs.ext4 -L <label>` is
# applied at host-side disk build time (see src/action/firecracker/overlay.ts).
#
# Responsibilities: mount /proc /sys /tmp /root, mount the two auxiliary
# filesystems, copy the user's config into the rootfs's canonical
# /etc/npm-jar/, prepend the host Node's bin/ to PATH, then exec the agent
# under that Node.

set -eu

mount -t proc proc /proc 2>/dev/null || true
mount -t sysfs sys /sys 2>/dev/null || true
mount -t tmpfs -o size=64m tmpfs /tmp 2>/dev/null || true
mount -t tmpfs -o size=16m tmpfs /root 2>/dev/null || true
# /dev is set up by the kernel device tree.

# Loopback is brought up by the Firecracker kernel driver before PID 1
# starts; no userspace setup needed. iproute2/net-tools are deliberately
# omitted to keep the rootfs small.

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
  mount -o ro "${REPO_DEV}" /work
else
  echo "[init] FATAL: no block device with filesystem label 'repo'" >&2
  exit 1
fi

# Copy the user's config from the repo disk into the rootfs's canonical
# /etc/npm-jar/config.yml so the agent can read it regardless of /work staying
# mounted.  overlay.ts stages the config at /work/etc/npm-jar/config.yml.
#
# Fail fast if the host overlay didn't stage it: the agent has no useful
# behaviour without a config, and a clear FATAL line is far easier to debug
# than the downstream YAML/parse errors we'd otherwise see.
mkdir -p /etc/npm-jar
if [ ! -f /work/etc/npm-jar/config.yml ]; then
  echo "[init] FATAL: /work/etc/npm-jar/config.yml not staged by host overlay" >&2
  exit 1
fi
cp /work/etc/npm-jar/config.yml /etc/npm-jar/config.yml

# --- Host-Node disk (filesystem label `host-node`) ----------------------------
# Mount the runner's packed Node install read-only at /opt/host-node, then
# prepend its bin/ to PATH.  This makes `node`, `npm`, `corepack`, `pnpm`, and
# `yarn` (when present in the host install) resolve to the host-installed
# binaries.  The rootfs itself ships NO Node.
#
# Same label-lookup rationale as the repo disk above.
mkdir -p /opt/host-node
# Same `set -e` + command-substitution caveat as the repo disk; see comment
# above the `blkid -L repo` block for the rationale on the if/then/else form.
if HOST_NODE_DEV="$(blkid -L host-node)" && [ -n "${HOST_NODE_DEV}" ]; then
  mount -o ro "${HOST_NODE_DEV}" /opt/host-node
else
  echo "[init] FATAL: no block device with filesystem label 'host-node'" >&2
  exit 1
fi

export PATH="/opt/host-node/bin:${PATH:-/usr/local/bin:/usr/bin:/bin}"

# Strace output directory used by phase B.
mkdir -p /tmp/npm-jar-strace

# Exec the agent through dumb-init so signals propagate and orphans are reaped.
# `node` here is the host-mounted binary thanks to PATH; the agent path is
# absolute so it loads regardless of cwd.
exec dumb-init node /usr/local/lib/npm-jar/guest-agent.cjs
