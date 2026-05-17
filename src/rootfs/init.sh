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
# /etc/script-jail/, prepend the host Node's bin/ to PATH, then exec the agent
# under that Node.

set -eu

mount -t proc proc /proc 2>/dev/null || true
mount -t sysfs sys /sys 2>/dev/null || true
mount -t tmpfs -o size=64m tmpfs /tmp 2>/dev/null || true
mount -t tmpfs -o size=16m tmpfs /root 2>/dev/null || true
# /dev is set up by the kernel device tree.

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

# --- eth0 (optional — only present when the host registered tap0/eth0) -------
# When the host passes `enableNetwork: true` (Phase A) the action creates a
# tap0 device on the host and registers it via Firecracker's
# `/network-interfaces/eth0`; the guest kernel then exposes it as `eth0`.
# Phase B leaves `enableNetwork: false`, in which case no eth0 exists here.
#
# We address eth0 statically because dhclient isn't in the rootfs (Dockerfile.base
# deliberately ships only busybox/strace/dumb-init/socat — adding ISC dhclient
# would pull in glibc-static and the entire init system).  The host-side NAT
# step in .github/workflows/e2e.yml uses 172.16.0.0/24 with the gateway at
# 172.16.0.1 (the runner's end of tap0), so the guest end gets .2.  The MAC
# matches the value `setupTapDevice` writes via the Firecracker API
# (06:00:AC:10:00:02) — that MAC is reverse-mapped to 172.16.0.2 by convention.
#
# DNS: GitHub-hosted runners forward 168.63.129.16 (Azure resolver), 1.1.1.1
# (Cloudflare) and 8.8.8.8 (Google).  The latter two are reachable directly;
# we don't need the Azure one inside the VM.  /etc/resolv.conf is written
# unconditionally because the rootfs image's stub may point at 127.0.0.53
# (systemd-resolved on the build host), which is meaningless inside the VM.
#
# All four commands tolerate failure (`|| true`): when eth0 is absent
# (Phase B-only test rig, missing /network-interfaces/eth0 on host), busybox
# prints "ifconfig: SIOCGIFFLAGS: No such device" and we continue with lo
# only.  Phase A will fail loudly downstream if it truly needed network.
busybox ifconfig eth0 172.16.0.2 netmask 255.255.255.0 up 2>/dev/null || true
busybox route add default gw 172.16.0.1 2>/dev/null || true
printf 'nameserver 1.1.1.1\nnameserver 8.8.8.8\n' > /etc/resolv.conf
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
  echo "[init] FATAL: no block device with filesystem label 'repo'" >&2
  exit 1
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
  echo "[init] FATAL: /work/etc/script-jail/config.yml not staged by host overlay" >&2
  exit 1
fi
cp /work/etc/script-jail/config.yml /etc/script-jail/config.yml

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
mkdir -p /tmp/script-jail-strace

# Hand off to the orchestrator under dumb-init.  dumb-init becomes PID 1 and
# reaps the two children (the agent and socat); orchestrate.sh is responsible
# for the startup ordering — start agent first, wait until its TCP listener
# is bound, THEN start socat, so the AF_VSOCK port doesn't accept a host
# connection before the agent's TCP target exists (see Task #14).
exec dumb-init /sbin/orchestrate
