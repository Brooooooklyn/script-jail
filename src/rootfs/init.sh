#!/bin/sh
# PID 1 inside the Firecracker microVM.
#
# Three virtio drives are attached by the host (see src/action/firecracker/launch.ts):
#   /dev/vda — rootfs       (this filesystem, already mounted by the kernel as /)
#   /dev/vdb — repo + config (label `repo`,      read-only)
#   /dev/vdc — host Node install (label `host-node`, read-only)
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

# --- Repo disk (/dev/vdb, label `repo`) ---------------------------------------
# The host always registers the repo drive when running through the action.
# Mount it read-only at /work; the guest agent reads the user's repo from here.
mkdir -p /work
mount -o ro /dev/vdb /work

# Copy the user's config from the repo disk into the rootfs's canonical
# /etc/npm-jar/config.yml so the agent can read it regardless of /work staying
# mounted.  overlay.ts stages the config at /work/etc/npm-jar/config.yml.
mkdir -p /etc/npm-jar
if [ -f /work/etc/npm-jar/config.yml ]; then
  cp /work/etc/npm-jar/config.yml /etc/npm-jar/config.yml
fi

# --- Host-Node disk (/dev/vdc, label `host-node`) -----------------------------
# Mount the runner's packed Node install read-only at /opt/host-node, then
# prepend its bin/ to PATH.  This makes `node`, `npm`, `corepack`, `pnpm`, and
# `yarn` (when present in the host install) resolve to the host-installed
# binaries.  The rootfs itself ships NO Node.
mkdir -p /opt/host-node
mount -o ro /dev/vdc /opt/host-node

export PATH="/opt/host-node/bin:${PATH:-/usr/local/bin:/usr/bin:/bin}"

# Strace output directory used by phase B.
mkdir -p /tmp/npm-jar-strace

# Exec the agent through dumb-init so signals propagate and orphans are reaped.
# `node` here is the host-mounted binary thanks to PATH; the agent path is
# absolute so it loads regardless of cwd.
exec dumb-init node /usr/local/lib/npm-jar/guest-agent.cjs
