#!/bin/sh
# PID 1 inside the Firecracker microVM.
# Responsibilities: mount /proc, /sys, /dev, /tmp, /root (tmpfs so $HOME is empty),
# bring up the agent over vsock, wait for it to exit, halt.

set -eu

mount -t proc proc /proc 2>/dev/null || true
mount -t sysfs sys /sys 2>/dev/null || true
mount -t tmpfs -o size=64m tmpfs /tmp 2>/dev/null || true
mount -t tmpfs -o size=16m tmpfs /root 2>/dev/null || true
# /dev is set up by the kernel device tree

# Loopback is brought up by the Firecracker kernel driver before PID 1
# starts; no userspace setup needed. iproute2/net-tools are deliberately
# omitted to keep the rootfs small.

# Create the strace output directory the agent always uses for Phase B
mkdir -p /tmp/npm-jar-strace

# Exec the agent via dumb-init so signals are forwarded and orphans are reaped
exec dumb-init node /usr/local/bin/agent
