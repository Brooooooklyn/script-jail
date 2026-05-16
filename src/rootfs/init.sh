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

# Bring up loopback for vsock
ip link set lo up 2>/dev/null || ifconfig lo up 2>/dev/null || true

# Create the strace output directory the agent always uses for Phase B
mkdir -p /tmp/npm-jar-strace

# Exec the agent via node (the agent bundle has no shebang; node is PID 2)
exec node /usr/local/bin/agent
