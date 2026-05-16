#!/bin/sh
# Cleanup script invoked by the orchestrator before reboot.
# Unmounts tmpfs entries created by init.sh.

set -eu

umount /root 2>/dev/null || true
umount /tmp  2>/dev/null || true
umount /sys  2>/dev/null || true
umount /proc 2>/dev/null || true
