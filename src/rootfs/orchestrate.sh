#!/bin/sh
# Orchestrates the guest agent and the AF_VSOCK <-> TCP bridge inside the
# Firecracker microVM.  Invoked by /sbin/init via `exec dumb-init /sbin/orchestrate`
# so that dumb-init runs as PID 1 and reaps both children.
#
# Startup ordering (see Task #14 review):
#   1. Start the agent (Node TCP listener on 127.0.0.1:10243) in the background.
#   2. Poll /proc/net/tcp until that listener is in the LISTEN state.
#   3. Only THEN start socat, which binds AF_VSOCK port 10242 and forwards
#      everything it accepts to 127.0.0.1:10243.
#   4. Wait on the agent; its exit becomes this script's exit, which becomes
#      dumb-init's exit, which terminates the VM.
#
# Order matters: if socat binds AF_VSOCK 10242 BEFORE the agent binds TCP 10243,
# the host's "CONNECT 10242\n" arrives and socat accepts the vsock leg but its
# TCP leg fails with ECONNREFUSED, closing the single control session before
# the agent is ready to see it.

set -eu

AGENT_PID=""
SOCAT_PID=""

cleanup() {
  if [ -n "${SOCAT_PID:-}" ]; then kill "${SOCAT_PID}" 2>/dev/null || true; fi
  if [ -n "${AGENT_PID:-}" ]; then kill "${AGENT_PID}" 2>/dev/null || true; fi
}
trap cleanup TERM INT

# 1. Start the agent.  `node` resolves through PATH to the vite-plus-
#    provisioned toolchain under /opt/vp, which init.sh prepended.
node /usr/local/lib/script-jail/guest-agent.cjs &
AGENT_PID=$!

# 2. Wait for the TCP listener on 127.0.0.1:10243 to appear in /proc/net/tcp.
#    The local-address column is "0100007F:2803" (127.0.0.1 in little-endian
#    hex, port 10243 = 0x2803) when bound; the state column is "0A" (LISTEN).
#    Poll for up to ~2 seconds (200 iterations x 10ms) — far longer than Node's
#    actual bind latency, but bounded so a wedged agent doesn't hang init.
i=0
while [ "${i}" -lt 200 ]; do
  if grep -q ' 0100007F:2803 [0-9A-F:]* 0A ' /proc/net/tcp 2>/dev/null; then
    break
  fi
  # If the agent died before binding, abort immediately with its exit code.
  if ! kill -0 "${AGENT_PID}" 2>/dev/null; then
    wait "${AGENT_PID}" || true
    echo "[orchestrate] FATAL: agent exited before binding TCP 10243" >&2
    exit 1
  fi
  sleep 0.01
  i=$((i + 1))
done
if [ "${i}" -ge 200 ]; then
  echo "[orchestrate] FATAL: agent did not bind TCP 127.0.0.1:10243 within 2s" >&2
  cleanup
  exit 1
fi

# 3. Start the AF_VSOCK <-> TCP bridge.
#
# The two host VMMs drive vsock in OPPOSITE directions:
#   Firecracker — the host VMM connects IN to a guest listener, so socat must
#     LISTEN on AF_VSOCK port 10242.  `fork` allows repeated host connects;
#     `reuseaddr` avoids TIME_WAIT refusal across relaunches in one VM life.
#   Apple VZ   — the host registers a VZVirtioSocketListener and waits for the
#     guest to connect OUT (see src/host-mac/src/vsock.rs), so socat must
#     CONNECT to the host's well-known CID 2 on port 10242.  If socat LISTENs
#     under VZ, both ends listen and the single control session never opens.
# The host bakes `sj_vsock=connect` into the kernel cmdline for the VZ path
# (src/cli/index.ts); its absence means Firecracker.
if grep -q 'sj_vsock=connect' /proc/cmdline 2>/dev/null; then
  socat VSOCK-CONNECT:2:10242 TCP:127.0.0.1:10243 &
else
  socat VSOCK-LISTEN:10242,fork,reuseaddr TCP:127.0.0.1:10243 &
fi
SOCAT_PID=$!

# Verify socat actually started — bad syntax, missing binary, kernel AF_VSOCK
# refusal, or (VZ connect path) a host listener that is not up would have it
# exit immediately.  socat binds/connects synchronously in its main thread
# before forking, so a 50ms liveness check is sufficient.
sleep 0.05
if ! kill -0 "${SOCAT_PID}" 2>/dev/null; then
  wait "${SOCAT_PID}" 2>/dev/null || true
  echo "[orchestrate] FATAL: socat AF_VSOCK<->TCP bridge failed to start" >&2
  kill "${AGENT_PID}" 2>/dev/null || true
  exit 1
fi

# 4. Wait on the agent; cleanup the bridge on exit.
#    `set -e` would abort on a non-zero wait status, skipping cleanup and the
#    explicit exit below; the `|| AGENT_STATUS=$?` suppresses that so we always
#    run cleanup and propagate the agent's exit code.
AGENT_STATUS=0
wait "${AGENT_PID}" || AGENT_STATUS=$?
# Make the agent's exit code visible on ttyS0 (the host's [fc:out] stream).
# Without this echo a non-zero agent exit produces only the eventual kernel
# panic ("Attempted to kill init! exitcode=…") on PID 1's exit — which is
# hard to map back to which guest component failed.  Cheap to emit, pays
# for itself the next time the agent dies before sending a final frame.
echo "[orchestrate] agent exited with status ${AGENT_STATUS}" >&2
cleanup
exit "${AGENT_STATUS}"
