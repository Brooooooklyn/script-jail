# npm-jar

Firecracker-sandboxed audit of package-manager lifecycle scripts. Designed to make the kind of supply-chain attacks that hit `chalk`/`debug` (Sep 2025) and Shai-Hulud (Nov 2025) visible at PR-review time.

## What it does

When `package-lock.json` / `pnpm-lock.yaml` / `yarn.lock` changes, the GitHub Action re-runs the install inside a Firecracker microVM with a minimal rootfs (no `gcc`, no `python`, no `$HOME`, no credentials). Inside the VM, `strace` + a tiny `LD_PRELOAD` shim record every file read/write that escapes a package's own directory, every env-var the install reads, every `execve` attempt, every `dlopen` attempt, and every network connection. The result is a deterministic, human-readable `.npm-jar.lock.yml` that's diffed against the committed copy — when the audit changes, the PR fails with a unified diff.

## Status

Pre-alpha. Project skeleton only. See [the design plan](./docs/design.md) (TODO) for details.

## Why a microVM

A pure-JS install sandbox can't close every gap: bun ignores `NODE_OPTIONS=--require`, `dlopen`/`execve` reach the kernel before any JS hook, and libuv-backed env reads sidestep a `process.env` Proxy. The kernel is the only honest boundary.
