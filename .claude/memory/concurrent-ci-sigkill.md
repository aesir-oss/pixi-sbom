---
name: concurrent-ci-sigkill
description: "Overlapping `pixi run ci` runs (mine + the stop hook) SIGKILL each other's test binaries on macOS; not a test failure"
metadata:
  type: project
---

`pixi run ci` failing with `process didn't exit successfully ... (signal: 9, SIGKILL: kill)` on a test or bench binary, with no test reported failing, means two CI runs overlapped. Both use `target/llvm-cov-target`; when one rebuilds a test binary while the other is executing it, macOS kills the running process because its code signature no longer matches the file. Seen 2026-10-09: a CI run of mine was backgrounded and the Stop hook (`.claude/hooks/stop-ci.sh`) started a second.

A second variant: `NotFoundError { path: ".../target/llvm-cov-target/debug/pixi-sbom" }` in tests/matrix.rs, the other run having cleaned the binary away. The other run can belong to a *different Claude session* in the same working tree: each session's Stop hook runs `pixi run ci` against the shared `target/` (seen 2026-10-09 with session pixi-sbom-76; find the owner with `ps -o ppid=` up to the `claude` process).

**Why:** it looks like a flaky test and invites a pointless "fix".

**How to apply:** check `pgrep -f "cargo-llvm-cov llvm-cov"`; wait for the other run to finish, then run the gate alone. Never run `pixi run ci` in the background while a turn may end (the hook will start another). Related: [[issue-delivery-loop]].
