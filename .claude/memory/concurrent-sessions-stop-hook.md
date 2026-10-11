---
name: concurrent-sessions-stop-hook
description: "Two Claude sessions in the same pixi-sbom working tree make their Stop hooks' `pixi run ci` runs kill each other's test binaries"
metadata:
  type: project
---

The Stop hook (.claude/hooks/stop-ci.sh) runs `pixi run ci` in the shared working tree and `target/llvm-cov-target`. When two sessions finish at about the same time, the runs collide: test binaries get SIGKILL or a NotFoundError for target/llvm-cov-target/debug/pixi-sbom, and dozens of tests fail at once. Seen on 2026-10-09 (41 failures).

Another session's uncommitted or in-progress work in the shared tree also makes the hook fail in a session that changed nothing (the 1.8.2 what's-new section failed tests/cli.rs the_whats_new_page_covers_every_release_since_1_0 until CHANGELOG had the release).

**Why:** both sessions use one checkout and one target dir.

**How to apply:** on a sudden mass failure, check `pgrep -f "cargo-llvm-cov llvm-cov"` and `ListAgents` before debugging; wait for the other run and rerun alone. If the other session keeps restarting its hook (seen 2026-10-10: three SIGKILLs in a row), give your run its own coverage dir: `CARGO_LLVM_COV_TARGET_DIR=$PWD/target/llvm-cov-<issue> pixi run ci` passes cleanly alongside it. Never edit another session's uncommitted files to make the hook pass. Related: [[issue-delivery-loop]].
