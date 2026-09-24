# Performance

## Goals (V1)

| Metric | Goal | Measured (dev VM, 4 vCPU, release build) |
|---|---|---|
| Overhead on **unmonitored** processes | < 5 % | Within noise: 4.3–4.9 µs vs 4.3–4.7 µs per `open`+`read`+`close` |
| Overhead on the **monitored** agent, syscall-heavy | < 50 % per hooked syscall trio; negligible for typical agents | 4.5 → ~6.0 µs per `open`+`read`+`close` (+~1.5 µs); `fork`+`exec` of `/bin/true` 1.15 → ~1.2 ms |
| Userspace throughput | ≥ 100k events/s | Engine + session + store: ~280k events/s single-threaded (`engine_bench`); end-to-end, including ring drain, decode and symlink resolution: ~120k events/s sustained |
| Dropped events at realistic agent rates | 0 | 0 drops for 100k file opens at ~170k opens/s (burst); drops begin with sustained floods above ~60k opens/s |
| Monitor memory | < 100 MB | ~14 MB anonymous + ~38 MB file-backed idle (mostly the 16 MB ring buffer, double-mapped); ~59 MB peak RSS under flood |
| Monitor CPU | proportional to agent activity | 0.9 CPU-s for 100k opens + 200 execs |
| Alert latency | < 100 ms from syscall to alert | Poll timeout is 100 ms and results are paired within 250 ms. Observed alerts appear within ~0.1–0.3 s |

## How to reproduce

```sh
cargo build --release
sudo bench/bench.sh 100000 200      # N file opens, N execs
cargo run --release -p killline-core --example engine_bench 200000
```

`bench/bench.sh` runs the workload (`bench/workload.py`) three times:

1. with no monitor;
2. as a **bystander** while Kill Line monitors an idle process, which shows the cost to the rest of the system;
3. as the **monitored agent** under `killline run --user 65534`.

It reports per-operation latency, events recorded, drops, final status, monitor CPU seconds and peak RSS.

## Where the cost is

- **Kernel:** each hooked syscall runs a tracepoint program: one map lookup for untracked tasks, which is why bystanders see nothing. Tracked tasks additionally write a 616-byte entry record and a 32-byte result record.
- **Userspace, before optimisation:** the engine re-normalised every pattern on every match (8.3 µs/event), and symlink resolution did ~4 `lstat` calls per open. That caused drops at 100k opens. Precompiled pattern sets (1.6 µs/event), a buffered timeline, and a 1 s per-process cache for intermediate directories (the final path component is always checked) removed the drops at that level.

## Known headroom

- Variable-size records (most events don't need the 256-byte `path2`).
- A separate drain/decode thread, so the kernel ring is emptied while the engine works.
- In-kernel aggregation of repetitive allowed runtime reads.
- A configurable ring-buffer size.

If an agent floods faster than Kill Line can record, Kill Line **says so** (GREY, drop count). With `response.on_degraded: freeze`, it also stops the agent instead of losing visibility silently.
