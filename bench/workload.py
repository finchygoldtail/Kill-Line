"""Syscall-heavy synthetic workload for KillLine overhead measurement.
Harmless: opens/reads small local files, stats, and spawns `true`."""
import os, subprocess, sys, time

d = sys.argv[1]
n_open = int(sys.argv[2]) if len(sys.argv) > 2 else 100000
n_exec = int(sys.argv[3]) if len(sys.argv) > 3 else 200
os.makedirs(d, exist_ok=True)
for i in range(100):
    p = os.path.join(d, f"f{i}")
    if not os.path.exists(p):
        with open(p, "w") as f:
            f.write("x" * 64)
t0 = time.perf_counter()
for i in range(n_open):
    with open(os.path.join(d, f"f{i % 100}"), "rb") as f:
        f.read()
t1 = time.perf_counter()
for i in range(n_exec):
    subprocess.run(["/bin/true"])
t2 = time.perf_counter()
print(f"open_read_close_us={(t1 - t0) / n_open * 1e6:.2f} exec_ms={(t2 - t1) / n_exec * 1e3:.3f}")
