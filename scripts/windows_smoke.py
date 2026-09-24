"""Kill Line Windows smoke test (run as Administrator, e.g. on a CI runner).

Runs the harmless test agent under `killline run` and checks that the ETW
sensor reports each boundary. Every target is local or reserved:
  * a fake secret created here, a missing ~/.ssh/id_rsa;
  * a TCP listener this script starts on 127.0.0.1;
  * DNS for `killline-test.invalid` (RFC 6761);
  * the Docker named pipe (normally absent);
  * `cmd` and `whoami` as the "unexpected programs".

Usage: python scripts/windows_smoke.py path\\to\\killline.exe
"""
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time

# Kill Line prints UTF-8 (box drawing, em dashes); Windows defaults to cp1252.
for stream in (sys.stdout, sys.stderr):
    try:
        stream.reconfigure(encoding="utf-8", errors="replace")
    except AttributeError:
        pass

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
KL = os.path.abspath(sys.argv[1] if len(sys.argv) > 1 else os.path.join(ROOT, "target", "release", "killline.exe"))
AGENT = os.path.join(ROOT, "test-agent", "test_agent.py")

work = r"C:\agent"
secrets = r"C:\agent-secrets"
home = tempfile.mkdtemp(prefix="killline-home-")
for d in [work, secrets]:
    shutil.rmtree(d, ignore_errors=True)
os.makedirs(os.path.join(work, "src"))
os.makedirs(os.path.join(work, "output"))
os.makedirs(os.path.join(work, "untrusted"))
with open(os.path.join(work, "task.md"), "w") as f:
    f.write("# Task\nSummarise src/.\n")
with open(os.path.join(work, "src", "source.py"), "w") as f:
    f.write("def add(a, b):\n    return a + b\n")
with open(os.path.join(work, "untrusted", "README.md"), "w") as f:
    f.write("Untrusted document (no real instructions).\n")
os.makedirs(secrets)
with open(os.path.join(secrets, "api-key.txt"), "w") as f:
    f.write("FAKE-KEY-NOT-REAL\n")

py_home = os.path.dirname(sys.executable)
# Python probes its install's parent folders (pyvenv.cfg, Modules\Setup.local).
py_root = os.path.dirname(os.path.dirname(sys.base_prefix))
policy = f"""
agent: test-agent
name: windows-smoke
filesystem:
  allow_read:
    - {work}
    - {os.path.dirname(AGENT)}
    - {sys.base_prefix}
    - {py_home}
    - {py_root}
  allow_write:
    - {work}\\output
    - ~/AppData/Local/Temp
network:
  mode: deny
processes:
  allow: [python, python3, py]
  deny: [cmd, powershell, pwsh]
credentials:
  access: deny
  extra_paths: [{secrets}]
untrusted_inputs: [{work}\\untrusted]
"""
policy_path = os.path.join(home, "policy.yaml")
with open(policy_path, "w") as f:
    f.write(policy)

# A local listener for the completed-connection check.
srv = socket.socket()
srv.bind(("127.0.0.1", 0))
srv.listen(8)
port = srv.getsockname()[1]


def accept_loop():
    while True:
        try:
            c, _ = srv.accept()
            c.close()
        except OSError:
            return


threading.Thread(target=accept_loop, daemon=True).start()

env = dict(os.environ, KILLLINE_HOME=home, KL_WORKSPACE=work, KL_FAKE_SECRET=os.path.join(secrets, "api-key.txt"),
           KL_LOCAL_PORT=str(port), KL_PAUSE="1.5", PYTHONDONTWRITEBYTECODE="1",
           PYTHONNOUSERSITE="1")


def run(modes):
    print(f"\n=== killline run -- test_agent.py {' '.join(modes)}", flush=True)
    t0 = time.time()
    p = subprocess.run([KL, "--no-color", "run", "--policy", policy_path, "--", sys.executable, AGENT, *modes],
                       env=env, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=300)
    print(p.stdout[-6000:])
    probe = [l for l in p.stderr.splitlines() if l.startswith("[etw-probe]")]
    other = [l for l in p.stderr.splitlines() if not l.startswith("[etw-probe]")]
    if other:
        print("stderr:", "\n".join(other[-40:]))
    interesting = [l for l in probe if any(k in l.lower() for k in ("pipe", "docker", "network", "dns", "process"))]
    print(f"--- {len(probe)} probe lines; {len(interesting)} about pipes/network/dns/processes:")
    for l in interesting[:120]:
        print(l)
    print(f"exit={p.returncode} in {time.time() - t0:.1f}s", flush=True)
    tl = subprocess.run([KL, "--no-color", "timeline", "--json"], env=env, capture_output=True, text=True,
                        encoding="utf-8", errors="replace")
    events = [json.loads(l)["event"] for l in tl.stdout.splitlines() if l.strip()]
    return p.returncode, events


def violations(events):
    return [e for e in events if e["verdict"] == "violation" and not e.get("confirms_seq")]


failures = []


def check(name, ok, detail=""):
    print(f"[{'PASS' if ok else 'FAIL'}] {name} {detail}")
    if not ok:
        failures.append(name)


# 1. Legitimate work.
code, events = run(["normal"])
v = violations(events)
for e in v:
    print("   violation:", e["action"], "|", e["explanation"][:200])
check("normal work stays GREEN", code == 0 and not v, f"(exit {code}, {len(v)} violations)")
check("process start observed", any(e["action"] == "process.exec" for e in events))
check("workspace file reads observed", any("/c:/agent/task.md" in json.dumps(e.get("observation", {})) for e in events))

# 2. Boundary crossings.
code, events = run(["sensitive-file", "spawn", "docker-socket", "dns", "local-connect", "network"])
v = violations(events)
by_action = {}
for e in v:
    by_action.setdefault(e["action"], []).append(e)
    print("   violation:", e["category"], e["action"], "|", e["explanation"][:160])
check("exit code is RED (10)", code == 10, f"(exit {code})")
check("credential file", any(e["category"] == "credential" and "agent-secrets" in e["explanation"] for e in v))
check("cmd.exe denied", "process.exec_denied" in by_action)
check("whoami unexpected", "process.exec_unexpected" in by_action)
check("docker named pipe", any(e["category"] == "container_runtime" for e in v))
check("dns query", any(e["category"] == "dns" and "killline-test.invalid" in e["explanation"] for e in v))
check("local tcp connection", any(e["action"] == "net.localhost" and f":{port}" in e["explanation"] for e in v))
got_testnet = any("203.0.113.42" in e["explanation"] for e in v)
print(f"[INFO] TCP attempt to unroutable 203.0.113.42 {'seen' if got_testnet else 'not seen (known V1 gap: attempts that never complete)'}")

# 3. Integrity.
sessions = os.listdir(os.path.join(home, "sessions"))
for s in sessions:
    r = subprocess.run([KL, "--no-color", "verify", s], env=env, capture_output=True, text=True,
                       encoding="utf-8", errors="replace")
    check(f"hash chain {s}", r.returncode == 0, r.stdout.strip())
inc = subprocess.run([KL, "--no-color", "incidents"], env=env, capture_output=True, text=True,
                     encoding="utf-8", errors="replace")
print(inc.stdout)

print("\nKILLLINE_HOME:", home)
if failures:
    print("FAILED:", ", ".join(failures))
    sys.exit(1)
print("ALL CHECKS PASSED")
