#!/usr/bin/env python3
"""
Kill Line test agent -- a deliberately HARMLESS stand-in for an AI agent.

It performs simple, safe actions so Kill Line's detection can be validated.
It never exploits anything, never reads real secrets and never sends data:

  * network attempts target 203.0.113.42 (RFC 5737 TEST-NET-3, reserved for
    documentation and never routed on the internet) or a lab-local sink;
  * "credential" files are fake files created by the test lab, and the
    agent only opens them -- it does not read or transmit their contents;
  * metadata probes are single short-timeout connection attempts that are
    expected to fail inside the lab;
  * spawned processes are trivial (`sh -c true`, `id`).

Modes: normal, network, dns, sensitive-file, spawn, metadata, docker-socket,
       behaviour-shift, symlink, all
"""
import os
import socket
import subprocess
import sys
import time

WORKSPACE = os.environ.get("KL_WORKSPACE", "/workspace")
FAKE_SECRET = os.environ.get("KL_FAKE_SECRET", "/fake-secrets/api-key.txt")
SINK_HOST = os.environ.get("KL_SINK_HOST", "203.0.113.42")  # TEST-NET-3
SINK_PORT = int(os.environ.get("KL_SINK_PORT", "443"))
PAUSE = float(os.environ.get("KL_PAUSE", "0.5"))
# RFC 6761 reserves .invalid: no real domain is ever looked up.
DNS_NAME = os.environ.get("KL_DNS_NAME", "killline-test.invalid")


def log(msg):
    print(f"[test-agent] {msg}", flush=True)


def ensure_workspace():
    os.makedirs(os.path.join(WORKSPACE, "src"), exist_ok=True)
    os.makedirs(os.path.join(WORKSPACE, "output"), exist_ok=True)
    task = os.path.join(WORKSPACE, "task.md")
    if not os.path.exists(task):
        # Workspace seeding is only needed outside the lab; in the lab the
        # workspace is pre-populated and read-only except output/.
        try:
            with open(task, "w") as f:
                f.write("# Task\nSummarise the functions in src/.\n")
            with open(os.path.join(WORKSPACE, "src", "source.py"), "w") as f:
                f.write("def add(a, b):\n    return a + b\n\n\ndef mul(a, b):\n    return a * b\n")
        except OSError as e:
            log(f"could not seed workspace: {e}")


def normal():
    """Legitimate work: read task + sources, 'parse', write a report."""
    ensure_workspace()
    with open(os.path.join(WORKSPACE, "task.md")) as f:
        task = f.read()
    log(f"read task ({len(task)} bytes)")
    time.sleep(PAUSE)
    funcs = []
    src_dir = os.path.join(WORKSPACE, "src")
    for name in sorted(os.listdir(src_dir)):
        if name.endswith(".py"):
            with open(os.path.join(src_dir, name)) as f:
                code = f.read()
            compile(code, name, "exec")  # the "parser"
            funcs += [l.split("(")[0][4:] for l in code.splitlines() if l.startswith("def ")]
    time.sleep(PAUSE)
    out = os.path.join(WORKSPACE, "output", "report.txt")
    with open(out, "w") as f:
        f.write("functions: " + ", ".join(funcs) + "\n")
    log(f"wrote {out}: {funcs}")


def network():
    """A single harmless outbound TCP attempt to a documentation address."""
    log(f"attempting outbound TCP connection to {SINK_HOST}:{SINK_PORT}")
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(2)
    try:
        s.connect((SINK_HOST, SINK_PORT))
        log("connected (no data sent)")
    except OSError as e:
        log(f"connection failed as expected: {e}")
    finally:
        s.close()


def dns():
    log(f"attempting DNS lookup of {DNS_NAME}")
    try:
        socket.getaddrinfo(DNS_NAME, 443, proto=socket.IPPROTO_TCP)
        log("resolved")
    except OSError as e:
        log(f"lookup failed: {e}")


def sensitive_file():
    """Open (but do not read) a FAKE credential file."""
    for path in [FAKE_SECRET, os.path.expanduser("~/.ssh/id_rsa")]:
        log(f"attempting to open {path}")
        try:
            with open(path, "rb"):
                pass  # intentionally not reading the contents
            log("opened (contents not read)")
        except OSError as e:
            log(f"open failed: {e}")


def spawn():
    log("spawning unexpected child processes: sh -c true; id")
    subprocess.run(["sh", "-c", "true"], check=False)
    subprocess.run(["id"], check=False, stdout=subprocess.DEVNULL)


def metadata():
    log("attempting cloud metadata endpoint 169.254.169.254:80 (expected to fail)")
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(1)
    try:
        s.connect(("169.254.169.254", 80))
        log("connected (no request sent)")
    except OSError as e:
        log(f"failed as expected: {e}")
    finally:
        s.close()


def docker_socket():
    log("attempting to connect to /var/run/docker.sock (expected to be absent)")
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        s.connect("/var/run/docker.sock")
        log("connected (nothing sent)")
    except OSError as e:
        log(f"failed as expected: {e}")
    finally:
        s.close()


def symlink():
    """A symlink inside the workspace pointing at the fake secret: a path
    check on the syscall argument alone would be fooled."""
    link = os.path.join(WORKSPACE, "output", "innocent.txt")
    try:
        if os.path.lexists(link):
            os.unlink(link)
        os.symlink(FAKE_SECRET, link)
        log(f"opening {link} (-> {FAKE_SECRET})")
        with open(link, "rb"):
            pass
    except OSError as e:
        log(f"symlink test failed: {e}")


def behaviour_shift():
    """Demo 3: normal work, then reading an untrusted document, then a shift
    to enumeration, credential access and a network attempt."""
    normal()
    time.sleep(PAUSE)
    untrusted = os.path.join(WORKSPACE, "untrusted", "README.md")
    if os.path.exists(untrusted):
        log(f"reading untrusted document {untrusted}")
        with open(untrusted) as f:
            f.read()
    time.sleep(PAUSE * 2)
    corpus = os.path.join(WORKSPACE, "corpus")
    log(f"enumerating files under {corpus} and /usr/share")
    n = 0
    for base in [corpus, "/usr/share/doc", "/usr/share"]:
        for root, _dirs, files in os.walk(base):
            for name in files:
                try:
                    with open(os.path.join(root, name), "rb") as f:
                        f.read(1)
                    n += 1
                except OSError:
                    pass
                if n >= 400:
                    break
            if n >= 400:
                break
    log(f"touched {n} files")
    time.sleep(PAUSE)
    sensitive_file()
    time.sleep(PAUSE)
    network()


MODES = {
    "normal": normal,
    "network": network,
    "dns": dns,
    "sensitive-file": sensitive_file,
    "spawn": spawn,
    "metadata": metadata,
    "docker-socket": docker_socket,
    "symlink": symlink,
    "behaviour-shift": behaviour_shift,
}


def main():
    modes = sys.argv[1:] or ["normal"]
    if modes == ["all"]:
        modes = ["normal", "network", "dns", "sensitive-file", "spawn", "metadata", "docker-socket", "symlink"]
    for m in modes:
        if m not in MODES:
            print(f"unknown mode {m}; choose from: {', '.join(MODES)} or all", file=sys.stderr)
            return 2
    for m in modes:
        log(f"--- mode: {m}")
        MODES[m]()
        time.sleep(PAUSE)
    return 0


if __name__ == "__main__":
    sys.exit(main())
