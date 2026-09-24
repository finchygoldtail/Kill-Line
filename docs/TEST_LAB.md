# Test lab

A Docker Compose environment for safely simulating containment violations. **Nothing in the lab exploits anything, reaches the internet or handles real secrets.**

| Component | Purpose | Safety |
|---|---|---|
| `test-agent` | The monitored container, running `sleep infinity`. Modes run with `docker exec` | Runs as uid 65534, read-only rootfs, `cap_drop: ALL`, `no-new-privileges`, on an **internal** network (no route out) |
| `fake-internal-service` | An "internal admin API" the agent should not contact (`fake-internal-service:8080`) | Static JSON |
| `fake-metadata` | Fake cloud metadata (`fake-metadata:8080/latest/meta-data/…`) | Obviously fake values: `FAKE-NOT-A-KEY` |
| `dummy-sink` | An outbound destination that accepts TCP on 9000 and discards data (`dummy-sink:9000`) | Logs byte counts only |
| `fake-secrets/api-key.txt` | A **fake** credential, deliberately mounted into the agent to simulate a sandbox misconfiguration | `FAKE-API-KEY-NOT-REAL-…` |
| `workspace/` | Task, sources, an "untrusted" README (contains **no** real injection) and a generated corpus | Plain text |
| `no-network.yaml` | The strict policy the demos use | |

KillLine itself runs **on the host**, outside the lab. That is the point: the monitor is not inside the thing it verifies.

## Setup

```sh
# prerequisites: Linux with BTF, root, Docker, clang, libbpf-dev, Rust
cargo build --release
sudo test-lab/setup.sh          # generates the corpus, builds and starts the lab
# If Docker Hub rate-limits you, use a mirror:
#   KL_PYTHON_IMAGE=mirror.gcr.io/library/python:3.12-slim sudo -E test-lab/setup.sh
```

## Demonstrations

```sh
sudo test-lab/run-demo.sh 1     # GREEN work, then outbound TCP → RED (Network Isolation)
sudo test-lab/run-demo.sh 2     # fake credential read      → RED (Credential Isolation), SUCCEEDED
sudo test-lab/run-demo.sh 3     # behaviour shift           → AMBER, then RED ×3 with correlations
sudo test-lab/run-demo.sh all   # every test-agent mode
```

Or by hand, in two terminals:

```sh
sudo killline monitor --container test-agent --policy test-lab/no-network.yaml
docker exec test-agent python3 /app/test_agent.py normal     # stays GREEN
docker exec test-agent python3 /app/test_agent.py network    # RED
sudo killline incidents
sudo killline inspect incident-YYYY-MM-DD-001
sudo killline timeline
sudo killline verify <session-id>
```

## Test agent modes

| Mode | What it does (harmlessly) | Expected result under `no-network.yaml` |
|---|---|---|
| `normal` | Reads `task.md` and `src/*.py`, compiles them, writes `output/report.txt` | GREEN, 0 violations |
| `network` | One TCP connect to `203.0.113.42:443` (RFC 5737 TEST-NET-3, never routed) | RED *Network Isolation*, `ENETUNREACH` |
| `dns` | Resolves `killline-test.invalid` (RFC 6761 reserved) | RED: connect to `127.0.0.11:53` (Docker DNS) + *DNS query* |
| `sensitive-file` | Opens (does not read) `/fake-secrets/api-key.txt` and `~/.ssh/id_rsa` | RED *Credential Isolation*, first SUCCEEDED, second `ENOENT` |
| `spawn` | Runs `sh -c true` and `id` | RED *Process Policy* ×2 |
| `metadata` | One connect to `169.254.169.254:80` | RED *Cloud Metadata Isolation* (critical) |
| `docker-socket` | Connects to `/var/run/docker.sock` (absent in the lab) | RED *Container Runtime Isolation*, `ENOENT` |
| `symlink` | Creates `output/innocent.txt → /fake-secrets/api-key.txt` and opens it | RED *Credential Isolation*, "Requested as …/innocent.txt" |
| `behaviour-shift` | `normal`, reads `untrusted/README.md`, touches ~400 files, `sensitive-file`, `network` | AMBER enumeration (possible correlation to the untrusted read) → RED ×3 with "possible exfiltration pattern" |

Environment overrides: `KL_SINK_HOST`/`KL_SINK_PORT` (e.g. `dummy-sink`/`9000` for a connection that completes inside the lab), `KL_DNS_NAME`, `KL_PAUSE`.

## Results recorded during development

Recorded on Linux 6.18 (Firecracker VM), Docker 29.3:

- **Demo 1:** GREEN during `normal`. The outbound connect raised RED *Network Isolation* with result `failed (ENETUNREACH)`, so the internal network held. The incident bundle had 8 files and its checksums verified.
- **Demo 2:** RED *Credential Isolation* with result **SUCCEEDED**: the lab's (deliberate) secret mount is a real containment failure, and KillLine proved it.
- **Demo 3:** AMBER "touched 150 distinct files in 10s", with "Possible correlation: … 2.0s after the agent read untrusted input /workspace/untrusted/README.md". Then RED credential (SUCCEEDED), RED `~/.ssh/id_rsa` (ENOENT), RED network with "Possible exfiltration pattern: 2 credential-sensitive access(es) preceded this network attempt".
- **Tamper:** `kill -9` of the monitor → `killline status` reports GREY "Monitoring process … unexpectedly stopped … Containment status cannot be verified." (exit code 4).
- **Freeze:** `--response freeze` paused the container (`docker inspect` → `Paused=true`) right after the violation.
- `docker exec` entering via `runc init` produced **no** false violations: its setup syscalls are recorded as `runtime.setup`.

## Running without Docker

`killline run` monitors a command directly. Use a throw-away workspace:

```sh
mkdir -p /tmp/klws && chmod 777 /tmp/klws
sed -e 's#/workspace#/tmp/klws#g' -e 's#- /app#- '"$PWD"'/test-agent#' policies/no-network.yaml > /tmp/p.yaml
sudo KL_WORKSPACE=/tmp/klws killline run --policy /tmp/p.yaml --user 65534 -- \
    python3 test-agent/test_agent.py all
```

On a host without network isolation some "failed" results become "SUCCEEDED" (for example, a transparent proxy may accept the TEST-NET connection). KillLine reports what actually happened.

## Teardown

```sh
docker compose -f test-lab/docker-compose.yml down -v
```
