# Policy format (version 1)

A policy is a YAML **containment contract**: what the agent is allowed to do. KillLine reports everything outside it. Unknown keys are rejected, so a typo cannot silently weaken a policy. Check a policy with:

```sh
killline validate-policy policy.yaml
```

`validate-policy` also tells you which parts of the policy KillLine **cannot** fully verify (for example `mcp:` in V1).

Templates: `killline template` lists them; `killline template offline-research > policy.yaml` writes one. They live in [`policies/`](../policies).

## Full example

```yaml
version: 1                     # optional, default 1
agent: research-agent-01       # [A-Za-z0-9._-]+
name: strict-no-network        # optional, shown in output
description: Workspace-only research agent

filesystem:
  allow:            [/workspace]          # read + write
  allow_read:       [/datasets]           # read only
  allow_write:      [/workspace/output, /tmp]
  deny:             [/root, /home, /etc/shadow, /var/run/secrets]
  runtime_read:     default               # or: none

network:
  mode: deny                              # deny | allowlist | allow
  # allow:       [github.com, "*.githubusercontent.com"]   (allowlist mode)
  # allow_cidr:  [10.0.0.0/24]
  allow_localhost: false

processes:
  allow: [python3, "python3.*", git]      # basename (globs ok) or absolute path; empty = any
  deny:  [sudo, su, ssh, nc, ncat, socat]
  deny_privileged: true                   # default true

credentials:
  access: deny                            # default deny
  extra_paths: [/fake-secrets]            # added to the built-in list
  allow_paths: [/workspace/.agent-token]  # explicitly granted credentials

cloud_metadata:
  access: deny                            # default deny

container_runtime:
  access: deny                            # default deny (docker.sock etc.)

inter_agent_communication:
  allow: false

mcp:                                      # parsed, NOT verified in V1
  allow_servers: [filesystem, github]
  deny_unknown_servers: true

untrusted_inputs: [/workspace/untrusted]  # used for "possible correlation"

anomaly:
  enabled: true
  file_burst_threshold: 150               # distinct non-runtime files per window
  window_secs: 10
  network_scan_threshold: 20              # distinct destinations per window
  exec_burst_threshold: 50                # execs per window

response:
  violation: alert                        # alert | freeze | terminate (default alert)
  on_degraded: alert                      # alert | freeze | terminate (fail-closed)
```

## Path rules

- Paths must be absolute, or start with `~/` (expanded to both `/root/` and `/home/*/`), or `**/`.
- A plain path matches itself and everything under it: `/workspace` matches `/workspace/a/b` but **not** `/workspace2`.
- Globs: `*` matches within one path segment, `**` matches any number of segments, `?` matches one character.
- Paths are evaluated **as the agent sees them** (inside its container / root), after `..` normalisation and symlink resolution.

### Evaluation order for file events

Earlier rules win:

1. **Escape indicators** (built in): `/proc/sys/kernel/core_pattern`, `/proc/sysrq-trigger`, `/proc/<other-pid>/root|mem`, `/proc/kcore`, `release_agent`, raw block devices, … → *Container Boundary*, critical.
2. **Container runtime sockets** (built in) → *Container Runtime Isolation*, critical, unless `container_runtime.access: allow`.
3. **Credentials**: built-in list plus `credentials.extra_paths`, minus `credentials.allow_paths` → *Credential Isolation*, critical, unless `credentials.access: allow`.
4. `filesystem.deny` → *Filesystem Boundary*, high.
5. Writes (open for write/create/truncate/append, unlink, rename, chmod): must match `allow` or `allow_write` (or `/dev/null`-style runtime paths).
6. Reads/lists: must match `allow`, `allow_read`, `allow_write` or the runtime baseline.

A **failed** write attempt to `__pycache__`/`*.pyc` is recorded as benign (interpreters try this routinely). A successful one is still evaluated.

### Built-in credential locations

`~/.ssh`, `~/.aws`, `~/.azure`, `~/.config/gcloud`, `~/.kube`, `~/.docker/config.json`, `~/.netrc`, `~/.git-credentials`, `~/.npmrc`, `~/.pypirc`, `~/.gnupg`, `~/.config/gh/hosts.yml`, `~/.password-store`, `**/.env`, `**/.env.*`, `**/credentials.json`, `**/service-account*.json`, `**/id_rsa*`, `**/id_ecdsa*`, `**/id_ed25519*`, `/etc/shadow`, `/etc/gshadow`, `/etc/sudoers`, `/etc/kubernetes`, `/var/run/secrets`, `/run/secrets`, `/proc/<other-pid>/environ`.

KillLine records **that** one of these was accessed. It never reads the contents.

### Runtime baseline (`runtime_read: default`)

Read-only locations every Linux program touches: `/usr`, `/lib*`, `/bin`, `/sbin`, `/opt`, the dynamic-linker cache, locale and timezone files, `/etc/passwd`, `/etc/group`, `/etc/hosts`, `/etc/resolv.conf`, TLS roots, `/proc/self`, a few `/proc` and `/sys` info files, and `/dev/null|zero|urandom|tty|pts`. The full list is `RUNTIME_READ_PATHS` in `crates/killline-core/src/policy.rs`. Explicit deny and credential rules always take precedence. Set `runtime_read: none` for maximum strictness, then list what is needed (see `untrusted-model-test`).

## Network rules

- `mode: deny`: any outbound connect/send to a non-loopback address, any DNS query, and any non-loopback listener is a violation.
- `mode: allowlist`: destinations in `allow_cidr` are allowed. DNS queries must match `allow` (exact name or `*.suffix`). A connection to another IP is **allowed but labelled "destination not verified"** if an allowed domain was resolved in the previous 300 s; otherwise it is a violation. V1 does not see DNS answers (see LIMITATIONS).
- `mode: allow`: network is not a boundary; metadata and runtime-socket rules still apply.
- The mode is inferred as `allowlist` if `allow` or `allow_cidr` is present, else `deny`.
- `allow_localhost` allows `127.0.0.0/8` and `::1`. In containers, Docker's embedded DNS is `127.0.0.11`, so a no-network policy will (correctly) report DNS attempts to it.
- Cloud metadata endpoints are always checked, in any mode: `169.254.169.254`, `fd00:ec2::254`, `169.254.170.2`, `169.254.170.23`, `168.63.129.16`, `100.100.100.200`, and the names `metadata.google.internal`, `metadata.goog`, `metadata`, `instance-data`. IPv4-mapped IPv6 forms are normalised.

## Process rules

- `deny`: exec of a matching program is a violation (high).
- `deny_privileged: true`: exec of `sudo`, `su`, `doas`, `pkexec`, `runuser`, `setpriv`, `nsenter`, `unshare`, `capsh`, `chroot`, `mount`, `umount`, `insmod`, `modprobe`, `newgrp`, `sg`, `docker`, `podman`, `nerdctl`, `ctr`, `crictl` or `kubectl` is a violation. So are setuid-to-root from a non-root uid, setuid-bit chmod, `unshare` with namespace flags, `setns`, `mount`/`chroot`/`pivot_root`, `ptrace` attach, raw sockets, `bpf()` and module loading. With `deny_privileged: false` these become AMBER anomalies instead.
- `allow` (non-empty): exec of anything else is a violation (medium). Exec attempts that fail with `ENOENT` (PATH search) are recorded but are not violations, unless the program is explicitly denied.

## Response

- `violation: alert` (default): record and alert; nothing is blocked.
- `violation: freeze`: on the first violation, `docker pause` (cgroup freezer) the container, or SIGSTOP the tracked processes. The agent's state is preserved for inspection.
- `violation: terminate`: `docker kill`, or SIGKILL the tracked processes.
- `on_degraded`: the same actions, triggered when events are dropped. Use `freeze` for fail-closed monitoring.

Responses happen **after** the triggering syscall has entered the kernel. KillLine V1 does not prevent the first violating action. `--response` on the CLI overrides `response.violation`.

## Limits and validation

Policies are capped at 256 KiB, 1024 entries per list and 1024 bytes per entry. Control characters are rejected. Domain names and CIDRs are syntax-checked. `mode: deny` combined with allow rules is an error.
