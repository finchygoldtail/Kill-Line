# Security policy

Kill Line runs with administrator rights, so vulnerabilities in it matter. Thank you for reporting them responsibly.

## Reporting a vulnerability

**Please do not open a public issue.** Use GitHub's private reporting: **Security → Report a vulnerability** on this repository. Include:

- what you found, and the affected version or commit;
- steps to reproduce, using safe simulations where possible;
- the impact, such as privilege escalation through Kill Line, a way for a monitored agent to blind or tamper with Kill Line, or data leaking from the dashboard.

We aim to acknowledge reports within 3 working days and agree a disclosure timeline with you. We will credit you unless you ask us not to.

## In scope

- The engine (`killline`), the eBPF program, the ETW sensor, the dashboard (`killline ui`) and the desktop app.
- Ways for a monitored agent to evade detection **without** a documented limitation. Check [docs/LIMITATIONS.md](docs/LIMITATIONS.md) and [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) first; known gaps are welcome as ordinary issues.
- Release integrity: signatures, attestations and the build pipeline.

## Supported versions

Kill Line is pre-1.0. Only the latest release and the default branch receive fixes.

## Verifying releases

Every release artifact is signed and has build provenance. See [docs/SIGNING.md](docs/SIGNING.md).
