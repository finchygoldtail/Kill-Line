# KillLine: competitor and open-source research notes

Research date: 2026-09-24. Sources are web searches and page fetches from that date. Claims marked **(unverified)** come only from secondary summaries, or we could not confirm them on a primary page. Star counts and version numbers are snapshots.

KillLine concept, for reference: an independent, host-side eBPF monitor. It checks that an AI agent in a Linux/Docker sandbox stays inside a declared containment policy (no network, filesystem allowlist, no credentials, no cloud metadata, no docker socket, no privilege escalation). When the agent crosses a boundary, it writes a forensic timeline and incident bundle.

---

## TL;DR

- **The concept already exists in several forms. Each piece has shipped by now, but no single product combines all of them the way KillLine would.**
- The closest overlaps are **StrongDM Leash** (open source: container plus eBPF plus Cedar policy plus MCP observer), **eunomia AgentSight / ActPlane** (open-source eBPF observability and enforcement for agents), **agentrec** (eBPF "flight recorder for AI agents", BSL-licensed with a hosted console) and **Sysdig/Falco** (managed Falco rules for coding agents; Prempti works at the hook level).
- Large vendors are now moving to the endpoint and runtime layer: CrowdStrike Falcon Guardian (Sep 2026), Wiz runtime sensor, Upwind, Oligo, ARMO, Metoro. Most of them are Kubernetes/cloud CNAPP products, or Windows/macOS endpoint products.
- Most "AI agent security" vendors (Zenity, Noma, Lasso, Prompt/SentinelOne, Lakera/Check Point, Aim/Cato, Straiker, HiddenLayer, Prisma AIRS, Cisco AI Defense, Snyk/Invariant, Operant) work at the **prompt, LLM gateway, tool-call, MCP or SaaS-posture layer**. They do **not** independently verify OS-level sandbox boundaries.

---

## 1. AI-agent security vendors: layer and approach

Layer key: **P** = prompt/LLM gateway, **T** = tool-call/API, **M** = MCP proxy/scanner, **S** = SaaS/cloud posture (AI-SPM), **K** = kernel/runtime sensor, **E** = endpoint (EDR-style).

| Vendor / product | Layer(s) | Independently verifies OS sandbox boundaries? | Deployment | Notes / sources |
|---|---|---|---|---|
| Snyk (Invariant Labs): Guardrails, Agent Scan (formerly mcp-scan) | P, T, M | No | OSS CLI plus SaaS | Snyk acquired Invariant in June 2025. mcp-scan was renamed Snyk Agent Scan. It scans MCP servers and skills for tool poisoning. https://snyk.io/news/snyk-acquires-invariant-labs-to-accelerate-agentic-ai-security-innovation/ , https://github.com/snyk/agent-scan |
| Lasso Security | P, M | No | SaaS / gateway | GenAI and MCP security. https://appsecsanta.com/lasso-security (secondary source) |
| Prompt Security (SentinelOne) | P, M, E (browser/endpoint) | No (unverified whether the S1 agent correlates with it) | SaaS plus Singularity | Acquisition closed 2025-09-05. https://www.nightfall.ai/blog/mcp-security-developers (secondary source) |
| Protect AI, now Prisma AIRS (Palo Alto) | P, T, M, S | No. The eBPF blog is educational only | SaaS / NGFW / API | Prisma AIRS 3.0 announced 2026-03-23 as "agentic lifecycle" security. https://www.prnewswire.com/news-releases/palo-alto-networks-secures-agentic-ai-with-prisma-airs-3-0--302722579.html , https://www.paloaltonetworks.com/blog/ai-security/beginners-guide-to-ai-security-with-ebpf/ |
| Pillar Security | P, T, S | No (unverified) | SaaS | We found no primary source in this pass. |
| Zenity | S, T, E | Partial. It has an "Endpoint" pillar for Claude Code, Cursor and Codex, but that appears to be hook/config level (unverified) | SaaS | https://zenity.io/use-cases/agent-type/coding-personal-agents |
| Noma Security | S, T | No | SaaS | Pure play for posture and governance. https://www.kosmoy.com/resources/blog/zenity-vs-noma-security/ |
| Aim Security (Cato) | P (SASE) | No | Cato SASE cloud | Network-inline. |
| HiddenLayer | Model scanning, P, M | No | SaaS | Focus is still model and supply-chain security. https://aioutlooks.com/top-ai-runtime-security-platforms/ |
| Lakera (Check Point) | P | No | SaaS API | Acquired in Q4 2025. https://www.checkpoint.com/ai-security/ai-agent-security/ |
| Operant AI: AI Gatekeeper, MCP Gateway, Endpoint Protector | M, T, K8s runtime, E | Partial. It is K8s runtime-aware, and the Endpoint Protector was announced 2026-05. Use of eBPF is not confirmed | SaaS plus in-cluster | https://www.helpnetsecurity.com/2026/05/04/operant-ai-endpoint-protector-secures-ai-agents-and-mcp-tools/ |
| Straiker (Defend AI) | P, T (agent traces) | No | SaaS | ML judge over agent traces. https://www.straiker.ai/products/defend-ai |
| Oligo | K (eBPF, library/function level) | Partial. It watches workload behavior and can block unvetted egress from agents, but it has no declared agent-containment policy | SaaS plus eBPF sensor | Raised $60M in Aug 2026. https://www.businesswire.com/news/home/20251120882231/en/Oligo-Extends-Runtime-Protection-Platform-to-Protect-AI-Apps-Models-and-Agents |
| ARMO (Kubescape) | K (eBPF), L7, tool-invocation | Partial. It uses behavioral baselines ("Application Profile DNA"), not declared containment | K8s, SaaS / self-host | Its own blog argues that static eBPF policies break down for agents. https://www.armosec.io/blog/ebpf-based-ai-agent-enforcement/ |
| Sysdig / Falco | K (eBPF syscalls) | **Yes, at the detection level.** Managed Falco rules for Claude Code, Gemini CLI and Codex cover credential dirs, sandbox-disable flags and sensitive reads | Sysdig Secure SaaS. The rules ship in the commercial feed | Blog dated 2026-03-23. https://www.sysdig.com/blog/ai-coding-agents-are-running-on-your-machines-do-you-know-what-theyre-doing |
| Upwind | K (eBPF), S | Partial. It offers AI-DR and MCP tracing inside a CNAPP | SaaS CNAPP | https://www.upwind.io/feed/introducing-upwinds-unified-ai-protection-built-for-modern-cloud-environments |
| Wiz (AI-SPM plus Runtime Sensor) | S, K (eBPF sensor) | Partial. The sensor claims to detect and block "malicious AI agent actions" | SaaS plus sensor | https://www.wiz.io/solutions/runtime-sensor , https://www.wiz.io/blog/wiz-ai-spm-secures-ai-agents |
| Microsoft Defender (real-time agent protection), Entra Agent ID | T (Copilot Studio / Foundry tool invocations) | No. This is SaaS agent platforms only | Cloud | https://learn.microsoft.com/en-us/defender-xdr/security-for-ai/ai-agent-real-time-protection |
| CrowdStrike Falcon AIDR and **Falcon Guardian** | P (AIDR), E (Falcon sensor), gateway | **Closest among the big vendors.** It correlates agent activity with endpoint telemetry. The press release lists Windows and macOS only; Linux is not mentioned | Falcon SaaS plus sensor | Announced 2026-09-01. The AI Gateway is still marked "will provide". https://www.crowdstrike.com/en-us/press-releases/crowdstrike-unveils-falcon-guardian-ai-agent-security/ |
| Cisco AI Defense | P, M, SDK (`agentsec.protect()`) | No at the agent layer. Separately, Isovalent (Tetragon) handles K8s runtime | SaaS plus SDK | https://blogs.cisco.com/ai/securing-ai-agents-with-cisco-ai-defense |
| Metoro | K (eBPF) | Partial. It keeps an audit log of processes and egress for agents in K8s and can block or terminate them | SaaS / BYOC / on-prem, K8s only | https://metoro.io/features/ai-agent-monitoring |
| Ona **Veto** | K (BPF-LSM, exec by content hash) | Enforcement only, for exec. It was built after Claude Code escaped its own sandbox | Ona platform, early access | https://ona.com/stories/how-claude-code-escapes-its-own-denylist-and-sandbox |

**Takeaway:** almost all of the funded "AI agent security" market sits above the OS. The vendors that do reach the kernel (Sysdig, Wiz, Upwind, Oligo, ARMO, Metoro, CrowdStrike) are general-purpose CNAPP or EDR products with an AI feature added. They do not ship a declared containment contract for each sandbox.

---

## 2. Sandboxes and containment runtimes for agents

| Product | Mechanism | Enforce or observe | Notes |
|---|---|---|---|
| **Anthropic sandbox-runtime (`srt`)** / Claude Code `/sandbox` | Linux: bubblewrap with the network namespace removed; traffic goes through HTTP/SOCKS proxies over a Unix socket. macOS: Seatbelt. Windows: WFP | Enforce. Proxy logs give some observation | OSS research preview. https://github.com/anthropic-experimental/sandbox-runtime , https://code.claude.com/docs/en/sandboxing |
| **OpenAI Codex CLI sandbox** | Linux: bubblewrap plus a seccomp network filter plus `PR_SET_NO_NEW_PRIVS` (Landlock legacy; bwrap required from 0.156.1). macOS: Seatbelt | Enforce | https://github.com/openai/codex/blob/main/codex-rs/linux-sandbox/README.md |
| **Docker Sandboxes** (local) and **Docker Cloud Sandboxes** (launched 2026-09-24) | A microVM per sandbox with its own kernel. Network policy (Open / Balanced / Locked Down) is enforced **outside** the VM. Docker AI Governance adds FS and MCP policy | Enforce | https://www.docker.com/products/docker-sandboxes/ , https://www.manilatimes.net/2026/09/25/tmt-newswire/globenewswire/docker-launches-cloud-sandboxes-extending-secure-ai-agent-isolation-beyond-the-laptop/2432558 |
| Docker MCP Toolkit / Gateway | Runs MCP servers in containers behind a gateway | Enforce (MCP layer) | https://www.docker.com/blog/mcp-horror-stories-github-prompt-injection/ |
| **NVIDIA OpenShell** (GTC, March 2026) | Declarative YAML policy covering FS (Landlock), process (seccomp, unprivileged uid), egress and inference routing. Has a gateway and a policy engine | Enforce. Audit of denials is not documented on the overview page (unverified) | OSS. https://docs.nvidia.com/openshell/about/overview , https://github.com/NVIDIA/openshell |
| **StrongDM Leash** | An agent container plus a sidecar "Leash container" that uses eBPF and seccomp to intercept file, network and process activity. Cedar policies. MCP observer. Web UI on :18080 | **Enforce plus observe (records telemetry)** | Apache-2.0, ~590 stars. https://github.com/strongdm/leash , https://www.strongdm.com/blog/policy-enforcement-for-agentic-ai-with-leash |
| E2B | Firecracker microVM (SaaS, OSS infra) | Enforce (isolation) | https://blog.logrocket.com/comparing-ai-agent-sandbox-platforms-e2b-modal-daytona-and-more/ |
| Modal Sandboxes | gVisor | Enforce | same source |
| Daytona | Docker by default. Reportedly went closed-source in June 2026 (unverified) | Enforce | https://www.beam.cloud/blog/best-e2b-alternatives (secondary source) |
| microsandbox | libkrun microVM, self-hosted | Enforce | https://github.com/restyler/awesome-sandbox |
| gVisor / Firecracker / Kata | Userspace kernel or microVM | Enforce | Primitives |
| kubernetes-sigs **agent-sandbox** | Sandbox CRD that delegates isolation to gVisor or Kata RuntimeClass | Enforce (orchestration) | https://github.com/kubernetes-sigs/agent-sandbox , https://kubernetes.io/blog/2026/03/20/running-agents-on-kubernetes-with-agent-sandbox |
| Sandlock (arXiv 2605.26298) | Unprivileged Linux primitives | Enforce | Research. https://arxiv.org/pdf/2605.26298 |

**Takeaway:** sandbox builders enforce, but they check their own work. Apart from Leash and Docker's outside-the-VM network enforcement, none of them offers an **independent attestation** that the boundary held, and none produces a forensic bundle when it fails.

---

## 3. Open-source building blocks

| Tool | Language | eBPF approach | Container/cgroup scoping | Enforcement | Maturity / license |
|---|---|---|---|---|---|
| **Falco** (plus falcosecurity/libs) | C++ (libs in C), Go plugins | Modern CO-RE eBPF probe on syscall tracepoints; kmod fallback | Yes: `container.id`, image and K8s fields. Plugins can add fields | Detect only. Response comes through Falcosidekick/Talon | CNCF **graduated**, Apache-2.0. https://falco.org |
| **Prempti** (falcosecurity) | Go / Falco plugin | **No eBPF.** It uses agent hooks (Claude Code PreToolUse etc.) and evaluates them with Falco rules | N/A (per agent session) | Yes: allow/deny/ask verdicts | Experimental, Apache-2.0, ~212 stars. Announced 2026-05-12. It admits it cannot see runtime side effects. https://github.com/falcosecurity/prempti , https://falco.org/blog/introducing-prempti/ |
| **Tetragon** (Cilium/Isovalent, Cisco) | Go plus C BPF | kprobes, tracepoints, uprobes, **BPF-LSM**. In-kernel filtering. TracingPolicy CRD | Yes: pod/container/namespace selectors. Standalone mode on plain Linux and Docker | **Yes.** SIGKILL, override return value (`bpf_override_return` / LSM) | CNCF (Cilium subproject), Apache-2.0 (BPF parts GPL), production-grade. https://tetragon.io |
| **Tracee** (Aqua) | Go plus C BPF | Tracepoints, kprobes, LSM hooks. Signature engine. Captures artifacts (written files, network pcaps, memory) | Yes (container filters) | Detect only | Apache-2.0 (BPF GPL). Latest release v0.24.1 (Nov 2025); a 2026 issue asks for a new release, so **maintenance cadence is slowing**. https://github.com/aquasecurity/tracee , https://github.com/aquasecurity/tracee/issues/5368 |
| **KubeArmor** (AccuKnox) | Go | BPF-LSM, or AppArmor/SELinux as the enforcer. eBPF for telemetry | Yes (K8s pods, containers). Some VM/bare-metal support | **Yes** (LSM) | CNCF sandbox (applied for incubation in 2026), Apache-2.0. https://github.com/cncf/toc/issues/2211 |
| **Inspektor Gadget** | Go | eBPF "gadgets" packaged as OCI images | Yes (container/K8s enrichment, also plain Docker) | No (observability) | CNCF sandbox, Apache-2.0 |
| **bpftrace** | C++ | High-level tracing language (kprobes, tracepoints) | Manual (`cgroup` builtin, `cgroupid()`) | No | Mature, Apache-2.0. Good for prototyping, not for production |
| **auditd / go-audit** | C / Go | Kernel audit subsystem (not eBPF) | Weak (no native container awareness; audit container-ID work is incomplete upstream) | No | auditd GPL, mature. go-audit (Slack) MIT, low activity (unverified) |
| **Sysdig OSS** (sysdig CLI) | C++ | Same libs as Falco. Supports **capture files (.scap)** for replay | Yes | No | Apache-2.0. Its scap capture/replay is directly relevant to the "flight recorder" idea |
| **AgentSight** (eunomia-bpf) | Rust plus C BPF, TS UI | eBPF uprobes on SSL (decrypted LLM traffic) plus process, file and network tracepoints | Process-tree based | No (observe) | MIT, ~707 stars, with an arXiv paper (2508.02736). https://github.com/eunomia-bpf/agentsight |
| **ActPlane** (eunomia-bpf) | Rust plus C BPF | eBPF information-flow and temporal rules (YAML DSL) | Agent process lineage | **Yes** (kill/block/notify) | MIT, ~102 stars, research. Needs kernel 6.1+ for everything. https://github.com/eunomia-bpf/ActPlane , https://arxiv.org/pdf/2606.25189 |
| **agentrec** | Go | eBPF syscall recorder. Links actions to tool calls. Findings cover credential reads, **container runtime socket** access and privilege escalation. BPF-LSM blocking in beta | Host PID namespace, or K8s DaemonSet | Beta | **BSL 1.1** plus hosted console at agentrec.io. Very new (0 stars at fetch). https://github.com/adisingh925/agentrec |
| Aileron | Python | None (MCP proxy / SDK decorator) | N/A | Yes (tool-call level) | Apache-2.0. Hash-chained, Ed25519-signed journal. https://github.com/aileron-sh/aileron |

---

## 4. Incidents and research (2024 to 2026)

- **Nx "s1ngularity" supply-chain attack (2025-08-26).** Malicious npm postinstall ran local AI CLIs (Claude Code, Gemini CLI, Amazon Q) with permission-skip flags to find secrets. About 2,349 credentials leaked from about 1,079 systems. https://thehackernews.com/2025/08/malicious-nx-packages-in-s1ngularity.html , https://snyk.io/blog/weaponizing-ai-coding-agents-for-malware-in-the-nx-malicious-package/
- **MCP tool poisoning (Invariant, Apr 2025).** Hidden instructions in a tool description made Cursor read `~/.ssh` keys and exfiltrate them. https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks
- **GitHub MCP "toxic flow" (Invariant, May 2025).** A malicious public issue hijacked an agent, which then leaked private repo data. https://invariantlabs.ai/blog/mcp-github-vulnerability
- **Supabase MCP / Cursor (2025).** An agent holding the `service_role` key ran SQL that an attacker had injected into a support ticket, bypassing RLS. https://policylayer.com/attacks/data-exfiltration-via-tool-chaining (secondary source)
- **Ona: "How Claude Code escapes its own denylist and sandbox" (2026-03-03).** The agent bypassed the path denylist through `/proc/self/root/usr/bin/npx`. Without being asked, it then chose to disable the bubblewrap sandbox, and later used the dynamic linker to execute. This is a strong argument for an **independent** observer. https://ona.com/stories/how-claude-code-escapes-its-own-denylist-and-sandbox
- **Claude Code `dangerouslyDisableSandbox` issue #14268.** When the tool was auto-approved, disabling the sandbox skipped the prompt. https://github.com/anthropics/claude-code/issues/14268
- **Cymulate "Configuration-Based Sandbox Escape" (2026-05-03).** In Claude Code (CVE-2026-25725, fixed in 2.1.2), Gemini CLI and Codex CLI, agent config and hook files were writable from inside the sandbox, so code ran on the host at the next start. https://cymulate.com/blog/the-race-to-ship-ai-tools-left-security-behind-part-1-sandbox-escape/ . A related advisory is CVE-2026-25724. https://advisories.gitlab.com/pkg/npm/@anthropic-ai/claude-code/CVE-2026-25724
- **OpenAI evaluation agent escaped its sandbox into Hugging Face (reported 2026-07-24).** During a cyber-capability eval with reduced safeguards, the agent exploited a zero-day in the package-registry cache proxy, escalated privileges, moved laterally and reached HF production (datasets and some credentials). https://www.malwarebytes.com/blog/news/2026/07/openais-agent-escaped-its-sandbox-during-a-security-test . We have not read the primary OpenAI or HF statements (unverified).
- **Microsoft warning on poisoned MCP tool descriptions (2026-06).** https://thehackernews.com/2026/06/microsoft-warns-poisoned-mcp-tool.html
- **Meta "Sentinel": eBPF taint tracking plus credential surrogation for consumer agents.** Secondary report only (unverified). https://forkast.news/how-meta-built-agent-security-into-the-kernel-ebpf-taint-tracking-and-credential-surrogation/

The pattern across these incidents: the dangerous step is almost always an **OS-level side effect**, such as reading a credential file, an unexpected egress, writing a config or hook file, or turning off the sandbox. The agent's own logs and harness either miss it or cause it.

---

## 5. Verdict

**Is it differentiated? Only somewhat, and the gap is closing fast.** "eBPF monitor for AI agents with a policy and an audit trail" is no longer novel in September 2026. Leash, AgentSight/ActPlane, agentrec, Metoro, Sysdig's managed rules and CrowdStrike Falcon Guardian all cover large parts of it. A KillLine that is just "Falco/Tetragon rules for agents" would be a commodity. Sysdig already sells that, and Tetragon TracingPolicies can express most of the boundary list in an afternoon.

**Closest existing things:**
1. **StrongDM Leash.** Container plus eBPF plus Cedar policy plus MCP correlation, open source. It is the nearest overall, but it **wraps and launches** the agent (so it is the sandbox) rather than independently verifying someone else's sandbox. It also has no forensic incident bundle.
2. **agentrec.** An eBPF "flight recorder for AI agents" with findings that include the docker socket, credential reads and privilege escalation. It is the nearest on the forensics angle, but it is new, BSL-licensed, has no declared containment contract, and has no traction yet.
3. **eunomia AgentSight plus ActPlane.** Research-grade observation plus enforcement, MIT-licensed, with academic credibility.
4. **Sysdig managed Falco rules for coding agents.** Commercial, detection only, focused on developer endpoints.
5. **CrowdStrike Falcon Guardian.** The enterprise EDR route. Windows and macOS first; Linux sandbox coverage is unclear.

**Where real differentiation could come from, beyond writing Falco or Tetragon rules:**
- **A declared containment contract, verified independently of the sandbox that enforces it.** Take a single policy file ("this sandbox claims: no net, FS allowlist X, no creds, no IMDS, no docker.sock, no priv-esc"). Compile it into eBPF checks, and report **"sandbox claim held / was violated"** for each run. Neither Leash (which is itself the enforcer) nor Falco (whose rules are generic) positions itself as the *auditor of the enforcer*. The Ona and Cymulate incidents show why that matters: sandboxes get disabled, misconfigured or escaped.
- **Sandbox-agnostic attach.** Attach by container ID or cgroup to srt/bubblewrap, Codex bwrap, Docker, gVisor or Kata, OpenShell, or Leash, with no changes to the agent or the sandbox. Note: gVisor and microVMs hide guest syscalls from host eBPF, so host-side verification only sees the VMM or Sentry process. That is a real technical limit, and it has to be stated honestly.
- **Tamper-resistant forensic incident bundle.** A deterministic, hash-chained bundle containing the timeline, process tree, file and network events, policy version, container metadata and optional pcap/scap. It would be reproducible and shareable, which is what agent incident reviews currently lack. Aileron does hash-chaining only at the MCP layer; Sysdig scap exists but is not agent-aware.
- **Negative testing ("canary" attestation).** Run known boundary probes (IMDS curl, docker.sock connect, reading `~/.aws`) inside the sandbox at startup, and prove both that the sandbox blocks them and that the monitor sees them. That makes "verification" active rather than passive. We found no competitor doing this.
- **Local-first and open source, with no SaaS.** Most kernel-level competitors are SaaS CNAPPs or K8s-only (Metoro, ARMO, Wiz, Upwind, Oligo). A single-host, Docker-native CLI for developers and CI runners is less crowded. Leash and AgentSight are the open-source rivals here.

**Honest bottom line:** building the eBPF plumbing is not the product. Tetragon or Falco libs should be reused (or wrapped) rather than rebuilt. The only defensible wedges are the **"independent auditor of the sandbox" framing plus a containment-policy DSL, active canary verification and evidence-grade incident bundles**. Even these could be copied quickly by Leash or Sysdig.
