# Running Kill Line on Windows

Kill Line on Windows uses Event Tracing for Windows (ETW). It needs Windows 10 or 11 (x64) and an **Administrator** account, because only administrators can start a kernel trace session.

## 1. Install

From the [Releases page](https://github.com/finchygoldtail/Kill-Line/releases), download one of:

| File | What it is |
|---|---|
| `Kill-Line_<version>_x64-setup.exe` | Desktop app installer (recommended) |
| `Kill-Line_<version>_x64_en-US.msi` | The same app as an MSI, for managed installs |
| `killline-windows-x86_64.exe` | The command-line engine on its own, no install |

The installer puts the app and the engine (`killline.exe`) in `C:\Program Files\Kill Line\`.

Until releases are Authenticode-signed, Windows SmartScreen shows "Windows protected your PC". Check the download first (below), then choose **More info → Run anyway**.

### Check the download (optional, recommended)

In PowerShell, in your Downloads folder:

```powershell
Get-FileHash .\Kill-Line_0.1.1_x64-setup.exe -Algorithm SHA256
```

Compare the result with the line for that file in `SHA256SUMS` on the release page. [SIGNING.md](SIGNING.md) covers signature checks with `cosign` and `gh attestation verify`.

## 2. Monitor an agent

Open **PowerShell as Administrator** (Start → type "PowerShell" → right-click → *Run as administrator*):

```powershell
cd "C:\Program Files\Kill Line"

# See the bundled Windows policies and save one to edit
.\killline.exe template
.\killline.exe template windows-coding-agent | Set-Content -Encoding ascii $env:USERPROFILE\my-policy.yaml
notepad $env:USERPROFILE\my-policy.yaml    # set your project folder, allowed programs and domains

# Check it (Notepad saves as UTF-8, which Kill Line reads)
.\killline.exe validate-policy $env:USERPROFILE\my-policy.yaml

# Launch the agent under Kill Line (everything it starts is monitored too)
.\killline.exe run --policy $env:USERPROFILE\my-policy.yaml -- python my_agent.py
```

To watch an agent that is already running, use its process id (Task Manager → Details → PID):

```powershell
.\killline.exe monitor --policy $env:USERPROFILE\my-policy.yaml --pid 1234
```

Press **Ctrl+C** to stop monitoring. The exit code is 0 for GREEN, 3 for AMBER, 4 for GREY and 10 for RED.

## 3. A quick harmless demo

This policy allows only Python, so starting `ping` breaks it, and a DNS lookup breaks the no-network rule. The name ends in `.invalid`, which can never exist, so no server is contacted; at most your DNS resolver answers "not found".

```powershell
.\killline.exe template windows-no-network | Set-Content -Encoding ascii $env:TEMP\demo.yaml
.\killline.exe run --policy $env:TEMP\demo.yaml -- ping -n 1 killline-test.invalid
```

Expect a RED "KILL LINE TRIGGERED" banner for the unexpected program and the DNS lookup, followed by a summary with the incident ids.

## 4. Look at the results

Open **Kill Line** from the Start menu and accept the administrator prompt. The dashboard lists sessions and incidents, and it can freeze, resume or terminate a monitored agent.

From PowerShell:

```powershell
.\killline.exe sessions
.\killline.exe incidents
.\killline.exe inspect incident-2026-09-25-001
.\killline.exe verify <session-id>      # checks the tamper-evident timeline
```

Everything is stored locally in `C:\ProgramData\KillLine`. Nothing is uploaded.

## What Windows does not show yet

Kill Line on Windows sees program starts, file creates and opens, deletes and renames, TCP connections (including ones that never complete), UDP sends and DNS lookups. It does not yet see named-pipe opens (such as the Docker Engine pipe), command-line arguments, whether a file open succeeded, or token and privilege changes. Each gap is listed on the session's coverage report and in [LIMITATIONS.md](LIMITATIONS.md).

Kill Line only detects and records; it does not block. `--response freeze` or `terminate` acts after a violation has been seen.
