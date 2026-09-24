# Signing and verifying Kill Line releases

Kill Line runs with administrator rights, so you should be able to prove that what you downloaded is what this repository built. Releases are produced only by [`.github/workflows/release.yml`](../.github/workflows/release.yml), never on anyone's laptop.

## What is signed

| Layer | Covers | Needs set-up? |
|---|---|---|
| **SHA256SUMS** | every file | no |
| **Sigstore (cosign) keyless signatures**: a `*.sigstore.json` bundle for each file | every file | no. Signed with the workflow's GitHub OIDC identity and recorded in the public Rekor transparency log. Public repositories only |
| **GitHub build provenance attestations** (SLSA) | every file | no. Public repositories on any plan; private ones need GitHub Enterprise Cloud |
| **Authenticode** | Windows `killline-windows-x86_64.exe`, the app, the NSIS installer, the MSI, and any shipped `.ps1` script | yes: a code-signing certificate (see below) |
| **GPG** detached signatures (`*.asc`) and `KEYS.asc` | Linux files and `SHA256SUMS` | yes: a GPG key (see below) |

Until the certificate and key are added, releases still carry checksums, Sigstore signatures and provenance, but Windows shows *Unknown publisher*.

## Verifying a download

```sh
# 1. Checksum
sha256sum --check --ignore-missing SHA256SUMS

# 2. Sigstore: signed by this repository's release workflow, from a tag
cosign verify-blob killline-linux-x86_64 \
  --bundle killline-linux-x86_64.sigstore.json \
  --certificate-identity-regexp '^https://github.com/finchygoldtail/Kill-Line/\.github/workflows/release\.yml@refs/tags/v' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com

# 3. Build provenance (GitHub CLI)
gh attestation verify killline-linux-x86_64 --repo finchygoldtail/Kill-Line

# 4. GPG (once enabled)
gpg --import KEYS.asc && gpg --verify SHA256SUMS.asc SHA256SUMS
```

On Windows (PowerShell):

```powershell
Get-AuthenticodeSignature .\Kill-Line_0.1.0_x64-setup.exe | Format-List Status, SignerCertificate
Get-FileHash .\Kill-Line_0.1.0_x64-setup.exe -Algorithm SHA256   # compare with SHA256SUMS
```

## Maintainer set-up

Add these under **Settings → Secrets and variables → Actions**. No secret is ever printed or committed. The certificate file only exists on the build machine for the duration of the job.

### Windows Authenticode

| Secret | Value |
|---|---|
| `WINDOWS_CERTIFICATE` | the code-signing certificate as a base64 `.pfx`: `[Convert]::ToBase64String([IO.File]::ReadAllBytes("cert.pfx"))` |
| `WINDOWS_CERTIFICATE_PASSWORD` | the `.pfx` password |

Ways to get a certificate:

- **SignPath Foundation**: free code signing for qualifying open-source projects. Recommended once the licence is chosen. It signs through its own service rather than a `.pfx`, so the workflow's signing step would be swapped for their GitHub action.
- **Azure Trusted Signing**: low monthly cost, trusted by Windows SmartScreen, keyless in CI (Microsoft's signing action).
- **An OV or EV certificate from a CA** (DigiCert, Sectigo, SSL.com, …). Since 2023 these keys must live in hardware or a cloud HSM, so a plain `.pfx` is only possible with some CAs' cloud options. Check with your CA.

Timestamps use `http://timestamp.digicert.com`, so signatures stay valid after the certificate expires.

### GPG for Linux files

```sh
gpg --quick-generate-key "Kill Line Releases <releases@your-domain>" ed25519 sign 2y
gpg --armor --export-secret-keys <KEYID>     # → secret GPG_PRIVATE_KEY
# set GPG_PASSPHRASE if the key has one; publish the public key (it is also attached as KEYS.asc)
```

### Making a release

```sh
git tag -s v0.2.0 -m "Kill Line 0.2.0"    # a signed tag
git push origin v0.2.0
```

The workflow builds on clean GitHub runners, signs, attests, and creates a **draft** release. Review it before publishing. A change to the workflow on a branch runs the same pipeline as a dry run, without publishing.

### Signed commits and tags

Contributors are encouraged to sign commits (`git config commit.gpgsign true`, with SSH or GPG). Maintainers should sign release tags. You can require signed commits on the default branch under **Settings → Branches → branch protection**.

## Not yet

- Linux repository signing (an apt repository with a signed `Release` file) for `apt install` updates.
- Auto-update. Tauri's updater would use its own minisign key; updates will be opt-in.
- macOS notarisation (with the macOS version).
