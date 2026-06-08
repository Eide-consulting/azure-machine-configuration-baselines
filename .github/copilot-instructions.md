# Copilot Instructions

## ⚠️ Security — Read First

**This repository has a high security blast radius.** The scripts here install software on a fleet of Windows machines via Azure Machine Configuration. A compromised manifest, allowlist, or signing key would allow an attacker to install arbitrary malicious software across all targeted VMs and Arc-connected servers — silently and at scale.

Security non-negotiables:
- **Never weaken or bypass signature verification.** Both `manifests/software.manifest.json` and `scripts/installers/package-allowlist.json` must be ECDSA-signed and verified before any build or deployment step. Removing or short-circuiting `Verify-Manifest.ps1` calls is not acceptable.
- **Never add secrets or private keys to source code.** Signing private keys live exclusively in Azure Key Vault and GitHub secrets.
- **Never disable `StrictMode` or `$ErrorActionPreference = 'Stop'`** — these are safety nets that prevent silent failures from leading to undetected bad deployments.
- **Never expand the installer arg pattern** (`^[a-zA-Z0-9/\\-_.=:]{1,256}$`) to allow whitespace or shell metacharacters — this is the primary guard against argument injection.
- **Treat every SHA256 value as a security control**, not just a checksum. Always compute it from the actual installer binary; never copy it from an untrusted source.
- **All changes to the manifest or allowlist require a re-sign** before they can be deployed. A stale or missing `.sig` file must be treated as a build-blocking error.

## Repository Purpose

This repo implements a framework for deploying Windows application baselines to Azure VMs and Azure Arc-enabled servers using **Azure Machine Configuration** (formerly Guest Configuration). The control plane is manifest-driven and cryptographically signed.

## Architecture

### Data flow (end-to-end)

1. **Allowlist** (`scripts/installers/package-allowlist.json`) — approved package names and installer types. Must be signed before commit.
2. **Manifest** (`manifests/software.manifest.json`) — per-package metadata: `name`, `version`, `installerPath` (blob-relative path), `sha256`, `packageType`, `installerArgs`, optional `verifyPath`, `rebootRequired`. Must be signed before commit.
3. **Validation** (`scripts/Validate-Manifest.ps1`) — structural and SHA256 checks; optionally verifies blob paths in Azure Storage with `-CheckBlobPaths`.
4. **Package build** (`scripts/machine-configuration/New-AppMachineConfigurationPackage.ps1`, run by `.github/workflows/build-and-publish-package.yml`) — produces a `.zip` GuestConfiguration package containing a MOF document and a `.metaconfig.json` (category must be `Custom`), then uploads it to blob storage with `contentHash` metadata.
5. **Policy generation** (`.github/workflows/get-policy-values.yml`) — downloads the published package and generates a ready-to-use Azure Policy `DeployIfNotExists` definition (JSON artifact) configured for system-assigned managed identity download.
6. **Deployment** — Azure Policy only. Create or update the policy definition and assignment from the generated artifact, and tag target machines with `MachineConfiguration=<app-name>`.

### Signed control files

Both `manifests/software.manifest.json` and `scripts/installers/package-allowlist.json` have companion `.sig` files committed alongside them. CI verifies both signatures before any build or deployment step. The signing algorithm is **ECDSA P-256 / SHA-256** (PowerShell 7+ required).

## Key Commands

### Validate the manifest locally (no Azure)
```powershell
./scripts/Validate-Manifest.ps1 -ManifestPath manifests/software.manifest.json
```

### Validate and check blob paths
```powershell
./scripts/Validate-Manifest.ps1 `
  -ManifestPath manifests/software.manifest.json `
  -StorageAccountName <name> `
  -ContainerName <container> `
  -CheckBlobPaths
```

### Generate a new manifest entry (outputs JSON to stdout)
```powershell
./scripts/New-ManifestEntry.ps1 `
  -Name notepadplusplus `
  -Version 8.9.3 `
  -InstallerPath path\to\local\installer.exe `
  -ShareInstallerPath packages/notepadplusplus/8.9.3/installer.exe `
  -PackageType exe-silent
```

### Sign a manifest (requires ECDSA private key as SecureString)
```powershell
$key = Get-Secret -Name ManifestSigningPrivateKeyPem -Vault AzureKeyVault
./scripts/signing/Sign-Manifest.ps1 -ManifestPath manifests/software.manifest.json -PrivateKeyPem $key
```

### Verify a manifest signature
```powershell
$key = Get-Secret -Name ManifestSigningPublicKeyPem
./scripts/signing/Verify-Manifest.ps1 -ManifestPath manifests/software.manifest.json -PublicKeyPem $key
```

## Conventions

### Manifest schema (`schemaVersion: "2.0"`)
- `packageType` must be one of: `exe-silent`, `msi-silent`, `exe-args`, `msi-args`
- `installerArgs` elements: only `[a-zA-Z0-9/\\-_.=:]`, max 256 chars, **no whitespace** (whitespace allows argument injection)
- `sha256` must be a 64-character hex string (case-insensitive in storage, uppercase in practice)
- `name`+`version` pairs must be unique within the manifest
- `installerPath` is blob-relative; backslashes are normalised to forward slashes at runtime

### Signing workflow
- **Never pass private keys as plain-text strings** — always use `SecureString`
- Signature files (`*.sig`) are committed to version control alongside their manifest
- CI re-registers SAS URIs as masked secrets (`::add-mask::`) in each new step to prevent log leakage

### PowerShell style
- All scripts use `Set-StrictMode -Version Latest` and `$ErrorActionPreference = 'Stop'`
- Scripts accept `SecureString` for any secret parameter; use `[System.Net.NetworkCredential]::new('', $value).Password` to extract plain text in-memory
- Splatting (`@params`) is preferred over long inline parameter lists

### Adding a new application (full approved flow)
See `docs/ADD-NEW-SOFTWARE.md`. In brief:
1. Add the name to `scripts/installers/package-allowlist.json` → re-sign → commit both files
2. Generate a manifest entry with `New-ManifestEntry.ps1` → append to `manifests/software.manifest.json` → re-sign → commit both files
3. Upload the installer binary to the blob container
4. Run the **Build And Publish Machine Configuration Package** workflow, then the **Get Policy Values** workflow
5. Create or update the Azure Policy definition and assignment from the generated artifact

### GitHub Actions secrets required
- `AZURE_CLIENT_ID`, `AZURE_TENANT_ID`, `AZURE_SUBSCRIPTION_ID`
- `STORAGE_ACCOUNT_NAME`, `BLOB_CONTAINER_NAME`, `INSTALLER_CONTAINER_NAME`
- `MANIFEST_SIGNING_PUBLIC_KEY_PEM` (public key for CI verification)
- Key generation and rotation: see `docs/KEY-MANAGEMENT.md` and `scripts/signing/New-EcdsaKeyPair.ps1`

### Ring-based rollout
Roll out by Azure Policy assignment scope (canary resource group → subscription → management group) and tag-based targeting (`MachineConfiguration=<app-name>`). Use separate assignments and `notScopes` exclusions per ring.

### Searching for content in files
Use built-in workspace search and direct file reads to gather the line references, rather than relying on external tools that may not be available in all environments (e.g. `jq`, `yq`).