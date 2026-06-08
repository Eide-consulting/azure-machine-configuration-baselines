# Add New Software

This guide explains the full, approved flow for adding a new application to this repository.

## Overview

The onboarding flow has two signed control points:

- `scripts/installers/package-allowlist.json`: controls which application names are approved for packaging (`allowedPackages`).
- `manifests/software.manifest.json`: defines installer metadata used by CI/package generation.

Both files must be signed after edits.

## Prerequisites

- Azure access to the target subscription and storage account.
- Access to the Key Vault secret used for signing (`ManifestSigningPrivateKeyPem`).
- `MANIFEST_SIGNING_PUBLIC_KEY_PEM` configured in GitHub repository secrets.
- Local PowerShell with required scripts available in this repo.
- Installer binary available locally so SHA256 can be computed.

For signing key setup, see `docs/KEY-MANAGEMENT.md`.

## 1. Prepare Installer Metadata

Collect:

- `name` (application identifier used in manifest and allowlist)
- `version`
- `installerPath` (path inside installer blob container, for example `packages/myapp/1.2.3/installer.exe`)
- `packageType` (`exe-silent`, `msi-silent`, `exe-args`, `msi-args`)
- `installerArgs` (only for args-based package types)
- optional `verifyPath`
- optional `configSha256` when using a companion config file

If needed, compute SHA256 manually:

```powershell
Get-FileHash -Path ./installer.exe -Algorithm SHA256
```

## 2. Approve App Name In Allowlist

Edit `scripts/installers/package-allowlist.json` and add the app name to `allowedPackages`.

Example:

```json
"allowedPackages": [
  "7zip",
  "notepadplusplus",
  "sysmon",
  "myapp"
]
```

Re-sign the allowlist:

```powershell
Connect-AzAccount
$key = Get-Secret -Name ManifestSigningPrivateKeyPem -Vault AzureKeyVault
./scripts/signing/Sign-Manifest.ps1 -ManifestPath scripts/installers/package-allowlist.json -PrivateKeyPem $key
```

Commit both files:

- `scripts/installers/package-allowlist.json`
- `scripts/installers/package-allowlist.json.sig`

## 3. Add Manifest Entry

Use the helper script (recommended):

```powershell
./scripts/New-ManifestEntry.ps1 -Name "myapp" -Version "1.2.3" -InstallerPath "./downloads/myapp-installer.exe" -ShareInstallerPath "packages/myapp/1.2.3/myapp-installer.exe" -PackageType "exe-silent" -InstallerArgs @() -VerifyPath "C:\\Program Files\\MyApp\\myapp.exe"
```

Copy the output JSON object into `manifests/software.manifest.json` under `packages`.

## 4. Validate Manifest Locally

Run structure validation:

```powershell
./scripts/Validate-Manifest.ps1 -ManifestPath manifests/software.manifest.json
```

Optional blob existence validation (recommended if blob already uploaded):

```powershell
./scripts/Validate-Manifest.ps1 -ManifestPath manifests/software.manifest.json -StorageAccountName STORAGE_ACCOUNT_NAME -ContainerName INSTALLER_CONTAINER_NAME -CheckBlobPaths
```

## 5. Upload Installer To Blob Storage

Upload installer to the same path used in `installerPath`.

If `installerPath` is `packages/myapp/1.2.3/myapp-installer.exe`, upload the file at that exact blob path.

## 6. Sign Manifest

Re-sign after any manifest change:

```powershell
Connect-AzAccount
$key = Get-Secret -Name ManifestSigningPrivateKeyPem -Vault AzureKeyVault
./scripts/signing/Sign-Manifest.ps1 -ManifestPath manifests/software.manifest.json -PrivateKeyPem $key
```

Commit both files:

- `manifests/software.manifest.json`
- `manifests/software.manifest.json.sig`

## 7. Run Packaging And Policy Workflows

Run GitHub Actions workflow `Build And Publish Machine Configuration Package` with:

- required: `applicationName`
- optional: `applicationVersion`

Then run GitHub Actions workflow `Get Policy Values` with the same app/version inputs.

Use the generated policy artifact to create or update Azure Policy definition and assignment.

The direct Assign Machine Configuration workflow is removed. Deployment is Azure Policy only.

CI verifies signatures for both manifest and allowlist before packaging.

## 8. Verify Outcome

Confirm:

- Build And Publish workflow succeeds and uploads the package.
- Get Policy Values workflow succeeds and publishes the policy artifact.
- Azure Policy definition and assignment are updated successfully.
- Target machines report policy compliance.

## Troubleshooting

- Error: `Application '<name>' is not in the installer allowlist`
  - Fix: add name to `allowedPackages`, re-sign allowlist, commit both allowlist files.
- Error: signature verification failed
  - Fix: re-sign the changed file and commit matching `.sig`.
- Error: invalid SHA256
  - Fix: recompute hash with `Get-FileHash` and update manifest.
- Error: installer not found in blob container
  - Fix: upload installer to the exact `installerPath` defined in manifest.
- Error: installerArg contains disallowed characters
  - Fix: use safe argument tokens only (no whitespace in a single arg element).

## Field Reference

Manifest package fields used by this process:

- required: `name`, `version`, `installerPath`, `sha256`, `packageType`
- recommended: `installerArgs`
- optional: `verifyPath`, `configSha256`, `rebootRequired`

`packageType` guidance:

- `exe-silent`: executable with built-in silent behavior handled by package script.
- `msi-silent`: MSI with silent behavior handled by package script.
- `exe-args`: executable requiring explicit installer arguments.
- `msi-args`: MSI requiring explicit installer arguments.

Use `verifyPath` when an executable path is a reliable install verification signal.
Use `configSha256` when a companion configuration file should trigger re-application on change.
