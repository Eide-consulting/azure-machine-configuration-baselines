# Machine Configuration

Framework for deploying and maintaining Windows application baselines with Azure Machine Configuration (formerly Guest Configuration), targeting both Azure VMs and Azure Arc-enabled servers.

## What Is Implemented

- Manifest-driven application metadata (`name`, `version`, `installerPath`, `sha256`, `packageType`, `installerArgs`, optional `verifyPath`, `configSha256`, `rebootRequired`).
- Machine Configuration package generator for a selected app.
- Azure Policy-driven deployment of guestConfigurationAssignments across Azure VMs and Arc machines.
- GitHub Actions workflows for package publish and policy value generation.

## Repository Structure

- manifests/software.manifest.sample.json: Sample application manifest.
- scripts/Validate-Manifest.ps1: Manifest schema and integrity validation.
- scripts/machine-configuration/New-AppMachineConfigurationPackage.ps1: Build one Machine Configuration package from one manifest entry.
- .github/workflows/build-and-publish-package.yml: Build and publish package pipeline.
- .github/workflows/get-policy-values.yml: Generate policy payload values from a published package.
- docs/DEPLOYMENT.md: Step-by-step setup and execution.
- .githooks/pre-commit and scripts/hooks/Invoke-PreCommit.ps1: Local pre-commit checks (lint, manifest validation, signature-staleness guard, tests). See [Development](#development).

## Quick Start

1. Configure GitHub OIDC federation and set repository secrets:
    - AZURE_CLIENT_ID
    - AZURE_TENANT_ID
    - AZURE_SUBSCRIPTION_ID
2. Grant the GitHub OIDC service principal Blob data permissions on the storage account.
3. Update manifests/software.manifest.json with real app entries and SHA256 checksums.
4. Run the Build And Publish Machine Configuration Package workflow and provide `applicationName`.
5. Run the Get Policy Values workflow for the same application/version.
6. Create or update Azure Policy definition and assignment using the generated policy artifact.

For the complete and approved onboarding flow (allowlist update, manifest update, validation, and signing), see [docs/ADD-NEW-SOFTWARE.md](docs/ADD-NEW-SOFTWARE.md).

## Scale And Targeting

- Policy assignments support `Microsoft.Compute/virtualMachines`.
- Policy assignments support `Microsoft.HybridCompute/machines` (Arc-enabled).
- Roll out by assignment scope (canary resource group, then broader scopes).
- Use multiple policy assignments, tags, and exclusions to control rollout rings.

## Important Notes

- The Assign Machine Configuration workflow is removed; deployment is Azure Policy only.
- Build And Publish uploads the package and stores `contentHash` metadata used by policy deployment.
- Get Policy Values generates a ready-to-use policy payload based on the published package.
- Assignment resource name can be descriptive (for example, Install-7zip), but guestConfiguration.name must match the package/MOF name.

## Development

### Pre-commit hooks

This repo ships a version-controlled pre-commit hook that runs fast, mostly-offline checks before each commit. The checks live in `scripts/hooks/Invoke-PreCommit.ps1` and are dispatched by `.githooks/pre-commit`.

What runs on commit:

- **PSScriptAnalyzer** lint on staged `*.ps1` files (blocks the commit on `Error`-severity findings; warnings are reported but non-blocking).
- **Validate-Manifest.ps1** structural + SHA256 checks when `manifests/software.manifest.json` is staged (no Azure, no secrets required).
- **Signature-staleness guard**: if a signed control file (`manifests/software.manifest.json` or `scripts/installers/package-allowlist.json`) is staged, its companion `.sig` must also exist and be staged in the same commit. This enforces a re-sign after every change to a signed control file.
- **Verify-Manifest.ps1** signature verification, run only when the public key is provided through the `MANIFEST_SIGNING_PUBLIC_KEY_PEM` environment variable.
- **Pester** tests, run when any `*.Tests.ps1` files exist in the repo.

The security-critical checks (manifest validation and the signature-staleness guard) use only built-in PowerShell and always run. The tooling checks (PSScriptAnalyzer, Pester) warn and skip when the module is not installed, rather than hard-blocking.

#### One-time setup

Each clone activates the hook locally (this is not done automatically by Git):

```bash
git config core.hooksPath .githooks
```

Verify it is set (should print `.githooks`):

```bash
git config core.hooksPath
```

Install the optional analysis modules (PowerShell 7+):

```powershell
Install-Module PSScriptAnalyzer -Scope CurrentUser
Install-Module Pester -Scope CurrentUser -SkipPublisherCheck
```

#### Bypassing

For an intentional exception (for example, a docs-only commit), skip the hook with:

```bash
git commit --no-verify
```

To disable the hook for this clone, run `git config --unset core.hooksPath`.
