# Manifest Signing Key Management

The manifest and allowlist are signed with an ECDSA P-256 private key and
verified with the corresponding public key. The private key stays in CI/local
signing environments only. VMs and verification jobs use only the public key.
This guide covers storing both PEM values in Azure Key Vault and retrieving
them locally without writing private key material to files.

For the complete operator flow to add a new application (including allowlist updates and both signing steps), see [ADD-NEW-SOFTWARE.md](ADD-NEW-SOFTWARE.md).

---

## 1. One-time workstation setup

Install the PowerShell SecretManagement framework and the Azure Key Vault
provider:

```powershell
Install-Module -Name Microsoft.PowerShell.SecretManagement -Scope CurrentUser -Force
Install-Module -Name Az.KeyVault                           -Scope CurrentUser -Force
```

> These modules only need to be installed once per workstation.

---

## 2. Register the Key Vault as a local secret vault

Run this once per workstation (and once per new team member):

```powershell
Connect-AzAccount

Register-SecretVault `
    -Name 'AzureKeyVault' `
    -ModuleName Az.KeyVault `
    -VaultParameters @{ AZKVaultName = '<your-keyvault-name>' } `
    -DefaultVault
```

Verify the vault is reachable:

```powershell
Get-SecretInfo -Vault AzureKeyVault
```

## 3. Create ECDSA key pair in Azure Key Vault

Use the included key generation helper script to create an ECDSA P-256 key pair
and store both PEM values as Key Vault secrets:

```powershell
Connect-AzAccount

./scripts/signing/New-EcdsaKeyPair.ps1 `
    -VaultName 'kv-machine-config-prod' `
    -PrivateSecretName 'ManifestSigningPrivateKeyPem' `
    -PublicSecretName 'ManifestSigningPublicKeyPem'
```

This script:

- Attempts to generate keys using .NET if available (PowerShell 7+/.NET 6+)
- Falls back to OpenSSL if .NET is unavailable (works on macOS)
- Validates the key pair with a test signature round-trip
- Stores private and public keys as Key Vault secrets
- Outputs values for GitHub Actions secrets

### After generating the key pair

1. Copy the printed private and public key PEM values.
2. Add them to GitHub repository secrets:
   - Settings → Secrets and variables → Actions
   - New repository secret: `MANIFEST_SIGNING_PUBLIC_KEY_PEM` (paste public key PEM)

---

---

## 4. Sign the manifest

After any change to `manifests/software.manifest.json`:

```powershell
Connect-AzAccount   # skip if already authenticated in this session

$key = Get-Secret -Name ManifestSigningPrivateKeyPem -Vault AzureKeyVault
# $key is a SecureString — the plain value is never exposed in your session.

./scripts/signing/Sign-Manifest.ps1 `
    -ManifestPath manifests/software.manifest.json `
    -PrivateKeyPem $key

git add manifests/software.manifest.json manifests/software.manifest.json.sig
git commit -m "chore: re-sign manifest"
git push
```

CI will fail with a clear error if `software.manifest.json.sig` is absent,
stale, or was produced with a different key.

---

## 4a. Sign the package allowlist

The file `scripts/installers/package-allowlist.json` controls which application
names are permitted to be packaged. It is signed with the same key and verified
by CI and by `New-AppMachineConfigurationPackage.ps1` at build time.

After any change to `scripts/installers/package-allowlist.json`:

```powershell
Connect-AzAccount   # skip if already authenticated in this session

$key = Get-Secret -Name ManifestSigningPrivateKeyPem -Vault AzureKeyVault

./scripts/signing/Sign-Manifest.ps1 `
    -ManifestPath scripts/installers/package-allowlist.json `
    -PrivateKeyPem $key

git add scripts/installers/package-allowlist.json scripts/installers/package-allowlist.json.sig
git commit -m "chore: re-sign package allowlist"
git push
```

CI will fail at the "Verify allowlist signature" step if the `.sig` file is
absent, stale, or was produced with a different key.

When onboarding a new app, follow the full sequence in [ADD-NEW-SOFTWARE.md](ADD-NEW-SOFTWARE.md) so allowlist and manifest updates stay in sync.

---

## 5. Key rotation

1. Generate and store a new key pair in Key Vault using step 2 above.
2. Update GitHub secret `MANIFEST_SIGNING_PUBLIC_KEY_PEM`.
3. Re-sign the manifest using step 4 above and commit both files.
4. Re-sign the package allowlist using step 4a above and commit both files.

Disable old secrets in Key Vault once new signatures are merged and CI passes.

---

## 6. Access control

Grant Key Vault read access only to the team members who are authorised to sign
manifests. Signers need access to the private-key secret, while verifiers only
need public-key secret access.

```powershell
New-AzRoleAssignment `
    -ObjectId '<user-or-group-object-id>' `
    -RoleDefinitionName 'Key Vault Secrets User' `
    -Scope "/subscriptions/<sub-id>/resourceGroups/<rg>/providers/Microsoft.KeyVault/vaults/<vault>"
```

`Key Vault Secrets User` allows `get` (read values) but not `set` (write
secrets). Use `Key Vault Secrets Officer` for the person responsible for key
rotation.  
CI signature verification uses the `MANIFEST_SIGNING_PUBLIC_KEY_PEM` GitHub secret.
In Azure Policy-only deployment, target machines do not need Key Vault read access
to the manifest public key.


---

## Note for forkers

The `.sig` files are **not included** in this public repository. Before running
CI workflows you must:

1. Generate your own ECDSA P-256 key pair (see step 2–3 above).
2. Sign both `manifests/software.manifest.json` and
   `scripts/installers/package-allowlist.json` with your private key.
3. Commit both `.sig` files alongside the manifests.
4. Add `MANIFEST_SIGNING_PUBLIC_KEY_PEM` to your GitHub repository secrets.
