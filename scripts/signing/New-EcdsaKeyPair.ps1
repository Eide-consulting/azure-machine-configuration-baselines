<#
.SYNOPSIS
    Generate an ECDSA P-256 key pair and store in Azure Key Vault.

.DESCRIPTION
    Creates a new ECDSA P-256 private/public key pair using OpenSSL (or .NET if available),
    validates it with a test signature/verification round-trip, and stores both PEM
    values as secrets in Azure Key Vault.

    This script is a one-time setup step for asymmetric manifest signing.

.PARAMETER VaultName
    Azure Key Vault name where secrets will be stored.

.PARAMETER PrivateSecretName
    Key Vault secret name for the private key PEM. Defaults to 'ManifestSigningPrivateKeyPem'.

.PARAMETER PublicSecretName
    Key Vault secret name for the public key PEM. Defaults to 'ManifestSigningPublicKeyPem'.

.PARAMETER KeyId
    Optional key identifier to embed in signatures (e.g., 'prod-2026-04-19').

.EXAMPLE
    ./scripts/signing/New-EcdsaKeyPair.ps1 `
        -VaultName 'kv-machine-config-prod' `
        -PrivateSecretName 'ManifestSigningPrivateKeyPem' `
        -PublicSecretName 'ManifestSigningPublicKeyPem'
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$VaultName,

    [string]$PrivateSecretName = 'ManifestSigningPrivateKeyPem',
    [string]$PublicSecretName = 'ManifestSigningPublicKeyPem',
    [string]$KeyId
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Write-Host "Generating ECDSA P-256 key pair..."

# Try .NET first (PowerShell 7+/.NET 6+); fall back to OpenSSL on macOS
$privatePem = $null
$publicPem = $null

# Attempt 1: Use .NET ECDsaCng directly (Windows CNG, most reliable on Windows PS7)
try {
    $ecdsa = [System.Security.Cryptography.ECDsaCng]::new(256)
    $privatePem = $ecdsa.ExportECPrivateKeyPem()
    $publicPem = $ecdsa.ExportSubjectPublicKeyInfoPem()
    $ecdsa.Dispose()
    Write-Host "Key pair generated with .NET ECDsaCng."
}
catch {
    Write-Host "Note: ECDsaCng unavailable ($($_.Exception.Message)); trying ECDsa factory."
}

# Attempt 2: Use ECDsa factory with named curve
if ([string]::IsNullOrWhiteSpace($privatePem)) {
    try {
        $curve = [System.Security.Cryptography.ECCurve]::NamedCurves.nistP256
        $ecdsa = [System.Security.Cryptography.ECDsa]::Create($curve)
        if ($null -ne $ecdsa) {
            $privatePem = $ecdsa.ExportECPrivateKeyPem()
            $publicPem = $ecdsa.ExportSubjectPublicKeyInfoPem()
            $ecdsa.Dispose()
            Write-Host "Key pair generated with .NET ECDsa."
        }
        else {
            Write-Host "Note: ECDsa.Create() returned null; falling back to OpenSSL."
        }
    }
    catch {
        Write-Host "Note: ECDsa.Create() failed ($($_.Exception.Message)); falling back to OpenSSL."
    }
}

# Attempt 3: Use OpenSSL if all .NET paths failed
if ([string]::IsNullOrWhiteSpace($privatePem) -or $null -eq $privatePem) {
    Write-Host "Generating key pair with OpenSSL..."

    # Capture private key PEM directly from stdout — no file touches disk.
    # 'openssl genpkey' writes PEM to stdout when -out is omitted.
    $rawLines = & openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 2>&1
    # Separate stderr diagnostics (strings starting with non-PEM content) from the PEM output.
    $privatePem = ($rawLines | Where-Object { $_ -is [string] } | Out-String).Trim()

    if ([string]::IsNullOrWhiteSpace($privatePem) -or -not $privatePem.Contains('PRIVATE KEY')) {
        throw "OpenSSL failed to generate private key via stdout."
    }

    # Derive public key from the in-memory private key via stdin/stdout pipeline.
    $publicPem = ($privatePem | & openssl pkey -pubout 2>&1 | Where-Object { $_ -is [string] } | Out-String).Trim()

    if ([string]::IsNullOrWhiteSpace($publicPem) -or -not $publicPem.Contains('PUBLIC KEY')) {
        throw "OpenSSL failed to extract public key via stdout pipeline."
    }

    Write-Host "Key pair generated with OpenSSL (no disk writes)."
}

if ([string]::IsNullOrWhiteSpace($privatePem) -or [string]::IsNullOrWhiteSpace($publicPem)) {
    throw "Failed to generate key pair. Ensure OpenSSL is installed or upgrade PowerShell/.NET."
}

Write-Host "Key pair generated successfully."

# Validate key pair with round-trip sign/verify
Write-Host "Validating key pair with test signature..."

try {
    # Import private key for signing
    $ecdsa = [System.Security.Cryptography.ECDsa]::Create()
    if (-not ($ecdsa | Get-Member -Name 'ImportFromPem' -MemberType Method)) {
        Write-Warning "ECDsa.ImportFromPem not available; skipping validation."
    }
    else {
        $ecdsa.ImportFromPem($privatePem.ToCharArray())
        
        $testData = [System.Text.Encoding]::UTF8.GetBytes('test-data-for-validation')
        $signature = $ecdsa.SignData($testData, [System.Security.Cryptography.HashAlgorithmName]::SHA256)
        $ecdsa.Dispose()
        
        # Import public key for verification
        $ecdsaPublic = [System.Security.Cryptography.ECDsa]::Create()
        $ecdsaPublic.ImportFromPem($publicPem.ToCharArray())
        
        $isValid = $ecdsaPublic.VerifyData($testData, $signature, [System.Security.Cryptography.HashAlgorithmName]::SHA256)
        $ecdsaPublic.Dispose()
        
        if (-not $isValid) {
            throw "Test signature verification failed."
        }
        
        Write-Host "✓ Key pair validation passed."
    }
}
catch {
    throw "Key pair round-trip validation failed: $_. The generated key pair has NOT been stored. Aborting."
}

# Store in Azure Key Vault
Write-Host "`nConnecting to Secret vault '$VaultName'..."

# Confirm vault is registered via SecretManagement
$registeredVault = Get-SecretVault -Name $VaultName -ErrorAction SilentlyContinue
if ($null -eq $registeredVault) {
    throw "Secret vault '$VaultName' not found. Verify the vault name is registered (Get-SecretVault) and accessible."
}
Write-Host "✓ Found vault: $($registeredVault.Name)"

Write-Host "Storing private key PEM as secret '$PrivateSecretName'..."
Set-Secret `
    -Name $PrivateSecretName `
    -Secret (ConvertTo-SecureString -String $privatePem -AsPlainText -Force) `
    -Vault $VaultName `
    -ErrorAction Stop
Write-Host "✓ Stored private key."

Write-Host "Storing public key PEM as secret '$PublicSecretName'..."
Set-Secret `
    -Name $PublicSecretName `
    -Secret (ConvertTo-SecureString -String $publicPem -AsPlainText -Force) `
    -Vault $VaultName `
    -ErrorAction Stop
Write-Host "✓ Stored public key."

# Output values for GitHub Actions secrets
Write-Host "`n=== GitHub Actions Secrets ===" 
Write-Host "Add these to your GitHub repository secrets:"
Write-Host ""
Write-Host "1. Go to: Settings → Secrets and variables → Actions"
Write-Host "2. Create or update these secrets:"
Write-Host ""
Write-Host "Secret: MANIFEST_SIGNING_PUBLIC_KEY_PEM"
Write-Host "Value:"
Write-Host $publicPem
Write-Host ""
Write-Host "✓ Key pair generation complete."
