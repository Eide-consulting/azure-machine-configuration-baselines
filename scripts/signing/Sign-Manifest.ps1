<#
.SYNOPSIS
    Signs a manifest file with an ECDSA P-256 detached signature.

.DESCRIPTION
    Computes an ECDSA P-256/SHA-256 signature over the canonical
    (whitespace-normalised UTF-8) content of the manifest JSON and writes a
    detached signature file next to it.

    The private key should be stored as a secret (for example in Azure Key Vault
    and the GitHub secret MANIFEST_SIGNING_PRIVATE_KEY_PEM). The signature file
    is committed to version control alongside the manifest so CI can verify it
    before any deployment step proceeds.

.PARAMETER ManifestPath
    Path to the manifest JSON file to sign.

.PARAMETER PrivateKeyPem
    ECDSA private key in PEM format as a SecureString. Retrieve from the secret
    store with:

        $key = Get-Secret -Name ManifestSigningPrivateKeyPem

    Never pass a plain-text string directly; use SecureString so the value stays
    DPAPI-protected in memory until the signature computation.

.PARAMETER KeyId
    Optional key identifier embedded in the detached signature metadata.

.PARAMETER SignaturePath
    Optional override for the output signature file path.
    Defaults to <ManifestPath>.sig

.EXAMPLE
    # Retrieve the key from Azure Key Vault (see docs/KEY-MANAGEMENT.md for
    # Register-SecretVault setup) and sign the manifest:
    $key = Get-Secret -Name ManifestSigningPrivateKeyPem -Vault AzureKeyVault
    ./scripts/signing/Sign-Manifest.ps1 `
        -ManifestPath manifests/software.manifest.json `
        -PrivateKeyPem $key

.LINK
    docs/KEY-MANAGEMENT.md
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$ManifestPath,

    [Parameter(Mandatory = $true)]
    [SecureString]$PrivateKeyPem,

    [string]$KeyId,

    [string]$SignaturePath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-PlainTextFromSecureString {
    param([Parameter(Mandatory = $true)][SecureString]$Value)

    $credential = [System.Net.NetworkCredential]::new('', $Value)
    try {
        return $credential.Password
    }
    finally {
        $credential.Password = [string]::Empty
    }
}

function Get-EcdsaFromPrivateKey {
    param([Parameter(Mandatory = $true)][string]$PrivateKeyText)

    $ecdsa = [System.Security.Cryptography.ECDsa]::Create()
    if (-not ($ecdsa | Get-Member -Name 'ImportFromPem' -MemberType Method)) {
        throw 'Current PowerShell runtime does not support ECDSA ImportFromPem. Use PowerShell 7+ on .NET that supports ImportFromPem.'
    }

    $ecdsa.ImportFromPem($PrivateKeyText.ToCharArray())
    return $ecdsa
}

$privateKeyText = Get-PlainTextFromSecureString -Value $PrivateKeyPem
try {
    if ([string]::IsNullOrWhiteSpace($privateKeyText)) {
        throw 'PrivateKeyPem is empty.'
    }
}
finally {
    # no-op; the key text is used immediately below and then released.
}

$resolvedManifest = (Resolve-Path -Path $ManifestPath).Path

if ([string]::IsNullOrWhiteSpace($SignaturePath)) {
    $SignaturePath = "$resolvedManifest.sig"
}

# Parse and re-serialise to canonical (sorted-key, no extra whitespace) JSON so
# that the signature is stable regardless of formatting differences.
$manifestContent = Get-Content -Path $resolvedManifest -Raw -Encoding UTF8
$manifestObj = $manifestContent | ConvertFrom-Json

# ConvertTo-Json with -Compress removes insignificant whitespace.
# Depth 10 ensures nested structures are not truncated.
$canonicalJson = $manifestObj | ConvertTo-Json -Depth 10 -Compress

$contentBytes = [System.Text.Encoding]::UTF8.GetBytes($canonicalJson)

$ecdsa = Get-EcdsaFromPrivateKey -PrivateKeyText $privateKeyText
try {
    $signatureBytes = $ecdsa.SignData(
        $contentBytes,
        [System.Security.Cryptography.HashAlgorithmName]::SHA256
    )
}
finally {
    $ecdsa.Dispose()
}

$signatureB64 = [Convert]::ToBase64String($signatureBytes)

$sigObject = [ordered]@{
    algorithm = 'ECDSA-P256-SHA256'
    keyId     = if ([string]::IsNullOrWhiteSpace($KeyId)) { $null } else { $KeyId }
    manifest  = Split-Path -Path $resolvedManifest -Leaf
    signature = $signatureB64
    signedAt  = (Get-Date).ToUniversalTime().ToString('o')
}

$sigObject | ConvertTo-Json -Depth 5 | Set-Content -Path $SignaturePath -Encoding UTF8

Write-Host "Signed '$resolvedManifest' -> '$SignaturePath'"
