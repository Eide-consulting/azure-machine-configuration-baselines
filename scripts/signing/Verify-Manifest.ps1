<#
.SYNOPSIS
    Verifies the ECDSA P-256 detached signature of a manifest file.

.DESCRIPTION
    Reads the manifest JSON and its companion .sig file, verifies an
    ECDSA P-256/SHA-256 signature over the canonical manifest content.

    Throws a terminating error if the signature is absent, malformed, or invalid.
    Call this script as an early gate in CI pipelines and in any script that
    consumes the manifest before build or deployment.

.PARAMETER ManifestPath
    Path to the manifest JSON file to verify.

.PARAMETER PublicKeyPem
    ECDSA public key in PEM format as a SecureString. Retrieve from the secret
    store with:

        $key = Get-Secret -Name ManifestSigningPublicKeyPem

    Must match the private key used by Sign-Manifest.ps1.

.PARAMETER ExpectedKeyId
    Optional key identifier expected in the detached signature metadata.

.PARAMETER SignaturePath
    Optional override for the signature file path.
    Defaults to <ManifestPath>.sig

.EXAMPLE
    $key = Get-Secret -Name ManifestSigningPublicKeyPem
    ./scripts/signing/Verify-Manifest.ps1 `
        -ManifestPath manifests/software.manifest.json `
        -PublicKeyPem $key
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$ManifestPath,

    [Parameter(Mandatory = $true)]
    [SecureString]$PublicKeyPem,

    [string]$ExpectedKeyId,

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

function Get-EcdsaFromPublicKey {
    param([Parameter(Mandatory = $true)][string]$PublicKeyText)

    $ecdsa = [System.Security.Cryptography.ECDsa]::Create()
    if (-not ($ecdsa | Get-Member -Name 'ImportFromPem' -MemberType Method)) {
        throw 'Current PowerShell runtime does not support ECDSA ImportFromPem. Use PowerShell 7+ on .NET that supports ImportFromPem.'
    }

    $ecdsa.ImportFromPem($PublicKeyText.ToCharArray())
    return $ecdsa
}

$publicKeyText = Get-PlainTextFromSecureString -Value $PublicKeyPem
try {
    if ([string]::IsNullOrWhiteSpace($publicKeyText)) {
        throw 'PublicKeyPem is empty.'
    }
}
finally {
    # no-op; key text is consumed immediately.
}

$resolvedManifest = (Resolve-Path -Path $ManifestPath).Path

if ([string]::IsNullOrWhiteSpace($SignaturePath)) {
    $SignaturePath = "$resolvedManifest.sig"
}

if (-not (Test-Path -Path $SignaturePath)) {
    throw "Signature file not found: '$SignaturePath'. Sign the manifest with Sign-Manifest.ps1 before deploying."
}

$sigContent = Get-Content -Path $SignaturePath -Raw -Encoding UTF8 | ConvertFrom-Json

if ([string]$sigContent.algorithm -ne 'ECDSA-P256-SHA256') {
    throw "Signature file '$SignaturePath' algorithm '$($sigContent.algorithm)' is not supported. Expected 'ECDSA-P256-SHA256'."
}

if (-not [string]::IsNullOrWhiteSpace($ExpectedKeyId) -and [string]$sigContent.keyId -ne $ExpectedKeyId) {
    throw "Signature file '$SignaturePath' keyId '$([string]$sigContent.keyId)' does not match expected keyId '$ExpectedKeyId'."
}

if ([string]$sigContent.manifest -ne (Split-Path -Path $resolvedManifest -Leaf)) {
    throw "Signature file '$SignaturePath' manifest field '$([string]$sigContent.manifest)' does not match target manifest '$resolvedManifest'."
}

$storedSignature = [string]$sigContent.signature
if ([string]::IsNullOrWhiteSpace($storedSignature)) {
    throw "Signature file '$SignaturePath' does not contain a signature value."
}

try {
    $signatureBytes = [Convert]::FromBase64String($storedSignature)
}
catch {
    throw "Signature file '$SignaturePath' does not contain a valid Base64 ECDSA signature."
}

# Recompute over canonical JSON (same logic as Sign-Manifest.ps1).
$manifestContent = Get-Content -Path $resolvedManifest -Raw -Encoding UTF8
$manifestObj = $manifestContent | ConvertFrom-Json
$canonicalJson = $manifestObj | ConvertTo-Json -Depth 10 -Compress

$contentBytes = [System.Text.Encoding]::UTF8.GetBytes($canonicalJson)

$ecdsa = Get-EcdsaFromPublicKey -PublicKeyText $publicKeyText
try {
    $isValid = $ecdsa.VerifyData(
        $contentBytes,
        $signatureBytes,
        [System.Security.Cryptography.HashAlgorithmName]::SHA256
    )
}
finally {
    $ecdsa.Dispose()
}

if (-not $isValid) {
    throw "Manifest signature verification FAILED for '$resolvedManifest'. The manifest may have been tampered with."
}

Write-Host "Manifest signature verified OK: '$resolvedManifest'"
