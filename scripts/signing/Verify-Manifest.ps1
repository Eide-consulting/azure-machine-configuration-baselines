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

$detachedSignatureHelperPath = Join-Path -Path $PSScriptRoot -ChildPath '../lib/Test-DetachedSignature.ps1'
if (-not (Test-Path -Path $detachedSignatureHelperPath)) {
    throw "Detached signature helper not found at '$detachedSignatureHelperPath'."
}

$detachedSignatureHelperPath = (Resolve-Path -Path $detachedSignatureHelperPath -ErrorAction Stop).Path
. $detachedSignatureHelperPath

$resolvedManifest = (Resolve-Path -Path $ManifestPath).Path

Test-DetachedSignature -TargetPath $resolvedManifest -PublicKeyPem $PublicKeyPem -ExpectedKeyId $ExpectedKeyId -SignaturePath $SignaturePath | Out-Null

Write-Host "Manifest signature verified OK: '$resolvedManifest'"
