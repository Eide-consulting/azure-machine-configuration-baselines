# Single source of truth for ECDSA P-256/SHA-256 detached-signature verification.
#
# Both scripts/signing/Verify-Manifest.ps1 (manifest) and
# scripts/machine-configuration/New-AppMachineConfigurationPackage.ps1
# (Confirm-AllowlistSignature, allowlist) dot-source this file and call
# Test-DetachedSignature instead of each carrying their own copy of the
# canonicalization / PEM-import / VerifyData logic.
#
# Keep all verification logic here so a future fix (e.g. a canonicalization
# bug) lands in exactly one place instead of being duplicated across the
# manifest and allowlist code paths.
#
# SECURITY: this file does not set Set-StrictMode or $ErrorActionPreference;
# callers own those settings. The PEM plaintext extracted from PublicKeyPem
# is never logged and is only held in memory for the duration of the
# ECDSA import/verify call.

function Test-DetachedSignature {
    <#
    .SYNOPSIS
        Verifies an ECDSA P-256/SHA-256 detached signature over a JSON control file.

    .DESCRIPTION
        Reads the target JSON file and its companion .sig envelope, then verifies
        an ECDSA P-256/SHA-256 signature over the canonical (re-serialised,
        whitespace-normalised UTF-8) content of the target file.

        Returns $true when the signature is valid. Throws a terminating error
        when the .sig file is missing, malformed, uses an unsupported algorithm,
        fails the optional keyId check, or the signature does not verify.

    .PARAMETER TargetPath
        Path to the JSON control file (manifest or allowlist) to verify.

    .PARAMETER PublicKeyPem
        ECDSA P-256 public key in PEM format as a SecureString. Must match the
        private key used to produce the signature (see Sign-Manifest.ps1).

    .PARAMETER SignaturePath
        Optional override for the signature file path. Defaults to <TargetPath>.sig

    .PARAMETER ExpectedKeyId
        Optional key identifier expected in the detached signature metadata.
        Skipped when blank or omitted.

    .EXAMPLE
        $key = Get-Secret -Name ManifestSigningPublicKeyPem
        Test-DetachedSignature -TargetPath manifests/software.manifest.json -PublicKeyPem $key
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$TargetPath,

        [Parameter(Mandatory = $true)]
        [SecureString]$PublicKeyPem,

        [string]$SignaturePath,

        [string]$ExpectedKeyId
    )

    $resolvedTarget = (Resolve-Path -Path $TargetPath).Path

    if ([string]::IsNullOrWhiteSpace($SignaturePath)) {
        $SignaturePath = "$resolvedTarget.sig"
    }

    if (-not (Test-Path -Path $SignaturePath)) {
        throw "Signature file not found: '$SignaturePath'. Sign the file with Sign-Manifest.ps1 before deploying."
    }

    $sigContent = Get-Content -Path $SignaturePath -Raw -Encoding UTF8 | ConvertFrom-Json

    if ([string]$sigContent.algorithm -ne 'ECDSA-P256-SHA256') {
        throw "Signature file '$SignaturePath' algorithm '$($sigContent.algorithm)' is not supported. Expected 'ECDSA-P256-SHA256'."
    }

    if (-not [string]::IsNullOrWhiteSpace($ExpectedKeyId) -and [string]$sigContent.keyId -ne $ExpectedKeyId) {
        throw "Signature file '$SignaturePath' keyId '$([string]$sigContent.keyId)' does not match expected keyId '$ExpectedKeyId'."
    }

    if ([string]$sigContent.manifest -ne (Split-Path -Path $resolvedTarget -Leaf)) {
        throw "Signature file '$SignaturePath' manifest field '$([string]$sigContent.manifest)' does not match target file '$resolvedTarget'."
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
    $targetContent = Get-Content -Path $resolvedTarget -Raw -Encoding UTF8
    $targetObj = $targetContent | ConvertFrom-Json
    $canonicalJson = $targetObj | ConvertTo-Json -Depth 10 -Compress

    $contentBytes = [System.Text.Encoding]::UTF8.GetBytes($canonicalJson)

    $credential = [System.Net.NetworkCredential]::new('', $PublicKeyPem)
    try {
        $publicKeyText = $credential.Password
        if ([string]::IsNullOrWhiteSpace($publicKeyText)) {
            throw 'PublicKeyPem is empty.'
        }

        $ecdsa = [System.Security.Cryptography.ECDsa]::Create()
        if (-not ($ecdsa | Get-Member -Name 'ImportFromPem' -MemberType Method)) {
            throw 'Current PowerShell runtime does not support ECDSA ImportFromPem. Use PowerShell 7+ on .NET that supports ImportFromPem.'
        }

        $ecdsa.ImportFromPem($publicKeyText.ToCharArray())
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
    }
    finally {
        $credential.Password = [string]::Empty
    }

    if (-not $isValid) {
        throw "Signature verification FAILED for '$resolvedTarget' using signature file '$SignaturePath'. The file may have been tampered with."
    }

    return $true
}
