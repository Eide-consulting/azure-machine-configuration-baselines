<#
.SYNOPSIS
    Pester tests for Test-DetachedSignature (scripts/lib/Test-DetachedSignature.ps1).

.DESCRIPTION
    Exercises the shared ECDSA P-256/SHA-256 detached-signature verification
    function against throwaway fixtures signed with Sign-Manifest.ps1, so the
    canonicalization used here stays consistent with production signing.
#>

BeforeAll {
    . (Join-Path -Path $PSScriptRoot -ChildPath 'Test-DetachedSignature.ps1')
    $script:signManifestScript = Join-Path -Path $PSScriptRoot -ChildPath '../signing/Sign-Manifest.ps1'

    # Throwaway ECDSA P-256 key pair, used only for these tests.
    # ECDsa.Create() defaults to P-256; on some platforms Create(ECCurve) returns
    # $null (see scripts/signing/New-EcdsaKeyPair.ps1), so use the parameterless factory.
    $ecdsa = [System.Security.Cryptography.ECDsa]::Create()
    $script:privateKeyPem = $ecdsa.ExportECPrivateKeyPem()
    $script:publicKeyPem = $ecdsa.ExportSubjectPublicKeyInfoPem()
    $ecdsa.Dispose()

    # Test-only: converts a throwaway PEM string to a SecureString for calling the
    # functions under test. Not a real secret, so plaintext conversion is safe here.
    function script:ConvertTo-TestSecureString {
        [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
            'PSAvoidUsingConvertToSecureStringWithPlainText', '',
            Justification = 'Throwaway ECDSA keypair generated per test run; not a real secret.')]
        param([Parameter(Mandatory = $true)][string]$PlainText)

        ConvertTo-SecureString -String $PlainText -AsPlainText -Force
    }

    function script:Get-PublicKeySecure {
        ConvertTo-TestSecureString -PlainText $script:publicKeyPem
    }

    # Writes a small JSON fixture to $TestDrive and signs it with Sign-Manifest.ps1,
    # returning the fixture's path.
    function script:New-SignedFixture {
        param(
            [Parameter(Mandatory = $true)]
            [string]$Name,

            [hashtable]$Content = @{ name = 'sample'; version = '1.0.0' },

            [string]$KeyId
        )

        $targetPath = Join-Path -Path $TestDrive -ChildPath "$Name.json"
        $Content | ConvertTo-Json -Depth 5 | Set-Content -Path $targetPath -Encoding UTF8

        $privateKeySecure = ConvertTo-TestSecureString -PlainText $script:privateKeyPem
        $signParams = @{
            ManifestPath  = $targetPath
            PrivateKeyPem = $privateKeySecure
        }
        if (-not [string]::IsNullOrWhiteSpace($KeyId)) {
            $signParams.KeyId = $KeyId
        }

        & $script:signManifestScript @signParams | Out-Null

        return $targetPath
    }
}

Describe 'Test-DetachedSignature' {
    It 'returns $true for a valid signature' {
        $targetPath = New-SignedFixture -Name 'valid'

        Test-DetachedSignature -TargetPath $targetPath -PublicKeyPem (Get-PublicKeySecure) | Should -BeTrue
    }

    It 'throws when the target file content has been tampered with after signing' {
        $targetPath = New-SignedFixture -Name 'tampered'

        $json = (Get-Content -Path $targetPath -Raw) -replace '1\.0\.0', '9.9.9'
        Set-Content -Path $targetPath -Value $json -Encoding UTF8 -NoNewline

        { Test-DetachedSignature -TargetPath $targetPath -PublicKeyPem (Get-PublicKeySecure) } |
            Should -Throw '*tampered*'
    }

    It 'throws a path-specific error when the target file is not valid JSON' {
        $targetPath = New-SignedFixture -Name 'malformed-target'
        Set-Content -Path $targetPath -Value 'not valid json' -Encoding UTF8

        { Test-DetachedSignature -TargetPath $targetPath -PublicKeyPem (Get-PublicKeySecure) } |
            Should -Throw "Target file is not valid JSON: '$targetPath'."
    }

    It 'throws a path-specific error when the target file is missing' {
        $targetPath = Join-Path -Path $TestDrive -ChildPath 'missing-target.json'

        { Test-DetachedSignature -TargetPath $targetPath -PublicKeyPem (Get-PublicKeySecure) } |
            Should -Throw "Target file not found: '$targetPath'."
    }

    It 'throws when the signature file is missing' {
        $targetPath = Join-Path -Path $TestDrive -ChildPath 'nosig.json'
        @{ name = 'nosig'; version = '1.0.0' } | ConvertTo-Json | Set-Content -Path $targetPath -Encoding UTF8

        { Test-DetachedSignature -TargetPath $targetPath -PublicKeyPem (Get-PublicKeySecure) } |
            Should -Throw '*Signature file not found*'
    }

    It 'throws when the signature file is not valid JSON' {
        $targetPath = New-SignedFixture -Name 'malformed'
        Set-Content -Path "$targetPath.sig" -Value 'not valid json' -Encoding UTF8

        { Test-DetachedSignature -TargetPath $targetPath -PublicKeyPem (Get-PublicKeySecure) } | Should -Throw
    }

    It 'throws when the algorithm field is unsupported' {
        $targetPath = New-SignedFixture -Name 'badalgo'
        $sig = Get-Content -Path "$targetPath.sig" -Raw | ConvertFrom-Json
        $sig.algorithm = 'RSA-SHA256'
        $sig | ConvertTo-Json | Set-Content -Path "$targetPath.sig" -Encoding UTF8

        { Test-DetachedSignature -TargetPath $targetPath -PublicKeyPem (Get-PublicKeySecure) } |
            Should -Throw '*is not supported*'
    }

    It 'throws when ExpectedKeyId does not match the signature keyId' {
        $targetPath = New-SignedFixture -Name 'keyidmismatch' -KeyId 'key-a'

        { Test-DetachedSignature -TargetPath $targetPath -PublicKeyPem (Get-PublicKeySecure) -ExpectedKeyId 'key-b' } |
            Should -Throw '*does not match expected keyId*'
    }

    It 'does not validate keyId when ExpectedKeyId is not supplied' {
        $targetPath = New-SignedFixture -Name 'keyidskip' -KeyId 'key-a'

        Test-DetachedSignature -TargetPath $targetPath -PublicKeyPem (Get-PublicKeySecure) | Should -BeTrue
    }

    It 'throws when the signature value is not valid Base64' {
        $targetPath = New-SignedFixture -Name 'badbase64'
        $sig = Get-Content -Path "$targetPath.sig" -Raw | ConvertFrom-Json
        $sig.signature = 'not-valid-base64!!'
        $sig | ConvertTo-Json | Set-Content -Path "$targetPath.sig" -Encoding UTF8

        { Test-DetachedSignature -TargetPath $targetPath -PublicKeyPem (Get-PublicKeySecure) } |
            Should -Throw '*valid Base64*'
    }

    It 'honors a SignaturePath override' {
        $targetPath = New-SignedFixture -Name 'customsig'
        $defaultSigPath = "$targetPath.sig"
        $customSigPath = Join-Path -Path $TestDrive -ChildPath 'customsig.sig.json'
        Move-Item -Path $defaultSigPath -Destination $customSigPath

        Test-DetachedSignature -TargetPath $targetPath -PublicKeyPem (Get-PublicKeySecure) -SignaturePath $customSigPath |
            Should -BeTrue
    }
}
