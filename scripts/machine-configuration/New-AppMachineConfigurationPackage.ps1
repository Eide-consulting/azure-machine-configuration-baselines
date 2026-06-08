[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$ApplicationName,

    [Parameter(Mandatory = $true)]
    [string]$ApplicationVersion,

    [Parameter(Mandatory = $true)]
    [string]$InstallerPath,

    [Parameter(Mandatory = $true)]
    [string]$InstallerSha256,

    [string]$ConfigSha256,

    [Parameter(Mandatory = $true)]
    [ValidateSet('exe-silent', 'msi-silent', 'exe-args', 'msi-args')]
    [string]$InstallerType,

    [string[]]$InstallerArgs = @(),

    [string]$VerifyPath,

    [bool]$RebootRequired = $false,

    [string]$PackageName,
    [string]$OutputDirectory = './out/machine-configuration',
    [ValidateSet('Audit', 'AuditAndSet')]
    [string]$PackageType = 'AuditAndSet',

    # ECDSA P-256 public key in PEM format used to verify allowlist signatures.
    # When provided, the allowlist must have a valid detached signature; if the .sig file is
    # absent, the script aborts rather than silently trusting an unsigned allowlist.
    [SecureString]$AllowlistPublicKeyPem,

    # Pass this switch when the allowlist signature has already been cryptographically verified
    # by a prior step (e.g. the CI workflow's dedicated 'Verify allowlist signature' step).
    # Mutually exclusive with AllowlistPublicKeyPem. One of the two must be supplied.
    [switch]$AllowlistPreVerified

)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# PS7 strict mode: $null.Count throws whereas PS5.1 silently returns 0.
# Normalise here so all subsequent code can safely use $InstallerArgs.Count.
if ($null -eq $InstallerArgs) { $InstallerArgs = [string[]]@() }

function Get-SafeName {
    param([Parameter(Mandatory = $true)][string]$Value)

    $safe = $Value.ToLowerInvariant() -replace '[^a-z0-9-]', '-'
    $safe = $safe -replace '-{2,}', '-'
    $safe = $safe.Trim('-')
    if ([string]::IsNullOrWhiteSpace($safe)) {
        return 'app'
    }

    return $safe
}

function Ensure-GuestConfigurationModule {
    if (-not (Get-Module -ListAvailable -Name GuestConfiguration)) {
        throw 'PowerShell module GuestConfiguration is not installed. Install with: Install-Module GuestConfiguration -Scope CurrentUser -Force'
    }

    Import-Module GuestConfiguration -ErrorAction Stop
}

function Ensure-PsDscResourcesModule {
    if (-not (Get-Module -ListAvailable -Name PSDscResources)) {
        throw 'PowerShell module PSDscResources is not installed. Install with: Install-Module PSDscResources -Scope CurrentUser -Force'
    }
}

function Ensure-ZipFileType {
    if (-not ('System.IO.Compression.ZipFile' -as [type])) {
        Add-Type -AssemblyName 'System.IO.Compression.FileSystem'
    }

    if (-not ('System.IO.Compression.ZipFile' -as [type])) {
        Add-Type -AssemblyName 'System.IO.Compression'
    }

    if (-not ('System.IO.Compression.ZipFile' -as [type])) {
        throw 'Unable to load type System.IO.Compression.ZipFile. Ensure .NET compression assemblies are available on the runner.'
    }
}

# Verifies the ECDSA P-256 signature of the allowlist JSON file.
function Confirm-AllowlistSignature {
    param(
        [Parameter(Mandatory = $true)]
        [string]$AllowlistPath,

        [Parameter(Mandatory = $true)]
        [SecureString]$PublicKeyPem
    )

    $sigPath = "$AllowlistPath.sig"
    if (-not (Test-Path -Path $sigPath)) {
        throw "Allowlist signature file not found: '$sigPath'. Sign the allowlist with Sign-Manifest.ps1 before deploying."
    }

    $credential = [System.Net.NetworkCredential]::new('', $PublicKeyPem)
    try {
        $publicKeyText = $credential.Password
        if ([string]::IsNullOrWhiteSpace($publicKeyText)) {
            throw 'AllowlistPublicKeyPem is empty.'
        }
    }
    finally {
        $credential.Password = [string]::Empty
    }

    $sigContent = Get-Content -Path $sigPath -Raw -Encoding UTF8 | ConvertFrom-Json
    if ([string]$sigContent.algorithm -ne 'ECDSA-P256-SHA256') {
        throw "Allowlist signature file '$sigPath' algorithm '$($sigContent.algorithm)' is not supported. Expected 'ECDSA-P256-SHA256'."
    }

    if ([string]$sigContent.manifest -ne (Split-Path -Path $AllowlistPath -Leaf)) {
        throw "Allowlist signature file '$sigPath' manifest field '$([string]$sigContent.manifest)' does not match target allowlist path '$AllowlistPath'."
    }

    $storedSig = [string]$sigContent.signature
    if ([string]::IsNullOrWhiteSpace($storedSig)) {
        throw "Allowlist signature file '$sigPath' does not contain a signature value."
    }

    try {
        $signatureBytes = [Convert]::FromBase64String($storedSig)
    }
    catch {
        throw "Allowlist signature file '$sigPath' does not contain a valid Base64 ECDSA signature."
    }

    $allowlistContent = Get-Content -Path $AllowlistPath -Raw -Encoding UTF8
    $allowlistObj = $allowlistContent | ConvertFrom-Json
    $canonicalJson = $allowlistObj | ConvertTo-Json -Depth 10 -Compress
    $contentBytes = [System.Text.Encoding]::UTF8.GetBytes($canonicalJson)

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

    if (-not $isValid) {
        throw "Allowlist signature verification FAILED for '$AllowlistPath'. The allowlist may have been tampered with."
    }

    Write-Host "Allowlist signature verified OK: '$AllowlistPath'"
}

if ([string]::IsNullOrWhiteSpace($PackageName)) {
    $PackageName = "mc-$ApplicationName"
}

$InstallerPath = $InstallerPath.Trim()

if ($InstallerSha256 -notmatch '^[A-Fa-f0-9]{64}$') {
    throw 'InstallerSha256 must be a 64-character SHA256 hex string.'
}

if ((-not [string]::IsNullOrWhiteSpace($ConfigSha256)) -and ($ConfigSha256 -notmatch '^[A-Fa-f0-9]{64}$')) {
    throw 'ConfigSha256 must be a 64-character SHA256 hex string when provided.'
}

if ($InstallerPath -notmatch '^https://') {
    throw "InstallerPath must be an HTTPS URL. Received: $InstallerPath"
}

try {
    $packageVersion = ([version]$ApplicationVersion).ToString()
}
catch {
    throw "ApplicationVersion must be a valid semantic version for Guest Configuration packaging. Received: $ApplicationVersion"
}

# Verify the application is in the approved installer allowlist.
if ($AllowlistPreVerified -and $null -ne $AllowlistPublicKeyPem) {
    throw 'Pass either -AllowlistPreVerified or -AllowlistPublicKeyPem, not both.'
}

$allowlistPath = Join-Path -Path $PSScriptRoot -ChildPath '../installers/package-allowlist.json'
if (Test-Path -Path $allowlistPath) {
    if ($null -ne $AllowlistPublicKeyPem) {
        Confirm-AllowlistSignature -AllowlistPath $allowlistPath -PublicKeyPem $AllowlistPublicKeyPem
    }
    elseif ($AllowlistPreVerified) {
        Write-Host "Allowlist signature pre-verified by a prior pipeline step; skipping inline ECDSA check."
    }
    else {
        throw "Allowlist integrity verification is required. Pass -AllowlistPublicKeyPem (inline verification) or -AllowlistPreVerified (when a prior step has already verified the signature)."
    }
    $allowlist = Get-Content -Path $allowlistPath -Raw | ConvertFrom-Json
    $allowedNames = @($allowlist.allowedPackages) | ForEach-Object { $_.ToLowerInvariant() }
    if ($ApplicationName.ToLowerInvariant() -notin $allowedNames) {
        throw "Application '$ApplicationName' is not in the installer allowlist. Add it to scripts/installers/package-allowlist.json after review."
    }
}

# Validate every installer argument: only safe characters, no whitespace (spaces would allow argument injection).
$safeArgPattern = '^[a-zA-Z0-9/\\\-_\.=:]{1,256}$'
foreach ($arg in $InstallerArgs) {
    if ($arg -notmatch $safeArgPattern) {
        throw "InstallerArg '$arg' contains disallowed characters. Each argument must match: $safeArgPattern"
    }
}

$safeAppName = Get-SafeName -Value $ApplicationName
$safePackageName = Get-SafeName -Value $PackageName
# The DSC configuration name must be a valid PowerShell identifier (must start with a letter).
# Use the package name (e.g. mc-7zip) which is always prefixed. The guestConfiguration.name in
# the policy must match this value so the GC agent resolves '<name>.mof' inside the package.
$configName = $safePackageName

$resolvedOutputDirectory = $OutputDirectory
if (-not (Test-Path -Path $resolvedOutputDirectory)) {
    New-Item -Path $resolvedOutputDirectory -ItemType Directory -Force | Out-Null
}

$resolvedOutputDirectory = (Resolve-Path -Path $resolvedOutputDirectory).Path
$packageRoot = Join-Path -Path $resolvedOutputDirectory -ChildPath "$safeAppName/$ApplicationVersion"
$compiledPath = Join-Path -Path $packageRoot -ChildPath 'compiled'

New-Item -Path $compiledPath -ItemType Directory -Force | Out-Null

Ensure-GuestConfigurationModule
Ensure-PsDscResourcesModule
Ensure-ZipFileType

$appNameLiteral = $ApplicationName.Replace("'", "''")
$appVersionLiteral = $ApplicationVersion.Replace("'", "''")
$installerPathLiteral = $InstallerPath.Replace("'", "''")
$installerHashLiteral = $InstallerSha256.ToLowerInvariant()
$configHashLiteral = if ([string]::IsNullOrWhiteSpace($ConfigSha256)) { '' } else { $ConfigSha256.ToLowerInvariant() }
$installerTypeLiteral = $InstallerType
$rawArgsJson = if ($InstallerArgs.Count -gt 0) { $InstallerArgs | ConvertTo-Json -Compress } else { '[]' }
$installerArgsJsonLiteral = $rawArgsJson.Replace("'", "''")
$verifyPathLiteral = if ([string]::IsNullOrWhiteSpace($VerifyPath)) { '' } else { $VerifyPath.Replace("'", "''") }
$rebootRequiredLiteral = if ($RebootRequired) { 'True' } else { 'False' }

$configurationScript = @"
configuration $configName {
    Import-DscResource -ModuleName PSDscResources

    Node localhost {
        Script ApplicationInstall {
            GetScript = {
                `$statePath = 'C:\ProgramData\MachineConfiguration\InstalledApps\$safeAppName.json'
                if (-not (Test-Path -Path `$statePath)) {
                    return @{ Result = 'Absent' }
                }

                if ('$safeAppName' -eq 'sysmon') {
                    `$sysmonService = Get-Service -Name 'Sysmon', 'Sysmon64' -ErrorAction SilentlyContinue | Select-Object -First 1
                    if (`$null -eq `$sysmonService) {
                        return @{ Result = 'Absent' }
                    }
                }

                `$state = Get-Content -Path `$statePath -Raw | ConvertFrom-Json
                return @{ Result = "`$(`$state.version)" }
            }

            TestScript = {
                `$statePath = 'C:\ProgramData\MachineConfiguration\InstalledApps\$safeAppName.json'
                if (-not (Test-Path -Path `$statePath)) {
                    return `$false
                }

                if ('$safeAppName' -eq 'sysmon') {
                    `$sysmonService = Get-Service -Name 'Sysmon', 'Sysmon64' -ErrorAction SilentlyContinue | Select-Object -First 1
                    if (`$null -eq `$sysmonService) {
                        return `$false
                    }
                }

                `$state = Get-Content -Path `$statePath -Raw | ConvertFrom-Json
                if ([string]`$state.version -ne '$appVersionLiteral') {
                    return `$false
                }

                if (-not [string]::IsNullOrWhiteSpace('$verifyPathLiteral')) {
                    if (-not (Test-Path -Path '$verifyPathLiteral')) {
                        return `$false
                    }
                }

                if (-not [string]::IsNullOrWhiteSpace('$configHashLiteral')) {
                    if ('$safeAppName' -eq 'sysmon') {
                        `$sysmonConfigCandidates = @('C:\Windows\Sysmon64.xml', 'C:\Windows\Sysmon.xml')
                        `$sysmonConfigPath = `$sysmonConfigCandidates | Where-Object { Test-Path -Path `$_ } | Select-Object -First 1
                        if ([string]::IsNullOrWhiteSpace(`$sysmonConfigPath)) {
                            # Active config not on disk; check the companion file staged beside the installer.
                            `$argsForTest = [string[]]('$installerArgsJsonLiteral' | ConvertFrom-Json)
                            if (`$null -eq `$argsForTest) { `$argsForTest = [string[]]@() }
                            `$cIdx = [Array]::IndexOf(`$argsForTest, '/c')
                            if (`$cIdx -lt 0 -or `$cIdx -ge `$argsForTest.Count - 1) {
                                # Also check /i position for packages built before migration to /c
                                `$cIdx = [Array]::IndexOf([string[]]`$argsForTest, '/i')
                            }
                            if (`$cIdx -lt 0 -or `$cIdx -ge `$argsForTest.Count - 1) {
                                return `$false
                            }
                            `$rawConfigPath = [string]`$argsForTest[`$cIdx + 1]
                            `$installerDirForTest = 'C:\ProgramData\MachineConfiguration\Installers'
                            `$resolvedConfigPath = if ([System.IO.Path]::IsPathRooted(`$rawConfigPath)) {
                                `$rawConfigPath
                            } else {
                                Join-Path -Path `$installerDirForTest -ChildPath `$rawConfigPath
                            }
                            if (-not (Test-Path -Path `$resolvedConfigPath)) {
                                return `$false
                            }
                            `$actualConfigHash = (Get-FileHash -Path `$resolvedConfigPath -Algorithm SHA256).Hash.ToLowerInvariant()
                            if (`$actualConfigHash -ne '$configHashLiteral') {
                                return `$false
                            }
                        }
                        else {
                            `$actualConfigHash = (Get-FileHash -Path `$sysmonConfigPath -Algorithm SHA256).Hash.ToLowerInvariant()
                            if (`$actualConfigHash -ne '$configHashLiteral') {
                                return `$false
                            }
                        }
                    }
                    else {
                        `$configHashProperty = `$state.PSObject.Properties['configSha256']
                        `$actualConfigHash = if (`$null -eq `$configHashProperty) { '' } else { [string]`$configHashProperty.Value }
                        if ([string]::IsNullOrWhiteSpace(`$actualConfigHash) -or `$actualConfigHash.ToLowerInvariant() -ne '$configHashLiteral') {
                            return `$false
                        }
                    }
                }

                return `$true
            }

            SetScript = {
                `$installer = '$installerPathLiteral'
                `$expectedHash = '$installerHashLiteral'
                `$expectedConfigHash = '$configHashLiteral'
                `$appName = '$appNameLiteral'
                `$appVersion = '$appVersionLiteral'
                `$packageType = '$installerTypeLiteral'
                `$installerArgs = [string[]]('$installerArgsJsonLiteral' | ConvertFrom-Json)
                if (`$null -eq `$installerArgs) { `$installerArgs = [string[]]@() }
                `$installerToRun = `$installer
                `$installerUri = `$null

                if (`$installer -match '^https?://') {
                    `$downloadDir = 'C:\ProgramData\MachineConfiguration\Installers'
                    New-Item -Path `$downloadDir -ItemType Directory -Force | Out-Null

                    `$installerUri = [System.Uri]`$installer.Trim()
                    `$fileName = [System.IO.Path]::GetFileName(`$installerUri.AbsolutePath)
                    if ([string]::IsNullOrWhiteSpace(`$fileName)) {
                        `$fileName = "$safeAppName-installer.bin"
                    }

                    `$localInstaller = Join-Path -Path `$downloadDir -ChildPath `$fileName

                    # Acquire a Managed Identity bearer token for Azure Storage.
                    # IDENTITY_ENDPOINT is set by the Azure Connected Machine Agent on Arc machines;
                    # fall back to the standard Azure VM IMDS endpoint otherwise.
                    if (-not [string]::IsNullOrWhiteSpace(`$env:IDENTITY_ENDPOINT)) {
                        `$tokenUrl = "`$(`$env:IDENTITY_ENDPOINT)?api-version=2020-06-01&resource=https://storage.azure.com/"
                    } else {
                        `$tokenUrl = 'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://storage.azure.com/'
                    }
                    `$tokenResponse = Invoke-RestMethod -Uri `$tokenUrl -Headers @{ Metadata = 'true' } -Method Get
                    `$bearerToken = `$tokenResponse.access_token
                    if ([string]::IsNullOrWhiteSpace(`$bearerToken)) {
                        throw 'Failed to acquire Managed Identity token for Azure Storage.'
                    }

                    `$downloadHeaders = @{
                        Authorization  = "Bearer `$bearerToken"
                        'x-ms-version' = '2020-04-08'
                    }
                    `$uriStr = `$installerUri.AbsoluteUri
                    try {
                        Invoke-WebRequest -Uri `$uriStr -Headers `$downloadHeaders -OutFile `$localInstaller -UseBasicParsing
                    } catch {
                        throw "Installer download failed for url: `$(`$uriStr.Substring(0, [Math]::Min(80, `$uriStr.Length))). Error: `$(`$_.Exception.Message)"
                    }
                    if (-not (Test-Path -Path `$localInstaller) -or (Get-Item -Path `$localInstaller).Length -eq 0) {
                        throw "Installer download succeeded but file is missing or empty: `$localInstaller"
                    }
                    `$installerToRun = `$localInstaller
                }

                if (-not (Test-Path -Path `$installerToRun)) {
                    throw "Installer path is not accessible: `$installerToRun"
                }

                `$actualHash = (Get-FileHash -Path `$installerToRun -Algorithm SHA256).Hash.ToLowerInvariant()
                if (`$actualHash -ne `$expectedHash) {
                    throw "Checksum mismatch for `$appName. Expected `$expectedHash but got `$actualHash"
                }

                `$installerDirectory = Split-Path -Path `$installerToRun -Parent
                if ([string]::IsNullOrWhiteSpace(`$installerDirectory) -or -not (Test-Path -Path `$installerDirectory)) {
                    throw "Unable to resolve installer working directory for `$installerToRun"
                }

                # Ensure companion config files referenced by /i or /c are available.
                `$configArgIdx = [Array]::IndexOf(`$installerArgs, '/c')
                if (`$configArgIdx -lt 0 -or `$configArgIdx -ge `$installerArgs.Count - 1) {
                    `$configArgIdx = [Array]::IndexOf(`$installerArgs, '/i')
                }
                if (`$configArgIdx -ge 0 -and `$configArgIdx -lt `$installerArgs.Count - 1) {
                    `$configFileName = [string]`$installerArgs[`$configArgIdx + 1]
                    if (`$configFileName -match '^[a-zA-Z0-9_\.\-/\\]+\.(?:xml|config|json|ini|txt)$') {
                        `$resolvedConfigPath = if ([System.IO.Path]::IsPathRooted(`$configFileName)) {
                            `$configFileName
                        } else {
                            Join-Path -Path `$installerDirectory -ChildPath `$configFileName
                        }

                        if (`$null -ne `$installerUri -and -not [System.IO.Path]::IsPathRooted(`$configFileName) -and -not (Test-Path -Path `$resolvedConfigPath)) {
                            `$installerPathUri = `$installerUri.GetLeftPart([System.UriPartial]::Path)
                            `$lastSlash = `$installerPathUri.LastIndexOf('/')
                            if (`$lastSlash -lt 0) {
                                throw "Unable to resolve installer URL directory from `$installerPathUri"
                            }
                            `$installerDirUri = [System.Uri]::new(`$installerPathUri.Substring(0, `$lastSlash + 1))
                            `$configUri = ([System.Uri]::new(`$installerDirUri, `$configFileName)).AbsoluteUri

                            # Acquire a fresh MI token for the companion download (token acquired per
                            # download to avoid expiry if the installer takes a long time to run).
                            if (-not [string]::IsNullOrWhiteSpace(`$env:IDENTITY_ENDPOINT)) {
                                `$companionTokenUrl = "`$(`$env:IDENTITY_ENDPOINT)?api-version=2020-06-01&resource=https://storage.azure.com/"
                            } else {
                                `$companionTokenUrl = 'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://storage.azure.com/'
                            }
                            `$companionTokenResponse = Invoke-RestMethod -Uri `$companionTokenUrl -Headers @{ Metadata = 'true' } -Method Get
                            `$companionToken = `$companionTokenResponse.access_token
                            if ([string]::IsNullOrWhiteSpace(`$companionToken)) {
                                throw 'Failed to acquire Managed Identity token for companion config download.'
                            }
                            `$companionHeaders = @{
                                Authorization  = "Bearer `$companionToken"
                                'x-ms-version' = '2020-04-08'
                            }
                            try {
                                Invoke-WebRequest -Uri `$configUri -Headers `$companionHeaders -OutFile `$resolvedConfigPath -UseBasicParsing
                            } catch {
                                throw "Failed downloading companion file `$configFileName. Error: `$(`$_.Exception.Message)"
                            }
                            if (-not (Test-Path -Path `$resolvedConfigPath) -or (Get-Item -Path `$resolvedConfigPath).Length -eq 0) {
                                throw "Companion file '`$configFileName' download succeeded but file is missing or empty."
                            }
                        }

                        if (-not (Test-Path -Path `$resolvedConfigPath)) {
                            throw "Companion config file '`$configFileName' was not found at '`$resolvedConfigPath'."
                        }

                        if (-not [string]::IsNullOrWhiteSpace(`$expectedConfigHash)) {
                            `$actualCompanionHash = (Get-FileHash -Path `$resolvedConfigPath -Algorithm SHA256).Hash.ToLowerInvariant()
                            if (`$actualCompanionHash -ne `$expectedConfigHash) {
                                throw "Companion config hash mismatch for '`$configFileName'. Expected `$expectedConfigHash but got `$actualCompanionHash"
                            }
                        }
                    }
                }

                if ('$safeAppName' -eq 'sysmon') {
                    `$sysmonService = Get-Service -Name 'Sysmon', 'Sysmon64' -ErrorAction SilentlyContinue | Select-Object -First 1
                    if (`$null -ne `$sysmonService) {
                        # For existing Sysmon installations: switch to config-update mode (/c) instead of install (/i).
                        `$installerArgs = [string[]](`$installerArgs | Where-Object { `$_ -notin @('/i', '/accepteula') })
                        if ('/c' -notin `$installerArgs) {
                            `$installerArgs = @('/c') + `$installerArgs
                        }
                    }
                }

                `$proc = `$null
                switch (`$packageType) {
                    'exe-silent' {
                        `$proc = Start-Process -FilePath `$installerToRun -ArgumentList '/S' -Wait -PassThru
                    }
                    'msi-silent' {
                        `$proc = Start-Process -FilePath 'msiexec.exe' -ArgumentList "/i `"`$installerToRun`" /quiet /norestart" -Wait -PassThru
                    }
                    'exe-args' {
                        `$proc = Start-Process -FilePath `$installerToRun -ArgumentList `$installerArgs -WorkingDirectory `$installerDirectory -Wait -PassThru
                    }
                    'msi-args' {
                        `$msiArgList = @('/i', `$installerToRun) + `$installerArgs
                        `$proc = Start-Process -FilePath 'msiexec.exe' -ArgumentList `$msiArgList -Wait -PassThru
                    }
                    default {
                        throw "Unknown packageType '`$packageType'. Must be one of: exe-silent, msi-silent, exe-args, msi-args."
                    }
                }

                `$successCodes = if ('$rebootRequiredLiteral' -eq 'True') { @(0, 3010) } else { @(0) }
                if (`$proc.ExitCode -notin `$successCodes) {
                    throw "Installer exited with code `$(`$proc.ExitCode) for `$appName `$appVersion"
                }

                if ('$safeAppName' -eq 'sysmon') {
                    `$sysmonService = Get-Service -Name 'Sysmon', 'Sysmon64' -ErrorAction SilentlyContinue | Select-Object -First 1
                    if (`$null -eq `$sysmonService) {
                        throw "Sysmon install completed but no Sysmon service (Sysmon or Sysmon64) was found."
                    }

                    if (-not [string]::IsNullOrWhiteSpace(`$expectedConfigHash)) {
                        `$sysmonConfigCandidates = @('C:\Windows\Sysmon64.xml', 'C:\Windows\Sysmon.xml')
                        `$sysmonConfigPath = `$sysmonConfigCandidates | Where-Object { Test-Path -Path `$_ } | Select-Object -First 1
                        if (-not [string]::IsNullOrWhiteSpace(`$sysmonConfigPath)) {
                            `$actualSysmonConfigHash = (Get-FileHash -Path `$sysmonConfigPath -Algorithm SHA256).Hash.ToLowerInvariant()
                            if (`$actualSysmonConfigHash -ne `$expectedConfigHash) {
                                throw "Sysmon config hash mismatch after apply. Expected `$expectedConfigHash but got `$actualSysmonConfigHash from `$sysmonConfigPath"
                            }
                        }
                        else {
                            `$argsForVal = [string[]]('$installerArgsJsonLiteral' | ConvertFrom-Json)
                            if (`$null -eq `$argsForVal) { `$argsForVal = [string[]]@() }
                            `$cIdxVal = [Array]::IndexOf(`$argsForVal, '/c')
                            if (`$cIdxVal -lt 0 -or `$cIdxVal -ge `$argsForVal.Count - 1) {
                                # Also check /i position for packages built before migration to /c
                                `$cIdxVal = [Array]::IndexOf(`$argsForVal, '/i')
                            }
                            if (`$cIdxVal -lt 0 -or `$cIdxVal -ge `$argsForVal.Count - 1) {
                                throw "Sysmon config hash validation could not find a companion config file in the installer args."
                            }
                            `$rawConfigPath = `$argsForVal[`$cIdxVal + 1]
                            `$resolvedConfigPath = if ([System.IO.Path]::IsPathRooted(`$rawConfigPath)) {
                                `$rawConfigPath
                            } else {
                                Join-Path -Path `$installerDirectory -ChildPath `$rawConfigPath
                            }
                            if (-not (Test-Path -Path `$resolvedConfigPath)) {
                                throw "Sysmon config validation: companion file not found at `$resolvedConfigPath"
                            }
                            `$actualSysmonConfigHash = (Get-FileHash -Path `$resolvedConfigPath -Algorithm SHA256).Hash.ToLowerInvariant()
                            if (`$actualSysmonConfigHash -ne `$expectedConfigHash) {
                                throw "Sysmon companion config hash mismatch. Expected `$expectedConfigHash but got `$actualSysmonConfigHash"
                            }
                        }
                    }
                }

                `$stateDir = 'C:\ProgramData\MachineConfiguration\InstalledApps'
                New-Item -Path `$stateDir -ItemType Directory -Force | Out-Null

                `$stateRecord = @{
                    name = `$appName
                    version = `$appVersion
                    installedAt = (Get-Date).ToString('o')
                }

                if (-not [string]::IsNullOrWhiteSpace(`$expectedConfigHash)) {
                    `$stateRecord.configSha256 = `$expectedConfigHash
                }

                `$stateRecord |
                    ConvertTo-Json -Depth 5 |
                    Set-Content -Path (Join-Path -Path `$stateDir -ChildPath '$safeAppName.json')
            }
        }
    }
}
"@

# Write the DSC configuration script to a private temp file and dot-source it
# instead of using Invoke-Expression. Dot-sourcing defines the 'configuration'
# function in the current scope (required for the & $configName call below) without
# using Invoke-Expression, which is PowerShell's most injection-prone construct.
$configTempDir = $null
try {
    $configTempDir = [System.IO.Path]::Combine(
        [System.IO.Path]::GetTempPath(),
        "mc_dsc_$(([System.IO.Path]::GetRandomFileName() -replace '\.', ''))"
    )
    New-Item -Path $configTempDir -ItemType Directory -Force | Out-Null

    # Restrict the directory to Administrators only — prevents another process
    # from swapping the script between write and dot-source.
    $acl = Get-Acl -Path $configTempDir
    $acl.SetAccessRuleProtection($true, $false)
    $adminSid = [System.Security.Principal.SecurityIdentifier]::new('S-1-5-32-544')
    $rule = [System.Security.AccessControl.FileSystemAccessRule]::new(
        $adminSid,
        [System.Security.AccessControl.FileSystemRights]::FullControl,
        [System.Security.AccessControl.AccessControlType]::Allow
    )
    $acl.AddAccessRule($rule)
    Set-Acl -Path $configTempDir -AclObject $acl

    $configScriptPath = Join-Path -Path $configTempDir -ChildPath "$configName.ps1"
    Set-Content -Path $configScriptPath -Value $configurationScript -Encoding UTF8

    # Dot-source: defines the configuration function in the current scope.
    . $configScriptPath
}
finally {
    # Delete immediately after dot-sourcing — the function is now in scope and
    # the file is no longer needed.
    if ($null -ne $configTempDir -and (Test-Path -Path $configTempDir)) {
        Remove-Item -Path $configTempDir -Recurse -Force -ErrorAction SilentlyContinue
    }
}

$null = & $configName -OutputPath $compiledPath

$mofPath = Join-Path -Path $compiledPath -ChildPath 'localhost.mof'
if (-not (Test-Path -Path $mofPath)) {
    throw "DSC compilation did not produce localhost.mof at $mofPath"
}

$packageResult = New-GuestConfigurationPackage `
    -Name $safePackageName `
    -Configuration $mofPath `
    -Version $packageVersion `
    -Type $PackageType `
    -Path $packageRoot

$packagePath = [string]$packageResult.Path
if ([string]::IsNullOrWhiteSpace($packagePath) -or -not (Test-Path -Path $packagePath)) {
    $candidate = Join-Path -Path $packageRoot -ChildPath "$safePackageName.zip"
    if (Test-Path -Path $candidate) {
        $packagePath = $candidate
    }
    else {
        throw 'Unable to resolve produced Guest Configuration package path.'
    }
}

# Patch the metaconfig inside the zip to use 'Custom' category.
# The GuestConfiguration module always generates category='Policy', which causes the GC agent
# worker to call policy_from_assignment_name. For direct (non-policy-backed) custom assignments
# this crashes with exit code 1 because there is no Azure Policy definition to resolve.
# Setting category='Custom' prevents that code path from being invoked.
$zipArchive = [System.IO.Compression.ZipFile]::Open($packagePath, 'Update')
try {
    $metaConfigEntries = @($zipArchive.Entries | Where-Object { $_.Name -like '*.metaconfig.json' })
    if ($metaConfigEntries.Count -eq 0) {
        throw "No *.metaconfig.json file found in package '$packagePath'."
    }

    foreach ($metaConfigEntry in $metaConfigEntries) {
        $reader = [System.IO.StreamReader]::new($metaConfigEntry.Open())
        $metaConfigJson = $reader.ReadToEnd()
        $reader.Close()
        $reader.Dispose()

        $metaConfig = $metaConfigJson | ConvertFrom-Json
        $metaConfig | Add-Member -MemberType NoteProperty -Name 'category' -Value 'Custom' -Force
        $patchedJson = $metaConfig | ConvertTo-Json -Depth 10 -Compress

        $entryFullName = $metaConfigEntry.FullName
        $metaConfigEntry.Delete()
        $newEntry = $zipArchive.CreateEntry($entryFullName)
        $writer = [System.IO.StreamWriter]::new($newEntry.Open())
        $writer.Write($patchedJson)
        $writer.Close()
        $writer.Dispose()

        Write-Host "Patched metaconfig category to 'Custom': $entryFullName"
    }
}
finally {
    $zipArchive.Dispose()
}

$contentHash = (Get-FileHash -Path $packagePath -Algorithm SHA256).Hash.ToLowerInvariant()

[pscustomobject]@{
    packageName = $safePackageName
    packageVersion = $packageVersion
    packagePath = (Resolve-Path -Path $packagePath).Path
    contentHash = $contentHash
    applicationName = $ApplicationName
    applicationVersion = $ApplicationVersion
} | ConvertTo-Json -Depth 5 -Compress
