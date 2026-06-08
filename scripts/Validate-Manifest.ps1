[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$ManifestPath,

    [string]$StorageAccountName,
    [string]$ContainerName,

    [SecureString]$SasToken,

    [ValidateSet('login', 'key', 'sas')]
    [string]$AuthMode = 'login',

    [switch]$CheckBlobPaths
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Add-ValidationError {
    param(
        [ref]$Errors,
        [string]$Message
    )

    $Errors.Value += $Message
}

function Get-OptionalStringProperty {
    param(
        [Parameter(Mandatory = $true)]
        [object]$InputObject,

        [Parameter(Mandatory = $true)]
        [string]$PropertyName
    )

    $property = $InputObject.PSObject.Properties[$PropertyName]
    if ($null -eq $property) {
        return ''
    }

    return [string]$property.Value
}

function Get-SecretPlainText {
    param(
        [Parameter(Mandatory = $true)]
        [SecureString]$Secret,

        [Parameter(Mandatory = $true)]
        [string]$ParameterName
    )

    $credential = [System.Net.NetworkCredential]::new('', $Secret)
    try {
        $plainText = $credential.Password
        if ([string]::IsNullOrWhiteSpace($plainText)) {
            throw "$ParameterName is empty."
        }

        return $plainText
    }
    finally {
        $credential.Password = [string]::Empty
    }
}

if (-not (Test-Path -Path $ManifestPath)) {
    throw "Manifest file not found: $ManifestPath"
}

$manifest = Get-Content -Path $ManifestPath -Raw | ConvertFrom-Json
$errors = @()

if (-not $manifest.schemaVersion) {
    Add-ValidationError -Errors ([ref]$errors) -Message 'schemaVersion is required.'
}

if (-not $manifest.packages -or $manifest.packages.Count -eq 0) {
    Add-ValidationError -Errors ([ref]$errors) -Message 'packages must contain at least one package.'
}

$seenPackageKeys = @{}

foreach ($pkg in $manifest.packages) {
    $name = [string]$pkg.name
    $version = [string]$pkg.version
    $installerPath = [string]$pkg.installerPath
    $sha256 = [string]$pkg.sha256
    $configSha256 = Get-OptionalStringProperty -InputObject $pkg -PropertyName 'configSha256'
    $packageType = Get-OptionalStringProperty -InputObject $pkg -PropertyName 'packageType'
    $installerArgsRaw = $pkg.PSObject.Properties['installerArgs']
    $installerArgs = if ($null -ne $installerArgsRaw) { [string[]]$installerArgsRaw.Value } else { @() }

    if ([string]::IsNullOrWhiteSpace($name)) {
        Add-ValidationError -Errors ([ref]$errors) -Message 'A package is missing name.'
        continue
    }

    if ([string]::IsNullOrWhiteSpace($version)) {
        Add-ValidationError -Errors ([ref]$errors) -Message "Package '$name' is missing version."
    }

    if ([string]::IsNullOrWhiteSpace($installerPath)) {
        Add-ValidationError -Errors ([ref]$errors) -Message "Package '$name' is missing installerPath."
    }

    $allowedPackageTypes = @('exe-silent', 'msi-silent', 'exe-args', 'msi-args')
    if ([string]::IsNullOrWhiteSpace($packageType) -or ($packageType -notin $allowedPackageTypes)) {
        Add-ValidationError -Errors ([ref]$errors) -Message "Package '$name' must define packageType as one of: $($allowedPackageTypes -join ', ')."
    }

    # No whitespace allowed — spaces in a single arg string would allow argument injection.
    $safeArgPattern = '^[a-zA-Z0-9/\\\-_\.=:]{1,256}$'
    $badArg = $installerArgs | Where-Object { $_ -notmatch $safeArgPattern } | Select-Object -First 1
    if ($null -ne $badArg) {
        Add-ValidationError -Errors ([ref]$errors) -Message "Package '$name' has an installerArg with disallowed characters: '$badArg'."
    }

    if ([string]::IsNullOrWhiteSpace($sha256) -or ($sha256 -notmatch '^[A-Fa-f0-9]{64}$')) {
        Add-ValidationError -Errors ([ref]$errors) -Message "Package '$name' must have a valid 64-char SHA256 value."
    }

    if ((-not [string]::IsNullOrWhiteSpace($configSha256)) -and ($configSha256 -notmatch '^[A-Fa-f0-9]{64}$')) {
        Add-ValidationError -Errors ([ref]$errors) -Message "Package '$name' has invalid configSha256. Expected a 64-char SHA256 value when provided."
    }

    $key = "$name|$version"
    if ($seenPackageKeys.ContainsKey($key)) {
        Add-ValidationError -Errors ([ref]$errors) -Message "Duplicate package entry found for '$name' version '$version'."
    }
    else {
        $seenPackageKeys[$key] = $true
    }
}

if ($CheckBlobPaths) {
    if ([string]::IsNullOrWhiteSpace($StorageAccountName) -or [string]::IsNullOrWhiteSpace($ContainerName)) {
        throw 'StorageAccountName and ContainerName are required when -CheckBlobPaths is used.'
    }

    if ($AuthMode -ieq 'sas' -and $null -eq $SasToken) {
        throw 'SasToken is required when -CheckBlobPaths is used with -AuthMode sas.'
    }

    $sasTokenPlainText = [string]::Empty
    if ($AuthMode -ieq 'sas') {
        $sasTokenPlainText = Get-SecretPlainText -Secret $SasToken -ParameterName 'SasToken'
        $env:AZURE_STORAGE_SAS_TOKEN = $sasTokenPlainText
    }

    try {
        foreach ($pkg in $manifest.packages) {
            $name = [string]$pkg.name
            $rawPath = [string]$pkg.installerPath

            if ([string]::IsNullOrWhiteSpace($rawPath)) {
                continue
            }

            $normalizedPath = $rawPath.Replace('\\', '/').TrimStart('/')

            $existsArgs = @(
                'storage', 'blob', 'exists',
                '--container-name', "$ContainerName",
                '--name', "$normalizedPath",
                '--account-name', "$StorageAccountName",
                '--only-show-errors',
                '--output', 'json'
            )

            if ($AuthMode -ine 'sas') {
                $existsArgs += @('--auth-mode', "$AuthMode")
            }

            $existsResult = az @existsArgs

            $existsPayload = $existsResult | ConvertFrom-Json
            if (-not $existsPayload.exists) {
                Add-ValidationError -Errors ([ref]$errors) -Message "Package '$name' installer not found in blob container '$ContainerName': $normalizedPath"
            }
        }
    }
    finally {
        if ($AuthMode -ieq 'sas') {
            Remove-Item -Path Env:AZURE_STORAGE_SAS_TOKEN -ErrorAction SilentlyContinue
        }
        $sasTokenPlainText = [string]::Empty
    }
}

if ($errors.Count -gt 0) {
    $errors | ForEach-Object { Write-Error $_ }
    throw "Manifest validation failed with $($errors.Count) error(s)."
}

Write-Host "Manifest validation succeeded for: $ManifestPath"
