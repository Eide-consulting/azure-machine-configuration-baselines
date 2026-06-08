[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$Name,

    [Parameter(Mandatory = $true)]
    [string]$Version,

    [Parameter(Mandatory = $true)]
    [string]$InstallerPath,

    [Parameter(Mandatory = $true)]
    [string]$ShareInstallerPath,

    [Parameter(Mandatory = $true)]
    [ValidateSet('exe-silent', 'msi-silent', 'exe-args', 'msi-args')]
    [string]$PackageType,

    [string[]]$InstallerArgs = @(),

    [string]$VerifyPath = '',

    [bool]$RebootRequired = $false
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Validate installer arguments: only safe characters, no whitespace (spaces would allow argument injection).
$safeArgPattern = '^[a-zA-Z0-9/\\\-_\.=:]{1,256}$'
$badArg = $InstallerArgs | Where-Object { $_ -notmatch $safeArgPattern } | Select-Object -First 1
if ($null -ne $badArg) {
    throw "InstallerArg '$badArg' contains disallowed characters. Each argument must match: $safeArgPattern"
}

if (-not (Test-Path -Path $InstallerPath)) {
    throw "Installer file not found: $InstallerPath"
}

$sha256 = (Get-FileHash -Path $InstallerPath -Algorithm SHA256).Hash.ToLowerInvariant()

$entry = [ordered]@{
    name          = $Name
    version       = $Version
    installerPath = $ShareInstallerPath.Replace('\', '/')
    sha256        = $sha256
    packageType   = $PackageType
    installerArgs = $InstallerArgs
    rebootRequired = $RebootRequired
}

if (-not [string]::IsNullOrWhiteSpace($VerifyPath)) {
    $entry['verifyPath'] = $VerifyPath
}

$entry | ConvertTo-Json -Depth 5
