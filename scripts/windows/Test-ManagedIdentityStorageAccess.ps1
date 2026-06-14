[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$StorageAccountName,

    [Parameter(Mandatory = $true)]
    [string]$InstallerContainerName,

    [Parameter(Mandatory = $true)]
    [string]$PackageContainerName
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Single source of truth for MI token acquisition (handles Azure VM IMDS and the
# Azure Arc 401 challenge-response handshake). Keep this in sync with the copy the
# package builder injects into the DSC SetScript by editing scripts/lib only.
. (Join-Path -Path $PSScriptRoot -ChildPath '..\lib\Get-MiAccessToken.ps1')

function Write-Result {
    param([string]$Label, [bool]$Ok, [string]$Detail = '')
    $status = if ($Ok) { 'PASS' } else { 'FAIL' }
    $color  = if ($Ok) { 'Green' } else { 'Red' }
    Write-Host "[$status] $Label" -ForegroundColor $color
    if ($Detail) { Write-Host "       $Detail" -ForegroundColor DarkGray }
}

# ---------------------------------------------------------------------------
# 1. Detect VM type (display only; the handshake selection is done in the helper)
# ---------------------------------------------------------------------------
$vmType = if (-not [string]::IsNullOrWhiteSpace($env:IDENTITY_ENDPOINT)) { 'Azure Arc' } else { 'Azure VM' }
Write-Host "Detected machine type : $vmType"
Write-Host "Storage account       : $StorageAccountName"
Write-Host ''

# ---------------------------------------------------------------------------
# 2. Acquire MI token
# ---------------------------------------------------------------------------
try {
    $token = Get-MiAccessToken -Resource 'https://storage.azure.com/'
    Write-Result 'Acquire MI token' $true
} catch {
    Write-Result 'Acquire MI token' $false $_.Exception.Message
    Write-Host ''
    Write-Host 'Cannot continue without a token. Ensure system-assigned Managed Identity is enabled on this machine.' -ForegroundColor Yellow
    exit 1
}

$headers = @{
    Authorization  = "Bearer $token"
    'x-ms-version' = '2020-04-08'
}

# ---------------------------------------------------------------------------
# 3. List blobs in installer container (verifies Storage Blob Data Reader)
# ---------------------------------------------------------------------------
foreach ($container in @($InstallerContainerName, $PackageContainerName)) {
    $listUri = "https://$StorageAccountName.blob.core.windows.net/$container`?restype=container&comp=list&maxresults=1"
    try {
        $response = Invoke-WebRequest -Uri $listUri -Headers $headers -UseBasicParsing -Method Get
        if ($response.StatusCode -eq 200) {
            Write-Result "List blobs in '$container'" $true
        } else {
            Write-Result "List blobs in '$container'" $false "HTTP $($response.StatusCode)"
        }
    } catch {
        $statusCode = $_.Exception.Response.StatusCode.value__
        $detail     = if ($statusCode -eq 403) { "HTTP 403 - MI is missing 'Storage Blob Data Reader' on this container." } `
                      elseif ($statusCode -eq 404) { "HTTP 404 - container not found. Check container name." } `
                      else { $_.Exception.Message }
        Write-Result "List blobs in '$container'" $false $detail
    }
}

Write-Host ''
Write-Host 'Done.' -ForegroundColor Cyan
