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

function Write-Result {
    param([string]$Label, [bool]$Ok, [string]$Detail = '')
    $status = if ($Ok) { 'PASS' } else { 'FAIL' }
    $color  = if ($Ok) { 'Green' } else { 'Red' }
    Write-Host "[$status] $Label" -ForegroundColor $color
    if ($Detail) { Write-Host "       $Detail" -ForegroundColor DarkGray }
}

# ---------------------------------------------------------------------------
# 1. Detect VM type and resolve IMDS token endpoint
# ---------------------------------------------------------------------------
if (-not [string]::IsNullOrWhiteSpace($env:IDENTITY_ENDPOINT)) {
    $tokenUrl  = "$($env:IDENTITY_ENDPOINT)?api-version=2020-06-01&resource=https://storage.azure.com/"
    $vmType    = 'Azure Arc'
    $extraHeaders = @{ Metadata = 'true' }
} else {
    $tokenUrl  = 'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://storage.azure.com/'
    $vmType    = 'Azure VM'
    $extraHeaders = @{ Metadata = 'true' }
}
Write-Host "Detected machine type : $vmType"
Write-Host "Storage account       : $StorageAccountName"
Write-Host ''

# ---------------------------------------------------------------------------
# 2. Acquire MI token
# ---------------------------------------------------------------------------
try {
    $tokenResponse = Invoke-RestMethod -Uri $tokenUrl -Headers $extraHeaders -Method Get
    $token = $tokenResponse.access_token
    if ([string]::IsNullOrWhiteSpace($token)) { throw 'access_token is empty.' }
    $expiry = [System.DateTimeOffset]::FromUnixTimeSeconds([long]$tokenResponse.expires_on).ToLocalTime()
    Write-Result 'Acquire MI token' $true "expires $expiry"
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
