# Single source of truth for Managed Identity (MI) access-token acquisition.
#
# This file is BOTH:
#   * dot-sourced by standalone scripts (e.g. Test-ManagedIdentityStorageAccess.ps1), and
#   * injected verbatim into the generated DSC SetScript by
#     New-AppMachineConfigurationPackage.ps1 (replacing its helper placeholder).
#
# Keep all token logic here so a future security/correctness fix lands in one place
# instead of being copied into the production code path and the diagnostic separately.
#
# SECURITY: on Azure Arc the WWW-Authenticate 'realm' points at a short-lived secret
# file that is a credential. The realm is attacker-influenceable, so the path is
# strictly validated before it is ever read, and neither the secret nor the resulting
# token is ever logged.

function Get-MiAccessToken {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Resource
    )

    # URL-encode the resource once so reserved characters can't produce an
    # invalid request or inject extra query parameters.
    $encodedResource = [System.Uri]::EscapeDataString($Resource)

    # Branch on IDENTITY_ENDPOINT (set by the Azure Connected Machine Agent):
    #   set   -> Azure Arc  -> 401 challenge-response handshake
    #   unset -> Azure VM    -> IMDS single-GET
    if ([string]::IsNullOrWhiteSpace($env:IDENTITY_ENDPOINT)) {
        # --- Azure VM (IMDS) -------------------------------------------------
        $tokenUrl = "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=$encodedResource"
        $tokenResponse = Invoke-RestMethod -Uri $tokenUrl -Headers @{ Metadata = 'true' } -Method Get
        $accessToken = $tokenResponse.access_token
        if ([string]::IsNullOrWhiteSpace($accessToken)) {
            throw 'Failed to acquire Managed Identity token from Azure VM IMDS endpoint (empty access_token).'
        }
        return $accessToken
    }

    # --- Azure Arc (HIMDS challenge-response) --------------------------------
    $tokenUrl = "$($env:IDENTITY_ENDPOINT)?api-version=2020-06-01&resource=$encodedResource"

    # Step 1: the first GET is EXPECTED to return 401. On Arc the 401 is not an
    # error -- it is step one of the protocol and carries the challenge header.
    $challengeResponse = $null
    try {
        Invoke-WebRequest -Uri $tokenUrl -Headers @{ Metadata = 'true' } -Method Get -UseBasicParsing | Out-Null
        throw 'Azure Arc identity endpoint unexpectedly returned success without the expected 401 challenge.'
    }
    catch {
        # Access .Response defensively: PS7 network failures throw
        # HttpRequestException (no Response property), which would otherwise throw
        # under StrictMode instead of yielding $null.
        $challengeResponse = $null
        $responseProperty = $_.Exception.PSObject.Properties['Response']
        if ($null -ne $responseProperty) {
            $challengeResponse = $responseProperty.Value
        }
        # Exception.Response is $null for network/DNS/TLS failures; extract the
        # status code null-safely and fall back to the exception message.
        if ($null -eq $challengeResponse) {
            throw "Failed to contact Azure Arc identity endpoint: $($_.Exception.Message)"
        }

        $statusCode = $null
        try { $statusCode = [int]$challengeResponse.StatusCode } catch { $statusCode = $null }
        if ($statusCode -ne 401) {
            throw "Azure Arc identity endpoint returned unexpected HTTP status '$statusCode' (expected a 401 challenge)."
        }
    }

    # Step 2: read the WWW-Authenticate header across PowerShell editions.
    #   PS 7+        : HttpResponseMessage.Headers.WwwAuthenticate (typed collection)
    #   Windows PS 5 : WebHeaderCollection string indexer
    $wwwAuthenticate = $null
    $rawHeaders = $challengeResponse.Headers
    if ($null -ne $rawHeaders) {
        if ($rawHeaders -is [System.Net.WebHeaderCollection]) {
            $wwwAuthenticate = [string]$rawHeaders['WWW-Authenticate']
        }
        else {
            try {
                $authValues = $rawHeaders.WwwAuthenticate
                if ($null -ne $authValues) {
                    $wwwAuthenticate = (@($authValues) | ForEach-Object { $_.ToString() }) -join ', '
                }
            }
            catch {
                $wwwAuthenticate = $null
            }
        }
    }
    if ([string]::IsNullOrWhiteSpace($wwwAuthenticate)) {
        throw 'Azure Arc 401 challenge did not include a readable WWW-Authenticate header.'
    }

    # Step 3: parse the realm (the secret-file path). Use a strict parse so a
    # greedy match cannot capture trailing parameters or a second challenge.
    $realmMatch = [regex]::Match(
        $wwwAuthenticate,
        'Basic\s+realm="?([^",]+)"?',
        [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
    if (-not $realmMatch.Success) {
        throw 'Azure Arc WWW-Authenticate header did not contain a parseable "Basic realm".'
    }
    $secretFilePath = $realmMatch.Groups[1].Value.Trim()

    # Step 4 (SECURITY): only read the secret file if it resolves UNDER the
    # Connected Machine Agent Tokens directory and carries the expected .key
    # extension. Defends against a spoofed/redirected realm pointing the
    # handshake at an arbitrary file.
    $resolvedSecretPath = [System.IO.Path]::GetFullPath($secretFilePath)
    if ([System.IO.Path]::GetExtension($resolvedSecretPath) -ne '.key') {
        throw 'Azure Arc secret file has an unexpected extension (.key required); refusing to read it.'
    }

    $expectedTokensDir = if (-not [string]::IsNullOrWhiteSpace($env:ProgramData)) {
        [System.IO.Path]::GetFullPath((Join-Path -Path $env:ProgramData -ChildPath 'AzureConnectedMachineAgent\Tokens'))
    }
    else {
        'C:\ProgramData\AzureConnectedMachineAgent\Tokens'
    }
    $expectedTokensPrefix = $expectedTokensDir.TrimEnd('\', '/') + [System.IO.Path]::DirectorySeparatorChar
    if (-not $resolvedSecretPath.StartsWith($expectedTokensPrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw 'Azure Arc secret file resolved outside the expected Tokens directory; refusing to read it.'
    }

    # Step 5: complete the handshake. The secret and the token are credentials --
    # never log either of them. Trim surrounding whitespace/newlines: a trailing
    # CR/LF (common in text files) in the header value would corrupt the request.
    $secret = (Get-Content -Path $resolvedSecretPath -Raw -ErrorAction Stop).Trim()
    if ([string]::IsNullOrWhiteSpace($secret)) {
        throw 'Azure Arc secret file was empty; cannot complete the challenge-response handshake.'
    }
    $authenticatedHeaders = @{
        Metadata      = 'true'
        Authorization = "Basic $secret"
    }
    $tokenResponse = Invoke-RestMethod -Uri $tokenUrl -Headers $authenticatedHeaders -Method Get
    $accessToken = $tokenResponse.access_token
    if ([string]::IsNullOrWhiteSpace($accessToken)) {
        throw 'Azure Arc challenge-response handshake completed but returned an empty access_token.'
    }
    return $accessToken
}
