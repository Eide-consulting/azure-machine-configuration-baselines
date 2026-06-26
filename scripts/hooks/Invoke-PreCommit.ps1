<#
.SYNOPSIS
    Pre-commit gate for this repository.

.DESCRIPTION
    Runs a set of fast, mostly-offline checks against the staged changes before a
    commit is allowed:

      1. PSScriptAnalyzer lint on staged *.ps1 files (blocks on Error-severity).
      2. Validate-Manifest.ps1 structural + SHA256 checks when the manifest is
         staged (no Azure, no secrets required).
      3. Signature-staleness guard: if a signed control file (manifest or
         allowlist) is staged, its companion .sig must also be staged and present.
      4. Optional signature verification via Verify-Manifest.ps1, only when the
         public key is provided through the MANIFEST_SIGNING_PUBLIC_KEY_PEM
         environment variable.
      5. Pester tests, when any *.Tests.ps1 files exist in the repository.

    The security-critical checks (2 and 3) use only built-in PowerShell so they
    always run. The optional tooling checks (PSScriptAnalyzer, Pester) warn and
    skip when the module is not installed, rather than hard-blocking contributors.

    Exit code 0 means the commit may proceed; any non-zero exit blocks the commit.
#>
[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repoRoot = (& git rev-parse --show-toplevel).Trim()
Set-Location -Path $repoRoot

# Signed control files: control-file path => companion signature path.
$signedControlFiles = [ordered]@{
    'manifests/software.manifest.json'          = 'manifests/software.manifest.json.sig'
    'scripts/installers/package-allowlist.json' = 'scripts/installers/package-allowlist.json.sig'
}

$manifestPath = 'manifests/software.manifest.json'

$problems = @()

function Write-Section {
    param([Parameter(Mandatory = $true)][string]$Message)
    Write-Host ''
    Write-Host "==> $Message" -ForegroundColor Cyan
}

# Staged files added, copied or modified (deletions excluded).
$stagedFiles = @(
    & git diff --cached --name-only --diff-filter=ACM |
        Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
)

if ($stagedFiles.Count -eq 0) {
    Write-Host 'No staged changes detected; nothing to check.'
    exit 0
}

# ---------------------------------------------------------------------------
# 1. PSScriptAnalyzer on staged PowerShell files.
# ---------------------------------------------------------------------------
$stagedPs1 = @($stagedFiles | Where-Object { $_ -like '*.ps1' -and (Test-Path -LiteralPath $_) })

if ($stagedPs1.Count -gt 0) {
    Write-Section "PSScriptAnalyzer on $($stagedPs1.Count) staged script(s)"

    if (Get-Module -ListAvailable -Name PSScriptAnalyzer) {
        Import-Module PSScriptAnalyzer -ErrorAction Stop

        $findings = @(Invoke-ScriptAnalyzer -Path $stagedPs1 -Severity Error, Warning)
        $errors = @($findings | Where-Object { $_.Severity -eq 'Error' })
        $warnings = @($findings | Where-Object { $_.Severity -eq 'Warning' })

        foreach ($finding in $findings) {
            $color = if ($finding.Severity -eq 'Error') { 'Red' } else { 'Yellow' }
            Write-Host ("  [{0}] {1}:{2} {3} ({4})" -f `
                    $finding.Severity, $finding.ScriptName, $finding.Line, `
                    $finding.Message, $finding.RuleName) -ForegroundColor $color
        }

        if ($warnings.Count -gt 0) {
            Write-Host "  $($warnings.Count) warning(s) found (non-blocking)." -ForegroundColor Yellow
        }

        if ($errors.Count -gt 0) {
            $problems += "PSScriptAnalyzer reported $($errors.Count) error-severity finding(s)."
        }
        else {
            Write-Host '  No error-severity findings.' -ForegroundColor Green
        }
    }
    else {
        Write-Host '  PSScriptAnalyzer not installed; skipping lint.' -ForegroundColor Yellow
        Write-Host '  Install with: Install-Module PSScriptAnalyzer -Scope CurrentUser' -ForegroundColor Yellow
    }
}

# ---------------------------------------------------------------------------
# 2. Validate the manifest structurally when it is staged.
# ---------------------------------------------------------------------------
if ($stagedFiles -contains $manifestPath) {
    Write-Section 'Validate-Manifest (structural + SHA256)'
    try {
        & "$repoRoot/scripts/Validate-Manifest.ps1" -ManifestPath $manifestPath
        Write-Host '  Manifest validation passed.' -ForegroundColor Green
    }
    catch {
        Write-Host "  $($_.Exception.Message)" -ForegroundColor Red
        $problems += 'Validate-Manifest.ps1 failed for the staged manifest.'
    }
}

# ---------------------------------------------------------------------------
# 3. Signature-staleness guard for signed control files.
# ---------------------------------------------------------------------------
$stagedControlFiles = @($signedControlFiles.Keys | Where-Object { $stagedFiles -contains $_ })

if ($stagedControlFiles.Count -gt 0) {
    Write-Section 'Signature-staleness guard'
    foreach ($controlFile in $stagedControlFiles) {
        $sigPath = $signedControlFiles[$controlFile]

        if (-not (Test-Path -LiteralPath $sigPath)) {
            Write-Host "  Missing signature file: $sigPath" -ForegroundColor Red
            $problems += "'$controlFile' is staged but its signature '$sigPath' does not exist. Re-sign before committing."
            continue
        }

        if ($stagedFiles -notcontains $sigPath) {
            Write-Host "  Stale signature: '$sigPath' was not re-staged with '$controlFile'." -ForegroundColor Red
            $problems += "'$controlFile' changed but '$sigPath' was not re-signed/staged. Re-sign before committing."
            continue
        }

        Write-Host "  OK: '$controlFile' has a co-staged signature." -ForegroundColor Green
    }

    # ---------------------------------------------------------------------------
    # 4. Optional cryptographic verification when a public key is available.
    # ---------------------------------------------------------------------------
    $publicKeyPem = $env:MANIFEST_SIGNING_PUBLIC_KEY_PEM
    if (($stagedControlFiles -contains $manifestPath) -and -not [string]::IsNullOrWhiteSpace($publicKeyPem)) {
        Write-Section 'Verify-Manifest (signature verification)'
        try {
            $secureKey = ConvertTo-SecureString -String $publicKeyPem -AsPlainText -Force
            & "$repoRoot/scripts/signing/Verify-Manifest.ps1" -ManifestPath $manifestPath -PublicKeyPem $secureKey
            Write-Host '  Manifest signature verified.' -ForegroundColor Green
        }
        catch {
            Write-Host "  $($_.Exception.Message)" -ForegroundColor Red
            $problems += 'Verify-Manifest.ps1 signature verification failed for the staged manifest.'
        }
    }
    elseif ($stagedControlFiles -contains $manifestPath) {
        Write-Host '  MANIFEST_SIGNING_PUBLIC_KEY_PEM not set; skipping cryptographic verification.' -ForegroundColor Yellow
    }
}

# ---------------------------------------------------------------------------
# 5. Pester tests, when any exist.
# ---------------------------------------------------------------------------
$testFiles = @(& git ls-files '*.Tests.ps1' | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })

if ($testFiles.Count -gt 0) {
    Write-Section "Pester ($($testFiles.Count) test file(s))"
    if (Get-Module -ListAvailable -Name Pester) {
        Import-Module Pester -ErrorAction Stop
        $result = Invoke-Pester -Path $testFiles -PassThru -Output Detailed
        if ($result.FailedCount -gt 0) {
            $problems += "Pester reported $($result.FailedCount) failing test(s)."
        }
        else {
            Write-Host "  All $($result.PassedCount) test(s) passed." -ForegroundColor Green
        }
    }
    else {
        Write-Host '  Pester not installed; skipping tests.' -ForegroundColor Yellow
        Write-Host '  Install with: Install-Module Pester -Scope CurrentUser -SkipPublisherCheck' -ForegroundColor Yellow
    }
}

# ---------------------------------------------------------------------------
# Summary.
# ---------------------------------------------------------------------------
Write-Host ''
if ($problems.Count -gt 0) {
    Write-Host 'Pre-commit checks FAILED:' -ForegroundColor Red
    foreach ($problem in $problems) {
        Write-Host "  - $problem" -ForegroundColor Red
    }
    Write-Host ''
    Write-Host 'Fix the issues above, or bypass intentionally with: git commit --no-verify' -ForegroundColor Yellow
    exit 1
}

Write-Host 'Pre-commit checks passed.' -ForegroundColor Green
exit 0
