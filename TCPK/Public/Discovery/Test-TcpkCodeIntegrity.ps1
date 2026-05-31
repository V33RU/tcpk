function Test-TcpkCodeIntegrity {
<#
.SYNOPSIS
    A15. AppxMetadata\CodeIntegrity.cat signature status.

.DESCRIPTION
    The CodeIntegrity catalog drives WDAC publisher rules at install time.
    If the catalog is missing or not Valid, package-level integrity
    enforcement is degraded.

.PARAMETER Path
    Path to an MSIX file or an already-extracted package directory.

.OUTPUTS
    [TcpkFinding]
#>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    if (-not (Assert-TcpkWindows 'Test-TcpkCodeIntegrity')) { return }

    $expanded = Expand-TcpkMsix -Path $Path
    $cat = Join-Path $expanded 'AppxMetadata\CodeIntegrity.cat'

    if (-not (Test-Path -LiteralPath $cat)) {
        New-TcpkFinding -Module 'static' -RuleId 'codeintegrity.no-cat' `
            -Severity 'INFO' -Confidence 'Confirmed' `
            -Title 'No AppxMetadata\CodeIntegrity.cat present' `
            -File $expanded
        return
    }

    $sig = Get-AuthenticodeSignature -FilePath $cat
    $sev = if ($sig.Status -ne 'Valid') { 'HIGH' } else { 'INFO' }

    New-TcpkFinding -Module 'static' -RuleId 'codeintegrity.cat-status' `
        -Severity $sev -Confidence 'Confirmed' `
        -Title "CodeIntegrity.cat signature status = $($sig.Status)" `
        -File $cat -Evidence $sig.StatusMessage `
        -Cwe @('CWE-347') `
        -Fix 'CodeIntegrity catalog drives WDAC publisher rules; must be Valid before release.'
}
