function Test-TcpkSecureStringUsage {
<#
.SYNOPSIS
    I03. SecureString / ProtectedData usage in first-party code.

.DESCRIPTION
    Flags whether the app *uses* memory-hygiene primitives (SecureString,
    ProtectedData) or just regular String for sensitive data. A reference is
    a signal, not proof of correct use; an absence is a missed-hardening
    finding for apps that handle credentials.

.PARAMETER Path
    File or directory.

.OUTPUTS
    [TcpkFinding]
#>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    $hygieneRefs = @('SecureString','ProtectedData','ProtectedMemory','SafeMemory','Marshal.ZeroFreeBSTR')
    $foundHygiene = $false
    $foundHygieneIn = $null

    foreach ($pe in Get-TcpkPeFiles -Path $Path) {
        if (Test-TcpkIsFrameworkFile $pe.Name) { continue }
        $text = Read-TcpkAllText -Path $pe.FullName
        if (-not $text) { continue }
        foreach ($r in $hygieneRefs) {
            if ($text.Contains($r)) {
                $foundHygiene = $true; $foundHygieneIn = $pe.FullName
                break
            }
        }
        if ($foundHygiene) { break }
    }

    # Only the ABSENCE is a (low) triage signal. A single-string "primitives referenced"
    # note falsely reassures (the marker may be imported but never used on the secret path),
    # so the positive case is no longer emitted as a finding.
    if (-not $foundHygiene) {
        New-TcpkFinding -Module 'memory' -RuleId 'mem.hygiene-absent' `
            -Severity 'LOW' -Confidence 'Inferred' `
            -Title 'No SecureString / ProtectedData markers in any first-party PE' `
            -Cwe @('CWE-316') `
            -Description 'Triage hint -- if this app handles passwords / tokens at runtime, those values may live in plain managed strings (GC-tracked, may persist in memory).' `
            -Fix 'For password and token handling, use SecureString and Marshal.SecureStringToGlobalAllocUnicode / ZeroFreeGlobalAllocUnicode, or wrap in ProtectedMemory blocks.'
    }
}
