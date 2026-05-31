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

    if ($foundHygiene) {
        New-TcpkFinding -Module 'memory' -RuleId 'mem.hygiene-present' `
            -Severity 'INFO' -Confidence 'Inferred' `
            -Title 'Memory-hygiene primitives referenced in first-party code' `
            -File $foundHygieneIn `
            -Description 'At least one first-party PE references SecureString / ProtectedData. Confirm in ILSpy that these are used on the secret-handling path, not just imported.'
    } else {
        New-TcpkFinding -Module 'memory' -RuleId 'mem.hygiene-absent' `
            -Severity 'LOW' -Confidence 'Inferred' `
            -Title 'No SecureString / ProtectedData markers in any first-party PE' `
            -Cwe @('CWE-316') `
            -Description 'Triage hint -- if this app handles passwords / tokens at runtime, those values may live in plain managed strings (GC-tracked, may persist in memory).' `
            -Fix 'For password and token handling, use SecureString and Marshal.SecureStringToGlobalAllocUnicode / ZeroFreeGlobalAllocUnicode, or wrap in ProtectedMemory blocks.'
    }
}
