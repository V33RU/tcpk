function Test-TcpkCredentialManager {
<#
.SYNOPSIS
    D02. Credential Manager entries belonging to the target.

.DESCRIPTION
    Runs cmdkey /list and parses Target: lines. Entries that match -NameLike
    (or all entries if -NameLike is empty) are emitted as INFO findings.
    Credential Manager values are decryptable as the logged-in user, so any
    secret material here is exposed to local-user code.

.PARAMETER NameLike
    Substring to match against target name. Empty/null -> all entries.

.OUTPUTS
    [TcpkFinding]
#>
    [CmdletBinding()]
    param([string]$NameLike)

    if (-not (Assert-TcpkWindows 'Test-TcpkCredentialManager')) { return }

    $out = & cmdkey /list 2>$null
    if (-not $out) { return }

    foreach ($line in $out) {
        if ($line -match 'Target:\s+(.+)') {
            $t = $matches[1].Trim()
            if ($NameLike -and $t -notlike "*$NameLike*") { continue }
            New-TcpkFinding -Module 'creds' -RuleId 'credman.entry' `
                -Severity 'INFO' -Confidence 'Confirmed' `
                -Title "Credential Manager entry: $t" `
                -File $t `
                -Description 'Decryptable as the logged-in user via vault APIs.' `
                -Cwe @('CWE-256')
        }
    }
}
