function Test-TcpkSelfIntegrityCheck {
<#
.SYNOPSIS
    J02. Self-integrity verification markers.

.DESCRIPTION
    Detects code that verifies the integrity of the app's own binaries
    (Authenticode self-check, hash comparison against a baked-in digest).
    Presence is a hardening signal; absence is informational.

.PARAMETER Path
    File or directory.

.OUTPUTS
    [TcpkFinding]
#>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    $markers = @(
        'WinVerifyTrust','Get-AuthenticodeSignature',
        'X509Chain.Build','SHA256.Create','SHA512.Create','ComputeHash'
    )
    $foundIn = @{}
    foreach ($pe in Get-TcpkPeFiles -Path $Path) {
        if (Test-TcpkIsFrameworkFile $pe.Name) { continue }
        $text = Read-TcpkAllText -Path $pe.FullName
        if (-not $text) { continue }
        if (Test-TcpkIsChromiumRuntime -Name $pe.Name -Text $text) { continue }   # Chromium's ComputeHash != app self-check
        foreach ($m in $markers) {
            if ($text.Contains($m)) {
                if (-not $foundIn.ContainsKey($pe.Name)) { $foundIn[$pe.Name] = @() }
                $foundIn[$pe.Name] += $m
            }
        }
    }
    if ($foundIn.Count -eq 0) {
        New-TcpkFinding -Module 'antidebug' -RuleId 'integrity.no-self-check-markers' `
            -Severity 'INFO' -Confidence 'Inferred' `
            -Title 'No self-integrity-check markers in first-party PEs' `
            -Description 'Informational. Not a defect; most apps do not self-check. Relevant for high-value targets where tamper detection matters.'
    } else {
        foreach ($f in $foundIn.Keys) {
            New-TcpkFinding -Module 'antidebug' -RuleId 'integrity.self-check-markers' `
                -Severity 'INFO' -Confidence 'Inferred' `
                -Title "$f references self-integrity-check primitives" `
                -File $f -Evidence ($foundIn[$f] -join ', ') `
                -Description 'Confirm in ILSpy that the hash/signature is actually compared and the path acts on the result.'
        }
    }
}
