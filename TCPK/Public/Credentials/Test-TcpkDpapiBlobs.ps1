function Test-TcpkDpapiBlobs {
<#
.SYNOPSIS
    D01. DPAPI blobs in the target path.

.DESCRIPTION
    Scans every file under the path for the DPAPI magic header
    (01 00 00 00 D0 8C 9D DF 01 15 D1 11). For each blob found, attempts to
    decrypt under the current user. If decryption succeeds, the blob was
    protected without an entropy argument and any local-user attacker can
    read it: HIGH severity. If decryption fails, the blob is likely
    LocalMachine-scoped or entropy-protected: INFO.

.PARAMETER Path
    Folder (recursive).

.OUTPUTS
    [TcpkFinding]
#>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    if (-not (Assert-TcpkWindows 'Test-TcpkDpapiBlobs')) { return }
    if (-not (Test-Path -LiteralPath $Path -PathType Container)) { return }

    Add-Type -AssemblyName System.Security -ErrorAction SilentlyContinue
    $magic = [byte[]](0x01,0x00,0x00,0x00,0xD0,0x8C,0x9D,0xDF,0x01,0x15,0xD1,0x11)

    foreach ($f in (Get-ChildItem -LiteralPath $Path -Recurse -File -ErrorAction SilentlyContinue)) {
        if ($f.Length -lt 32 -or $f.Length -gt 16MB) { continue }
        try { $head = [IO.File]::ReadAllBytes($f.FullName) | Select-Object -First 12 } catch { continue }

        $isDpapi = $true
        for ($i = 0; $i -lt 12; $i++) {
            if ($head[$i] -ne $magic[$i]) { $isDpapi = $false; break }
        }
        if (-not $isDpapi) { continue }

        try {
            $allBytes = [IO.File]::ReadAllBytes($f.FullName)
            $clear = [Security.Cryptography.ProtectedData]::Unprotect($allBytes, $null, 'CurrentUser')
            $prev = ([Text.Encoding]::UTF8.GetString($clear) -replace '[^\x20-\x7E]','.')
            if ($prev.Length -gt 120) { $prev = $prev.Substring(0,120) }
            New-TcpkFinding -Module 'creds' -RuleId 'dpapi.user-decryptable' `
                -Severity 'HIGH' -Confidence 'Confirmed' `
                -Title 'DPAPI CurrentUser blob -- decryptable as logged-in user' `
                -File $f.FullName -Evidence $prev `
                -Cwe @('CWE-522','CWE-256') `
                -Fix 'Pass optionalEntropy to Protect/Unprotect; or use LocalMachine scope + SYSTEM-only ACL.'
        } catch {
            New-TcpkFinding -Module 'creds' -RuleId 'dpapi.machine-or-entropy-protected' `
                -Severity 'INFO' -Confidence 'Confirmed' `
                -Title 'DPAPI blob (LocalMachine or entropy-protected)' `
                -File $f.FullName
        }
    }
}
