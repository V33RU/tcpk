function Test-TcpkProgramDataAcls {
<#
.SYNOPSIS
    C13. World-writable app data dirs under %ProgramData% / %PUBLIC% (EoP / TOCTOU).

.DESCRIPTION
    Apps frequently create a data directory under C:\ProgramData\<Vendor> or
    C:\Users\Public\<Vendor> and leave it writable by all users so the
    unprivileged UI can write there. If a privileged component (service,
    elevated updater, SYSTEM scheduled task) later reads or executes content
    from that directory, a standard user can plant a malicious file, swap a
    binary, or win a symlink/TOCTOU race -> privilege escalation.

    Reports each first-level vendor directory under %ProgramData% / %PUBLIC%
    whose DACL grants Write/Modify/FullControl to a standard-user principal.

.PARAMETER NameLike
    Vendor / product substring to match the directory name.

.OUTPUTS
    [TcpkFinding]
#>
    [CmdletBinding()]
    param([string[]]$NameLike)

    if (-not (Assert-TcpkWindows 'Test-TcpkProgramDataAcls')) { return }

    $terms = Get-TcpkNameTerms -NameLike $NameLike
    if (-not $terms.Count) { return }

    $bases = @($env:ProgramData, (Join-Path $env:SystemDrive 'Users\Public')) | Where-Object { $_ -and (Test-Path $_) }
    $userPrincipals = '(?i)\b(Everyone|Authenticated Users|BUILTIN\\Users|\\Users$|^Users$|INTERACTIVE)\b'

    foreach ($base in $bases) {
        $dirs = Get-ChildItem -LiteralPath $base -Directory -ErrorAction SilentlyContinue |
            Where-Object { Test-TcpkTermMatch -Text $_.Name -Terms $terms }
        foreach ($d in $dirs) {
            $acl = $null
            try { $acl = Get-Acl -LiteralPath $d.FullName -ErrorAction Stop } catch { continue }
            $weak = $acl.Access | Where-Object {
                $_.AccessControlType -eq 'Allow' -and
                "$($_.IdentityReference)" -match $userPrincipals -and
                "$($_.FileSystemRights)" -match 'Write|Modify|FullControl'
            }
            if ($weak) {
                $grant = ($weak | ForEach-Object { "$($_.IdentityReference)=$($_.FileSystemRights)" } | Select-Object -Unique) -join '; '
                New-TcpkFinding -Module 'os' -RuleId 'acl.programdata-user-writable' `
                    -Severity 'HIGH' -Confidence 'Confirmed' `
                    -Title "User-writable app data dir: $($d.FullName)" `
                    -File $d.FullName -Evidence $grant -Cwe @('CWE-732','CWE-367') `
                    -Description 'A standard user can write into this directory. If any privileged process reads, loads, or executes content from here, a planted file / swapped binary / symlink race yields privilege escalation. Confirm no SYSTEM/elevated component trusts files in this path.' `
                    -Fix 'Remove inherited write for standard users; grant write only to the specific identity that needs it, and have privileged readers validate file ownership + signature before use.'
            }
        }
    }
}
