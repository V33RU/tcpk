function Test-TcpkRegistryAcl {
<#
.SYNOPSIS
    C12. Weak DACL on the app's HKLM registry keys (privilege escalation).

.DESCRIPTION
    Surveys HKLM Software (+ WOW6432Node, + Classes) for keys matching the
    product / vendor terms and checks whether a standard user (Users /
    Authenticated Users / Everyone / INTERACTIVE) holds SetValue / CreateSubKey /
    WriteKey / FullControl.

    If a privileged process (service, elevated app) later reads such a key to
    decide a path, command, or flag, a low-privileged user who can rewrite it
    achieves privilege escalation. Only machine-wide (HKLM) keys are checked --
    HKCU is the user's own hive and not a privesc primitive.

.PARAMETER NameLike
    One or more vendor / product / package search terms (substring, case-
    insensitive). Pass the set from Get-TcpkIdentityTerms for app-aware coverage.

.OUTPUTS
    [TcpkFinding]
#>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string[]]$NameLike)

    if (-not (Assert-TcpkWindows 'Test-TcpkRegistryAcl')) { return }

    $terms = @($NameLike | Where-Object { $_ })
    if (-not $terms.Count) { return }

    $riskyRights = 'SetValue|CreateSubKey|WriteKey|TakeOwnership|ChangePermissions|FullControl'
    $userPrincipals = '(?i)\b(Everyone|Authenticated Users|BUILTIN\\Users|^Users$|\\Users$|INTERACTIVE|NT AUTHORITY\\INTERACTIVE)\b'

    foreach ($r in (Get-TcpkRegistrySearchRoots -MachineOnly)) {
        if (-not (Test-Path $r)) { continue }
        # PERF: don't enumerate the whole tree. Match the vendor root key(s) at the
        # top level (cheap), then recurse ONLY under those small subtrees.
        $vendorRoots = Get-ChildItem -Path $r -ErrorAction SilentlyContinue |
            Where-Object { Test-TcpkTermMatch -Text $_.PSChildName -Terms $terms }
        $keys = foreach ($vr in $vendorRoots) {
            $vr
            Get-ChildItem -Path $vr.PSPath -Recurse -Depth 3 -ErrorAction SilentlyContinue
        }
        foreach ($k in $keys) {
            $acl = $null
            try { $acl = Get-Acl -Path $k.PSPath -ErrorAction Stop } catch { continue }
            $weak = $acl.Access | Where-Object {
                $_.AccessControlType -eq 'Allow' -and
                "$($_.IdentityReference)" -match $userPrincipals -and
                "$($_.RegistryRights)" -match $riskyRights
            }
            if ($weak) {
                $grant = ($weak | ForEach-Object { "$($_.IdentityReference)=$($_.RegistryRights)" } | Select-Object -Unique) -join '; '
                $keyPath = $k.PSPath -replace 'Microsoft\.PowerShell\.Core\\Registry::',''
                New-TcpkFinding -Module 'os' -RuleId 'registry.weak-dacl' `
                    -Severity 'HIGH' -Confidence 'Confirmed' `
                    -Title "User-writable HKLM key: $($k.PSChildName)" `
                    -File $keyPath -Evidence $grant -Cwe @('CWE-732','CWE-269') `
                    -Description 'A standard user can modify this machine-wide key. If any privileged process reads it for a path / command / configuration decision, rewriting the value yields privilege escalation.' `
                    -Fix 'Tighten the key DACL so only SYSTEM/Administrators can write. Standard users should have read-only access.'
            }
        }
    }
}
