function Test-TcpkServicePermissions {
<#
.SYNOPSIS
    C02. Service binary writable / weak SDDL.

.DESCRIPTION
    For every Win32 service matching -NameLike, inspects:
      - The binary file ACL (writable by non-admin? -> service hijack)
      - The service SDDL (weak DACL granting non-admins control class access?)

.PARAMETER NameLike
    Substring to match against the service Name (case-insensitive).

.PARAMETER Path
    The audited target's install/expand root. A matched service is reported at HIGH only when
    its binary resolves inside this tree (install-footprint attribution); a service that merely
    name-matches the target but lives elsewhere on the operator's machine is reported AMBIENT
    at INFO, so operator machine state is never attributed to the target.

.OUTPUTS
    [TcpkFinding]
#>
    [CmdletBinding()]
    param([string[]]$NameLike, [string]$Path)

    if (-not (Assert-TcpkWindows 'Test-TcpkServicePermissions')) { return }

    $terms = Get-TcpkNameTerms -NameLike $NameLike
    if (-not $terms.Count) { return }

    foreach ($s in (Get-TcpkCimSafe -ClassName Win32_Service |
                    Where-Object { Test-TcpkTermMatch -Text $_.Name -Terms $terms })) {
        $exe = ($s.PathName -split '"')[1]
        if (-not $exe) { $exe = ($s.PathName -split ' ')[0] }
        if ($exe -and (Test-Path -LiteralPath $exe)) {
            try { $acl = Get-Acl -LiteralPath $exe -ErrorAction Stop } catch { $acl = $null }
            if ($acl) {
                $w = $acl.Access | Where-Object {
                    $_.IdentityReference.Value -match '(?i)\b(Everyone|Authenticated Users|Users|INTERACTIVE)\b' -and
                    $_.FileSystemRights -match 'Write|Modify|FullControl' -and
                    $_.AccessControlType -eq 'Allow'
                }
                if ($w) {
                    $grant = ($w | ForEach-Object { "$($_.IdentityReference) $($_.FileSystemRights)" }) -join '; '
                    $sa = Resolve-TcpkHostStateBasis -ImagePath $exe -TargetRoot $Path -ActionableSeverity 'HIGH' -MatchDetail "Service '$($s.Name)' matched target term"
                    New-TcpkFinding -Module 'os' -RuleId 'service.writable-binary' `
                        -Description 'The service executable is writable by a non-admin user. The service account, usually LocalSystem, runs whatever is at that path, so replacing the binary is direct code execution as SYSTEM.' `
                        -Severity $sa.Severity -Confidence 'Confirmed' `
                        -Title "Service '$($s.Name)' binary writable by non-admin" `
                        -File $exe -Evidence $grant -Cwe @('CWE-732') `
                        -AttributionBasis $sa.Basis -Subject $sa.Subject
                }
            }
        }
        # Service SDDL via sc.exe sdshow
        $sddl = & sc.exe sdshow $s.Name 2>$null
        if ($sddl -and ($sddl -match 'D:[^;]*?\(A;;[^;]*?[KW][CD][^;]*?;;[^;]*?(WD|BU|AU)\)')) {
            $svcSubject = if ($exe) { $exe } else { $s.Name }
            $sa = Resolve-TcpkHostStateBasis -ImagePath $exe -TargetRoot $Path -ActionableSeverity 'HIGH' -Subject $svcSubject -MatchDetail "Service '$($s.Name)' matched target term"
            New-TcpkFinding -Module 'os' -RuleId 'service.weak-dacl' `
                -Description 'The service DACL grants a non-admin principal control-class access: change config, start or stop, or change permissions. A standard user can repoint the service binary or account and gain code execution as the service account.' `
                -Severity $sa.Severity -Confidence 'Confirmed' `
                -Title "Service '$($s.Name)' grants control-class access to non-admin" `
                -File $s.Name -Evidence ($sddl -join ' ') -Cwe @('CWE-732') `
                -AttributionBasis $sa.Basis -Subject $sa.Subject
        }
    }
}
