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

.OUTPUTS
    [TcpkFinding]
#>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$NameLike)

    if (-not (Assert-TcpkWindows 'Test-TcpkServicePermissions')) { return }

    foreach ($s in (Get-CimInstance Win32_Service -ErrorAction SilentlyContinue |
                    Where-Object { $_.Name -like "*$NameLike*" })) {
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
                    New-TcpkFinding -Module 'os' -RuleId 'service.writable-binary' `
                        -Severity 'HIGH' -Confidence 'Confirmed' `
                        -Title "Service '$($s.Name)' binary writable by non-admin" `
                        -File $exe -Evidence $grant -Cwe @('CWE-732')
                }
            }
        }
        # Service SDDL via sc.exe sdshow
        $sddl = & sc.exe sdshow $s.Name 2>$null
        if ($sddl -and ($sddl -match 'D:[^;]*?\(A;;[^;]*?[KW][CD][^;]*?;;[^;]*?(WD|BU|AU)\)')) {
            New-TcpkFinding -Module 'os' -RuleId 'service.weak-dacl' `
                -Severity 'HIGH' -Confidence 'Confirmed' `
                -Title "Service '$($s.Name)' grants control-class access to non-admin" `
                -File $s.Name -Evidence ($sddl -join ' ') -Cwe @('CWE-732')
        }
    }
}
