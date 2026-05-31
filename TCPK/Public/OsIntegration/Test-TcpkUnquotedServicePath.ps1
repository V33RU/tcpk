function Test-TcpkUnquotedServicePath {
<#
.SYNOPSIS
    C03. Classic unquoted-service-path LPE primitive.

.DESCRIPTION
    Lists services whose PathName contains a space, is NOT quoted, and is
    NOT a single .exe with no embedded space. Standard Windows LPE primitive
    (Microsoft.Public.Win32.Security.Service.Unquoted-Service-Path).

.PARAMETER NameLike
    Substring to match (case-insensitive). Default '*' matches all.

.OUTPUTS
    [TcpkFinding]
#>
    [CmdletBinding()]
    param([string]$NameLike = '*')

    if (-not (Assert-TcpkWindows 'Test-TcpkUnquotedServicePath')) { return }

    $svcs = Get-CimInstance Win32_Service -ErrorAction SilentlyContinue | Where-Object {
        $_.Name -like $NameLike -and
        $_.PathName -match ' ' -and
        $_.PathName -notmatch '^"' -and
        $_.PathName -notmatch '^[A-Za-z]:\\[^ ]+\.exe$'
    }
    foreach ($s in $svcs) {
        New-TcpkFinding -Module 'os' -RuleId 'service.unquoted-path' `
            -Severity 'HIGH' -Confidence 'Confirmed' `
            -Title "Unquoted service path: $($s.Name)" `
            -File $s.Name -Evidence $s.PathName -Cwe @('CWE-428') `
            -Fix "sc.exe config $($s.Name) binPath= '\""C:\\Path With Spaces\\svc.exe\""'"
    }
}
