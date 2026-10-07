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
    param([string[]]$NameLike = @(), [string]$Path)

    if (-not (Assert-TcpkWindows 'Test-TcpkUnquotedServicePath')) { return }

    $svcs = @(Get-TcpkCimSafe -ClassName Win32_Service | Where-Object {
        (Test-TcpkNameInclude -Text $_.Name -Terms $NameLike) -and
        $_.PathName -match ' ' -and
        $_.PathName -notmatch '^"' -and
        $_.PathName -notmatch '^[A-Za-z]:\\[^ ]+\.exe$'
    })
    foreach ($s in $svcs) {
        $sa = Resolve-TcpkHostStateBasis -ImagePath $s.PathName -TargetRoot $Path -ActionableSeverity 'HIGH' -MatchDetail "Service '$($s.Name)' matched target term"
        New-TcpkFinding -Module 'os' -RuleId 'service.unquoted-path' `
            -Description 'The service ImagePath is unquoted and contains spaces. Windows resolves such a path by trying each space-delimited prefix, so a file planted at an earlier prefix (for example C:\Program.exe) runs as the service account instead of the real binary.' `
            -Severity $sa.Severity -Confidence 'Confirmed' `
            -Title "Unquoted service path: $($s.Name)" `
            -File $s.Name -Evidence $s.PathName -Cwe @('CWE-428') `
            -AttributionBasis $sa.Basis -Subject $sa.Subject `
            -Fix "sc.exe config $($s.Name) binPath= '\""C:\\Path With Spaces\\svc.exe\""'"
    }
}
