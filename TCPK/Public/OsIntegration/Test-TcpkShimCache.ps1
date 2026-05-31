function Test-TcpkShimCache {
<#
.SYNOPSIS
    C08. AppCompat shim registrations for the target.

.DESCRIPTION
    Surveys HKLM\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\
    {Custom, InstalledSDB} subkeys for entries naming or pointing at the
    target. Each entry is INFO -- forensic and hardening interest.

.PARAMETER NameLike
    Substring to match against subkey names and values (default '*').

.OUTPUTS
    [TcpkFinding]
#>
    [CmdletBinding()]
    param([string]$NameLike = '*')

    if (-not (Assert-TcpkWindows 'Test-TcpkShimCache')) { return }

    $keys = @(
        'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Custom',
        'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\InstalledSDB'
    )
    foreach ($k in $keys) {
        if (-not (Test-Path $k)) { continue }
        foreach ($sub in (Get-ChildItem $k -ErrorAction SilentlyContinue)) {
            $props = Get-ItemProperty $sub.PSPath -ErrorAction SilentlyContinue
            if (-not $props) { continue }
            foreach ($p in $props.PSObject.Properties) {
                if ($p.Name.StartsWith('PS')) { continue }
                if ($NameLike -ne '*' -and $p.Name -notlike "*$NameLike*" -and "$($p.Value)" -notlike "*$NameLike*") { continue }
                New-TcpkFinding -Module 'os' -RuleId 'shim.applied' `
                    -Severity 'INFO' -Confidence 'Confirmed' `
                    -Title "AppCompat shim entry: $($p.Name)" `
                    -File $sub.PSPath -Evidence "$($p.Value)"
            }
        }
    }
}
