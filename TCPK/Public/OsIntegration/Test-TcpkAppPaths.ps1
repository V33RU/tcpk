function Test-TcpkAppPaths {
<#
.SYNOPSIS
    C10. App Paths registry entries.

.DESCRIPTION
    HKLM\Software\Microsoft\Windows\CurrentVersion\App Paths\<name>.exe
    is consulted by ShellExecute when the OS resolves a bare executable
    name. An attacker who can write to a referenced App Paths entry can
    redirect callers (e.g. "Run -> notepad.exe" lookup) to attacker code.

.PARAMETER NameLike
    Substring to match against the .exe key name (default '*').

.PARAMETER Path
    The audited target's install/expand root. A writable App Paths target is reported at HIGH
    only when the referenced binary resolves inside this tree; an entry on the operator's
    machine that merely name-matches is reported AMBIENT at INFO.

.OUTPUTS
    [TcpkFinding]
#>
    [CmdletBinding()]
    param([string[]]$NameLike = @(), [string]$Path)

    if (-not (Assert-TcpkWindows 'Test-TcpkAppPaths')) { return }

    $terms = Get-TcpkNameTerms -NameLike $NameLike

    $roots = @(
        'HKLM:\Software\Microsoft\Windows\CurrentVersion\App Paths',
        'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\App Paths',
        'HKCU:\Software\Microsoft\Windows\CurrentVersion\App Paths'
    )
    foreach ($r in $roots) {
        if (-not (Test-Path $r)) { continue }
        foreach ($k in (Get-ChildItem $r -ErrorAction SilentlyContinue)) {
            if ($terms.Count -and -not (Test-TcpkTermMatch -Text $k.PSChildName -Terms $terms)) { continue }
            $default = (Get-ItemProperty -LiteralPath $k.PSPath -ErrorAction SilentlyContinue).'(default)'
            if (-not $default) { continue }

            # Severity: writable target path is the actionable case
            $sev = 'INFO'
            $note = ''
            if (Test-Path -LiteralPath $default -ErrorAction SilentlyContinue) {
                try {
                    $acl = Get-Acl -LiteralPath $default -ErrorAction Stop
                    $w = $acl.Access | Where-Object {
                        $_.IdentityReference.Value -match '(?i)\b(Everyone|Authenticated Users|Users|INTERACTIVE)\b' -and
                        $_.FileSystemRights -match 'Write|Modify|FullControl' -and
                        $_.AccessControlType -eq 'Allow'
                    }
                    if ($w) { $sev = 'HIGH'; $note = ' (target writable by non-admin)' }
                } catch { }
            }
            $sa = Resolve-TcpkHostStateBasis -ImagePath $default -TargetRoot $Path -ActionableSeverity $sev -Subject $k.PSPath -MatchDetail "App Paths entry '$($k.PSChildName)' matched target term"
            New-TcpkFinding -Module 'os' -RuleId 'app-paths.entry' `
                -Severity $sa.Severity -Confidence 'Confirmed' `
                -Title "App Paths: $($k.PSChildName) -> $default$note" `
                -File $k.PSPath -Evidence $default `
                -AttributionBasis $sa.Basis -Subject $sa.Subject `
                -Cwe @('CWE-426','CWE-427')
        }
    }
}
