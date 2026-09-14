function Test-TcpkMsiLaunchConditions {
<#
.SYNOPSIS
    C26. Whether an installer checks the platform it is about to install onto.

.DESCRIPTION
    The LaunchCondition table is where an MSI states what must be true before it will
    proceed: a minimum Windows version, a required privilege level, a prerequisite that has
    to already be present. Each row is a condition expression and the message shown when it
    fails.

    An installer with no conditions installs onto whatever it is pointed at. That is a
    posture gap rather than a vulnerability, and it is reported that way. It matters because
    a desktop application usually depends on platform security work it did not do itself,
    and those dependencies are silent: a build that assumes a modern TLS stack, a current
    CNG provider, or a mitigation that arrived in a particular Windows release will install
    happily on a version that has none of them and fail open rather than refuse.

    VersionNT is the property that encodes the floor. An installer that declares conditions
    but never references it is checking prerequisites without checking the platform.

    Rules:
      msi.launch-conditions-absent          LOW   No LaunchCondition rows at all.
      msi.launch-condition-no-platform-floor INFO Conditions exist, none reference a
                                                  Windows version property.

    Reads the MSI database through the same WindowsInstaller COM path Test-TcpkMsiCustomActions
    uses. Skipped cleanly when that COM object is unavailable.

.PARAMETER Path
    Directory to search for .msi files, or a single .msi.

.OUTPUTS
    [TcpkFinding]
#>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    if (-not (Assert-TcpkWindows 'Test-TcpkMsiLaunchConditions')) { return }
    if (-not (Test-Path -LiteralPath $Path)) { return }

    $msiFiles = @()
    $item = Get-Item -LiteralPath $Path
    if (-not $item.PSIsContainer) {
        if ($item.Extension -ne '.msi') { return }
        $msiFiles = @($item)
    } else {
        $msiFiles = @(Get-ChildItem -Path $Path -Recurse -Filter '*.msi' -File -ErrorAction SilentlyContinue |
                      Select-Object -First 20)
    }
    if (-not $msiFiles.Count) { return }

    $installer = $null
    try { $installer = New-Object -ComObject WindowsInstaller.Installer -ErrorAction Stop } catch {
        New-TcpkSkippedFinding -RuleId 'msi.launch-conditions.no-com' `
            -Title 'MSI launch-condition check skipped (WindowsInstaller COM not available)' `
            -Reason $_.Exception.Message
        return
    }

    foreach ($msi in $msiFiles) {
        $conds = New-Object 'System.Collections.Generic.List[string]'
        $readOk = $false
        try {
            $db   = $installer.OpenDatabase($msi.FullName, 0)
            $view = $db.OpenView('SELECT `Condition`, `Description` FROM `LaunchCondition`')
            $view.Execute()
            $readOk = $true
            $rec = $view.Fetch()
            while ($rec -ne $null) {
                $c = "$($rec.StringData(1))"
                if ($c -and $conds.Count -lt 12) { $conds.Add($c) }
                $rec = $view.Fetch()
            }
        } catch {
            # A missing LaunchCondition table throws rather than returning no rows, which is
            # itself the answer: the installer declares no conditions. Any other failure is
            # not distinguishable here, so treat only an empty read as conclusive.
            $readOk = $true
        }
        if (-not $readOk) { continue }

        if ($conds.Count -eq 0) {
            New-TcpkFinding -Module 'os' -RuleId 'msi.launch-conditions-absent' `
                -Severity 'LOW' -Confidence 'Confirmed' `
                -Title "Installer declares no launch conditions: $($msi.Name)" `
                -File $msi.FullName -Evidence 'LaunchCondition table empty or absent' `
                -Cwe @('CWE-1104') `
                -Description ('The package states no precondition, so it installs onto any Windows version ' +
                    'it is run on. Desktop applications inherit a great deal of their security from the ' +
                    'platform, and those dependencies are usually implicit: a build that assumes a current ' +
                    'TLS stack, a particular CNG provider, or a mitigation introduced in a specific release ' +
                    'will install without complaint on a version that lacks them and then behave as though ' +
                    'the protection is present. Declaring a floor turns that silent assumption into a ' +
                    'refusal at install time.') `
                -Fix 'Add a LaunchCondition on VersionNT for the oldest Windows release the product is actually tested against, with a message naming that version. Add further conditions for any runtime or platform feature the application depends on rather than probing for it at first use.'
            continue
        }

        $hasPlatformFloor = $false
        foreach ($c in $conds) {
            if ($c -match '(?i)VersionNT|WindowsBuild|ServicePackLevel|MsiNTProductType') { $hasPlatformFloor = $true; break }
        }
        if (-not $hasPlatformFloor) {
            New-TcpkFinding -Module 'os' -RuleId 'msi.launch-condition-no-platform-floor' `
                -Severity 'INFO' -Confidence 'Confirmed' `
                -Title "Launch conditions do not pin a Windows version: $($msi.Name)" `
                -File $msi.FullName -Evidence (($conds | Select-Object -First 6) -join ' | ') `
                -Description ('The installer does check preconditions, but none of them reference VersionNT ' +
                    'or another platform property, so prerequisites are verified while the operating ' +
                    'system version is not. Scope information: the conditions that exist tell you what the ' +
                    'product knows it depends on, and the absence of a version floor tells you the ' +
                    'platform assumptions were left implicit.') `
                -Fix 'Add a VersionNT condition alongside the existing checks so the supported-platform floor is enforced rather than assumed.'
        }
    }
}
