function Test-TcpkMsixExtensions {
<#
.SYNOPSIS
    B07. fullTrustProcess / appExecutionAlias / contextMenu / shortcutInfo extensions.

.DESCRIPTION
    Inventory of the high-impact desktop extensions in AppxManifest.xml.
    Each one widens the attack surface in a specific way:
      - desktop:Extension fullTrustProcess     -- spawns a process outside the sandbox
      - uap3:Extension    appExecutionAlias    -- registers a CLI entry point in PATH
      - desktop4:Extension fileExplorerContextMenus -- shell extension surface
      - uap:Extension     shortcutInfo / startupTask -- persistence

.PARAMETER Path
    MSIX file or extracted directory.

.OUTPUTS
    [TcpkFinding]
#>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    $expanded = Expand-TcpkMsix -Path $Path
    $m = Read-TcpkAppxManifest -ExpandedPath $expanded
    if (-not $m) { return }
    $nsm = Get-TcpkAppxNsMgr -Manifest $m
    if (-not $nsm) { return }

    $rules = @(
        @{ Xpath='//desktop:Extension[@Category="windows.fullTrustProcess"]'
           Id='fullTrustProcess'; Sev='HIGH'
           Title='Out-of-sandbox process spawn declared (windows.fullTrustProcess)' },
        @{ Xpath='//uap3:Extension[@Category="windows.appExecutionAlias"]'
           Id='appExecutionAlias'; Sev='MEDIUM'
           Title='CLI execution alias declared (PATH-reachable entry point)' },
        @{ Xpath='//desktop4:Extension[@Category="windows.fileExplorerContextMenus"]'
           Id='fileExplorerContextMenus'; Sev='MEDIUM'
           Title='Shell context menu extension declared' },
        @{ Xpath='//desktop:Extension[@Category="windows.startupTask"]'
           Id='startupTask'; Sev='LOW'
           Title='Startup task declared (auto-run at login)' },
        @{ Xpath='//uap:Extension[@Category="windows.backgroundTasks"]'
           Id='backgroundTasks'; Sev='LOW'
           Title='Background task declared' }
    )

    # Common tools an appExecutionAlias could shadow on PATH. The alias stub lives
    # in %LOCALAPPDATA%\Microsoft\WindowsApps (a per-user, user-writable PATH dir),
    # so an alias whose name collides with a real tool can hijack that command.
    $commonTools = @(
        'python','python3','pip','pip3','node','npm','npx','git','code','pwsh','powershell',
        'dotnet','java','javac','kubectl','docker','ssh','scp','curl','wget','az','aws','gcloud',
        'terraform','go','ruby','php','perl','cmake','msbuild','nuget','helm','make','cargo','rustc'
    )

    foreach ($r in $rules) {
        $nodes = $m.DocumentElement.SelectNodes($r.Xpath, $nsm)
        if (-not $nodes -or $nodes.Count -eq 0) { continue }
        foreach ($n in $nodes) {
            New-TcpkFinding -Module 'manifest' -RuleId "msix.extension.$($r.Id)" `
                -Severity $r.Sev -Confidence 'Confirmed' `
                -Title $r.Title -File $Path `
                -Evidence ($n.OuterXml.Substring(0, [Math]::Min(180, $n.OuterXml.Length))) `
                -Cwe @('CWE-250','CWE-668')

            if ($r.Id -ne 'appExecutionAlias') { continue }
            # Extract every Alias="..." name and flag those that shadow a common tool.
            foreach ($mm in [regex]::Matches($n.OuterXml, 'Alias="([^"]+)"')) {
                $alias = $mm.Groups[1].Value
                $bare  = [IO.Path]::GetFileNameWithoutExtension($alias).ToLowerInvariant()
                if ($commonTools -notcontains $bare) { continue }
                New-TcpkFinding -Module 'manifest' -RuleId 'msix.alias-shadowing' `
                    -Severity 'HIGH' -Confidence 'Inferred' `
                    -Title "Execution alias '$alias' shadows a common command on PATH" `
                    -File $Path -Evidence $alias `
                    -Cwe @('CWE-426','CWE-427') `
                    -Description "This package registers the appExecutionAlias '$alias', whose stub is placed in %LOCALAPPDATA%\Microsoft\WindowsApps -- a per-user, user-writable directory on PATH. Because the name collides with the common tool '$bare', invoking '$bare' may run THIS app instead of the real tool (command shadowing / hijack), or a malicious package could pre-register the alias to intercept it." `
                    -Fix 'Use a unique, app-specific alias name; do not register aliases that collide with common system or developer tools.'
            }
        }
    }
}
