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
           Id='appExecutionAlias'; Sev='LOW'
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

    foreach ($r in $rules) {
        $nodes = $m.DocumentElement.SelectNodes($r.Xpath, $nsm)
        if (-not $nodes -or $nodes.Count -eq 0) { continue }
        foreach ($n in $nodes) {
            New-TcpkFinding -Module 'manifest' -RuleId "msix.extension.$($r.Id)" `
                -Severity $r.Sev -Confidence 'Confirmed' `
                -Title $r.Title -File $Path `
                -Evidence ($n.OuterXml.Substring(0, [Math]::Min(180, $n.OuterXml.Length))) `
                -Cwe @('CWE-250','CWE-668')
        }
    }
}
