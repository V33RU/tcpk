function Get-TcpkInfo {
<#
.SYNOPSIS
    Reports TCPK version, host environment, and which testcases are implemented.
.DESCRIPTION
    Quick sanity check after Import-Module. Prints PowerShell host info,
    elevation state, module path, and counts of cmdlets by bucket.
.PARAMETER Banner
    Print a framed, colour-coded summary to the console (for a screenshot / banner) instead
    of returning the info object. Without it, Get-TcpkInfo returns the object as before.
.EXAMPLE
    Import-Module .\TCPK\TCPK.psd1 -Force
    Get-TcpkInfo
.EXAMPLE
    Get-TcpkInfo -Banner
#>
    [CmdletBinding()] param([switch]$Banner)

    $manifest = Import-PowerShellDataFile (Join-Path $script:TcpkRoot 'TCPK.psd1')
    $totalPublic = (Get-ChildItem (Join-Path $script:TcpkRoot 'Public') -Recurse -Filter '*.ps1' -EA SilentlyContinue).Count

    $info = [pscustomobject]@{
        Version          = $manifest.ModuleVersion
        ModuleRoot       = $script:TcpkRoot
        PowerShell       = Get-TcpkPsVersion
        Elevated         = Test-TcpkIsAdmin
        IsWindows        = Test-TcpkIsWindows
        DiscoveryCount   = (Get-ChildItem (Join-Path $script:TcpkRoot 'Public\Discovery')     -Filter '*.ps1' -EA SilentlyContinue).Count
        ManifestCount    = (Get-ChildItem (Join-Path $script:TcpkRoot 'Public\Manifest')      -Filter '*.ps1' -EA SilentlyContinue).Count
        OsIntegration    = (Get-ChildItem (Join-Path $script:TcpkRoot 'Public\OsIntegration') -Filter '*.ps1' -EA SilentlyContinue).Count
        Credentials      = (Get-ChildItem (Join-Path $script:TcpkRoot 'Public\Credentials')   -Filter '*.ps1' -EA SilentlyContinue).Count
        Runtime          = (Get-ChildItem (Join-Path $script:TcpkRoot 'Public\Runtime')       -Filter '*.ps1' -EA SilentlyContinue).Count
        Network          = (Get-ChildItem (Join-Path $script:TcpkRoot 'Public\Network')       -Filter '*.ps1' -EA SilentlyContinue).Count
        WebView2         = (Get-ChildItem (Join-Path $script:TcpkRoot 'Public\WebView2')      -Filter '*.ps1' -EA SilentlyContinue).Count
        Logging          = (Get-ChildItem (Join-Path $script:TcpkRoot 'Public\Logging')       -Filter '*.ps1' -EA SilentlyContinue).Count
        Memory           = (Get-ChildItem (Join-Path $script:TcpkRoot 'Public\Memory')        -Filter '*.ps1' -EA SilentlyContinue).Count
        AntiDebug        = (Get-ChildItem (Join-Path $script:TcpkRoot 'Public\AntiDebug')     -Filter '*.ps1' -EA SilentlyContinue).Count
        Exploit          = (Get-ChildItem (Join-Path $script:TcpkRoot 'Public\Exploit')       -Filter '*.ps1' -EA SilentlyContinue).Count
        Verify           = (Get-ChildItem (Join-Path $script:TcpkRoot 'Public\Verify')        -Filter '*.ps1' -EA SilentlyContinue).Count
        Report           = (Get-ChildItem (Join-Path $script:TcpkRoot 'Public\Report')        -Filter '*.ps1' -EA SilentlyContinue).Count
        Recon            = (Get-ChildItem (Join-Path $script:TcpkRoot 'Public\Recon')         -Filter '*.ps1' -EA SilentlyContinue).Count
        Llm              = (Get-ChildItem (Join-Path $script:TcpkRoot 'Public\Llm')           -Filter '*.ps1' -EA SilentlyContinue).Count
        TotalCmdlets     = $totalPublic
    }

    if (-not $Banner) { return $info }

    # --- console banner (for a screenshot) ------------------------------------------------
    # Plain-ASCII logo on purpose: block/box glyphs corrupt when PS 5.1 loads a .ps1 that has
    # no BOM, so the art uses only ASCII and the rule below is built from a char code.
    $bar  = ([string][char]0x2500) * 56   # horizontal rule
    $elev = if ($info.Elevated) { 'yes' } else { 'no' }
    Write-Host ''
    foreach ($ln in @(
        " _____  ____ ____  _  __",
        "|_   _|/ ___|  _ \| |/ /",
        "  | | | |   | |_) | ' / ",
        "  | | | |___|  __/| . \ ",
        "  |_|  \____|_|   |_|\_\"
    )) { Write-Host ("   " + $ln) -ForegroundColor Cyan }
    Write-Host ''
    Write-Host ("   Thick Client Pentest Kit    v{0}" -f $info.Version) -ForegroundColor White
    Write-Host ("   PowerShell {0}    elevated: {1}    windows: {2}" -f $info.PowerShell,$elev,$info.IsWindows) -ForegroundColor DarkGray
    Write-Host ("  {0}" -f $bar) -ForegroundColor Cyan
    Write-Host ''

    # Each row is a pscustomobject on purpose: an array literal of inner @(...) arrays
    # unrolls into one flat list in PowerShell, so a row would not survive as a 4-item array.
    $rows = @(
        [pscustomobject]@{ L='Static / Discovery'; LV=$info.DiscoveryCount; R='Exploit'; RV=$info.Exploit }
        [pscustomobject]@{ L='OS integration';     LV=$info.OsIntegration;  R='Verify';  RV=$info.Verify }
        [pscustomobject]@{ L='Runtime';            LV=$info.Runtime;        R='Report';  RV=$info.Report }
        [pscustomobject]@{ L='Credentials';        LV=$info.Credentials;    R='Recon';   RV=$info.Recon }
        [pscustomobject]@{ L='Network';            LV=$info.Network;        R='LLM';     RV=$info.Llm }
        [pscustomobject]@{ L='Manifest';           LV=$info.ManifestCount;  R='';        RV=$null }
        [pscustomobject]@{ L='WebView2';           LV=$info.WebView2;       R='';        RV=$null }
        [pscustomobject]@{ L='Logging';            LV=$info.Logging;        R='';        RV=$null }
        [pscustomobject]@{ L='Memory';             LV=$info.Memory;         R='';        RV=$null }
        [pscustomobject]@{ L='Anti-debug';         LV=$info.AntiDebug;      R='';        RV=$null }
    )
    foreach ($r in $rows) {
        Write-Host ('   {0,-20}' -f $r.L) -ForegroundColor Gray -NoNewline
        Write-Host ('{0,4}' -f $r.LV)     -ForegroundColor Cyan -NoNewline
        if ($r.R) {
            Write-Host ('      {0,-14}' -f $r.R) -ForegroundColor Gray -NoNewline
            Write-Host ('{0,4}' -f $r.RV)        -ForegroundColor Cyan
        } else {
            Write-Host ''
        }
    }
    Write-Host ''
    Write-Host ('   {0,-20}{1,4}      {2,-14}{3}' -f 'Cmdlets',$info.TotalCmdlets,'Finding types','800+') -ForegroundColor Green
    Write-Host ''
}
