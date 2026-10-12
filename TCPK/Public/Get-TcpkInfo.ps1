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

    # --- framed console banner (for a screenshot) -----------------------------------------
    $bar = ([string][char]0x2550) * 52
    $tl=[char]0x2554; $tr=[char]0x2557; $bl=[char]0x255A; $br=[char]0x255D; $v=[char]0x2551
    $elev = if ($info.Elevated) { 'yes' } else { 'no' }
    Write-Host ''
    Write-Host ("  {0}{1}{2}" -f $tl,$bar,$tr) -ForegroundColor Cyan
    Write-Host ("  {0} {1,-50} {2}" -f $v,'TCPK   Thick Client Pentest Kit',$v) -ForegroundColor Cyan
    Write-Host ("  {0} {1,-50} {2}" -f $v,("v{0}   PowerShell {1}   elevated: {2}" -f $info.Version,$info.PowerShell,$elev),$v) -ForegroundColor DarkGray
    Write-Host ("  {0}{1}{2}" -f $bl,$bar,$br) -ForegroundColor Cyan
    Write-Host ''

    $rows = @(
        @('Static / Discovery', $info.DiscoveryCount, 'Exploit', $info.Exploit)
        @('Manifest',           $info.ManifestCount,  'Verify',  $info.Verify)
        @('OS integration',     $info.OsIntegration,  'Report',  $info.Report)
        @('Credentials',        $info.Credentials,    'Recon',   $info.Recon)
        @('Runtime',            $info.Runtime,        'LLM',     $info.Llm)
        @('Network',            $info.Network,        '',        $null)
        @('WebView2',           $info.WebView2,       '',        $null)
        @('Logging',            $info.Logging,        '',        $null)
        @('Memory',             $info.Memory,         '',        $null)
        @('Anti-debug',         $info.AntiDebug,      '',        $null)
    )
    foreach ($r in $rows) {
        Write-Host ('   {0,-20}' -f $r[0]) -ForegroundColor Gray -NoNewline
        Write-Host ('{0,4}' -f $r[1])      -ForegroundColor Cyan -NoNewline
        if ($r[2]) {
            Write-Host ('      {0,-14}' -f $r[2]) -ForegroundColor Gray -NoNewline
            Write-Host ('{0,4}' -f $r[3])        -ForegroundColor Cyan
        } else {
            Write-Host ''
        }
    }
    Write-Host ''
    Write-Host ('   {0,-20}{1,4}      {2,-14}{3,4}' -f 'Total cmdlets',$info.TotalCmdlets,'Checks',$totalPublic) -ForegroundColor Green
    Write-Host ('   {0,-20}{1}' -f 'Finding types','800+') -ForegroundColor Green
    Write-Host ''
}
