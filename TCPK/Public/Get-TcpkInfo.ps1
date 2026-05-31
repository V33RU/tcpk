function Get-TcpkInfo {
<#
.SYNOPSIS
    Reports TCPK version, host environment, and which testcases are implemented.
.DESCRIPTION
    Quick sanity check after Import-Module. Prints PowerShell host info,
    elevation state, module path, and counts of cmdlets by bucket.
.EXAMPLE
    Import-Module .\TCPK\TCPK.psd1 -Force
    Get-TcpkInfo
#>
    [CmdletBinding()] param()

    $manifest = Import-PowerShellDataFile (Join-Path $script:TcpkRoot 'TCPK.psd1')
    $totalPublic = (Get-ChildItem (Join-Path $script:TcpkRoot 'Public') -Recurse -Filter '*.ps1' -EA SilentlyContinue).Count

    [pscustomobject]@{
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
}
