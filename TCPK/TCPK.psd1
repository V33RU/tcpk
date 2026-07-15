@{
    RootModule        = 'TCPK.psm1'
    ModuleVersion     = '2.4.4'
    GUID              = 'a3f7c1d2-9b4e-4c8a-b1f3-7c2a4d5e8f01'
    Author            = 'TCPK contributors'
    CompanyName       = 'Open source'
    Copyright         = '(c) 2026 TCPK contributors. MIT License.'
    Description       = 'Thick Client Pentest Kit. Portable PowerShell toolkit for authorized penetration testing of Windows thick-client applications. 100+ testcases across 12 buckets (static, manifest, OS, creds, runtime, network, webview2, logging, memory, anti-debug, recon, exploit), with target reconnaissance profiling, interesting-strings extraction, and optional local/cloud LLM finding verification.'
    PowerShellVersion = '5.1'

    # Functions to export are populated by TCPK.psm1 via dot-sourcing Public/.
    # Listed here as '*' for early development; will be enumerated explicitly
    # before first release.
    FunctionsToExport = @('*')
    AliasesToExport   = @()
    CmdletsToExport   = @()
    VariablesToExport = @()

    PrivateData = @{
        PSData = @{
            Tags         = @('Security','Pentest','Thick-Client','MSIX','DotNet','WinUI','WebView2')
            LicenseUri   = 'https://opensource.org/licenses/MIT'
            ProjectUri   = ''
            ReleaseNotes = 'See CHANGELOG.md for the full release history. v2.4.4 (stable release of the 2.4.x line): the full thick-client pentest layer -- interception (mitmproxy proxy + Frida hook + in-flight tamper) and the workbench Interception tab; secret recovery; credential liveness; the Frida return-bypass of a client-side check; and Windows Credential Manager extraction. All exploit paths are gated (Enable-TcpkExploit). Plus a review pass on the LLM + MCP subsystems: the LLM API-key config file is no longer git-tracked, the MCP server reports the live module version and the correct online-CVE tool description, and the default Claude model is refreshed. The previous full release was v2.3.0.'
        }
    }
}
