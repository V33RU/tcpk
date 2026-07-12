@{
    RootModule        = 'TCPK.psm1'
    ModuleVersion     = '2.4.3'
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
            Prerelease   = 'dev'
            LicenseUri   = 'https://opensource.org/licenses/MIT'
            ProjectUri   = ''
            ReleaseNotes = 'See CHANGELOG.md for the full release history. v2.4.3-dev (in development): closes the last thick-client pentest gaps -- NEW Test-TcpkCredentialLiveness (gated) replays a recovered/observed credential against a live http/sql/ftp service and reports Confirmed (exploit) if it authenticates; and Invoke-TcpkIntercept -Mode Tamper modifies matching traffic in flight (mitmproxy) to probe server-side authorization/injection. v2.4.2-dev: Interception tab in the workbench. v2.4.1-dev: Invoke-TcpkIntercept (proxy + Frida hook interception). v2.3.0: agent call-graph tools, a prover verification gate, and Invoke-TcpkSecretRecovery + a Confirmed (exploit) tier.'
        }
    }
}
