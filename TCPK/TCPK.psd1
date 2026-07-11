@{
    RootModule        = 'TCPK.psm1'
    ModuleVersion     = '2.4.1'
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
            ReleaseNotes = 'See CHANGELOG.md for the full release history. v2.4.1-dev (in development): NEW Invoke-TcpkIntercept adds thick-client traffic interception by orchestrating mitmproxy (mitmdump) and parsing captured flows into intercept.* findings -- endpoints confirmed on the wire, HTTP Basic / bearer credentials, credential parameters, and cleartext-http transport (Confirmed dynamic). v2.3.0: the autonomous agent gained call-graph + taint-trace tools and a prover verification gate; Invoke-TcpkSecretRecovery + a Confirmed (exploit) tier recover a plaintext secret from a shipped key + IV + ciphertext.'
        }
    }
}
