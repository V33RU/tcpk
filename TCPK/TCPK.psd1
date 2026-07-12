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
            Prerelease   = 'dev'
            LicenseUri   = 'https://opensource.org/licenses/MIT'
            ProjectUri   = ''
            ReleaseNotes = 'See CHANGELOG.md for the full release history. v2.4.4-dev (in development): NEW Invoke-TcpkHookBypass (gated) forces the return value of a named native export via Frida -- flip a client-side auth/license/integrity check the app trusts (verified: forced libc atoi to return 999 in a live process); and NEW Get-TcpkStoredCredentials (gated, Windows) enumerates and decrypts the Windows Credential Manager. v2.4.3-dev: Test-TcpkCredentialLiveness + Invoke-TcpkIntercept -Mode Tamper. v2.4.1-2.4.2-dev: Invoke-TcpkIntercept (proxy + Frida hook) and the workbench Interception tab. v2.3.0: agent call-graph tools, a prover verification gate, and Invoke-TcpkSecretRecovery.'
        }
    }
}
