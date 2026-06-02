@{
    RootModule        = 'TCPK.psm1'
    ModuleVersion     = '1.0.0'
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
            ReleaseNotes = 'v1.0.0: First stable release. 160 cmdlets across buckets A-L. Adds application-aware registry/OS search (multi-term identity derivation), Confirm- bucket (Mono.Cecil IL-proof of TLS-bypass/deserialization/callsites), session-handling, package-manifest CVEs, Java-archive and Electron-asar unpacking, dev-artifact detection, file-system snapshot/diff, and a gated live TLS-handshake probe. Reporting is CVSS v4.0 with MITRE ATT&CK and OWASP TASVS / Desktop App Top 10 mapping (Get-TcpkTasvsMap). Coverage aligned to OWASP TASVS v1.8. See docs\CHECKS.md.'
        }
    }
}
