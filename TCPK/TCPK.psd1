@{
    RootModule        = 'TCPK.psm1'
    ModuleVersion     = '1.0.1'
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
            ReleaseNotes = 'v1.0.1: Computed CVSS v4.0 base scores -- a faithful port of the FIRST.org reference algorithm + macrovector lookup table assigns a real, derived score (not an estimate) per finding via attack-archetype vectors, so a LOCAL issue is no longer mislabelled with a network attack vector. TLS cert-validation-bypass findings now carry the exact location (assembly / namespace / type / method signature / metadata token / call site / IL proof) for direct ILSpy/dnSpy navigation. Optional inline LLM triage in Invoke-TcpkAudit via -EnableLlm (local-only by default; -AllowCloudLlm to permit a cloud backend); the GUI AI pass warns before sending decompiled IL to a cloud provider. Fix: triage no longer demotes an IL-proven CRITICAL cert-bypass when a weaker callsite rule fires on the same file (the proven verdict wins). Docs clarify supported targets (MSIX / MSI / ClickOnce / portable; thin-client = client-side binaries). 160 cmdlets. v1.0.0: First stable release. 160 cmdlets across buckets A-L. Application-aware registry/OS search (multi-term identity derivation), Confirm- bucket (Mono.Cecil IL-proof of TLS-bypass/deserialization/callsites), session-handling, package-manifest CVEs, Java-archive and Electron-asar unpacking, dev-artifact detection, file-system snapshot/diff, and a gated live TLS-handshake probe. Reporting is CVSS v4.0 with MITRE ATT&CK and OWASP TASVS / Desktop App Top 10 mapping (Get-TcpkTasvsMap). Coverage aligned to OWASP TASVS v1.8. See docs\CHECKS.md.'
        }
    }
}
