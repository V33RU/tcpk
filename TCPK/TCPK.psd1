@{
    RootModule        = 'TCPK.psm1'
    ModuleVersion     = '2.7.1'
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
            ReleaseNotes = 'See CHANGELOG.md for the full release history. v2.7.1 (scoping + GUI patch): five scanners (WritablePath, AvExclusions, WerExposure, TokenCaches, WerPolicy) now scope findings to the target directory instead of reporting machine-wide state; GUI findings table streams findings live during the audit instead of only after completion. v2.7.0 (19 new cmdlets -- 184 -> 203): the biggest detection release yet. NEW STATIC: gRPC/Protobuf surface (proto files, services, reflection), WebView2 DLL sideloading, AMSI evasion surface, process hollowing / DLL injection / APC injection API sequences, AppDomainManager hijack, .NET AOT detection gate, ClickOnce deployment hijack, MSIX PSF script extraction, phantom DLL planting, diagnostic config exposure, DLL sideload candidates. NEW OS/RUNTIME: COM per-user CLSID hijack, WER crash dump exposure, writable PATH abuse, shared memory DACL audit, window message attack surface, clipboard secret monitoring. NEW EXPLOIT: IL binary patching (Mono.Cecil), IFEO/registry persistence PoC generator. ENHANCED: electron-updater signature bypass + Squirrel detection, WDAC bypass via signed Electron dirs, NuGet vuln scanning, severity re-baseline (10 rules), exploit-map linkage fixes. HEX WORKBENCH: PE structure overlay, entropy heatmap, XOR/decode toolkit, binary diff. AGENTIC: hash-based tab routing (#tab=N), full 13-tab documentation with screenshots. 5 new test files. v2.6.1 (Asar supply-chain audit + UI fix): the Asar tab gains an npm audit action -- OSV / GHSA CVE matching plus npm-registry deprecation flags. v2.6.0 (detection uplift + accuracy + UI pass): severity-anchored CVSS v4.0, Electron-aware provenance gate, crypto-constant / TypeNameHandling / cross-assembly taint IL verdicts, token-privilege / integrity-level checks, CVE native-banner scan, Dashboard + DLL Decompiler GUI tabs, MCP decompiler. v2.5.0 (GUI + workbench pass): Hex Data Inspector, Process Monitor tab, Runtime / Asar / Hex in workbench. v2.4.4 (stable): interception, secret recovery, credential liveness, Frida bypass, Credential Manager extraction.'
        }
    }
}
