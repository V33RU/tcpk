@{
    RootModule        = 'TCPK.psm1'
    ModuleVersion     = '2.6.0'
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
            Prerelease   = 'rc1'
            LicenseUri   = 'https://opensource.org/licenses/MIT'
            ProjectUri   = ''
            ReleaseNotes = 'See CHANGELOG.md for the full release history. v2.6.0-rc1 (detection uplift -- release candidate): a recall + IL-proof pass on the detection engine. +17 modern secret-provider rules (OpenAI / Anthropic / GitLab / Google-OAuth / Slack webhook+app / SendGrid / npm / PyPI / Vault / DigitalOcean / Databricks / Postman / Shopify / basic-auth-in-URL + header), lifting recall across the static, live-memory and env scans at once. The deterministic IL prover gains base-type SQL sinks (Dapper / EF-raw / DbProviderFactory via System.Data.Common.DbCommand / IDbCommand) plus HttpMessageInvoker, and routes reflection.dynamic-load through it so a tainted Assembly.LoadFrom reaches Confirmed (IL); IL taint sources broadened to desktop input channels (file dialogs, drag-drop, clipboard, deserialized results). Electron insecure-by-DEFAULT (an old runtime with an omitted nodeIntegration / contextIsolation / sandbox key inherits the insecure default), CISA KEV enrichment on CVE matches, named-pipe DACL In / Out / Duplex probing (reads write-accepting servers), and JSON REST-body secret scanning in Frida hook mode. v2.5.0 (GUI + workbench pass): the Hex view gains a Data Inspector (bytes at an offset as typed values), go-to / find, a strings extractor, and ImHex-style per-byte colouring -- in both the desktop GUI and the agentic web workbench. New Process Monitor tab (desktop): Live watch re-renders one process (identity, memory, full module list, TCP connections, child processes) on an interval; Activity capture logs new module loads / connections / child processes over a window (0 = until Stop). Colour-coded, filterable, save-to-file; Live watch is also in the agentic workbench. The Runtime / Live tab reflows to an 8-column grid with a Clear-output button, and the Live Exploit / Creds boxes go side-by-side with a draggable splitter for the output console. Folds in v2.5.0-dev (workbench + GUI tooling): a Runtime / Live tab consolidating every process-based dynamic tool; an Asar tab that unpacks an Electron app.asar to read its JavaScript source; a Hex view; and a matching Runtime / Asar / Hex set plus a focused per-binary "Audit selected" in the agentic workbench. v2.4.5-dev (precision pass on top of stable 2.4.4): the audit now separates PROVEN findings (Confirmed* tiers -- act on these first) from LEADS (Inferred pattern matches to triage with AI). New Get-TcpkAssuranceSplit and Invoke-TcpkAudit -ConfirmedOnly; the summary leads with "N proven, M leads". This targets the false-positive concern -- the agentic AI verifies leads rather than reporting them as bugs. v2.4.4 (stable release of the 2.4.x line): the full thick-client pentest layer -- interception (mitmproxy proxy + Frida hook + in-flight tamper) and the workbench Interception tab; secret recovery; credential liveness; the Frida return-bypass of a client-side check; and Windows Credential Manager extraction. All exploit paths are gated (Enable-TcpkExploit). Plus a review pass on the LLM + MCP subsystems: the LLM API-key config file is no longer git-tracked, the MCP server reports the live module version and the correct online-CVE tool description, and the default Claude model is refreshed. The previous full release was v2.3.0.'
        }
    }
}
