TCPK: Thick Client Pentest Kit (Portable)
=============================================

Drop this entire folder on a USB stick. Double-click TCPK.bat to launch.
No install needed. (Keep the whole folder together: the launcher must sit
beside the TCPK\ module folder.)


QUICK START
-----------

1. Double-click TCPK.bat (the recommended launcher).
   (TCPK.exe is a compiled alternative; if it shows "module missing",
    use TCPK.bat -- the exe must be rebuilt to find the module folder.)

2. In the target box, paste the MSIX install dir or the path to a .msix file:
     C:\Program Files\WindowsApps\YourApp_x.y.z_x64__hash

3. Click "Auto-Detect". It will fill in PackageName and ProcessName.

4. Pick a profile from the drop-down:
     Quick:    static binary checks only, ~30 s on a 100 MB target
     Standard: static + manifest + OS integration, ~2 min
     Full:     everything except deep runtime opt-ins, ~3 min

5. Click "Run Audit".

6. Watch the live progress on the left. As each check fires, you see
   timing and finding count. Findings stream into the table on the right
   coloured by severity (CRITICAL = dark red, HIGH = red, MEDIUM = orange,
   LOW = green, INFO = grey).

7. When done, click "Open HTML report" to view the full report in your
   browser, or "Open output folder" to see all artefacts.


WHAT'S IN HERE
--------------

  TCPK.bat          Recommended launcher (runs the GUI script in STA mode).
  Start-TCPKGui.ps1 The GUI source script (run directly with -STA if you prefer).
  TCPK.exe          Compiled launcher (branded icon). Must sit beside the TCPK\
                    module folder AND be rebuilt from Start-TCPKGui.ps1 to find it.
  TCPK\             The PowerShell module that does the actual work.
  assets\           Logo / icon (tcpk.ico, tcpk-logo.png). Swap to rebrand.
  docs\             methodology, bug-classes, CHECKS.md, disclosure-guide.
  Start-TcpkMcpServer.ps1  Native MCP server (see docs\MCP-USAGE.md).


SUPPORTED TARGETS
-----------------

TCPK is path-based, not installer-specific. Point -Target (or the GUI
target box) at any of these:

  - An MSIX / AppX / .msixbundle / .zip package file (auto-extracted).
  - An already-installed or extracted app folder.
  - A single .exe (portable apps that run from a folder or USB stick).

So it works the same on MSIX, MSI, ClickOnce, Squirrel and fully portable
apps -- whatever lands as files you can point a path at. The 8 MSIX-manifest
checks (bucket B) auto-skip when there is no AppxManifest.xml: no error,
they simply report nothing. Everything else (static binary, credentials,
OS integration, network, WebView2, logging, anti-debug, and live-process
runtime) runs identically regardless of how the app was packaged.

Thin clients: TCPK audits the CLIENT-SIDE binaries that land on the
endpoint, the same as any thick client. The remote server / API the client
talks to is out of scope -- that is a separate web/API engagement (TCPK
surfaces the backend endpoints and their TLS posture, but does not exercise
them). The thin-client terminal OS / appliance itself (IGEL, ThinOS, kiosk)
is also out of scope: TCPK analyses Windows PE binaries, so run it on the
machine where those binaries live (e.g. a Citrix/RDP published-app host).


REQUIREMENTS
------------

  Windows 10 / 11.
  PowerShell 5.1 or 7+ (ships with Windows by default).
  Admin elevation only required for some deep runtime checks
  (DLL search trace ETW, memory dump scan). Static checks run fine
  without admin.


SCOPE / AUTHORIZATION
---------------------

This tool is for authorised security testing only. Test software your
organisation owns or that you have written authorisation to test.

Running against third-party software you don't own and aren't authorised
to test may violate computer-misuse laws and licence terms. Don't.


REPORTS
-------

Every audit writes these to its own out\ folder:

  index.html         Human-readable report: severity-coloured findings,
                     confidence + CVSS band, evidence, CWE + MITRE ATT&CK,
                     copy-paste "Verify (manual)" commands, and the brand logo.

  report.xlsx        Multi-sheet Excel: Summary, Findings, DLL Hardening
                     (ASLR/DEP/CFG/HighEntropyVA/SafeSEH matrix), CVEs.

  attack-surface.json  Ranked entry-point map (protocols, IPC, listeners).
  sbom.cdx.json        CycloneDX software bill of materials.
  findings.json        Machine-readable findings (CI / GUI / MCP).
  strings.json, exploits.json, run.jsonl   recon strings, exploit plan, trace.

(Markdown and JSON-as-report were dropped; HTML + Excel are the deliverables.)


TROUBLESHOOTING
---------------

  "Window doesn't open": check that .NET Framework 4.8+ is installed
  (it ships with Windows 10/11 by default).

  "Audit hangs": some HKCR/HKLM scans take 30+ seconds on machines with
  many keys. Wait it out; if it exceeds 5 minutes, the audit log will
  show which check is hanging.

  "Reports folder not found": by default reports go next to TCPK.exe in
  an .\out\ subfolder. Make sure the folder is writable.


COVERAGE
--------

172 cmdlets across buckets A to L. See docs\CHECKS.md for the full list of
every check and which bucket it lives in (run Get-TcpkInfo for live counts).

  A Static binary   B MSIX manifest   C OS integration   D Credentials
  E Runtime/live    F Network         G WebView2          H Logging
  I Memory          J Anti-debug      (K Exploit, gated)  + Recon / Report

The Exploit bucket and all ACTIVE dynamic tools (memory flag-flip, GUI
unlock, pipe probe, input fuzz) are OFF by default. Enable for a session:
  Enable-TcpkExploit -Acknowledge      (PowerShell, after Import-Module)
In the GUI, tick the authorization box on the "Exploit / CVE" tab. The
read-only live tools (memory/env secret scan, process DACL) need no gate.


VERSION
-------

  TCPK v1.4.1, June 2026. 172 cmdlets; HTML + Excel
  reports with COMPUTED CVSS v4.0 base scores (FIRST.org algorithm),
  MITRE ATT&CK, OWASP TASVS / Desktop Top 10, SBOM and an attack-surface
  map. Optional local-LLM triage (-EnableLlm / GUI "AI-verify findings").
