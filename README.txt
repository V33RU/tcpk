TCPK: Thick Client Pentest Kit (Portable)
=============================================

Drop this entire folder on a USB stick. Double-click TCPK.exe to launch.
No install needed.


QUICK START
-----------

1. Double-click TCPK.exe.

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

  TCPK.exe          The GUI tool (self-contained .exe, branded icon).
  TCPK.bat          Alternate launcher (calls PowerShell directly).
  Start-TCPKGui.ps1 The source script (the .exe is this, compiled).
  TCPK\             The PowerShell module that does the actual work.
  assets\           Logo / icon (tcpk.ico, tcpk-logo.png). Swap to rebrand.
  docs\             methodology, bug-classes, CHECKS.md, disclosure-guide.
  Start-TcpkMcpServer.ps1  Native MCP server (see docs\MCP-USAGE.md).


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

159 cmdlets across buckets A to L. See docs\CHECKS.md for the full list of
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

  TCPK v0.2.0, June 2026. 159 cmdlets; HTML + Excel
  reports with CVSS v4.0, MITRE ATT&CK, OWASP TASVS / Desktop Top 10,
  SBOM and an attack-surface map.
