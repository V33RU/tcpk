# Changelog

Release history for TCPK. Newest first.

## Unreleased

**Mono.Cecil now ships inside the module** at `TCPK/lib/Cecil/`, not in a repo-root sibling.
`Install-Module` packages the `TCPK/` folder only, so the old sibling at
`tools/ILSpy/Mono.Cecil.dll` disappeared under any published install and every IL-based
verdict silently degraded to `null`. Moved the four DLLs (Cecil, Rocks, Pdb, Mdb) into
the module. Resolver in `_Decompile.ps1` now checks the in-module path FIRST, keeps the
legacy sibling as a fallback, and the two ILSpy install paths after that.

Silent degradation ended: `Initialize-TcpkCecil` failure now emits
`Add-TcpkScanSkip -Kind CecilMissing` once per audit. Test-TcpkScanCoverage reports it as
MEDIUM `scan.incomplete-coverage` with a title that names the missing capability
("IL prover was NOT LOADED"), so the report cannot be mistaken for a clean managed target.

NOTICE, REQUIREMENTS, docs/INSTALL, docs/index.html and the GUI Decompiler status line all
point at the new path. Old sibling reference kept in the resolver and one test to protect
existing checkouts.

**Invoke-TcpkFirmwarePlantProbe (K25).** Dynamic sibling to Test-TcpkFirmwareImages (A49).
Backs up a shipped firmware image, optionally appends 4 sentinel bytes ('TCPK') so any
signature check fails, launches the vendor updater, and observes via the shared ETW
kernel-file trace whether the updater's process tree reads the file at flash time.
Restores from backup in the finally block before returning, verified byte-for-byte
against the pre-tamper hash.

Three gates layered so no single missed check can touch the file:
- Enable-TcpkExploit -Acknowledge (session)
- -ConfirmActive (per-invocation)
- -AllowDevicePresent (required only in AppendMarker mode; operator assertion that no
  real device is connected which could accept a tampered image if the updater ignores
  the marker)

Verdicts:
- firmware.plant.read-confirmed        HIGH Confirmed (dynamic), read observed
- firmware.plant.tampered-read         CRITICAL Confirmed (dynamic), AppendMarker + read
- firmware.plant.not-read              INFO, no read in the window
- firmware.plant.no-admin / .no-image / .no-updater / .etw-start-failed / .launch-failed / .exception  Skipped

Six Pester cases pin the safety gates and confirm the firmware file stays byte-identical
when a gate rejects the call. The observation half needs Windows admin and a live
updater, so it stays out of CI.

**Fix the BOM-migration regex that ate the previous line at 8 sites.** The migration in
`d391aa6` used a regex with `[\s\S]{0,50}?` in the value capture. That allowed the match
to cross a newline, so at 8 sites the rewriter consumed the assignment line before each
`ConvertTo-Json` pipeline and produced two garbled lines like `Save-TcpkJson -Value $path
= Join-Path $Dir 'coverage.json'` and `$obj -Path $path -Depth 6`. The audit died with
parse errors on the first affected file loaded (`_Coverage.ps1`, `_Llm.ps1`, `_Osv.ps1`,
`Invoke-TcpkAudit.ps1`, `Save-TcpkFileSnapshot.ps1`, `Save-TcpkRegistrySnapshot.ps1`).
The brace balance checker did not catch it because the braces still balanced.

Every corrupted site restored to a proper `Save-TcpkJson -Value $x -Path $p -Depth n`
call on its own line.

**Fix a bad regex in the pre-flight guard that aborted the whole audit on any Windows
target.** The guard used `-match '(?i)\Program Files\WindowsApps\'`. .NET regex parses
`\P` as an invalid Unicode-property escape and throws on compile, before the check loop
ran. The user saw "audit complete -- 0 findings" and no findings.json, which read as
"target was empty" but was actually the audit dying at line 218. Switched to `-like` (no
regex, backslashes are literal) and wrapped the whole pre-flight in try/catch, so any
future mistake here degrades to "assume readable, run everything" instead of taking the
audit down.

**Version rolled back to 2.7.1 to match the last actual release.** The manifest ran ahead
of the last tag ever since it was bumped to 2.9.0 without a release cut. The banner said
2.9.0 while the Latest release on GitHub said 2.7.1. The rule going forward is the one
already written down: never bump ModuleVersion without a tag in the same commit.

**Audit refuses an unreadable target instead of reporting 0 findings.** A real run against
C:\Program Files\WindowsApps\ConfigurePro_* printed "audit complete -- 0 findings" and
produced no findings.json, because the WindowsApps ACL grants read only to TrustedInstaller
and SYSTEM; an elevated Administrator still gets Access Denied on the recursive walk. New
HIGH scan.target-unreadable finding fires when Get-ChildItem returns zero files, with a
specific WindowsApps message. Guarded by TargetReadable.Tests.ps1.

**Test-TcpkUpdateChannel (A53).** Firmware-updater desktop apps ship the same three
under-tested surfaces every time: a release-channel selector (release/beta/dev/nightly),
an update endpoint held in a config file, and a locally persisted "current version" the
client uses in its comparison. Test-TcpkUpdateFlow (F02) already covers signature
verification. This one covers the config-side attack surface. Five rules:

- update.channel-selectable        MEDIUM when the config file is user-writable, INFO otherwise
- update.endpoint-in-writable-config  HIGH when a discovered update URL sits in a Users-writable file
- update.endpoint-plaintext        HIGH for any http:// update URL in config
- update.endpoint-in-config        MEDIUM when neither of the above but a URL is present
- update.state-in-writable-path    MEDIUM when the client persists its own "current version"
- update.device-fanout             INFO scope only, when the binaries reference connected-device
                                    updates alongside app updates

**Test-TcpkCefSharp (A52).** CefSharp is the .NET Chromium embedding used across
industrial and engineering software, and its JavaScript-to-native bridge is the same
class as Android's addJavascriptInterface. Detects four things: RegisterJsObject /
JavascriptObjectRepository (HIGH Confirmed), CefSettings.RemoteDebuggingPort (HIGH),
WebSecurityDisabled and --disable-web-security (HIGH), and file-scheme cross-access
(MEDIUM). Also emits a scope-only INFO when the assembly embeds CefSharp but nothing
higher fires. Text-based; first-party CefSharp assemblies are skipped by name.

**Cheap correctness pass.**

Every findings.json, sbom.cdx.json, report.sarif and coverage.json shipped so far started
EF BB BF. Set-Content -Encoding UTF8 emits utf-8-BOM on PowerShell 5.1, and Node's JSON.parse
plus Python's strict json.load both reject it. No test suite ever caught it because every
internal reader uses ConvertFrom-Json, which strips the BOM. A shared Save-TcpkJson helper in
_JsonOut.ps1 now routes every writer through IO.File.WriteAllText with UTF8Encoding(false),
and the shipped DVTA sample artifacts were stripped in place.

Also fixed:

- SARIF informationUri, which was 'https://github.com/' as a placeholder, now points at the
  Pages site.
- Tool version was hardcoded as '2.7.1' in the SARIF exporter, the SBOM exporter, the intel
  dashboard and the agentic launcher, all of which drifted from the actual ModuleVersion.
  Get-TcpkModuleVersion resolves it at runtime.
- exploit-map.json routed on strongname\.absent; the emitted RuleId is strongname.unsigned.
  Dead route until now.
- TC18's checklist rule was the empty string, so it was pinned to MANUAL-ONLY regardless of
  any error probe. Now matches ^(error|log\.stack-trace)\., coverage moved from GAP to PARTIAL.
- TC02/TC03/TC08/TC23/TC25 widened to catch the exploit RuleIds the tool actually emits:
  tamper, expiry, logout, authmatrix, fixation, exploit.stored-credential, com.auto-elevates,
  flagflip. Before, 71 of 94 exploit RuleIds reached no checklist row.

Two suites cover both halves: ExploitToChecklist.Tests.ps1 pins the widened regexes and
IoTCompanion.Tests.ps1 already has a BOM assertion via the writer.

---

**Phase 1 IoT companion coverage.** Four new detectors and eight new credential rules,
targeting the seam TCPK is uniquely placed to see: Windows desktop apps that provision,
configure and update a physical connected device.

- **Test-TcpkFirmwareImages** (A49). Reports device firmware shipped inside the install
  tree: UF2, DFU suffix, ELF, Intel HEX, Motorola SREC, raw .bin and ZIP flash bundles.
  Reads header magic where a single value settles the format so a .bin with the wrong
  content is not miscalled. Escalates to HIGH when the resting DACL grants write to a
  non-admin group.
- **Test-TcpkDeviceComm** (A50). Enumerates the device-communication channels a binary
  references: serial (System.IO.Ports and native SetupComm), USB HID, WinUSB, libusb,
  BLE central role, classic Bluetooth SPP, and DeviceIoControl to a vendor driver. Reads
  .NET IL and native PE imports. Inferred; a runtime trace closes it.
- **Test-TcpkDiscoveryProtocols** (A51). mDNS/Bonjour, SSDP/UPnP, WS-Discovery, ONVIF,
  LLMNR/NetBIOS, and generic UDP broadcast usage in the client. Names the surface a LAN
  tester can respond to.
- **Test-TcpkShippedTooling** (D09). Signed vendor programming CLIs bundled next to the
  GUI: esptool, espefuse, ST-LINK_CLI, JLink, OpenOCD, dfu-util, avrdude, nrfjprog and
  more. Fuse and secure-boot writers grade HIGH because they are permanent operations.
- **secrets.json** gains eight IoT / cloud credential rules: AWS IoT and ATS endpoints,
  Azure IoT Hub connection strings and SAS tokens, GCP IoT registries, MQTT URLs with
  embedded credentials, Particle.io tokens, and Espressif provisioning PoP strings.

All four cmdlets run inside `Invoke-TcpkAudit` next to the existing static detectors.
Eight Pester cases in `IoTCompanion.Tests.ps1` use synthetic firmware and fake vendor
binaries, so they run without Windows.


**Invoke-TcpkParamTamper (K24)** and the response body it needed.

`New-TcpkHttpSnapshot` returned Status, Len, Hash, a 256-char BodyHead, Redirect,
ServerDate and ElapsedMs, so everything downstream decided by hash equality and
status code. That cannot answer verbose-error disclosure, session fixation or
parameter tampering. It now also returns `BodyText`, `BodyBytes` and `Headers`,
with `-MaxBodyBytes` and `-RetainSensitive`. Additive; both existing callers are
untouched.

The tamper probe sends three requests per parameter: baseline, tampered, and a
bogus control no correct server should accept. The control is what makes the
verdict defensible. Without it an endpoint that returns 200 to anything reads as
"tampering accepted" on every parameter it has, so that case reports NOT
CONCLUSIVE instead. Classes covered are price, quantity, boolean entitlement
flags, role and page limit, across query parameters, JSON body leaves and form
fields. Path segments, cookies and headers are excluded on purpose: a tampered
cookie is indistinguishable from a broken session.


ProcMon-equivalent rework. The three ETW checks were one piece of code copied three
times, and the duplication was the defect: a rule fixed in one was silently not fixed
in the other two.

**New cmdlets (260 -> 261)**

- **Invoke-TcpkActivityTrace** (E24) -- one ETW capture window, analysed three ways.
  Starts a single logman session carrying both the kernel file and kernel registry
  providers, then runs the DLL-probe, file-write and registry-write analysers over the
  same capture. `-Include` / `-Exclude` regex filters, `-IncludeChildren`, `-KeepEtl`,
  and `-Check` to pick analysers. Emits an `activity-trace.window` scope line stating
  the event count, the PIDs covered and any provider that failed to attach.

**Fixed**

- **The audit made you exercise the app three times.** `Test-TcpkDllSearchTrace`,
  `Test-TcpkRegistryWrites` and `Test-TcpkFileActivity` each opened their own 30 second
  session and ran in sequence. The first two subscribe to the SAME provider, so a DLL
  probe and the write that followed it came from different windows and could never be
  correlated. The audit now runs one window.
- **Child process activity was discarded.** Every check filtered on the exact target
  PID, so a thick client that spawns a helper, updater or renderer had all of that
  child's file and registry activity dropped. `-IncludeChildren` covers the process
  tree, and the audit passes it. The limit is stated rather than hidden: a child that
  both starts and exits inside the window is still missed.
- **The capture was deleted even when parsing failed.** That is the one case where the
  operator wants the .etl, since re-recording costs another full exercise cycle. It is
  now retained on a parse failure regardless of `-KeepEtl`, and its path is named in the
  finding.
- **No way to narrow or silence.** Filters were hardcoded regexes. `-Include` and
  `-Exclude` apply on top of each check's own rules. Exclude beats Include, and an
  invalid pattern keeps the event rather than manufacturing a clean result.
- Evidence now names the PID that actually raised the event, which may be a child,
  rather than always naming the target.

**Internal**

- New `_Etw.ps1` (capture: session, process tree, one-pass ETL parse, operator filter)
  and `_EtwRules.ps1` (the three analysers as pure functions over parsed records).
  Rule ids, severities, CWEs and finding text are carried over unchanged.
- The three cmdlets are now thin wrappers over that engine, 298 lines lighter.
- **These checks now have a test suite, and could not have had one before.** Capture and
  analysis were the same function, so testing meant admin rights, a live ETW session and
  a 30 second sleep. 23 cases in `EtwActivity.Tests.ps1` feed synthetic records instead.

## v2.9.0

Proof and honesty release. Two themes. Three new active probes prove a server-side
control is missing rather than inferring it, and a run of "clean-looking" views
turned out to be hiding how much they had dropped.

**New cmdlets (254 -> 260)**

- **Invoke-TcpkAuthMatrix** (K19) -- vertical authorization matrix. Replays one
  captured request once per role with only the credential swapped. The first role is
  the baseline and must be accepted, otherwise the capture is stale and every
  comparison below it is a false pass, so the run stops and says so.
- **Invoke-TcpkExpiryProbe** (K22) -- proves a server honours a token past the expiry
  it issued. Both times come from the server: the deadline is the signed `exp`, the
  current time is the response `Date` header. No local clock is consulted, which
  removes "your clock was wrong" as a rebuttal. Does not wait out the window.
- **Invoke-TcpkLogoutProbe** (K23) -- replays an authenticated request after the app's
  own logout succeeds. The verdict depends on `-SessionModel`, because a stateless JWT
  surviving logout is a documented trade-off while a server-side session surviving it
  is a defect. A JWT with no usable `exp` that also survives is HIGH regardless: nothing
  expires it and nothing revokes it.
- **Test-TcpkEmbeddedBlobs** (A48) -- finds formats embedded at arbitrary offsets (PE,
  SQLite, archive, private key). Structural validation is the whole check: the shipped
  Mono.Cecil.dll alone contains four bare `MZ` sequences, so a match-only scan reports
  three phantom executables in TCPK's own tools directory. Rejected candidates are
  counted and surfaced.
- **Invoke-TcpkJavaDecompile** -- real Java decompilation via CFR, the counterpart to
  Invoke-TcpkDecompile. CFR and a JRE are resolved, never redistributed. "Not installed"
  and "installed but produced nothing" are separate warnings.
- **Get-TcpkFileStructure** -- applies a byte pattern (a flat table of name/offset/size/
  type) and returns a header as decoded fields. Deliberately not a pattern language.
  Ships patterns for SQLite, ZIP local header, PE DOS header and WAV, each verified
  against a real file. `-BaseOffset` parses a structure located by Test-TcpkEmbeddedBlobs.

**Fixed: views that hid how much they dropped**

- Dashboard "Top findings" capped at 14 rows and never said so, so 14-of-14 and
  14-of-212 rendered identically. The heading now carries the count.
- The Hex entropy strip read only the first 10 MB while its caller had sized blocks to
  span the whole file, so on any target over 10 MB the colours described one range and
  the click handler jumped to another. Streaming removed the cap; peak memory dropped
  from 10 MB to one block.
- Pcap Conversations hid the real column header and hand-drew a substitute that could
  not scroll. With 1200px of columns, scrolling right desynchronised every heading from
  its data permanently.
- Hex search offered ascii and hex only. Windows stores string literals as UTF-16LE, so
  searching a binary for a string it demonstrably contains returned nothing. Kinds are
  now auto (the default, both encodings), ascii, utf16le, hex, regex. The agentic UI
  carried a second copy of the same matcher and had the identical defect.
- The Dashboard gained a readiness verdict: complete / degraded / unreliable. The case
  it exists for is a packed binary, where every check runs, the coverage totals read
  100%, and the report is short and tidy because the scanners could see nothing.

**Fixed: MCP security**

- `tcpk_audit` executed an attacker-supplied MSI's custom actions. Expand-TcpkTarget
  routes `.msi` to `msiexec /a`, an administrative install runs the package's own code,
  and this handler removed both CLI safeguards by hardcoding `Acknowledge` and piping
  through `*>$null`. Now requires `runInstaller=true`, decided by asking Get-Item for
  the extension exactly as the dispatcher does.
- `outDir` refused for UNC and device paths on every tool (opening `\host\share`
  performs SMB session setup and leaks Net-NTLMv2 before the file-exists check returns),
  and confined to the tool folder for the two tools that create things.
- One boolean parser replaces four. `[bool]` on the string "false" is `$true` in
  PowerShell; that was handled correctly once for `authorized` and then not reused.
- `processName` rejects wildcards, which would attach live-process checks to unrelated
  processes.

**Fixed: Copilot never connected**

The GUI enabled the cloud consent with `if ($needsKey)`. needsKey asks whether the
operator types a credential; cloud asks whether the target's code leaves the machine.
Every other cloud provider answers yes to both, so the conflation was invisible until
copilot, which needs no key but is cloud. The gate never got set, the backend resolver
threw before opening a socket, and the proxy log stayed empty. Test-TcpkLlm reported
the reason on the warning stream, which the GUI does not display, so every failure
looked like a bare "Reachable=False"; it now returns the reason and reads the HTTP
response body, where a SAML SSO refusal actually names itself.

**Hex tab**

Data inspector gained GUID, FILETIME and int64 BE. New modes: Byte Pattern and Byte
Map (one pixel per byte, blocks averaged rather than sampled because aliasing invents
structure that is not there). Diff gained a whole-file summary and Prev/Next
navigation, with a size mismatch reported as a length delta rather than counted as
thousands of differing bytes.

**Surfaces**

MCP gained tcpk_byte_search, tcpk_embedded_blobs, tcpk_file_structure and
tcpk_file_diff. The agentic UI gained /api/agent/structure, /embedded and /filediff.
Byte Map is deliberately not exposed to MCP: it is a picture and a model cannot use one.

**Other**

Log-file tampering ACLs (`log.tamperable-file`, `log.tamperable-directory`). The eight
new active-probe findings mapped to TASVS by exact rule id, not prefix, because the
other 17 rules those cmdlets emit are refusals and clean results that must stay
untagged. DVTA credited. Nine new test suites.

## v2.8.0

Coverage and honesty release. The theme is that a check which cannot run must say
so, rather than returning nothing and looking like a clean result.

**New cmdlets (250 -> 254)**

- **Test-TcpkJavaSigning** -- unsigned JARs (severity raised when the containing
  directory is writable), mixed-signature archives where content entries are covered
  by no `.SF` or `MANIFEST.MF` entry, and MD5/SHA1 digests. Structural reading only;
  no signature is cryptographically verified and every finding says so.
- **Expand-TcpkPyInstaller** -- carves the PyInstaller CArchive and cx_Freeze /
  py2exe `library.zip`, so a Python thick client's code surface is readable. Recovers
  `.pyc`; it does not decompile it. Refuses entries that resolve outside the output
  directory.
- **Test-TcpkGoRustDeps** -- recovers Go build-info modules and Rust crate versions
  from statically linked binaries and feeds them to the existing OSV matching, so Go
  and Rust targets get supply-chain coverage for the first time.
- **Test-TcpkQtSurface** -- QSettings credential storage (value masked), the QProcess
  single-string API family reported as surface rather than proven injection, bundled
  Qt WebEngine, QML dynamic construction, and a `.rcc` inventory.

**Coverage honesty**

`Test-TcpkScanCoverage` now also reports four conditions where every check ran to
completion and the results still are not evidence: a **packed** binary (the text rules
read the stub), a **single-file bundle above the extractor ceiling** (its assemblies
were never carved), a **non-managed target** (the IL provers had nothing to parse), and
a **failed CVE lookup** (TCPK ships no offline CVE data, so the dependency surface was
not tested). The first three and the CVE case raise the finding to MEDIUM and rewrite
the title to say UNRELIABLE, INCOMPLETE or NOT TESTED.

**Everything TCPK creates now lives inside the tool folder**

Reports, extractions, captures, memory dumps and traces moved from `%TEMP%` and from
CWD into `work\` under the tool folder (`out`, `extract`, `capture`, `dump`, `trace`,
`vulndb`, `run`). Windows does not clear `%TEMP%` on reboot, so engagement data used to
outlive the engagement and survive deleting TCPK. There is deliberately no fallback to a
temp or profile path; `Set-TcpkWorkRoot` is the explicit override. `work/` is gitignored.

**Fixes**

- `Invoke-TcpkOnFileText -Utf8Only` built its view list in a way PowerShell unrolled on
  assignment, so every caller received a one-character string. Nothing errored and the
  checks simply matched nothing. This had silently disabled cert-validation bypass, IPC
  handler-to-sink correlation, contextBridge analysis, deep-link surface and zip-slip
  detection on Electron targets. Restores 26 detection tests and the benchmark's
  `recall = 1.0` assertion.
- `Test-TcpkMemoryDump` and `Invoke-TcpkDecompile` built their bundled-tool path with
  `'..\..\'` from the module root, which resolved to a sibling of the tool folder, so a
  bundled `procdump.exe` or `ilspycmd.exe` could never be found.
- `Test-TcpkMemoryDump` deleted an operator-supplied `-DumpPath` it had not created.
- The JIT allowlist in `Test-TcpkMemoryRegions` listed `vulkan-1.dll` and
  `d3dcompiler_47.dll`, which ship in System32. Any Vulkan or D3D app tripped the JIT
  gate and had a genuine RWX finding downgraded from HIGH to INFO.
- The GUI called Pester's `InModuleScope`, undefined on a machine without Pester, so
  AI-verify threw on a stock Windows box. It resolved `tshark` by PATH only, and
  Wireshark does not add itself to PATH, so the Pcap tab silently did nothing on a
  normal install.
- Removed five strings promising an offline CVE catalogue that does not exist.

**Documentation**

- New `docs/INSTALL.md`: the eight optional tools, what each unlocks, and the two ways
  TCPK finds them (a `tools\<name>\` folder checked before PATH, or a normal install).
- `NOTICE` added, reproducing the Mono.Cecil MIT and CVSS v4.0 BSD-2-Clause notices with
  the SHA256 of each shipped assembly.
- Reconciled the check counts, which previously disagreed across seven documents.

## v2.7.1

Scoping and GUI quality-of-life patch.

**Target-scoping fixes** -- five scanners that reported machine-wide state unrelated to the audit target now correctly scope findings to the target directory:

- **Test-TcpkWritablePath** -- only reports PATH directories that are parents, children, or equal to the target install directory (was: every writable PATH entry system-wide).
- **Test-TcpkAvExclusions** -- no longer reports every non-matching Defender exclusion as INFO.
- **Test-TcpkWerExposure** -- removed default WER path scan and global WER policy finding; only per-app WER settings for the target remain.
- **Test-TcpkTokenCaches** -- removed hardcoded well-known Azure/MSAL path scan; only the target directory is scanned.
- **Test-TcpkWerPolicy** -- removed global WER default/global policy findings; only per-app WER policy for the target exe remains.

**GUI live findings feed** -- findings now stream into the Findings table in real-time during the audit, not just after completion:

- Job pipeline detects TCPKFND information records and emits them as FND lines (was: wrapped as LOG lines, so they appeared in the log pane but never reached the findings table).
- Drain loop after job completion now also parses FND lines so no findings are lost in the final batch.
- ListView is cleared before the JSON reload phase to prevent doubling streamed findings with CVSS-enriched ones.

## v2.7.0

The biggest detection release yet: 19 new public cmdlets (184 -> 203) covering attack surfaces, DLL hijack paths, IPC channels, and exploit tooling. Full agentic workbench documentation with screenshots of all 13 tabs.

**New static analysis scanners.**

- **Test-TcpkGrpcSurface** -- detects shipped `.proto` files, gRPC service definitions, and reflection-enabled configs. Maps to T1046 Network Service Discovery. (jsmon.sh 2025)
- **Test-TcpkWv2Sideload** -- flags WebView2 apps vulnerable to `WebView2Loader.dll` sideloading via missing fixed-version runtime. Maps to T1574.002 DLL Side-Loading. (Black Hills InfoSec 2025)
- **Test-TcpkAmsiSurface** -- identifies AMSI integration points (AmsiInitialize/AmsiScanBuffer) in first-party PEs, flagging the evasion surface. Maps to T1562.001 Disable or Modify Tools. (CrowdStrike VEH2 2025)
- **Test-TcpkHollowingApis** -- detects process hollowing, DLL injection, and APC injection API sequences (NtUnmapViewOfSection + WriteProcessMemory + SetThreadContext, VirtualAllocEx + CreateRemoteThread, QueueUserAPC). Sequence correlation elevates from MEDIUM (individual API) to HIGH (complete injection chain). Maps to T1055.012 Process Hollowing. (Google Cloud / hasherezade 2025)
- **Test-TcpkAppDomainHijack** -- scans for AppDomainManager injection surface via `.config` files or registry keys that redirect the CLR's domain manager. Maps to T1574.
- **Test-TcpkAotBinary** -- detects .NET AOT/NativeAOT/ReadyToRun binaries and gates the IL pipeline (Mono.Cecil cannot decompile AOT-compiled code). Prevents false negatives from silent IL parse failures.
- **Test-TcpkClickOnce** -- scans ClickOnce deployment manifests (`.application`, `.manifest`) for full-trust permission sets, unsafe file associations, and update-URL hijack surface.
- **Test-TcpkMsixPsf** -- extracts and analyses MSIX Package Support Framework (PSF) `config.json` scripts. Flags script injection, DLL fixups, and writable VFS redirections.
- **Test-TcpkPhantomDlls** -- identifies phantom DLL planting opportunities: known DLL names that the target imports but does not ship, which an attacker can plant in the application directory.
- **Test-TcpkDiagConfig** -- scans for diagnostic configuration exposure: `.diagcfg`, ETW trace configs, WCF diagnostics, and Application Insights keys that leak telemetry endpoints or enable verbose logging.
- **Test-TcpkDllSideload** -- identifies DLL sideloading candidates by cross-referencing the target's imports against its shipped DLLs, flagging any first-party EXE that loads a DLL it does not bundle.

**New OS / runtime scanners.**

- **Test-TcpkComHijack** -- scans for COM per-user CLSID hijack opportunities: CLSIDs registered under HKLM that an unprivileged user can shadow by writing to HKCU, redirecting COM activation to attacker-controlled code.
- **Test-TcpkWerExposure** -- checks Windows Error Reporting (WER) crash dump settings for the target process. Flags LocalDumps configurations that write full memory dumps to world-readable directories.
- **Test-TcpkWritablePath** -- scans the system PATH for directories writable by the current user. Any writable PATH directory is a DLL planting / binary hijack vector.
- **Test-TcpkSharedMemoryDacl** -- audits shared memory (memory-mapped file) DACLs for open sections that allow cross-process read/write, an IPC tampering vector.
- **Test-TcpkWindowMessages** -- detects the window message attack surface: registered window classes, message-only windows, clipboard listeners, and WM_COPYDATA handlers.
- **Test-TcpkClipboardSecrets** -- monitors the clipboard for secrets (API keys, tokens, passwords) placed by the target application. Point-in-time capture; read-only.

**New exploit / PoC tooling.**

- **New-TcpkIlPatch** -- deterministic IL binary patching via Mono.Cecil. Patches a method body in a .NET assembly (NOP a branch, force a return value) and writes the modified binary. Gated behind Enable-TcpkExploit.
- **New-TcpkRegistryHijackTemplate** -- generates IFEO (Image File Execution Options) and AppInit_DLLs registry persistence PoC `.reg` files for a target executable. Gated behind Enable-TcpkExploit.

**Enhanced existing scanners.**

- **Test-TcpkElectron** -- added electron-updater signature bypass detection and Squirrel.Windows update hijack scanning.
- **Test-TcpkDebugFlags** -- WDAC bypass detection via signed Electron resource directories.
- **Test-TcpkSignature** -- NuGet package vulnerability scanning wired into the CVE matching pipeline.
- Severity re-baseline: downgraded 10 over-rated rules to accurate severity levels.
- exploit-map.json linkage fixed for 7 existing exploit tools.

**Hex workbench enhancements.**

- PE structure overlay with section-colored hex regions.
- Entropy heatmap strip alongside the hex view.
- XOR/decode toolkit in the toolbar.
- Binary diff (side-by-side compare two files).

**Agentic workbench.**

- Hash-based tab routing (`#tab=N` URL fragment) for direct tab navigation.
- Full documentation with screenshots of all 13 tabs (`docs/AGENTIC-WORKBENCH.md`).

**Testing.** 5 new test files: AttackSurface2.Tests.ps1, AttackSurface3.Tests.ps1, AdvancedDetection.Tests.ps1, ExploitMapAndRegistry.Tests.ps1, NewSecurityFeatures.Tests.ps1. All ATT&CK, TASVS, and CVSS mappings covered.

## v2.6.1

An Asar-tab supply-chain audit plus a GUI alignment fix. Cmdlet count unchanged (184; the new helpers are private).

**Asar tab: npm supply-chain audit.**

- New **npm audit** action on the Asar tab. Point it at an Electron `app.asar` (or the install folder) and it inventories every bundled npm package (walking the packed `node_modules` tree), matches them for known CVEs against **OSV / GHSA** (reusing the existing OSV engine, `-Ecosystem 'npm'`), and -- the signal a plain CVE feed misses -- flags packages the **npm registry marks deprecated / unmaintained**. The result prints as an npm-audit-style report (severity-sorted vulnerabilities with fix versions, then deprecated packages) into the source pane. Read-only; the deprecation check is capped and the whole path fails closed offline.
- Backend is three private helpers in `_EcosystemCve.ps1` (`Get-TcpkAsarNpmAudit`, `Get-TcpkNpmDeprecation`, `Format-TcpkNpmAuditReport`); the formatter is pure so it is unit-tested (`NpmAudit.Tests.ps1`). Verified end-to-end against a real 205-package Electron app.

**Fixes.**

- **Asar "filter files" alignment**: the filter textbox was anchored Left+Right inside the fixed-width left panel and stretched past it (to ~646px in a 430px panel), spilling into the source viewer. It is now a contained fixed width.
- `Split-Path -LiteralPath ... -Parent` is an ambiguous parameter set on PowerShell 5.1; the npm-audit path now uses `[IO.Path]::GetDirectoryName` instead.
- Report output stays pure ASCII even when an npm registry / advisory string carries emoji or other non-ASCII characters (folded to spaces).

## v2.6.0

Finalises the 2.6.0 line: the detection uplift shipped in `v2.6.0-rc1` plus an accuracy pass, a UI pass, and an MCP pass. Cmdlet count unchanged (184; every new helper is private).

**Accuracy (the false-positive pass).**

- Severity-anchored **CVSS v4.0**: the computed score is now derived from a per-severity, per-attack-vector band (`$script:TcpkCvssBandVector`) instead of a generic archetype, so a LOW finding scores LOW and a HIGH scores HIGH -- the report's number matches its badge rather than inflating it. A purely local bug can only reach CRITICAL with genuine subsequent-system impact. CVE / dependency findings defer to the advisory score.
- **Electron-aware provenance gate** (`Test-TcpkIsFirstParty`): the single largest false-positive source on Electron apps was a secret / import / endpoint matched *inside a bundled file* (the Electron main exe, a Chromium DLL, an NSIS uninstaller, a `LICENSES.*` blob) being attributed to first-party code. The gate classifies those as not-first-party -- by name, by size, and structurally (a loose PE beside `resources\app.asar`) -- and is wired into the noisy scanners (secrets, entropy, endpoints, callsites, native APIs, self-hosted server, update flow, ETW). Genuine app code (`app.asar` JS, the vendor's own DLLs) is still scanned.
- Secret-scan guards for natural-language values (a `WRONG_PASSWORD: "Wrong Password"` UI string is a label, not a credential) and for the canonical `user:pass@host` doc placeholder. Loopback endpoints (`127.0.0.1` / `localhost`) are now INFO `endpoints.loopback` instead of a non-production HIGH.

**Detection (beyond rc1).** Crypto-constant, `TypeNameHandling` and cross-assembly taint IL verdicts; token-privilege / integrity-level checks; CVE native-banner scan; intercept response-body mining + tamper differential; HKCR URI-activation scoping; Windows TLS hooks (schannel / winhttp / wininet); a gated launch-and-observe harness; credential-store decryption (DPAPI + BCrypt-GCM); and three new exploit chains.

**UI.** The desktop GUI gains a **Dashboard** landing tab (severity tiles, max CVSS, an assurance donut of proven vs leads vs likely-FP, and a top-findings table) and a **DLL Decompiler** tab (Mono.Cecil type / method browser with IL, optional `ilspycmd` C#, wrap toggle and hover tooltips), on a refreshed teal palette. The agentic workbench gets the matching Dashboard. `Invoke-TcpkGuiUnlock` now also detects and unlocks read-only (`ES_READONLY`) fields alongside disabled controls and masked password fields.

**MCP.** The server exposes the decompiler -- `tcpk_list_modules` and `tcpk_decompile` (a module's sink-bearing methods, and per-instruction IL with sink flags: the evidence behind `Confirmed (IL)`). `tcpk_get_findings` now returns findings enriched through the same intel model the reports use (computed CVSS, CWE, ATT&CK, TASVS, how-to-verify). Tools carry read-only / destructive / network annotations so a client can auto-approve the safe ones and still prompt on the gated PoC generator. First MCP test coverage (`McpServer.Tests.ps1`).

---

Detection uplift (as shipped in `v2.6.0-rc1`) -- a recall + IL-proof pass on the detection engine (grounded in a code-level capability review).

- Secrets: +17 modern provider rules -- OpenAI, OpenAI-project, Anthropic, GitLab, Google OAuth, Slack webhook + app token, SendGrid, npm, PyPI, HashiCorp Vault, DigitalOcean, Databricks, Postman, Shopify, credentials-in-URL, and hardcoded HTTP Basic auth header. All loss-free (explicit prefilters), so recall rises across the static, live-memory, and env scans at once.
- IL prover reach: added the base `System.Data.Common.DbCommand` / `IDbCommand` / `DbDataAdapter` types (Dapper / EF-raw / DbProviderFactory) and `System.Net.Http.HttpMessageInvoker` to the injection sink map, so SQL / SSRF through the abstraction layer is now invocation- and taint-checked instead of invisible. Routed `reflection.dynamic-load` through `Confirm-TcpkCallsiteUsage` (new `reflection-load` sink family) so a tainted `Assembly.LoadFrom(path)` reaches `Confirmed (IL)`.
- IL taint sources broadened to the input channels desktop apps actually use: `OpenFileDialog`/`SaveFileDialog`, drag-drop (`DataObject` / `DragEventArgs`), `Clipboard`, and deserialized-object results.
- Electron insecure-by-default: correlates the extracted Electron major with an *omitted* hardening key -- `nodeIntegration` defaults ON before v5 (CRITICAL), `contextIsolation` OFF before v12 (HIGH), sandbox OFF before v20 (MEDIUM). This is the common real misconfig the explicit-value checks missed.
- CVE triage: CISA KEV enrichment (`Get-TcpkKevSet`, cacheable + fails closed) flags every CVE match on the actively-exploited list -- the HTML report + exploit plan already render the badge.
- Named-pipe DACL now probes In -> Out -> Duplex, so write-accepting pipe servers (the cross-user injection primitive) are read instead of reported unreadable.
- Frida hook-mode capture parser now scans JSON REST bodies for secrets (parity with proxy mode).
- New `DetectionUplift.Tests.ps1` (17): each new secret rule detects a real positive; the sink-map / taint / reflection additions are present and a reflection finding is IL-processed; Electron insecure-by-default fires on an old runtime and not a modern one; KEV returns a HashSet and matches case-insensitively.

## v2.5.0-rc1

Release candidate for 2.5.0 -- a GUI + agentic-workbench pass on top of the workbench file tooling in v2.5.0-dev below.

- Hex view (desktop GUI + agentic workbench): a Data Inspector that decodes the bytes at an offset as typed values (int/uint 8/16/32/64 LE+BE, float/double, ASCII, UTF-16, u32 epoch); go-to-offset plus hex/ASCII find with row highlighting; a strings extractor (printable ASCII + UTF-16 "wide" strings with byte offsets, filterable, click a row to jump); and ImHex-style per-byte colouring (nulls dim, printable ASCII green, whitespace blue, control orange, high/extended purple) across both the hex and ASCII columns.
- Process Monitor tab (desktop GUI): one tab, two clickable modes sharing a process picker + console. Live watch re-renders a target's full state on an interval -- identity, version/company/owner/command line, memory counters, the COMPLETE loaded-module list with paths, TCP connections, child processes -- colour-coded into sections, with a module filter and Save-to-file. Activity capture baselines the target then logs NEW module loads / TCP connections / child processes with timestamps over a window (duration 0 = run until Stop, or until the process exits). Read-only and poll-based (driver-free -- not a kernel Procmon).
- Agentic workbench: Live watch ported to a new Process pane (loopback /api/agent/procmon, browser-polled). Read-only / discovery-only.
- Desktop GUI layout: Runtime / Live reflowed to an 8-column button grid with a Clear-output button; the Live Exploit / Creds group boxes go side-by-side and full-width with a draggable splitter between the controls and the output console; the Hex strings controls fold into the find row.

## v2.5.0-dev

Workbench + GUI file-analysis tooling, on top of the 2.4.5-dev precision work below.

- Desktop GUI: consolidated every process-based dynamic tool into a single Runtime / Live tab -- the read-only checks (loaded modules, ports, token, mitigations, DACL, env, memory, handles, windows, DLL-hijack ETW trace, named pipes/ALPC, COM/named-objects/RPC) plus the gated active tools (GUI unlock, pipe probe, flag-flip, input fuzz) moved out of the Exploit tab, which is now just CVE matches + PoC generation. Split the old Interception tab into Interception (mitmproxy proxy/tamper) and Live Exploit / Creds (Frida hook, Credential Manager dump, credential-liveness replay).
- Desktop GUI: two new file tabs -- Asar (unpack an Electron app.asar and read its JavaScript source in a dark-themed file browser) and Hex View (paged hex + ASCII of any file). Fixed the Exploit tab's clipped bottom row (the tab control overlapped the disclaimer strip).
- Agentic workbench: matching Runtime, Asar and Hex panels. The Decompile "Audit selected" now runs a FOCUSED per-binary audit (file-scoped PE / IL / secret / signing checks on the one module) instead of re-auditing the whole app, so each DLL gets its own findings instead of the same app.asar results repeated for every binary. The module list leads with decompilable .NET modules (native binaries behind a toggle); removed the confidence-ladder / severity legend from the rail.
- HTML report: dropped the redundant "Reading this table" explainer under the CVE section.

## v2.4.5-dev

PRECISION pass -- directly addresses the false-positive / low-assurance complaint. Root cause: TCPK was built breadth-first (~150 pattern detectors), and the deterministic IL prover only verifies callsites.* and deser.*, so most rules can only emit Inferred. The default output showed those unverified pattern hits next to the handful of proven bugs, which reads as noise (on DVTA: 10 proven vs 18 leads of 30 findings).

The audit now separates findings by ASSURANCE. NEW Get-TcpkAssuranceSplit partitions findings into PROVEN (a Confirmed* tier -- IL / dynamic / exploit / LLM / plain Confirmed, verified, act on these first) and LEADS (Inferred / Unverified -- pattern matches to triage, not confirmed bugs). The audit summary and console now lead with "N proven, M leads" and point the leads at AI triage (-EnableLlm) -- the agentic AI's real job is precision: verify a lead and promote it to Confirmed (LLM) or demote it, not add more noise. NEW Invoke-TcpkAudit -ConfirmedOnly returns PROVEN findings only (the reports still contain the leads, segregated by confidence), so a CI / scripted run acts on verified bugs.

Verified on DVTA via userspace pwsh: the summary reframes to "10 proven + 18 leads"; -ConfirmedOnly returns the 10 proven (all Confirmed*). Pure PowerShell, no Windows-runtime dependency. Follow-ups: default the HTML report view to proven-first with leads collapsed, and gate per-rule precision (false-positive rate) in bench/.

DETERMINISTIC XXE proof (converts a lead class into proven findings). The old xxe.* rules regex the assembly's raw text for source expressions like "DtdProcessing = DtdProcessing.Parse", which do NOT survive C# compilation (they become ldc.i4.2 + set_DtdProcessing), so XXE went effectively undetected in compiled thick clients. NEW Get-TcpkXxeVerdicts (Mono.Cecil, modelled on the proven Get-TcpkTlsCallbackVerdicts) reads the CONSTANT fed to each System.Xml setter, so it tells DtdProcessing.Parse (unsafe, ldc.i4.2) apart from Prohibit/Ignore (safe) and a real XmlResolver from the null-resolver mitigation -- a distinction a text scan cannot make. Test-TcpkXxe now emits xxe.dtd-processing-parse / xxe.external-xml-resolver / xxe.prohibitdtd-false at Confidence 'Confirmed (IL)'; a method that both enables DTD and assigns a non-null resolver (full external-entity read primitive) is escalated to CRITICAL, either alone is HIGH. Verified with a compiled fixture (TCPK/Tests/Xxe.Tests.ps1, 6 assertions): the four vulnerable methods are flagged, all four safe variants (Prohibit, Ignore, null resolver, default) are not.

LLM SKEPTIC-REFUTE lead triage (the agentic precision engine). The audit's -EnableLlm pass was single-shot and default-benign (promote if the model says "real"), which trusts one possibly-hallucinated verdict. It is now an ADVERSARIAL N-vote skeptic. NEW Invoke-TcpkLlmSkepticVote runs the refute prompt up to N times (default 3, early-stop at a majority, so ~2 calls per lead) and requires a MAJORITY of "real" verdicts to promote; a model throw, an unparseable reply, or an "uncertain" verdict is an abstain that can never create a "real" majority (default-refuted-if-uncertain). Invoke-TcpkLlmCodeJudgment now triages LEADS ONLY (Inferred / Unverified) and NEVER second-guesses a deterministic tier -- a local model can no longer override a Confirmed (IL) proof. A real majority promotes the lead to Confirmed (LLM) (it moves into PROVEN); a not-real majority demotes it to Likely-FP (LLM); anything unresolved stays the lead it was. The system prompt is reframed as an adversarial reviewer that defaults to not-real. Deterministic unit tests (TCPK/Tests/LlmSkeptic.Tests.ps1, Invoke-TcpkLlm mocked) prove the aggregation, early-stop, abstain-on-error, and the leads-only guard; verified end to end against a live local ollama (Inferred lead -> a parsed verdict -> confidence rewritten). Caveat surfaced by that run: the verdict is only as good as the backend model (a weak local 8B misjudged), which is exactly why the default is 3 votes and why deterministic proofs are never handed to the model. Use a capable model (qwen2.5-coder or a cloud provider, cloud-gated) for real triage.

## v2.4.4

Stable release of the 2.4.x line. It consolidates the interception + exploitation work in the v2.4.1-dev through v2.4.4-dev entries below, and adds a review pass on the LLM and MCP subsystems:

- SECURITY: Data/llm-config.json (which stores a cloud API key in plaintext once the operator configures one) is no longer tracked in git. The .gitignore rule for it was already present, but the file had been committed, so a tracked file bypasses the ignore and a key-write could have been staged; it is now untracked (the committed copy held an empty key, so nothing leaked). The module falls back to a built-in default when the file is absent, so a fresh clone is unaffected.
- MCP server: serverInfo.version is now read live from the module (was a hardcoded, stale 2.1.0); the tcpk_cve_match tool description now states LIVE online CVE (OSV + NVD, network required) instead of the removed offline catalog; and the tcpk_audit summary points at report.md (was a non-existent findings.md).
- LLM: the default Claude model is refreshed to claude-sonnet-5 (the previous id was stale); the model field is still free-text so any provider model can be typed.
- Desktop GUI: Start-TCPKGui.ps1 gains an Interception / Live Exploit tab surfacing the active 2.4.x cmdlets that were previously CLI-only (Invoke-TcpkIntercept proxy/hook/tamper, Invoke-TcpkHookBypass, Get-TcpkStoredCredentials, Test-TcpkCredentialLiveness), each behind the exploit gate.
- The standalone web control panel (Start-TcpkWebUi / TCPK-WebUI.bat) was removed. The agentic workbench (Start-TcpkAgentic / TCPK-Agentic.bat) provides the loopback browser surface and reuses the same web API engine, so there is one source of truth.
- Windows-verify fixes found while testing the active layer on Windows: Invoke-TcpkIntercept no longer fails to launch a target with no extra args; the http credential-liveness probe loads System.Net.Http on Windows PowerShell 5.1; and the verify-hint helper no longer throws when a finding's file field is a .NET type name rather than a path.

Verified on Linux: the MCP server answers a real JSON-RPC handshake (initialize / tools/list / ping) and a live tcpk_info tool call; the module imports and the LLM backend resolves (ollama, cloud-gated). Windows-runtime paths were verified on Windows earlier in this line.

## v2.4.4-dev

Adds the remaining thick-client exploitation primitives (the last specializations on top of the existing K01-K10 Exploit bucket).

NEW Invoke-TcpkHookBypass (Exploit bucket, GATED) -- the runtime-manipulation MANIPULATE leap. Injects a Frida hook that FORCES the return value of a named native export, so a client-side auth / license / integrity check the app trusts can be flipped by code running in its process. Reports exploit.check-bypassed as Confirmed (exploit) when the forced return actually executes. Targets native exports by name (a managed .NET method needs the frida-clr bridge, out of scope). Verified end to end on Linux with real Frida: a generated bypass forced libc atoi("7") to return 999 inside a live process, and TCPK parsed it to Confirmed (exploit).

NEW Get-TcpkStoredCredentials (Exploit bucket, GATED, Windows) -- the stored-credential extraction primitive. Enumerates and decrypts the current user's Windows Credential Manager via CredEnumerate (advapi32) and reports each recoverable secret as exploit.stored-credential (masked unless -Reveal). Win32-only; parse-checked here and degrades to a Skipped note off Windows -- verify on Windows.

Both gated behind Enable-TcpkExploit plus a -ConfirmDynamic / -Confirm acknowledgement; authorized targets only. Still open (the last two niche items, to build and verify on a live/Windows target): SQL-injection execution for a Confirmed (IL) sink, and deep-link / protocol-handler active exploitation.

Agentic workbench cleanup (keep-what-is-real pass): removed the decorative dashboard risk-gauge and severity donut, a dead unused CSS block, and a stale "building next" comment. The real severity counters, the findings triage table, and all eight functional tabs (Connect / Target / Audit / Decompile / AI review / Report / Autonomous agent / Interception) are unchanged.

## v2.4.3-dev

Closes the last two genuine thick-client pentest gaps. (The rest of the exploitation surface was already the K01-K10 Exploit bucket: DPAPI decrypt, memory flag-flip, GUI unlock, Frida TLS-bypass generator, pipe MITM, DLL/COM hijack scaffolds -- so this adds only what was actually missing, not duplicates.)

NEW Test-TcpkCredentialLiveness (Exploit bucket, GATED). Replays a credential recovered by Invoke-TcpkSecretRecovery or observed by Invoke-TcpkIntercept against a live service (http / sql / ftp) and reports exploit.credential-live as Confirmed (exploit) CRITICAL if the service accepts it -- turning an exposed secret into demonstrated impact. HTTP uses a with-credential vs without-credential comparison so an unprotected URL cannot false-positive (confirmed only when anonymous is rejected and authenticated is accepted); SQL uses whichever .NET SqlClient the host has; FTP attempts a listing. Gated behind Enable-TcpkExploit + -ConfirmActive; authorized targets only.

NEW Invoke-TcpkIntercept -Mode Tamper. mitmproxy MODIFIES matching traffic in flight (literal find=>replace rules via -TamperRules and the bundled tcpk_tamper.py addon), so you can probe whether the backend re-validates client-supplied values (role / authorization / price / injection) server-side or trusts the client. Each change is reported as intercept.tamper-applied (Confirmed dynamic). Complements the observe-only proxy/hook modes.

Verified on Linux: credential liveness passes 4/4 against a local HTTP listener (valid credential -> Confirmed exploit, wrong credential rejected, gate + -ConfirmActive enforced); the tamper addon is proven with a REAL mitmproxy round-trip -- a request body role=user was rewritten to role=admin before it reached the upstream, which echoed the modified value. Windows-pending: launching a real Windows target through tamper/proxy mode, and SQL/FTP liveness against a live backend.

## v2.4.2-dev

NEW Interception tab in the agentic workbench (Start-TcpkAgentic). Load a captured traffic session -- a mitmproxy flows.jsonl (proxy) or a Frida hook.log (hook) written by Invoke-TcpkIntercept -- and it renders the intercept.* findings in the workbench, colour-coded by severity and confidence. DISCOVERY-SAFE by design: the tab only PARSES a local capture via the ungated -FlowFile / -HookFile path (a new /api/agent/intercept endpoint backed by Get-TcpkAgentInterceptReview); it never launches or injects, so the gated active capture stays a CLI operation and off the loopback browser -- preserving the workbench's discovery-only invariant. Verified on Linux: the backend endpoint returns findings from real captures and errors gracefully on a missing file; the workbench HTML + JS is intact and JavaScript-syntax-valid; the full 71-file test suite shows ZERO regressions from the change (identical pass/fail with and without it). Windows/browser-pending: the interactive click-through in a real browser.

## v2.4.1-dev

NEW Invoke-TcpkIntercept (Verify bucket) -- thick-client traffic interception, the phase-3 gap in the pentest workflow. TCPK does not reimplement a proxy: it orchestrates mitmproxy (mitmdump) with a bundled capture addon (Data/tcpk_capture.py) and parses the captured flows into intercept.* findings -- backend endpoints confirmed on the wire (Confirmed dynamic, upgrading the static backend-endpoint inference), HTTP Basic and bearer/session credentials, credential/secret parameters in the query or body, and cleartext-http transport (CWE-319/522). Two modes: a cross-platform, ungated PARSE mode (-FlowFile parses an existing mitmproxy capture into findings) and a GATED active mode (-Target launches the app through a local mitmdump and observes its traffic; needs Enable-TcpkExploit + -ConfirmDynamic, Windows, and the app to trust the mitmproxy CA and honour the system proxy -- TCPK's static tls.pinning-absent finding says in advance whether that will work). Read-only observation: the addon never modifies a flow. mitmdump is NOT bundled -- drop the portable binary in tools/mitmproxy/ or on PATH. New test Intercept.Tests.ps1 feeds a synthetic capture and asserts the findings (runs without mitmproxy). Dev build: the flow parser is verified end to end on Linux (real mitmproxy round-trip); the active app-launch path is Windows-verified-pending.

NEW hook mode (-Mode Hook) -- inline API hooking via Frida, the Echo Mirage approach, for the proxy-ignoring / certificate-pinned / non-HTTP thick clients that proxy mode cannot reach. TCPK orchestrates Frida with a bundled hook script (Data/tcpk_hook.js) that hooks the socket and TLS functions (Winsock send/recv, OpenSSL SSL_write/SSL_read, libc send/recv) and reads plaintext AT the API, so it works regardless of proxy routing, CA trust, certificate pinning or protocol. It emits the same intercept.* findings plus intercept.api-hook-plaintext when TLS plaintext is recovered. The static recon network-stack fingerprint tells you which functions the app uses. A new ungated cross-platform -HookFile mode parses an existing hook capture. Frida is not bundled (pip install frida-tools, or drop the binary in tools/frida/ or PATH). Verified end to end on Linux with real Frida 17: the hook injects into a live process, captures the plaintext socket buffer, and TCPK recovers the credential -- a real run that also surfaced and fixed a resolver bug (Module.getExportByName was removed in Frida 17, so the first script silently hooked nothing). Windows-pending: injection into a real Windows thick client. Parser has its own tests in Intercept.Tests.ps1.

## v2.3.0

Autonomous agent -- call-graph + taint investigation tools, deepening "agent proposes, IL prover disposes". Beyond the original list / inspect / submit / finish, the agent gains three READ-ONLY tools: get_taint_trace returns the deterministic source->sink verdict for a method straight from the audit's IL prover (Get-TcpkCallsiteUsage) -- tainted-reachable (external input reaches a reachable sink), constant-only (not injectable), reachable-nonconstant-no-source, or no-sink; get_callers walks the call graph UP (each caller carrying its own reachability) toward an entry point / event handler to establish attacker reachability; get_callees drills DOWN into what a method invokes, with sinks flagged. submit_finding now records the prover's taint_verdict on every finding, and the system prompt directs the model to ground a candidate with get_taint_trace before submitting. The step budget is raised 14 -> 20 for the richer inspect -> taint -> callers -> submit flow. All helpers are private and read-only; the exploit bucket is never exposed to the agent. New test AgentTools.Tests.ps1 compiles a C# fixture and asserts the tool verdicts mirror the IL prover (public parameter -> Process.Start is tainted-reachable; a constant argument is constant-only). A deterministic verification gate (Resolve-TcpkAgentFindings) then runs at the end of the loop and partitions the agent's submitted findings by their recorded taint verdict into confirmed (tainted-reachable) / review (reachable, source unproven) / refuted (constant-only, no-sink), annotates each with verdict_class, and returns the partition + counts on the loop result (surfaced live as a "prover gate" line) -- so the agent's claims are honestly triaged, not taken at face value.

NEW Invoke-TcpkSecretRecovery (Verify bucket) and a new Confirmed (exploit) evidence tier -- the first capability that turns a finding into a demonstrated effect, not just a detection. When an app ships a symmetric key, IV and ciphertext together (the classic thick-client anti-pattern), it decrypts the ciphertext with the shipped key/IV (AES / TripleDES / DES x CBC / ECB x PKCS7) and recovers the plaintext, collapsing three Inferred secret findings into one DEMONSTRATED recovery (exploit.secret-recovered, CRITICAL, CWE-321/798/312). Lab-safe by construction: it reads local artifacts and does arithmetic -- it launches nothing, makes no network call, writes nothing to the target. The recovered secret is masked in the evidence unless -Reveal is passed. Verified end to end against the DVTA testbed: it recovers the AES-256-CBC encrypted sa password from DVTA.exe.config. The HTML report's confidence ladder, colour map and sort order now carry the Confirmed (exploit) tier. New test SecretRecovery.Tests.ps1 builds the ciphertext at runtime with .NET AES, so it runs without a C# compiler (5/5 on Linux PowerShell).

## v2.2.0

CVE and SBOM are now ONLINE-ONLY. The bundled offline CVE catalog (Data/cve/catalog.json) and both offline CVE cmdlets (Test-TcpkDependencyCves and Test-TcpkPackageManifests, plus the secrets.json cve_packages list) are REMOVED. All CVE data is queried live through one engine, Get-TcpkCveMatches: OSV for NuGet (deps.json / packages.config / .csproj), npm (package.json / lockfile + the bundled Electron runtime) and Maven (pom.xml); and NVD by CPE for native C libraries (Get-TcpkNvdMatches, private) -- the version-accurate path OSV cannot provide for native code. The SBOM stays CycloneDX with its vulnerabilities[] built purely from these live results. CVE matching runs only with -OnlineCve (it needs network) and there is no offline fallback -- with no network the report states CVE data unavailable rather than a false clean, and the GUI / web / agentic UIs default the online-CVE toggle ON. OSV is the wrong source for native libs because it keys native results to distro packages (Alpine / Debian / RHEL advisories) versioned per distro rather than to the upstream library -- a mis-versioned false-positive firehose (a plain zlib query returns 100+ distro advisories). NVD is CPE-based and version-accurate: for each mapped native library the audit builds cpe:2.3:a:vendor:product:version and keeps ONLY the CVEs whose CPE match range actually BOUNDS the shipped version, dropping the unbounded / wildcard matches (old CVEs with no versionEnd) that otherwise flag a current, patched library. So a patched OpenSSL 3.0.21 returns ZERO native CVEs (no false positive) while a genuinely old OpenSSL 3.0.0 returns its real bounded CVEs (including CVE-2023-0286, fixed in 3.0.8). It sends only the public vendor:product:version (never findings, secrets, file contents, or the target name), and an optional NVD_API_KEY environment variable raises the NVD rate limit. The numeric version comparison (Test-TcpkSemVerLt) means a lexical string compare no longer mis-orders native versions -- 3.0.21 is correctly newer than 3.0.8 -- so a current library is never falsely flagged. REPORT CLARITY: the CVE table Fixed column is renamed Fixed in and rendered as a floor (>= 3.0.8), because the fixed-in version is where the fix FIRST landed, not an older version to downgrade to -- a bare Fixed: 3.0.8 next to Shipped: 3.0.21 read backwards; the HTML report also gains a reading-guide note that matches are queried live (OSV + NVD) and that Fixed in is a floor, not a downgrade. Applied to both the HTML and Excel CVE tables. NEW library version-currency / end-of-life awareness (online, Get-TcpkLibraryCurrency + Get-TcpkLibLifecycle, private): zero known CVEs is NOT the same as up to date, so the audit now tells you WHICH library, its shipped version, and the LATEST supported release + current LTS + branch end-of-life date (sourced from endoflife.date), and flags a library that is on an END-OF-LIFE branch (MEDIUM), nears end-of-life (LOW), or is simply behind the latest release (INFO). The remediation points at the latest supported version and the LTS -- never at an old CVE fix-in version -- e.g. OpenSSL 3.0.21 reports 0 open CVEs yet is flagged LOW because branch 3.0 reaches EOL 2026-09-07 while 4.0.1 / 3.5-LTS are current. Covers the libraries endoflife.date tracks (OpenSSL, SQLite); runs only on the online path; all helpers are private so the public cmdlet count is unchanged. UI: the online-CVE toggle now sits on the MAIN scan-options row of the desktop GUI (it was previously buried on the SBOM tab and only visible there), is CHECKED by default in the desktop GUI, the web control panel and the agentic workbench, and is relabelled online CVE (OSV + NVD) -- so an interactive run gets live CVE for NuGet, Electron AND native libraries by default; uncheck it for an offline / air-gapped run. The command-line CVE step is opt-in (add -OnlineCve, needs network) so scripted / CI runs stay deterministic, while the GUI / web / agentic UIs default it ON. New online helpers (NVD, endoflife, version) are all private; two offline CVE cmdlets were removed. NEW pre-audit application identity (Get-TcpkAppIdentity): a fast "what kind of application is this" fingerprint -- app type, runtime / language, UI framework, architecture, publisher and code-signing -- shown in the desktop GUI, the web control panel AND the agentic workbench the moment you Identify / Auto-Detect a target, BEFORE the audit runs, so the operator sees whether they are about to scan a native C/C++ Win32 app, a .NET desktop app, Electron, Java, Python, Go/Rust or MSIX. It reuses the recon profiler (Get-TcpkTargetProfile) and emits no findings. NATIVE-APP PROFILING: the recon profiler is no longer managed-.NET-centric -- it now reads the NATIVE import union across the app binaries (the main exe is often a thin launcher, so the real UI/networking lives in sibling DLLs), so a native C/C++ app reports its real UI (Win32 user32/gdi32, Direct2D / Direct3D) and network stack (Winsock, WinHTTP, WinINet, SChannel/SSPI, bundled OpenSSL) instead of "unknown / not determined", and a sibling updater binary is detected. Fixes a case where the identity header read "Network: not determined" even though the audit itself found backend hosts and a TLS accept-all-certificates bug. CVE COVERAGE (closing the bare-DLL and native gaps): the online CVE engine now (a) reads a bare managed .NET DLL OWN assembly identity via Mono.Cecil -- assembly name + AssemblyInformationalVersion (the true NuGet version, never the frozen AssemblyVersion) -- and OSV-checks it, so a shipped Newtonsoft.Json.dll (etc.) is covered even with NO deps.json / packages.config manifest (Get-TcpkManagedNugetComponents); (b) expands the native NVD/CPE map from 7 to about 28 libraries (curl, libpng, libtiff, ffmpeg, openjpeg, libssh / libssh2, gnutls, mbedtls, wolfssl, nettle, harfbuzz, zstd, xz, brotli, nghttp2, c-ares, protobuf, libxslt, libvpx, jpeg-turbo, bzip2, lz4, jansson, ...), each CPE VERIFIED live against NVD (curl is haxx:curl not curl:curl; four CPEs that did not resolve were dropped rather than left as false confidence), with ABI-suffix handling (libpng16 -> libpng, libssl-3 -> libssl) that does NOT collapse distinct products (pcre2 / nghttp2 / libxml2 stay themselves); and (c) falls back to a native library embedded version banner (the "OpenSSL 3.0.21" string) when its DLL exposes no usable FileVersion. On a mixed native + .NET sample this lifts CVE coverage from a couple of binaries to every identifiable third-party component (the rest are the vendor own proprietary code, which has no CVE identity anywhere). All new helpers are private -- no cmdlet-count change. MULTI-ECOSYSTEM CVE: the online engine now also covers Java (Maven coordinates from each shipped JAR META-INF/maven/pom.properties -> OSV Maven), Python (requirements.txt pins + dist-info / egg-info METADATA -> OSV PyPI), Rust (Cargo.lock -> OSV crates.io), Go (the runtime/debug build-info dep list embedded in a Go binary -> OSV Go) and an Electron app OWN bundled npm dependencies (every package.json extracted from app.asar via a minimal asar reader -> OSV npm) -- so a mixed app is CVE-checked across ALL its component ecosystems (NuGet + npm + Maven + PyPI + Go + crates.io + native CPE), not just NuGet and native. All collectors are private and guarded (a malformed input yields nothing, never an error): Get-TcpkJarMavenComponents / Get-TcpkPythonComponents / Get-TcpkRustComponents / Get-TcpkGoComponents / Get-TcpkAsarNpmComponents. REPORT: the Known-vulnerability (CVE) section now ALWAYS renders -- at zero matches it states "No known vulnerabilities" and names what was actually checked (the shipped components matched live against OSV + NVD) instead of the section vanishing, so a clean result is visible proof-of-coverage rather than silence that reads as "CVE was not run"; a run with online CVE disabled says "not checked" (Export-TcpkReportHtml -CveChecked, passed from -OnlineCve).

## v2.1.0

Detection additions + agentic-workbench UX. NEW Test-TcpkRegistryCredentialStore (static: first-party code that writes to the registry AND references a credential field -- the insecure-local-storage anti-pattern -- as a LOW / Inferred review pointer, complementing the runtime Test-TcpkRegistryValues). NEW config-secret rules (Data/secrets.json): hardcoded .NET appSettings password (config-hardcoded-secret), crypto key (config-hardcoded-crypto-key), IV (config-hardcoded-iv) and a database connection string with an embedded password (config-connection-string-password) -- a hardcoded key + IV + ciphertext together is a decryptable credential. NEW cleartext ftp:// detection in Test-TcpkInsecureSchemes (scheme.cleartext-ftp; IPv4 hosts allowed, an embedded user:pass@host raises severity). FALSE-POSITIVE FIX: the runtime loaded-module checks (Test-TcpkLoadedModulePaths / Test-TcpkLoadedModuleSignatures) now EXCLUDE the process own main .exe -- the main module always sits in the app dir and is not a DLL-search-order hijack candidate, so it no longer generates a guaranteed false positive on every per-user-installed app; dependency DLLs stay in scope. AGENTIC WORKBENCH: the Decompile step now scans the whole target folder and lists every module -- managed .NET modules decompile to IL (as before) while native / non-.NET modules show a PE view (ASLR / DEP / CFG hardening, Authenticode signing, high-risk imported APIs) instead of a dead end; typing a target path (not only Auto-Detect) now loads modules; modules can be ticked to run a focused per-binary audit from the Decompile step; and findings stream live into the triage counters during a run. 9 new tests plus a published docs sample (a genuine, unedited audit of a public vulnerable-thick-client testbed under docs/samples). REPORT FIDELITY: finding aggregation now PRESERVES the matched value for secrets / entropy / authenticode / trust-store / strong-name findings -- a hardcoded key / password or a signer certificate that appears in two files (e.g. app.exe.config + app.vshost.exe.config) is no longer hidden behind a file list; Authenticode findings now carry the FULL decoded signer certificate (Subject / Issuer / Serial / Thumbprint / Algorithm / KeySize / EKU / validity), not just the signer common name; and the HTML report collapses long evidence (a certificate, a large value) behind a show-full toggle so the finding card stays compact.

## v2.0.0

Agentic workbench + autonomous AI security agent. NEW TCPK-Agentic (Start-TcpkAgentic, launched by TCPK-Agentic.bat) -- a loopback-only, discovery-only browser workbench that takes a target from audit to decompiled source to AI review in one phased UI, reusing the proven web-control-panel API (target discovery, identity, async audit, live log, report download) so the two never drift. Two engines sit on top: (1) REAL .NET decompilation via Mono.Cecil (now bundled under tools\ILSpy) -- a module / method browser that lists sink-bearing methods (matched against the SHARED callsite sink map, so the viewer shows exactly what the IL verifier proves) and dumps a method's IL with the sink calls highlighted; and (2) a per-method AI review (Get-TcpkAgentReview) where the selected agent judges exploitability from the IL while the deterministic reachability is shown beside it -- advisory only, it never overrides the evidence. CAPSTONE: a genuine autonomous agent (Invoke-TcpkAgentAudit / the loop in _Agent.ps1, surfaced as the workbench Agent tab) -- given a plain-English goal the model DRIVES a reason -> call-tool -> observe loop, choosing which read-only tool to call (list_sink_methods / inspect_method / submit_finding / finish); it is not a scripted pipeline. Bounded by design: the toolset is read / analyze ONLY (the exploit bucket is never exposed), a step budget caps the loop, submissions are de-duplicated, and every finding the agent submits is re-checked against the deterministic IL reachability engine -- agent proposes, IL prover disposes. Local-first: it talks to ollama via a portable JSON-action protocol (no native tool-calling required) streamed live into the workbench transcript and console; a capable code model (qwen2.5-coder:7b) is recommended for reliable multi-step behaviour, and the Connect step lists locally-installed ollama models and hints a pull when ollama is empty. FALSE-POSITIVE FIXES (surfaced by dogfooding the new decompile view): callsites.ldap-query matched the bare type name DirectoryEntry and so fired on any class so named (e.g. a library's own CompoundDocumentFormat.DirectoryEntry) -- both the string rule (Data/secrets.json) and the IL sink map (_Decompile.ps1) now require the System.DirectoryServices namespace; the clipboard-access sink was likewise namespace-qualified to System.Windows / System.Windows.Forms Clipboard. UI: the workbench uses the dark console theme (risk gauge + severity donut + findings triage + confidence-ladder legend), the phase rail is grouped into WORKFLOW (1-6) and AUTONOMOUS (7), and a theme bug where bare <input> fields rendered white is fixed.

## v1.8.2

Report redesign + secrets-scan performance + live progress. REPORT: Export-TcpkReportHtml is redesigned to a modern dark console theme -- a computed risk-index gauge and a severity donut lead the dashboard; finding cards now use a terminal-style Verify block that separates the paste-and-run command (highlighted) from the explanation (muted) and adds a one-click Copy that copies just the command (base64-encoded so quoting survives, with a file:// clipboard fallback); the monospace font is Cascadia Code (Fira Code / Consolas fallback, still no CDN / fully offline); and the body fonts are larger. Two NEW sections are built from data the report already has: a Remediation plan (prioritized, de-duplicated -- one row per fix, P1/P2/P3 by severity, with the affected-finding count) and a Standards-coverage matrix (the OWASP Desktop App Top 10 as a heatmap -- green = clear, colored by worst severity -- plus a by-MITRE-ATT&CK-technique breakdown). The scope footer no longer prints Buckets or Coverage-gaps. PERF (fixes a no-size-cap slowdown on large single-file Electron apps): ten secret rules whose regex had no cheap literal gate (Azure SAS, AWS access-key-id, AWS secret-key context, GCP service-account key, JWT, GitHub classic PAT, Slack, Stripe, DB connection-string-with-password, RSA-private-key-in-XML) now carry a loss-free prefilter keyword, so the heavy / backtracking regex only runs on a file view that actually contains the trigger word -- a 200 MB packed exe scanned in three encodings no longer grinds the password / connection-string regex over hundreds of MB that could never match. Coverage is unchanged: every file, byte and encoding is still scanned; only work that cannot produce a finding is avoided. VISIBILITY: a live progress heartbeat (Write-TcpkProgress) shows the currently-running check -- so a slow check is visibly working, not frozen -- plus a per-file scanning <file> [i/n] line inside the secrets scanner; a host hook lets the web panel and GUI surface the same. New helpers are private, so the public cmdlet count is unchanged. A QA pass (adversarial review) also fixed two latent false-negatives: Test-TcpkJwt no longer throws on a non-numeric or out-of-range exp claim (it coerces with -as [int64] and guards the conversion), and the private-key-in-XML rule is now exempt from the placeholder guard whose generic <tag> pattern matched the key elements (<RSAKeyValue>/<Modulus>) and was silently suppressing every hit.

## v1.8.1

Audit-coverage-gap closeouts + honest CVE reporting. NEW auto-attach -- when -ProcessName is not supplied, the audit finds the target's own running process (an install-dir exe intersected with the running-process list) and runs the 11 live-process checks automatically; previously they were silently gated and never ran. -NoAutoProcess opts out; an explicit -ProcessName still wins. NEW coverage manifest -- every check now records Ran / SkippedQuickProfile / GatedNoProcess / NeedsElevation / NotImplemented / Failed into coverage.json, with a Coverage section in the HTML (scope footer + gap list) and Excel reports and a one-line console summary, so a less-than-complete run is VISIBLE instead of implied: the gated live-process and elevation-only checks are listed, not hidden. NEW self-elevation -- -Elevate relaunches the audit as admin via UAC so elevation-gated checks (Defender exclusions, deeper ACLs) actually run; on a declined UAC it continues non-elevated and the manifest shows the NeedsElevation rows. NEW ALPC enumeration -- Test-TcpkMailslotsAlpc now enumerates \RPC Control via a compile-guarded NtQueryDirectoryObject P/Invoke and reports app-attributed ALPC ports (alpc.port), falling back to the honest not-enumerated stub on any failure. CVE -- the OSV online path now CACHES results to %LOCALAPPDATA%\TCPK\cve-cache.json (7-day TTL, fail-open) so repeat -OnlineCve runs are fast and work offline once warmed; and the electron.outdated-runtime finding now reports WHAT THE CHECK ACTUALLY DID -- it lists the concrete CVE / GHSA IDs when OSV returns them, states that it queried and found none when OSV has no data for the bundled version (instead of the misleading run-with-OnlineCve hint after the flag was already used), and keeps the hint only when run offline. New helpers are all private, so the public cmdlet count is unchanged.

## v1.8.0

Electron/JS proof + report excellence. NEW Electron certificate-validation bypass detection -- the biggest known proof gap for Electron, which has no IL to verify: Test-TcpkElectron now reads the bundled JS and flags the accept-all TLS shapes -- a session.setCertificateVerifyProc whose callback has NO callback(-2) reject path (the trust-on-first-use-that-never-rejects shape, so ANY server certificate is trusted), an explicit rejectUnauthorized:false, NODE_TLS_REJECT_UNAUTHORIZED=0, and an unconditional certificate-error handler (electron.cert-validation-bypass / electron.cert-error-accept-all). The new rules are mapped to a transport-MITM CVSS v4.0 archetype, OWASP DA7 Insecure Communication, and MITRE T1557 Adversary-in-the-Middle, so the score and standards tags read as MITM rather than generic RCE. REPORTS: a new plain-text Markdown deliverable (Export-TcpkReportMarkdown -> report.md, written in every audit alongside HTML/Excel/SARIF/intel) with an executive summary and severity-grouped findings carrying the full CVSS / CWE / ATT&CK / TASVS / Desktop-Top-10 mapping; delta / re-test reports (Compare-TcpkAudit) that diff two audits into NEW / FIXED / REGRESSED / unchanged at rule-plus-location granularity and write a delta.md; and an always-on executive-summary narrative at the top of the HTML report (what was audited, the severity shape, how much is proven vs needs manual verification, the correlated attack paths, and the few findings that matter most). report.md is exposed in the web control panel downloads and the desktop GUI. NEW detection benchmark (bench/): a curated corpus of planted-vulnerability and clean fixtures with a verified expectations manifest, scored into precision / recall and gated by the test suite so detection quality cannot silently regress (Invoke-TcpkBenchmark -> SCORECARD.md). FIXES (surfaced by a live-app audit): the secret scanner now reads files a RUNNING target holds open -- Read-TcpkStringViews opens with FileShare.ReadWrite|Delete so Chromium cache block files, logs, and SQLite WAL/journal the app has open for write are no longer silently skipped; and the scanner no longer skips ANY file by size -- files over 64MB are streamed in bounded overlapping chunks instead of being capped, so nothing is dropped for being big and a multi-GB file cannot exhaust memory. The same no-size-skip policy was swept across the other content scanners (entropy, endpoints, JWT, crypto-misuse, DPAPI, plaintext-config, PII-in-logs, RPC, CSV, Java/asar): their per-cmdlet size caps were removed, so file size never decides whether a file is analyzed. NEW secrets.cleartext-credential rule (CWE-256/522/798) flags plaintext password / credential literals (password=value, JSON password:value, single-quoted, userPassword/dbPassword) in config, source, or cached HTTP bodies -- the previous rule set only matched API-key / token / connection-string formats, so a cached username+password pair was missed; and a companion secrets.credential-encoded rule (MEDIUM, CWE-522/916) surfaces hashed / encrypted credential material too -- bcrypt / argon2 / sha-crypt and LDAP {SSHA}/{SHA}/{MD5} hashes -- so non-plaintext stored passwords are reported rather than ignored. COVERAGE: Test-TcpkAppStack now also fingerprints bundled native C libraries (OpenSSL / zlib / SQLite / libpng / libcurl / FreeType) by their embedded version string and reports each as recon (INFO) with its version -- native deps are a common CVE source the managed-IL analysis does not reach; cross-check with -OnlineCve / OSV. NEW Test-TcpkElectronJs (A41): a data-driven Electron/JS vulnerable-code-pattern scan covering the published XSS-to-RCE attack-chain surface -- it flags dangerous sinks in the bundled JS as Inferred leads: code/command execution (child_process / eval / new Function / vm.runInThisContext), shell.openExternal/openPath with file:// or a non-literal target (file-exec / download-and-execute), DOM XSS sinks (innerHTML / document.write / dangerouslySetInnerHTML / v-html / srcdoc), markdown rendered without a sanitizer, a custom resource protocol without path containment (local-file-leak), a missing will-navigate / setWindowOpenHandler guard, and prototype-pollution sinks (electronjs.*); patterns live in Data/electron-js-sinks.json so they can be tuned without code changes. A second research-informed round (the NDSS DOM-tree-type study) extended the same electronjs.* family with navigation-injection (location.href / window.open / javascript:), CSS-injection (scriptless), weak-CSP (unsafe-inline / unsafe-eval / hardcoded nonce), and string-argument setTimeout/setInterval rules. A third round (the SK Shieldus EQST methodology report) added the nodeIntegrationInSubFrames / experimentalFeatures / enableBlinkFeatures BrowserWindow flags (Test-TcpkElectron) plus unsafe-<webview>-tag and wildcard-postMessage rules (electronjs.*). A fourth round (the USENIX Inspectron study) added the nodeIntegrationInWorkers / webviewTag / webSQL flags plus dangerous-command-line-switch and dynamic-executeJavaScript rules. This is the static counterpart the talk authors called for as future work -- TCPK still cannot PROVE a JS bug (no JS taint/AST engine), so these are leads, not confirmations. NEW Test-TcpkElectronFuses (A42): parses the @electron/fuses wire from the app binary (sentinel + version + state bytes) and reports insecure fuse states as CONFIRMED facts -- EnableCookieEncryption off (plaintext cookies), RunAsNode / EnableNodeCliInspectArguments on (node-exec / --inspect LOLBins), EnableEmbeddedAsarIntegrityValidation off (tamperable app.asar) -- the binary-hardening gap the Inspectron and SK-Shieldus studies flag, and one of the few Electron checks TCPK can PROVE rather than infer. A fifth round (the original Electronegativity checklist + the Altpeter thesis) added experimentalCanvasFeatures, insertCSS, --debug/--debug-brk switches, <webview blinkfeatures>, and an always-allow-permission-handler rule -- closing the last gaps from the foundational static-analysis references.

## v1.7.0

Report redesign + Electron/Chromium/Node bundled-runtime CVE detection + OWASP Desktop Top 10 mapping + machine-wide-attribution scoping + reliability fixes. Reports now LEAD with the risk: a correlated attack-path callout (from the exploit-chain engine), a confidence rollup, and finding cards rebuilt to put proof first -- CWE / ATT&CK / TASVS as compact tags, a computed CVSS v4.0 score + vector (no redundant severity word), distinct What / Impact / Why-here lines, the FULL path of every aggregated occurrence (not just the file name), a fixed Verify command for aggregated findings, and a demoted Audit-notes footer that keeps internal [TCPK]/[LLM] process notes out of the finding text. NEW bundled-runtime detection: an Electron app's embedded Electron / Chromium / Node version (a string in the main exe, invisible to deps.json) is now extracted and recorded (electron.runtime-version) and flagged electron.outdated-runtime when the embedded Chromium is majors behind the shipped baseline -- closing the biggest known-CVE blind spot for Electron / thick-client apps; with -OnlineCve the audit also queries OSV's npm ecosystem for electron@<version> and merges the advisories. FIXES: Get-AuthenticodeSignature (Microsoft.PowerShell.Security) is imported eagerly at module load so the signing / integrity checks no longer fail in the web-UI background-job runspace (and Test-TcpkLoadedModuleSignatures degrades to an honest Skipped finding if the host truly cannot load it); Test-TcpkCallsites now skips bundled native runtimes (libGLESv2 / ffmpeg / d3dcompiler / ...), removing a Chromium false-positive class -- and the SAME gating now covers the telemetry / cleartext-scheme / backend-endpoint scanners, so a domain baked into the bundled Chromium (e.g. google-analytics.com) or a stock helper-binary homepage (nsis.sf.net from the NSIS stub, int3.de from the stock elevate.exe) is no longer reported as the audited app's; the entropy scanner skips cert-pin / trust stores (cert-pins.json holds PUBLIC cert fingerprints, not secrets); callsites.insecure-temp gets a real CVSS v4.0 vector instead of the per-finding placeholder. NEW machine-wide-attribution scoping: OS / creds findings (firewall allow-rules, COM servers) are now path-anchored to the target's install dir via Test-TcpkPathUnderTarget plus a generic-token stopword list, so a thin updater folder no longer inherits unrelated Windows system entries (DesktopAppInstaller, SurfaceCaptureAPO, ...) as target findings. NEW OWASP Desktop Application Top 10 (2021) mapping: every finding carries a single best-fit DA category (Get-TcpkOwaspDa) shown in the HTML / Excel / SARIF / intel reports, and the older coarse DA items were de-duplicated out of the TASVS tags so the two no longer disagree on a card (an argv/session override is DA2 Broken Authentication, a disabled sandbox is DA6 Security Misconfiguration).

## v1.6.0

Live CVE option + confidence-segregated reports + secret-scan recall fixes. NEW opt-in -OnlineCve (Get-TcpkCveMatches / Invoke-TcpkAudit; off by default) queries the OSV API (api.osv.dev) for the shipped NuGet components on top of the offline catalog and merges the hits into the CycloneDX vulnerabilities[] -- sends only public package name + version, fails closed with no network. Exposed as an "online CVE (OSV)" checkbox in BOTH the desktop GUI (SBOM tab) and the web control panel (off by default; one tick covers the session). HTML reports now SEGREGATE by confidence: IL/dynamic-proven findings sort first, with an evidence-tier summary line and a "Confirmed only" filter, and the flagship Confirmed (IL) tier now has its own colour (it previously rendered grey like INFO). Secret-scan recall fixed: the binary/string scanner now also reads odd-byte-aligned UTF-16 strings (the odd view was decoded but never scanned), and a quick-literal pre-filter bug that silently skipped the AWS / GitHub fine-grained PAT / Stripe / Aptabase rules (it extracted regex syntax as the literal) is corrected -- those high-value key types are detected in files again. Plus false-positive hardening on the config / log / PII scanners (placeholder guards + IPv4 octet/range validation), a web-panel installed-app Find / Auto-Detect fix, and repo hygiene (a .gitattributes pinning LF).

## v1.5.0

Program-intelligence report + a local web control panel. NEW Export-TcpkReportIntel writes a self-contained, OFFLINE intel.html alongside the HTML/Excel/SARIF reports in every audit -- a dark dashboard that EXPLAINS the findings: a severity + confidence breakdown with the evidence ladder spelled out (Inferred = pattern match, Confirmed = verifiable fact, Confirmed (IL) = bytecode proof, Confirmed (dynamic) = observed at runtime), a classified recon endpoint map, and filterable per-finding cards (what/why, evidence, affected list, how-to-verify, fix, CWE / ATT&CK / TASVS / computed CVSS). No server, no CDN, no external assets -- one file you double-click. NEW Start-TcpkWebUi: a loopback-only web control panel that drives a DISCOVERY audit from the browser. Safe by construction -- it binds 127.0.0.1 only; every API call needs a per-session X-TCPK-Token custom header (a web page you visit cannot set it on a cross-origin request, so there is no localhost CSRF / DNS-rebind); the Host header is validated; and the gated exploit bucket is never reachable from the browser. It runs the audit as a background job with live progress, a streaming per-check log, and Pause / Resume / Cancel, then shows result tabs (Findings, Recon, SBOM, DLL Mitigation matrix, DLL Signing, Logs) and lets you download the HTML / Excel / SARIF / SBOM / intel reports (whitelisted, path-traversal-guarded). The AI-verify panel writes the chosen provider / model / key through to the audit (Set-TcpkLlmConfig) and has a Test AI button; an installed-app auto-detect picker fills the target. Launch it with the new TCPK-WebUI.bat (it prints the URL + token and stays open; Ctrl+C to stop) or Start-TcpkWebUi (optional -Token pins a stable URL).

## v1.4.0

Interprocedural taint + full-certificate reporting. The deterministic IL verifier (Confirm-TcpkCallsiteUsage) now follows source-to-sink taint ACROSS method boundaries, not just within the sink method itself: a helper that reads external input and returns it taints its caller, whether passed inline (Process.Start(ReadConfig())) or through a local (var x = ReadConfig(); Process.Start(x)); and a tainted FIELD is tracked cross-method -- input stashed in a field in one method (Configure) and read into a sink in another (Run) is marked Confirmed (IL). The cross-method signal is a cached fixpoint over the call graph plus per-method tainted-local and tainted-field dataflow, kept precise (direct assignment from a known source only) so the added recall does not re-introduce false positives. NEW: the code-signing matrix (Get-TcpkSigningMatrix) and its HTML / Excel / signing.json outputs now carry the FULL signer certificate -- Subject, Issuer, serial number, thumbprint, key size and EKU -- not just the common name. FIX: the embedded-PEM-key detector (secrets.pem-private-key and Test-TcpkKeyMaterial) now matches legacy ENCRYPTED PKCS#1 keys whose RFC1421 Proc-Type / DEK-Info header lines previously broke the body scan and hid the key. The optional LLM judge now locates the method behind a generic callsite finding by the sink API it invokes (via a shared sink map kept in lock-step with the deterministic verifier), so it annotates findings whose method name says nothing about the weakness.

## v1.4.1

Multi-target sweep + a full Electron/JS coverage round + dynamic confirmation + classified recon + broader target formats. NEW Invoke-TcpkSweep audits an app that is installed across several folders in ONE call: pass an explicit -Target list and/or -AppName to auto-discover every install location (Programs / Local / Roaming / Program Files / ProgramData), run the full audit per location into its own subfolder, and get a merged sweep-summary.html + sweep-summary.json + sweep-findings.json across all of them, with a -FailOn gate spanning the whole sweep. The single-target Invoke-TcpkAudit is unchanged -- the sweep is a thin orchestration layer on top, so the proven audit path stays simple. Electron config detection is now COMMENT-AWARE: a renderer-security flag (webSecurity / sandbox / nodeIntegration / contextIsolation) that only appears in a JS comment no longer fires, and a match is marked Confirmed only inside a webPreferences / BrowserWindow context (Inferred otherwise) -- removing a false-positive class. Electron preload analysis now inventories the contextBridge surface (exposeInMainWorld) and flags over-broad exposure -- raw ipcRenderer, a caller-supplied channel passthrough, or a Node/Electron primitive handed to the renderer (electron.bridge-*). It also maps the deep-link / file-association / command-line surface -- a registered custom URI scheme, a file-type open-command handler, and command-line session/credential overrides (--host / --token / ...) reachable via a crafted shortcut, deep link, or forwarded second-instance argument (electron.custom-protocol / file-assoc-handler / argv-session-override). It inventories the main-process IPC handler surface (ipcMain.handle/on) and flags handlers with no event.senderFrame / sender-origin validation (electron.ipc-surface / electron.ipc-no-sender-validation). It flags the app's own unsafe archive extraction when no path-containment guard is present (electron.archive-zip-slip) and an embedded HTTP server bound to all interfaces / with permissive CORS (electron.local-server-exposed). And Test-TcpkSignature now cross-checks signing: binaries that are unsigned DESPITE a code-signing / notarization pipeline reference in the bundle are flagged (authenticode.unsigned-despite-pipeline). The dev-artifact scan now also flags INTERNAL spec / threat / QE docs leaked into a shipped bundle (Gherkin acceptance criteria, user-story IDs, source-tree paths, CI/build references) via devartifact.internal-docs, scanning shipped markdown / text and inside the asar. NEW (GATED) dynamic confirmation: Invoke-TcpkDynamicConfirm (Verify bucket, behind Enable-TcpkExploit -Acknowledge + -ConfirmDynamic) launches the target with a command-line host/token override pointed at a TCPK loopback listener and OBSERVES whether the app connects -- upgrading the inferred argv-override finding to Confirmed (dynamic). Benign by design (a loopback connection + a random sentinel, no code execution); the target is launched minimized and killed when the probe ends. This is the first slice of a dynamic-evidence harness that turns inferred Electron/JS findings into demonstrated ones. RECON: the target-profile network endpoints are now normalized and CLASSIFIED (first-party / telemetry / cloud-storage / cdn / auth / update) with risk flags (cleartext, raw-ip, private-ip, internal, non-prod) and deduped into an EndpointMap, so the recon section shows WHO the app talks to and HOW. INPUT FORMATS: the audit now unwraps more target types automatically -- an MSI (msiexec /a administrative install, no system changes), a ZIP (safe, zip-slip-guarded extraction), and (as before) MSIX/AppX -- so you can point -Target straight at an installer/archive instead of extracting it first; a directory or single EXE is scanned as-is, and any unwrap failure degrades to scanning the file.

## v1.3.0

Reporting clarity. NEW DLL Signing matrix (Get-TcpkSigningMatrix): an information-only per-DLL view of code-signing status (SIGNED / CATALOG / UNSIGNED / TAMPERED / UNTRUSTED + signer), surfaced as a new GUI "DLL Signing" tab, an HTML signing table, an Excel "DLL Signing" sheet, and a signing.json sidecar -- the signing counterpart to the DLL hardening matrix. NEW finding aggregation: multiple occurrences of the SAME rule (same RuleId + Severity + Confidence) are now collapsed into ONE finding whose Affected[] lists every occurrence (e.g. six cleartext http:// endpoints become one finding affecting six URLs), so the report shows distinct vulnerabilities instead of one row per file/URL (use Resolve-TcpkFindings -NoAggregate to keep them separate). NEW deterministic IL verification (Confirm-TcpkCallsiteUsage): for callsites.* AND deser.* findings it reads the IL with Mono.Cecil and applies a bounded source-to-sink taint check across both managed and P/Invoke (native) sinks -- it marks a finding Confirmed (IL) when external input (a file / registry / network / IPC / HTTP-request source in the method, or a caller parameter) reaches the sink, Likely-FP (IL) when the API is never actually invoked (string-only match) or is called only with constant arguments, and leaves a reachable-but-unproven dynamic call at its original confidence with a review note rather than over-claiming. Deserialization is confirmed when an unsafe-formatter Deserialize/ReadObject is actually invoked; P/Invoke command execution (CreateProcess / WinExec / ShellExecute) and capability APIs (keyboard hook / screen capture / token impersonation) are matched by method name, so a declared-but-never-called native capability is demoted to INFO. Separates real bugs from false positives, no model required, and runs before the LLM so reports inherit the verdict. CHANGE: missing binary hardening (ASLR/DEP/CFG/HighEntropyVA) is now reported as POSTURE in the DLL Mitigation Matrix only, NOT as per-DLL findings -- a missing mitigation is defense-in-depth, not an exploitable bug, and per-DLL findings inflated severity; run Test-TcpkPeMitigations directly if you need them as findings. GUI: the "AI-verify findings" pass now runs INLINE inside the audit (single AI-aware report generation, no write-then-rewrite); fixed -AllowCloudLlm so it actually opens the cloud gate for a cloud provider. Also in v1.3.0 -- coverage-gap features from a thick-client methodology gap-analysis. NEW single-file (.NET PublishSingleFile) bundle extraction: the audit detects a single-file apphost, extracts the managed assemblies bundled inside the .exe (decompressing where needed), and re-runs the managed static checks against them, so secret / callsite / TLS-bypass / deserialization / CVE scanning is no longer blind on single-file apps (Expand-TcpkSingleFile is also available standalone). NEW Test-TcpkUiLeakSurface (A37): flags missing screen-capture protection (SetWindowDisplayAffinity) on sensitive-input UIs, and clipboard writes with no Windows Clipboard History / Cloud Clipboard exclusion. NEW Test-TcpkBrowserTokenStore (D08): finds the Chromium / Electron / NW.js cookie + token store and reports whether its key is App-Bound Encrypted (Chrome 127+) or plain DPAPI (the infostealer primitive). NEW Test-TcpkTauriConfig (A38): audits tauri.conf.json (v1 + v2) for missing CSP, allowlist.all, shell / fs access, remote IPC, and unsigned / cleartext updater. NEW Test-TcpkRpcChannels (F10): flags insecure gRPC credentials and cleartext SignalR hubs / gRPC targets. NEW Test-TcpkCsvInjection (A39, CWE-1236): flags CSV / Excel export sinks (CsvHelper / ClosedXML / EPPlus / NPOI / Office Interop / json2csv) that ship with no formula-character neutralization, so an exported field starting with = + - @ could run as a spreadsheet formula. Native coverage: the unsafe-CRT scan (Test-TcpkUnsafeNativeApis) now also catches the SDL-banned A/W-decorated Win32 helpers (lstrcpyW / StrCpyW / StrCatW / wsprintfW / wvsprintfW) and the no-null-terminate printf family (_snprintf / _vsnprintf / _snwprintf / _vsnwprintf) that the old word-boundary pattern missed; and the DLL hardening matrix gains a GS column (/GS stack cookie, read from the load-config SecurityCookie) across the GUI, HTML and Excel. The thick-client checklist grows to 55 cases (TC55 = CSV / formula injection). Recon now fingerprints Tauri and Flutter desktop apps. NEW Test-TcpkAppStack (A40): fingerprints the application technology stack (Python PyInstaller / Nuitka, Go, Rust-native, .NET MAUI / Avalonia / WinUI 3, Qt, NW.js) and states per stack what the managed-IL analysis can and cannot reach, so a Python or Go app no longer reads as clean merely because nothing was decompiled. NEW SARIF 2.1.0 export (Export-TcpkReportSarif -> report.sarif): an audit now ingests into GitHub Advanced Security / Azure DevOps code scanning, ranked by the computed CVSS v4.0 score. PERF: the IL verifier caches the parsed Mono.Cecil assembly per file, so a multi-sink rule no longer re-reads the same DLL once per sink. Also in v1.3.0 -- model-agnostic AI. The AI backend now supports any provider and any model: added Google Gemini and xAI Grok alongside Ollama (local), Claude, OpenAI and DeepSeek, plus a custom option for any other OpenAI-compatible endpoint. The model field is free-text -- the hardcoded model dropdown lists were removed, so you type any model the provider exposes, or click Test AI to load the live list from your key. Gemini and Grok use the OpenAI chat-completions dialect with Bearer auth, so they need no special handling. GUI fix: disabled buttons (Open HTML report, Open Excel report, Open output folder, Pause) rendered with near-invisible grey text on the dark theme and are now owner-drawn with a legible muted label. Also new in this line: Pause/Resume audit control (the audit holds at the next check boundary so you can make changes on the target, then resume).

## v1.2.0

Computed CVSS v4.0 base scores -- a faithful port of the FIRST.org reference algorithm + macrovector lookup table assigns a real, derived score (not an estimate) per finding via attack-archetype vectors, so a LOCAL issue is no longer mislabelled with a network attack vector. TLS cert-validation-bypass findings now carry the exact location (assembly / namespace / type / method signature / metadata token / call site / IL proof) for direct ILSpy/dnSpy navigation. Optional inline LLM triage in Invoke-TcpkAudit via -EnableLlm (local-only by default; -AllowCloudLlm to permit a cloud backend); the GUI AI pass warns before sending decompiled IL to a cloud provider. New: an Excel "Checklist" sheet auto-correlates findings to a 54-case thick-client test plan (honest auto-status; the tester sets the final PASS/FAIL). New detections (data-driven callsite rules): dynamic XAML / ObjectDataProvider RCE gadget (CWE-502/94), UAC-bypass registry hijack keys (Fodhelper / sdclt / eventvwr class, CWE-250/269), and the COM elevation moniker. Fix: triage no longer demotes an IL-proven CRITICAL cert-bypass when a weaker callsite rule fires on the same file (the proven verdict wins). Reliability fix: the UTF-16 string scan now decodes both byte alignments, so wide string literals at odd file offsets are no longer missed (improves secrets / endpoints / callsites across the board). CVE fix: the native/embedded matcher no longer mis-attributes statically-linked CVEs (zlib / libwebp) to asset files -- the DLL inventory is filtered to real binaries (the Get-ChildItem -Include + -LiteralPath gotcha) and the embedding-host names are anchored (a bare "nw" no longer matches "appicoNWideTile.png"). SBOM is now CVE-aware: managed components carry the true NuGet package id + version from deps.json (accurate pkg:nuget purls, so sbom.cdx.json is consumable by Dependency-Track / Grype / OSV), and the CycloneDX output embeds a vulnerabilities[] array linking the CVE matches to the affected component bom-ref. GUI: two new tabs, SBOM (every shipped component with its purl, SHA-256 and matched CVEs) and DLL Mitigation Matrix (per-DLL ASLR / DEP / CFG / HighEntropyVA / SafeSEH / ForceIntegrity, colour-coded), populated from the sbom.cdx.json and a new hardening.json sidecar. Launcher: hardened module-path resolution (probes the exe/working dir, not just PSScriptRoot); TCPK.bat is the recommended launcher. Docs: new README.md with a GUI screenshot + the 54-case coverage table; supported targets clarified (MSIX / MSI / ClickOnce / portable; thin-client = client-side binaries).

## v1.0.0

First stable release. across buckets A-L. Application-aware registry/OS search (multi-term identity derivation), Confirm- bucket (Mono.Cecil IL-proof of TLS-bypass/deserialization/callsites), session-handling, package-manifest CVEs, Java-archive and Electron-asar unpacking, dev-artifact detection, file-system snapshot/diff, and a gated live TLS-handshake probe. Reporting is CVSS v4.0 with MITRE ATT&CK and OWASP TASVS / Desktop App Top 10 mapping (Get-TcpkTasvsMap). Coverage aligned to OWASP TASVS v1.8. See docs\CHECKS.md.
