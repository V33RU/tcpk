# TCPK - Check Catalogue

Public cmdlets, grouped by bucket. This page covers 235 of the 260 that ship; run
`Get-TcpkInfo` or `Get-Command -Module TCPK` for the authoritative live list.
**GATED** cmdlets require `Enable-TcpkExploit -Acknowledge`.

**Supported targets:** TCPK is path-based, not installer-specific. Point it at an
MSIX/AppX/`.msixbundle`/`.zip` package, an installed/extracted app folder, or a single
`.exe` (portable apps). It works the same on MSIX, MSI, ClickOnce, Squirrel and portable
apps; the 8 MSIX-manifest checks (bucket B) auto-skip when there is no `AppxManifest.xml`.
For thin-client apps it audits the **client-side binaries** only -- the remote server/API
is out of scope (separate web/API engagement), as is the thin-client terminal OS/appliance
(run TCPK where the Windows PE binaries live, e.g. a Citrix/RDP published-app host).

## A - Static binary analysis  (60)

- **Test-TcpkCefSharp** - A52. Detects CefSharp / CEF JavaScript-to-native bridge registration, remote-debugging port, WebSecurityDisabled and file-scheme cross-access. HIGH on the bridge and disabled-security flags; INFO scope-only when CefSharp is embedded but nothing higher fires.
- **Test-TcpkUpdateChannel** - A53. Firmware-updater surfaces the base F02 check does not test: release-channel selectability, update endpoint in a Users-writable config file, and locally persisted current-version state that a client-side comparison would trust. Also flags the connected-device fanout pattern.
- **Test-TcpkDeviceComm** - A50. Device-communication surface: serial, USB HID/WinUSB/libusb, BLE, Bluetooth Classic and DeviceIoControl driver calls. Reads .NET IL and native PE imports; emits one finding per channel referenced.
- **Test-TcpkDiscoveryProtocols** - A51. Local-network discovery protocols the client speaks: mDNS, SSDP/UPnP, WS-Discovery, ONVIF, LLMNR/NetBIOS, vendor UDP broadcast.
- **Test-TcpkFirmwareImages** - A49. Firmware images shipped inside the install tree (UF2, DFU, ELF, Intel HEX, SREC, raw .bin, ZIP flash bundles). Escalates to HIGH when the resting DACL is user-writable.
- **Test-TcpkShippedTooling** - D09. Vendor programming CLIs shipped inside the install tree (esptool, espefuse, ST-LINK, J-Link, OpenOCD, dfu-util, avrdude, nrfjprog, and 15 others). Fuse and secure-boot writers grade HIGH; flashers and debuggers grade MEDIUM.
  It also reports three conditions where every check ran to completion and the results still are not evidence, because the bytes examined were not the application code. **Packed** (a protector was confirmed, so the text-level checks read the stub and a low finding count is not a clean result), **bundle-too-large** (a .NET single-file apphost above the extractor ceiling, so its assemblies were never carved and the managed surface is absent rather than clean), and **native-only** (a non-managed stack, so the IL provers had nothing to parse). The first two raise the finding to MEDIUM and rewrite the title to say UNRELIABLE or INCOMPLETE, because a whole family of checks is invalidated rather than one subtree being missed. Native-only stays LOW: the native checks did run and their results stand.
- **Get-TcpkPeHardening** - Per-DLL binary-hardening matrix (ASLR / DEP / CFG / HighEntropyVA / ...).
- **Get-TcpkSigningMatrix** - Per-DLL code-signing matrix (signed / not signed -- information only; SIGNED / CATALOG / UNSIGNED / TAMPERED / UNTRUSTED + signer). Drives the GUI 'DLL Signing' tab, HTML signing table and Excel 'DLL Signing' sheet.
- **Test-TcpkAmsiSurface** - A26. AMSI integration and evasion surface detection.
- **Test-TcpkAotBinary** - A27. .NET Native AOT binary detection (evades IL-based analysis).
- **Test-TcpkAppDomainHijack** - A28. AppDomainManager injection surface in .NET executables (T1574.014).
- **Test-TcpkAppStack** - A40. Application technology-stack fingerprint with analysis-coverage note.
- **Test-TcpkAuthFlags** - A23. Client-side authentication / licensing boolean flags.
- **Test-TcpkCallsites** - A11. Static reference scan for dangerous .NET API patterns.
- **Test-TcpkClickOnce** - A29. ClickOnce deployment hijack surface detection.
- **Test-TcpkCodeIntegrity** - A15. AppxMetadata\CodeIntegrity.cat signature status.
- **Test-TcpkCrashReporter** - A47. Electron / Crashpad crash-reporting exposure (T1005). Electron apps use Crashpad, not Windows Error Reporting, so the WER checks do not apply to them and this one does. Recovers crashReporter.start() config (uploadToServer, submitURL, extra{}) from app.asar and loose first-party JS, and inspects the Crashpad database under the app's own userData directory for dumps and a weak ACL. Attribution is by construction: the database lives inside %APPDATA%\<productName>\Crashpad, so no other product's crash data is examined.
- **Test-TcpkCryptoMisuse** - A13. Crypto-misuse hunter -- hardcoded key material + weak KDF / padding.
- **Test-TcpkCsvInjection** - A39. CSV / spreadsheet formula injection on export (CWE-1236): export sink with no formula-character neutralization.
- **Test-TcpkDebugFlags** - A16. Debug switches, security-disabling flags, and backdoor markers.
- **Test-TcpkDeserialization** - A10. Static heuristic for unsafe .NET deserialization patterns.
- **Test-TcpkDevArtifacts** - A36. Leftover dev/build artifacts shipped in the release (TASVS-CONF-1.4): debug symbols, source, backups, dev-config, API specs, .git/IDE dirs.
- **Test-TcpkDiagConfig** - A30. Shipped diagnostic/logging framework configs with exposure risk.
- **Test-TcpkDllSideload** - A31. DLL side-loading opportunities via known target DLL names (T1574.002). Examines every first-party PE module (.exe, .dll, .node, .pyd), not just executables, since DLL-to-DLL side-loading is the same primitive. Delay-load imports count too and are called out as the stronger case. Emits one finding per target DLL listing its importers, rather than one per importing module.
- **Test-TcpkDotnetHostHijack** - A43. Modern .NET host redirection (T1574.012 / T1574.001). Covers the .NET Core / 5+ vectors that replaced AppDomainManager injection: CLR profiler (COR_PROFILER / CORECLR_PROFILER, an unmanaged DLL loaded before any managed code runs), DOTNET_STARTUP_HOOKS, runtimeconfig.json additionalProbingPaths, writable runtimeconfig.json / deps.json, and single-file bundle extraction (DOTNET_BUNDLE_EXTRACT_BASE_DIR). Findings are split by attribution: the app's own files and shipped launchers are vendor-reportable, while profiler and hook variables already set in the machine or user environment are labelled as environment state the vendor cannot fix, and are reported only when they resolve to something.
- **Test-TcpkElectron** - A24. Electron / Chromium-embedded insecure configuration (renderer flags incl. nodeIntegration / contextIsolation / sandbox / webSecurity / nodeIntegrationInSubFrames / experimentalFeatures / enableBlinkFeatures / nodeIntegrationInWorkers / webviewTag / webSQL / experimentalCanvasFeatures). Also flags TLS certificate-validation bypass in the bundled JS (electron.cert-validation-bypass, electron.cert-error-accept-all): a setCertificateVerifyProc with no callback(-2) reject path, rejectUnauthorized:false, NODE_TLS_REJECT_UNAUTHORIZED=0, or an accept-all certificate-error handler.
- **Test-TcpkElectronFuses** - A42. Electron Fuses audit: parses the @electron/fuses wire from the app binary and flags insecure fuse states as Confirmed facts (EnableCookieEncryption off = plaintext cookies; RunAsNode / EnableNodeCliInspectArguments on = node-exec / --inspect LOLBins; EnableEmbeddedAsarIntegrityValidation off = tamperable app.asar) plus a full fuse-posture summary.
- **Test-TcpkElectronJs** - A41. Electron/JS vulnerable-code-pattern scan: dangerous sinks in the bundled JS (child_process/eval/Function/string-setTimeout exec, shell.openExternal file://, innerHTML/document.write/v-html DOM XSS, unsanitized markdown, resource-protocol path traversal, missing navigation guard, prototype pollution, script-initiated navigation (location.href/window.open/javascript:), CSS-injection/scriptless, weak CSP unsafe-inline/eval/hardcoded-nonce, unsafe <webview> tag, wildcard postMessage, dangerous command-line switches, dynamic executeJavaScript, insertCSS, always-allow permission handler) emitted as Inferred leads. Rules in Data/electron-js-sinks.json.
- **Test-TcpkEmbeddedBlobs** - A48. Whole-file signature scan: find file formats embedded at arbitrary offsets.
- **Test-TcpkEmbeddedScripts** - A20. Embedded script files shipped in the package.
- **Test-TcpkEndpoints** - A09 -- URL extraction + dev / qe / staging classifier.
- **Test-TcpkEntropySecrets** - A12. Entropy-based secret detection in text / config / source files.
- **Test-TcpkGoRustDeps** - Recover the dependency set embedded in statically-linked binaries: Go build-info modules and versions, and Rust crate names/versions inferred best-effort from Cargo registry source paths. Feeds the same OSV/CVE matching as NuGet and npm.
- **Test-TcpkHollowingApis** - A32. Process hollowing / DLL injection / APC injection P/Invoke patterns in .NET PEs.
- **Test-TcpkJavaBundle** - A35. Crack shipped Java archives (jar/war/ear) and scan entries for secrets + insecure-TLS markers.
- **Test-TcpkJavaNativeLoad** - A46. Java/JNI native library loading (T1574.001 / T1129). Java thick clients load Windows DLLs through System.loadLibrary (resolved against java.library.path) and System.load (an absolute path). Flags a writable directory on java.library.path set by a shipped launcher, .bat/.vbs/.cmd wrapper or config file; a writable JAR whose manifest Class-Path pulls in siblings; and shipped native libraries next to the JARs. A loadLibrary call whose path TCPK cannot resolve statically is reported as an unevaluated lead (jni.load-path-unevaluated) rather than silently dropped, so an unresolvable case is visible instead of looking clean.
- **Test-TcpkJavaSigning** - JAR signing structure: unsigned archives (severity raised when the containing directory is writable), mixed-signature JARs where content entries appear in no .SF or MANIFEST.MF Name section, and MD5/SHA1 digest algorithms. Structural reading only; no signature is cryptographically verified, so pair it with `jarsigner -verify`.
- **Test-TcpkJwt** - A14. Embedded JSON Web Token (JWT) discovery + weakness analysis.
- **Test-TcpkMsixPsf** - A33. Package Support Framework (PSF) script injection in MSIX packages.
- **Test-TcpkNativeInterop** - A18. Native interop -- unsafe Marshal / pointer patterns.
- **Test-TcpkPacker** - A22. Packer / obfuscator detection -- and the inverse: source-recoverable
- **Test-TcpkPeExports** - A04. PE export surface enumeration (for proxy-DLL planning).
- **Test-TcpkPeImports** - A03 -- Phantom DLL imports (DLL hijack candidates).
- **Test-TcpkPeMitigations** - A02 -- PE compile-time mitigations (ASLR, DEP, CFG, HighEntropyVA). NOT in the default audit (opt-in / compliance use): the audit reports hardening as posture in the DLL Mitigation Matrix (Get-TcpkPeHardening), not as findings.
- **Test-TcpkPhantomDlls** - A34. Phantom DLL planting opportunities in PE import tables. Scans BOTH the normal import table (`dllsearch.phantom-dll`) and the delay-import table, data directory 13 (`dllsearch.delayload-phantom`, resolved at first call, so a wider hijack window). Calibrated against live KnownDLLs and System32/SysWOW64 to suppress names that cannot be planted, and severity is gated on install-root writability.
- **Test-TcpkPInvokeSurface** - A17. P/Invoke surface -- bare-name DllImport declarations.
- **Test-TcpkQtSurface** - Qt/C++ security surface: QSettings credential storage in .ini/.conf/.cfg (value always masked), the QProcess single-string command API family (surface, not proven injection), bundled Qt WebEngine Chromium and its observed version, QML dynamic construction (Qt.createQmlObject / Qt.include / eval) and remote QML, plus a .rcc resource-bundle inventory.
- **Test-TcpkReflectionLoading** - A16. Dynamic code loading via reflection.
- **Test-TcpkRegistryCredentialStore** - A35b. First-party code writing credentials to registry (insecure local-data-storage anti-pattern).
- **Test-TcpkResources** - A07. Embedded resource audit.
- **Test-TcpkScanCoverage** - A44. Reports what the scan could NOT read, so a partial scan is not mistaken for a clean result. The safe walker drops three classes of subtree: unreadable (ACL, which is the norm for WindowsApps), past the depth cap, and reparse points it refuses to follow. All three were previously silent. Runs LAST in the audit so the counters cover the whole run. LOW when directories were unreadable (a genuine unknown), INFO when only the deliberate limits fired. Says nothing about the application: it is a statement about the completeness of the audit.
- **Test-TcpkSecrets** - A08 -- Hardcoded-secret scan (regex rules over UTF-8 + UTF-16LE views).
- **Test-TcpkSessionHandling** - A33. Session-handling hygiene (cookie HttpOnly/Secure/SameSite, token in URL, weak token generation, expiry) over shipped config / scripts / PE strings.
- **Test-TcpkSignature** - A01. Authenticode chain validation.
- **Test-TcpkStrings** - A06. Strings extraction with summary classification.
- **Test-TcpkStrongName** - A05. .NET assembly strong-name presence check.
- **Test-TcpkTauriConfig** - A38. Audit a Tauri app config (tauri.conf.json) for insecure CSP / allowlist / shell / fs / IPC / updater settings (v1 + v2).
- **Test-TcpkTlsBypass** - A12. TLS validation bypass patterns.
- **Test-TcpkUiLeakSurface** - A37. UI data-leak surface: screen-capture protection (SetWindowDisplayAffinity) and clipboard-history / cloud-clipboard hygiene.
- **Test-TcpkUnsafeNativeApis** - A25. Dangerous C/C++ runtime functions in native binaries (overflow surface).
- **Test-TcpkV8Bytecode** - A45. Electron JavaScript compiled to V8 bytecode (bytenode / .jsc). When an app ships bytecode instead of source, asar extraction succeeds but every JS check reads nothing, so a clean report would be WRONG rather than merely incomplete. Detects .jsc files (loose and inside app.asar, verified binary not just by extension), bytenode as a declared dependency, and bytenode API use. Deliberately does NOT flag v8-compile-cache or Electron's code cache, which sit alongside readable JS and blind nothing. Severity rises when little readable .js remains.
- **Test-TcpkWcfConfig** - A14. Audit shipped WCF config files for cleartext / unauthenticated bindings.
- **Test-TcpkWebViewNavTargets** - A21. URLs that an embedded WebView2 will navigate to.
- **Test-TcpkXxe** - A13. XXE indicators in shipped XML + risky XML reader settings in code.
- **Test-TcpkZipSlip** - A15. Archive-extraction (zip-slip / path-traversal) surface detection.

## B - MSIX manifest  (9)

- **Test-TcpkMsixAppInstaller** - B05. AppInstaller (auto-update) declaration in AppxManifest.xml.
- **Test-TcpkMsixCapabilities** - B01. Risky capabilities declared in AppxManifest.xml.
- **Test-TcpkMsixComServers** - B06. COM server registrations in AppxManifest.xml.
- **Test-TcpkMsixDeclaredVsUsed** - B08. Declared-vs-used capability cross-check.
- **Test-TcpkMsixExtensions** - B07. fullTrustProcess / appExecutionAlias / contextMenu / shortcutInfo extensions. Flags `msix.alias-shadowing` (HIGH) when an appExecutionAlias name collides with a common PATH tool.
- **Test-TcpkMsixFileAssocs** - B04. File type associations declared in AppxManifest.xml.
- **Test-TcpkMsixFrameworkDeps** - B02. Framework dependencies (VCLibs / WindowsAppRuntime) declared correctly.
- **Test-TcpkMsixProtocols** - B03. URI scheme handlers declared in AppxManifest.xml. Adds a sink-reachability pass: emits `protocol.sink-reachable` (HIGH) when a binary both handles activation args and references a dangerous sink.
- **Test-TcpkUacManifest** - B09. UAC execution level in embedded RT_MANIFEST (and sidecar .manifest).

## C - OS integration  (30)

- **Expand-TcpkAsar** - Parse an Electron app.asar file-table, extract each module to disk, and scan the extracted JS/config for secrets + insecure Electron flags.
- **Get-TcpkTasvsMap** - Map findings / rule IDs to OWASP TASVS controls and the OWASP Desktop App Security Top 10 (report-time lookup; pipe findings, pass -RuleId, or dump the table).
- **Compare-TcpkFileSnapshot** - C19b. Diff two file-system snapshots -- files the app created/modified/deleted at runtime (exec drops HIGH).
- **Compare-TcpkRegistrySnapshot** - C18b. Diff two registry snapshots (Regshot-style) -- what the app changed.
- **Save-TcpkFileSnapshot** - C19a. Regshot-style file-system snapshot (path/size/mtime/SHA-256) for before/after diffing.
- **Save-TcpkRegistrySnapshot** - C18a. Regshot-style registry snapshot (before/after the app runs).
- **Test-TcpkAppPaths** - C10. App Paths registry entries.
- **Test-TcpkComHijack** - C20. Per-user COM CLSID hijack opportunities (T1546.015).
- **Test-TcpkAutoStart** - C04. Autostart entries (Run / RunOnce keys + scheduled tasks).
- **Test-TcpkAvExclusions** - C17. Microsoft Defender exclusions attributable to the app.
- **Test-TcpkFirewallRules** - C16. Windows Firewall rules created by the app (overly-broad inbound).
- **Test-TcpkFolderAcls** - C05. Recursive ACL audit on a folder.
- **Test-TcpkIfeoHijack** - C11. Image File Execution Options debugger-key hijack.
- **Test-TcpkInstallDirAcl** - C01. Non-admin-writable files in an admin-installed directory.
- **Test-TcpkKernelDrivers** - C14. Kernel-mode drivers (.sys) shipped or installed by the app.
- **Test-TcpkProgramDataAcls** - C13. World-writable app data dirs under %ProgramData% / %PUBLIC% (EoP / TOCTOU).
- **Test-TcpkProtocolHandlers** - C07. HKCR protocol handlers (system-wide URI scheme registrations).
- **Test-TcpkRegistryAcl** - C12. Weak DACL on the app's HKLM registry keys (privilege escalation).
- **Test-TcpkRegistryFootprint** - C06. Registry footprint of the app (HKCU and HKLM).
- **Test-TcpkRegistryValues** - C17. Secrets stored in the app's registry VALUES (not just key names).
- **Test-TcpkScheduledTaskAcl** - C15. User-modifiable scheduled tasks (privilege escalation).
- **Test-TcpkServiceBinaryAcl** - C18. Non-admin-writable service / scheduled-task BINARY (EoP).
- **Test-TcpkServicePermissions** - C02. Service binary writable / weak SDDL.
- **Test-TcpkShimCache** - C08. AppCompat shim registrations for the target.
- **Test-TcpkSxsManifests** - C09. Side-by-side activation context manifests + .local files.
- **Test-TcpkTrustStore** - C15. Certificate trust-store pollution by the app/installer.
- **Test-TcpkUnquotedServicePath** - C03. Classic unquoted-service-path LPE primitive.
- **Test-TcpkWritablePath** - C22. Writable directories in the system PATH (binary planting surface, T1574.007).
- **Test-TcpkWerExposure** - C21. Windows Error Reporting (WER) crash dump data exposure (T1005). Dump files are filtered to the target's own executables, because the dump folder is shared machine-wide. LocalDumps is off by default on Windows, so this normally emits nothing; a global policy is reported only where it governs the target AND there is real exposure. Does NOT cover the default WER ReportArchive/ReportQueue folders. Not applicable to Electron apps, which use Crashpad.
- **Test-TcpkWmiPersistence** - C16. WMI permanent event subscriptions (persistence mechanism).
- **Test-TcpkServiceDll** - C24. svchost ServiceDll hijack (T1574.011 / T1543.003). A shared-service DLL runs as SYSTEM inside svchost, so a non-admin-writable ServiceDll file, a writable directory that reaches it, or a writable service / Parameters key that repoints it is a direct local escalation. Directory grants are graded honestly: DELETE_CHILD / WRITE_DAC / WRITE_OWNER / GENERIC_ALL can replace the existing DLL (HIGH), while ADD_FILE / GENERIC_WRITE alone is only a planting primitive (MEDIUM) and the finding says so. Scope with -Path to the audited install tree; unscoped runs are machine-wide and report services the audited vendor does not own. Refuses to run under a 32-bit host, because WOW64 redirection would resolve System32 paths to SysWOW64 and report the wrong file's ACL. Always emits a coverage record so a clean result is distinguishable from a run that never looked.
- **Test-TcpkAppInitDlls** - C25. AppInit_DLLs and AppCertDlls (T1546.010 / T1546.009). Every user-mode process that loads user32.dll also loads whatever AppInit_DLLs names, which makes it a machine-wide injection point. Reports the configured state, whether Secure Boot / RequireSignedAppInit mitigates it, and whether any listed DLL is writable. Separates the two attributions that matter: a DLL the AUDITED APP registered is a vendor finding, while a value already present from other software is machine state the vendor cannot fix. Emits appinit.clean on a clean read so silence is not ambiguous.
- **Test-TcpkRegistryLoadPoints** - C26. Five registry-driven DLL load points not covered by the COM (Test-TcpkComHijack) or SxS paths: Winsock LSP/NSP catalogs, print monitors and processors, LSA extensions/notification packages, netsh helpers, and Winlogon notify. Each entry is resolved to a DLL on disk and its ACL read. Filtered to the audited install tree so it reports the vendor's own registrations rather than the whole machine, with a census record covering what was enumerated.
- **Test-TcpkInstallerPlanting** - C27. Installer / setup-binary DLL planting (T1574.001). Every other DLL check in TCPK inspects an INSTALLED application; this one inspects the installer, which runs from wherever the browser saved it (usually %USERPROFILE%\Downloads) and resolves DLLs from its own directory first. A DLL the installer imports but does not ship beside itself is loaded from the download folder if one is sitting there, and installers are commonly elevated, so the payload lands as Administrator. The attacker never touches the installer, so its signature stays valid. Splits the result: imports resolvable NOWHERE are HIGH/Confirmed (the loader is guaranteed to find nothing), imports that exist in System32 are MEDIUM/Inferred (the app directory still precedes System32, but SafeDllSearchMode and manifest dependencies can change the outcome). api-ms-win-* and ext-ms-* API sets are excluded -- the loader resolves those from a schema, never from disk. Emits a coverage record when nothing was found, so silence means "looked" rather than "never looked".

## D - Credential storage  (9)

- **Test-TcpkAppConfigSecrets** - D04. .NET Framework .config secrets (connection strings, machine keys).
- **Test-TcpkBrowserTokenStore** - D08. Chromium / Electron / NW.js cookie + token store, and whether its os_crypt key is App-Bound-Encrypted or plain DPAPI.
- **Test-TcpkCredentialManager** - D02. Credential Manager entries belonging to the target.
- **Test-TcpkDpapiBlobs** - D01. DPAPI blobs in the target path.
- **Test-TcpkKeyMaterial** - D07. Private-key and certificate material inventory.
- **Test-TcpkLocalDb** - D07. Local databases at rest (SQLite / .db) -- unencrypted + world-readable.
- **Test-TcpkPlaintextConfigs** - D03. Token-shaped strings in small config files under the path.
- **Test-TcpkTokenCaches** - D05. MSAL / ADAL / custom OAuth token cache files under the target path. KNOWN GAP: the well-known per-user locations MSAL and ADAL actually write to (%LOCALAPPDATA%\.IdentityService\, %USERPROFILE%\.azure\) are not scanned, so this finds nothing for an MSAL-based app.
- **Test-TcpkWebViewCreds** - D06. WebView2 Edge user profile -- saved login state.

## E - Runtime / live process  (22)

- **Invoke-TcpkActivityTrace** - E24. One ETW capture window analysed three ways: DLL probes, file writes, registry writes. Replaces three separate 30s captures, so the app is exercised once and a DLL probe can be correlated with the write that followed it. Supports -Include / -Exclude filters, -IncludeChildren and -KeepEtl.
- **Test-TcpkChildProcesses** - E14. Direct child processes spawned by the target.
- **Test-TcpkComObjects** - E06. COM objects registered in HKCR\CLSID pointing at the target.
- **Test-TcpkDllSearchTrace** - E08. ETW capture of NAME NOT FOUND DLL probes during a window.
- **Test-TcpkGuiInspector** - E17. Live GUI object inspection (UI Automation) -- hidden/disabled controls
- **Test-TcpkHandleEnumeration** - E11. Open handle counts and types for the process (triage summary).
- **Test-TcpkListeningPorts** - E03. TCP listeners + UDP endpoints owned by the process.
- **Test-TcpkLoadedModulePaths** - E10. Native modules loaded into the process from non-system paths. Checks BOTH the file ACL (module replaceable in place) and the parent directory ACL (a module can be planted). Program Files is intentionally in scope: installers routinely loosen ACLs on their own subdirectories.
- **Test-TcpkMemoryRegions** - E18. Virtual memory region protection (T1055 / T1620). Walks the process address space with VirtualQueryEx and reports RWX pages (writable and executable at once, so a memory write needs no DEP bypass) and executable memory not backed by a mapped image (the shape a manual-map or reflective loader produces). JIT-calibrated: .NET, V8/Node and the JVM generate code at runtime, so when one of those is loaded the finding is reported as posture rather than a defect. Read-only, opens with PROCESS_QUERY_INFORMATION only.
- **Test-TcpkThreadDacl** - E19. Running-thread DACL (T1055.003). Test-TcpkProcessDacl covers the process object; this covers the THREAD objects inside it. THREAD_SET_CONTEXT alone redirects execution by rewriting register state, with no process memory-write right needed, so a sound process DACL does not imply a sound thread one. Deduplicated per (account, rights) so a many-threaded process does not emit one finding per thread.
- **Test-TcpkTokenDacl** - E20. Access-token DACL (T1134.001). Test-TcpkProcessToken reports what the token CONTAINS; this reports who may OPERATE ON it. TOKEN_DUPLICATE on an elevated process is a direct escalation with no code injection: clone the token and CreateProcessAsUser. HIGH for DUPLICATE / IMPERSONATE / WRITE_DAC / ALL_ACCESS.
- **Test-TcpkProcessVirtualization** - E21. UAC file and registry virtualization state (T1548.002). Windows applies the shim only to 32-bit processes with no requestedExecutionLevel, so a modern app running virtualized is both unmanifested and writing security-relevant state into a user-writable VirtualStore. Reports enabled (MEDIUM) and allowed-but-not-enabled (LOW) separately.
- **Test-TcpkHandleDacl** - E22. DACLs on the kernel objects a running process actually holds open. The RUNTIME half of Test-TcpkNamedObjects, which infers a squatting surface statically from name literals: this reads the real DACL on the real handles. Grades Event / Mutant / Semaphore / Section / Job / Timer / Key. File-type handles are counted but never name-queried, because NtQueryObject(ObjectNameInformation) blocks indefinitely on a synchronous file or pipe handle with pending I/O. Pipes are covered by Test-TcpkNamedPipeDacl. Needs PROCESS_DUP_HANDLE, so generally elevated.
- **Test-TcpkThreadStart** - E23. Unbacked thread start addresses (T1055 / T1620). Reads each thread's Win32 start address with NtQueryInformationThread and compares it against the address ranges of every loaded module. A start address inside a mapped image is normal; one outside every image is the shape CreateRemoteThread against manual-mapped or reflectively-loaded code produces. JIT-calibrated against the same runtime module list as Test-TcpkMemoryRegions (CLR, JVM, Node, CEF), so a legitimately jitted thread drops to INFO instead of MEDIUM. Refuses to report when fewer than two module ranges are readable, or when a 32-bit host is inspecting a 64-bit target, because either would flag every backed thread as unbacked. Deduplicated per 64 KB region, capped, and the exact totals are carried separately from the capped sample.
- **Test-TcpkLoadedModuleSignatures** - E02. Authenticode status of every module loaded into the live process.
- **Test-TcpkMailslotsAlpc** - E07. Mailslots and ALPC ports.
- **Test-TcpkMemoryDump** - E09. Dump the process and scan the dump for secrets.
- **Test-TcpkNamedObjects** - E15. Named kernel objects (mutex/event/section) -- squatting / race surface.
- **Test-TcpkNamedPipeDacl** - E05. Named pipe DACL inspection (TCAWin gap).
- **Test-TcpkNamedPipes** - E04. Named pipes whose name suggests a relationship to the target.
- **Test-TcpkProcessDacl** - E15. Running-process DACL -- injectable by low-privileged users?
- **Test-TcpkProcessEnvSecrets** - E16. Secrets in a running process's environment block (read-only).
- **Test-TcpkProcessMitigations** - E01. Runtime process mitigations (DEP, ASLR, CFG, SEHOP, etc.).
- **Test-TcpkProcessToken** - E13. Process token owner / integrity level / impactful privileges.
- **Test-TcpkRpcSurface** - E16. MS-RPC server interface surface (static).
- **Test-TcpkSharedMemoryDacl** - E13. Shared-memory / memory-mapped file DACL inspection.
- **Test-TcpkWindowEnumeration** - E12. Top-level windows owned by the process (Shatter / UIA surface).
- **Test-TcpkWindowMessages** - E12b. Window-message attack surface (WM_COPYDATA injection + drop-files).

## F - Network  (11)

- **Test-TcpkBackendEndpoints** - F03. Inventory backend API endpoints + inferred auth model.
- **Test-TcpkCrlOcsp** - F06. CRL / OCSP revocation-checking behavior.
- **Test-TcpkDnsLeakage** - F05. DNS pre-resolution / hostname leakage indicators.
- **Test-TcpkGrpcSurface** - F11. gRPC / Protobuf service surface enumeration (proto files, services, reflection).
- **Test-TcpkInsecureSchemes** - F07. Cleartext network scheme references (http:// and ws://).
- **Test-TcpkRpcChannels** - F10. gRPC / SignalR channel security: insecure (no-TLS) credentials in first-party code + cleartext ws:// / http:// hubs and gRPC targets in shipped config / JS.
- **Test-TcpkSelfHostedServer** - F07. Self-hosted HTTP/web-server surface detection.
- **Test-TcpkTlsHandshake** - F09. ACTIVE (gated) per-version TLS handshake probe to backends + cert-validity result; flags negotiable SSL3/TLS1.0/1.1.
- **Test-TcpkTlsPinning** - F01. TLS certificate pinning detection.
- **Test-TcpkTlsProtocols** - F04. TLS protocol version markers (1.0 / 1.1 fallback?).
- **Test-TcpkUpdateFlow** - F02. Update mechanism: signed manifest? signed payload? downgrade defense?

## G - WebView2  (7)

- **Test-TcpkWv2DevTools** - G05. WebView2 DevTools enabled in shipped build.
- **Test-TcpkWv2HostObjects** - G01. AddHostObjectToScript -- .NET object exposure to JS.
- **Test-TcpkWv2ResourcePolicy** - G07. WebResourceRequested / external-resource fetch policy.
- **Test-TcpkWv2ScriptInjection** - G06. AddScriptToExecuteOnDocumentCreated -- script auto-injection.
- **Test-TcpkWv2VirtualHost** - G04. SetVirtualHostNameToFolderMapping (local content as a web origin).
- **Test-TcpkWv2Sideload** - G08. WebView2 DLL sideloading opportunities (T1574.002).
- **Test-TcpkWv2WebMessage** - G02. WebMessageReceived handler presence (one-way JS-to-host bridge).

## H - Logging / telemetry  (4)

- **Test-TcpkEtwProviders** - H04. Custom ETW / EventSource providers (cross-process telemetry leak).
- **Test-TcpkLogFiles** - H01. Log files under the target path. Inventory, sensitive-keyword and stack-trace content scan, plus the log-TAMPERING question, which is separate from what a log leaks: can a non-admin principal rewrite or delete the record. Checks the ACL of each log file (`log.tamperable-file`) and of its containing directory (`log.tamperable-directory`) for Write / Modify / FullControl / Delete granted to Everyone, Authenticated Users, Users or INTERACTIVE. The directory is reported separately and matters more: on Windows, Delete on the parent removes a file whose own ACL denies it, so a hardened log inside a loose directory is still deletable. Append-only (AppendData without WriteData) is deliberately not flagged, since that is the correct posture.
- **Test-TcpkPiiInLogs** - H03. PII patterns in shipped logs / templates / data files.
- **Test-TcpkTelemetrySdks** - H02. Third-party telemetry SDK enumeration.

## I - Memory hygiene  (5)

- **Test-TcpkClipboardSecrets** - I05. Clipboard secret monitoring during a test session (polls for passwords, API keys, tokens).
- **Test-TcpkMemorySecrets** - I04. Live-memory secret scan (read-only) of a running process.
- **Test-TcpkPageFile** - I02. Page file / hibernation file secrecy hygiene.
- **Test-TcpkSecureStringUsage** - I03. SecureString / ProtectedData usage in first-party code.
- **Test-TcpkWerPolicy** - I01. Windows Error Reporting LocalDumps per-app policy for the target executable. LocalDumps is not enabled by default and requires admin, so an absent key emits nothing by design: that is machine posture the vendor cannot fix. Not applicable to Electron apps, which use Crashpad.

## J - Anti-debug  (4)

- **Test-TcpkAntiDebugRefs** - J01. Anti-debug API references (IsDebuggerPresent etc.).
- **Test-TcpkAntiInjection** - J03. Anti-injection / process-hollowing detection markers.
- **Test-TcpkSelfIntegrityCheck** - J02. Self-integrity verification markers.
- **Test-TcpkTimingAntiDebug** - J04. Timing-based anti-debug markers (RDTSC, QueryPerformanceCounter).

## K - Exploitation (GATED, off by default)  (29)

- **Invoke-TcpkParamTamper** - K24. Mutates one parameter of a captured request (price, quantity, boolean flag, role, limit) and sends three requests per parameter: baseline, tampered, and a bogus control. An endpoint that accepts the bogus value too reports NOT CONCLUSIVE rather than a false positive.
- **New-TcpkProxyDll** - K01. Generate a proxy-DLL source scaffold for a flagged phantom-import.
- **New-TcpkFridaTlsBypass** - K02. Generate a Frida JS script template that bypasses a flagged TLS validation callback.
- **New-TcpkPoisonedUpdateManifest** - K03. Generate a TEMPLATE update-manifest that demonstrates an unsigned-update supply-chain finding.
- **Invoke-TcpkDpapiCrossUser** - K04. Attempt to decrypt a DPAPI blob under each available DPAPI scope.
- **New-TcpkComHijackTemplate** - K05. Generate a proxy-COM scaffold for a flagged COM-server CLSID.
- **Start-TcpkPipeMitm** - K06. Local-loopback named-pipe MITM listener.
- **Invoke-TcpkMemoryFlagFlip** - K07. Locate and optionally patch an in-memory flag to prove client-side gating (e.g. IsLicensed/IsTrial false->true).
- **Invoke-TcpkPipeProbe** - K08. Connect to a named pipe and send a benign probe.
- **Invoke-TcpkInputFuzz** - K09. Dumb file/argument fuzzer with crash capture.
- **Invoke-TcpkGuiUnlock** - K10. Enable disabled controls / unmask password / unlock read-only fields (Win32).
- **Invoke-TcpkComProbe** - K11. Actively probe a discovered COM server: try to instantiate it, test whether it AUTO-ELEVATES via the Elevation moniker, and enumerate its callable member surface. Logic-PoC: it instantiates and reads the type info; it never invokes a method.
- **Invoke-TcpkRpcProbe** - K12. Enumerate the live local RPC endpoint mapper -- the runtime counterpart to the static rpc.server-interface marker. Read-only: it lists the registered interfaces (UUID / binding / annotation); it never binds or calls a method.
- **Invoke-TcpkJwtCrack** - K13. Prove a JWT's forgeability OFFLINE: decode + analyze it, and recover a weak HMAC signing secret by dictionary attack. Makes NO network call.
- **Invoke-TcpkJwtAttack** - K14. Forge JWT attack tokens and test which ones a live backend ACCEPTS. Proves auth-bypass by BODY comparison against baselines, never by HTTP status alone.
- **Invoke-TcpkReplay** - K15. Replay a captured request with its credential REMOVED to prove missing function-level authorization (CWE-862). Confirmed by protected-body comparison.
- **Invoke-TcpkIdorProbe** - K16. Prove horizontal IDOR / broken object-level authorization (CWE-639): identity A, using A's credential, reads identity B's object. Four baselines kill the public-object and soft-404 false positives.
- **New-TcpkChainPoc** - K17. Emit a concrete, lab-safe proof-of-concept PROCEDURE for each correlated exploit chain (Get-TcpkExploitChains). Turns a HIGH/CRITICAL correlation into the exact steps an operator runs to demonstrate it -- benign marker only, stop at proof-of-control.
- **Invoke-TcpkApiTrace** - K18. Trace security-relevant Windows API calls in a RUNNING target with Frida and report what it did: weak crypto, process/command launch, secrets written to disk/registry, DPAPI use. READ-ONLY: it observes calls, it never modifies them.
- **Invoke-TcpkAuthMatrix** - K19. Vertical authorization matrix: replay one role's request under another role's credential and report where a lower-privilege identity is accepted.
- **New-TcpkIlPatch** - K20. IL binary patching via Mono.Cecil (gated exploit).
- **New-TcpkRegistryHijackTemplate** - K21. Generate registry-based persistence / hijack PoC artifacts.
- **Invoke-TcpkExpiryProbe** - K22. Prove a backend accepts a token AFTER the expiry the backend itself issued, judged against the server's own clock.
- **Invoke-TcpkLogoutProbe** - K23. Replay an authenticated request AFTER logging out, using the same credential, to show whether logout actually revoked anything server-side.
- **Get-TcpkCveMatches** - Match the target's shipped components against LIVE online CVE sources.
- **Get-TcpkExploitPlan** - Build a unified, actionable exploit plan from CVE matches + exploitable findings.
- **Get-TcpkStoredCredentials** - Enumerate and decrypt the current user's Windows Credential Manager entries -- the stored-credential extraction primitive.
- **Invoke-TcpkHookBypass** - Force the return value of a named native export at runtime via Frida -- flip a client-side auth / license / integrity check the thick client trusts.
- **Test-TcpkCredentialLiveness** - Prove a recovered/observed credential actually AUTHENTICATES to a live service -- turning an exposed secret into demonstrated impact (Confirmed exploit).

## Recon / target profiling  (4)

- **Get-TcpkAttackSurface** - R11. Synthesize a ranked attack-surface map from audit findings.
- **Get-TcpkExploitChains** - R12. Correlate individual findings into multi-step exploit CHAINS (emits CRITICAL/HIGH `chain.*` findings when co-occurring conditions form an attack path: unsigned-update+writable-dir, web-content+host-bridge, writable-privileged-binary, SYSTEM+IPC impersonation, URI-handler+dangerous-sink).
- **Get-TcpkReconStrings** - R11. Extract + categorize interesting literal strings from first-party binaries.
- **Get-TcpkTargetProfile** - R00. Recon / fingerprint pass. Builds a target-application profile for the

## Verify / triage  (21)

- **Confirm-TcpkCallsiteUsage** - Deterministic IL verification of callsites.* and deser.* findings: is the flagged API actually invoked, reachable, and fed by external input -- or a false positive?.
- **Confirm-TcpkCallsites** - Phase-2 confirmation for dangerous-API callsite findings.
- **Confirm-TcpkDeserialization** - Phase-2 confirmation for unsafe-deserialization findings.
- **Confirm-TcpkTlsBypass** - Phase-2 confirmation for TLS certificate-validation bypass findings.
- **Disable-TcpkExploit** - Turn off the Exploit bucket for this PowerShell session.
- **Enable-TcpkExploit** - Toggle on the Exploit bucket (K01-K06) for this PowerShell session.
- **Expand-TcpkAsar** - Parse an Electron app.asar header file-table, extract each bundled module, and scan the extracted JS/config for secrets and insecure Electron flags.
- **Expand-TcpkPyInstaller** - Carve the CArchive out of a PyInstaller-frozen .exe (and extract a cx_Freeze / py2exe library.zip) so the rest of TCPK can actually read the app's code surface.
- **Expand-TcpkSingleFile** - Extract the managed assemblies bundled inside a .NET single-file (PublishSingleFile) apphost so the rest of TCPK can actually scan them.
- **Get-TcpkCaptureInterface** - List the network capture interfaces available via the operator's installed Wireshark (tshark -D). For picking an interface for Invoke-TcpkPcapCapture.
- **Get-TcpkFileStructure** - Apply a byte pattern to a file and return its header as named, decoded fields.
- **Get-TcpkPcapBtFindings** - Analyse a Bluetooth / BLE packet capture for security findings.
- **Get-TcpkPcapZigbeeFindings** - Analyse a Zigbee / IEEE 802.15.4 packet capture for security findings.
- **Invoke-TcpkDecompile** - Drive ILSpy CLI to decompile and return source context for a method.
- **Invoke-TcpkDynamicConfirm** - GATED, observation-only dynamic confirmation: does the target app TRUST a command-line / deep-link session override at runtime? (Dynamic harness, slice 1.).
- **Invoke-TcpkIntercept** - Traffic interception for a thick client, via mitmproxy. Two modes: parse an existing mitmproxy capture into findings (-FlowFile, cross-platform, ungated), or actively launch the target through a local mitmdump and observe its traffic (-Target, GATED).
- **Invoke-TcpkJavaDecompile** - Drive CFR to decompile a .jar / .war / .class and return source context for a symbol.
- **Invoke-TcpkPcapCapture** - Capture live traffic on an interface (via the operator's dumpcap), then analyse it for security issues. LIVE capture needs a capture driver (npcap on Windows) and elevation -- it is the operator's dumpcap doing the privileged work; TCPK ships no driver.
- **Invoke-TcpkPcapReview** - Analyse a packet capture (.pcap / .pcapng) for security issues, via the operator's installed Wireshark (tshark). Read-only: it dissects a capture you already made; it does not capture live and needs no admin.
- **Invoke-TcpkSecretRecovery** - Turn shipped crypto material into a DEMONSTRATED secret. When an app ships a symmetric key + IV + ciphertext together, decrypt it and recover the plaintext - upgrading three 'Inferred' findings to one 'Confirmed (exploit)'.
- **Resolve-TcpkFindings** - Triage pipeline: dedupe + false-positive killers + confidence refinement.

## Reporting  (8)

- **Compare-TcpkAudit** - Diff two audits (baseline vs current) into NEW / FIXED / REGRESSED / unchanged at rule+location granularity; optional Markdown delta report.
- **Export-TcpkReportExcel** - Export a multi-sheet .xlsx report: Summary, Findings, DLL Hardening (+ CVEs).
- **Export-TcpkReportHtml** - Export TCPK findings as a self-contained, interactive HTML report (leads with an executive summary + attack-path callout).
- **Export-TcpkReportIntel** - Export a self-contained offline intel.html dashboard (severity/confidence + evidence ladder, recon endpoint map, filterable cards).
- **Export-TcpkReportJson** - Export TCPK findings as JSON for CI / re-processing.
- **Export-TcpkReportMarkdown** - Export findings as a plain-text Markdown report (exec summary + severity-grouped findings with full CVSS / CWE / ATT&CK / TASVS / Desktop-Top-10 mapping).
- **Export-TcpkReportSarif** - Export SARIF 2.1.0 for GitHub / Azure DevOps code-scanning ingest.
- **Export-TcpkSbom** - Export a CycloneDX 1.5 SBOM (software bill of materials) of bundled components.

## LLM (optional, local-first)  (6)

- **Disable-TcpkLlmCloud** - Turn off cloud LLM use for this session (reverts to local-only).
- **Enable-TcpkLlmCloud** - Allow TCPK to send findings to a CLOUD LLM backend for this session.
- **Get-TcpkLlmModels** - List the model IDs the configured provider + key can actually use (live).
- **Get-TcpkLlmProvider** - List the built-in LLM providers (for the GUI dropdown) or the current selection.
- **Invoke-TcpkLlmCodeJudgment** - L1 -- LLM-assisted verification of code-construct findings.
- **Test-TcpkLlm** - Connectivity + sanity check for the configured LLM provider.

---
**243 of 268 cmdlets are documented here.** The remainder are reachable via `Get-Command -Module TCPK`.
Run `Get-TcpkInfo` for the authoritative live count, which is computed from the module folder rather than
from this page (v2.7.1: 268 cmdlets across 19 buckets, 174 of them `Test-*` detection checks).
