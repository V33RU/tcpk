# TCPK - Check Catalogue

Every public cmdlet, grouped by bucket. Run `Get-TcpkInfo` for live counts.
**GATED** cmdlets require `Enable-TcpkExploit -Acknowledge`.

**Supported targets:** TCPK is path-based, not installer-specific. Point it at an
MSIX/AppX/`.msixbundle`/`.zip` package, an installed/extracted app folder, or a single
`.exe` (portable apps). It works the same on MSIX, MSI, ClickOnce, Squirrel and portable
apps; the 8 MSIX-manifest checks (bucket B) auto-skip when there is no `AppxManifest.xml`.
For thin-client apps it audits the **client-side binaries** only -- the remote server/API
is out of scope (separate web/API engagement), as is the thin-client terminal OS/appliance
(run TCPK where the Windows PE binaries live, e.g. a Citrix/RDP published-app host).

## A - Static binary analysis  (50)

- **Get-TcpkPeHardening** - Per-DLL binary-hardening matrix (ASLR / DEP / CFG / HighEntropyVA / ...).
- **Get-TcpkSigningMatrix** - Per-DLL code-signing matrix (signed / not signed -- information only; SIGNED / CATALOG / UNSIGNED / TAMPERED / UNTRUSTED + signer). Drives the GUI 'DLL Signing' tab, HTML signing table and Excel 'DLL Signing' sheet.
- **Test-TcpkAmsiSurface** - A26. AMSI integration and evasion surface detection.
- **Test-TcpkAotBinary** - A27. .NET Native AOT binary detection (evades IL-based analysis).
- **Test-TcpkAppDomainHijack** - A28. AppDomainManager injection surface in .NET executables (T1574.014).
- **Test-TcpkAppStack** - A40. Application technology-stack fingerprint with analysis-coverage note.
- **Test-TcpkAuthFlags** - A23. Client-side authentication / licensing boolean flags.
- **Test-TcpkCallsites** - A11. Static reference scan for dangerous .NET API patterns.
- **Test-TcpkCodeIntegrity** - A15. AppxMetadata\CodeIntegrity.cat signature status.
- **Test-TcpkClickOnce** - A29. ClickOnce deployment hijack surface detection.
- **Test-TcpkCryptoMisuse** - A13. Crypto-misuse hunter -- hardcoded key material + weak KDF / padding.
- **Test-TcpkCsvInjection** - A39. CSV / spreadsheet formula injection on export (CWE-1236): export sink with no formula-character neutralization.
- **Test-TcpkDebugFlags** - A16. Debug switches, security-disabling flags, and backdoor markers.
- **Test-TcpkDeserialization** - A10. Static heuristic for unsafe .NET deserialization patterns.
- **Test-TcpkDevArtifacts** - A36. Leftover dev/build artifacts shipped in the release (TASVS-CONF-1.4): debug symbols, source, backups, dev-config, API specs, .git/IDE dirs.
- **Test-TcpkDiagConfig** - A30. Shipped diagnostic/logging framework configs with exposure risk.
- **Test-TcpkDllSideload** - A31. DLL side-loading opportunities via known target DLL names (T1574.002). Examines every first-party PE module (.exe, .dll, .node, .pyd), not just executables, since DLL-to-DLL side-loading is the same primitive. Delay-load imports count too and are called out as the stronger case. Emits one finding per target DLL listing its importers, rather than one per importing module.
- **Test-TcpkElectron** - A24. Electron / Chromium-embedded insecure configuration (renderer flags incl. nodeIntegration / contextIsolation / sandbox / webSecurity / nodeIntegrationInSubFrames / experimentalFeatures / enableBlinkFeatures / nodeIntegrationInWorkers / webviewTag / webSQL / experimentalCanvasFeatures). Also flags TLS certificate-validation bypass in the bundled JS (electron.cert-validation-bypass, electron.cert-error-accept-all): a setCertificateVerifyProc with no callback(-2) reject path, rejectUnauthorized:false, NODE_TLS_REJECT_UNAUTHORIZED=0, or an accept-all certificate-error handler.
- **Test-TcpkElectronFuses** - A42. Electron Fuses audit: parses the @electron/fuses wire from the app binary and flags insecure fuse states as Confirmed facts (EnableCookieEncryption off = plaintext cookies; RunAsNode / EnableNodeCliInspectArguments on = node-exec / --inspect LOLBins; EnableEmbeddedAsarIntegrityValidation off = tamperable app.asar) plus a full fuse-posture summary.
- **Test-TcpkCrashReporter** - A42. Electron / Crashpad crash-reporting exposure (T1005). Electron apps use Crashpad, not Windows Error Reporting, so the WER checks do not apply to them and this one does. Recovers crashReporter.start() config (uploadToServer, submitURL, extra{}) from app.asar and loose first-party JS, and inspects the Crashpad database under the app's own userData directory for dumps and a weak ACL. Attribution is by construction: the database lives inside %APPDATA%\<productName>\Crashpad, so no other product's crash data is examined.
- **Test-TcpkDotnetHostHijack** - A43. Modern .NET host redirection (T1574.012 / T1574.001). Covers the .NET Core / 5+ vectors that replaced AppDomainManager injection: CLR profiler (COR_PROFILER / CORECLR_PROFILER, an unmanaged DLL loaded before any managed code runs), DOTNET_STARTUP_HOOKS, runtimeconfig.json additionalProbingPaths, writable runtimeconfig.json / deps.json, and single-file bundle extraction (DOTNET_BUNDLE_EXTRACT_BASE_DIR). Findings are split by attribution: the app's own files and shipped launchers are vendor-reportable, while profiler and hook variables already set in the machine or user environment are labelled as environment state the vendor cannot fix, and are reported only when they resolve to something.
- **Test-TcpkScanCoverage** - A44. Reports what the scan could NOT read, so a partial scan is not mistaken for a clean result. The safe walker drops three classes of subtree: unreadable (ACL, which is the norm for WindowsApps), past the depth cap, and reparse points it refuses to follow. All three were previously silent. Runs LAST in the audit so the counters cover the whole run. LOW when directories were unreadable (a genuine unknown), INFO when only the deliberate limits fired. Says nothing about the application: it is a statement about the completeness of the audit.
- **Test-TcpkElectronJs** - A41. Electron/JS vulnerable-code-pattern scan: dangerous sinks in the bundled JS (child_process/eval/Function/string-setTimeout exec, shell.openExternal file://, innerHTML/document.write/v-html DOM XSS, unsanitized markdown, resource-protocol path traversal, missing navigation guard, prototype pollution, script-initiated navigation (location.href/window.open/javascript:), CSS-injection/scriptless, weak CSP unsafe-inline/eval/hardcoded-nonce, unsafe <webview> tag, wildcard postMessage, dangerous command-line switches, dynamic executeJavaScript, insertCSS, always-allow permission handler) emitted as Inferred leads. Rules in Data/electron-js-sinks.json.
- **Test-TcpkEmbeddedScripts** - A20. Embedded script files shipped in the package.
- **Test-TcpkEndpoints** - A09 -- URL extraction + dev / qe / staging classifier.
- **Test-TcpkEntropySecrets** - A12. Entropy-based secret detection in text / config / source files.
- **Test-TcpkHollowingApis** - A32. Process hollowing / DLL injection / APC injection P/Invoke patterns in .NET PEs.
- **Test-TcpkJavaBundle** - A35. Crack shipped Java archives (jar/war/ear) and scan entries for secrets + insecure-TLS markers.
- **Test-TcpkJwt** - A14. Embedded JSON Web Token (JWT) discovery + weakness analysis.
- **Test-TcpkMsixPsf** - A33. Package Support Framework (PSF) script injection in MSIX packages.
- **Test-TcpkNativeInterop** - A18. Native interop -- unsafe Marshal / pointer patterns.
- **Test-TcpkPacker** - A22. Packer / obfuscator detection -- and the inverse: source-recoverable
- **Test-TcpkPeExports** - A04. PE export surface enumeration (for proxy-DLL planning).
- **Test-TcpkPeImports** - A03 -- Phantom DLL imports (DLL hijack candidates).
- **Test-TcpkPeMitigations** - A02 -- PE compile-time mitigations (ASLR, DEP, CFG, HighEntropyVA). NOT in the default audit (opt-in / compliance use): the audit reports hardening as posture in the DLL Mitigation Matrix (Get-TcpkPeHardening), not as findings.
- **Test-TcpkPhantomDlls** - A34. Phantom DLL planting opportunities in PE import tables. Scans BOTH the normal import table (`dllsearch.phantom-dll`) and the delay-import table, data directory 13 (`dllsearch.delayload-phantom`, resolved at first call, so a wider hijack window). Calibrated against live KnownDLLs and System32/SysWOW64 to suppress names that cannot be planted, and severity is gated on install-root writability.
- **Test-TcpkPInvokeSurface** - A17. P/Invoke surface -- bare-name DllImport declarations.
- **Test-TcpkReflectionLoading** - A16. Dynamic code loading via reflection.
- **Test-TcpkRegistryCredentialStore** - A35b. First-party code writing credentials to registry (insecure local-data-storage anti-pattern).
- **Test-TcpkResources** - A07. Embedded resource audit.
- **Test-TcpkSecrets** - A08 -- Hardcoded-secret scan (regex rules over UTF-8 + UTF-16LE views).
- **Test-TcpkSessionHandling** - A33. Session-handling hygiene (cookie HttpOnly/Secure/SameSite, token in URL, weak token generation, expiry) over shipped config / scripts / PE strings.
- **Test-TcpkSignature** - A01. Authenticode chain validation.
- **Test-TcpkStrings** - A06. Strings extraction with summary classification.
- **Test-TcpkStrongName** - A05. .NET assembly strong-name presence check.
- **Test-TcpkTauriConfig** - A38. Audit a Tauri app config (tauri.conf.json) for insecure CSP / allowlist / shell / fs / IPC / updater settings (v1 + v2).
- **Test-TcpkTlsBypass** - A12. TLS validation bypass patterns.
- **Test-TcpkUiLeakSurface** - A37. UI data-leak surface: screen-capture protection (SetWindowDisplayAffinity) and clipboard-history / cloud-clipboard hygiene.
- **Test-TcpkUnsafeNativeApis** - A25. Dangerous C/C++ runtime functions in native binaries (overflow surface).
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

## E - Runtime / live process  (21)

- **Test-TcpkChildProcesses** - E14. Direct child processes spawned by the target.
- **Test-TcpkComObjects** - E06. COM objects registered in HKCR\CLSID pointing at the target.
- **Test-TcpkDllSearchTrace** - E08. ETW capture of NAME NOT FOUND DLL probes during a window.
- **Test-TcpkGuiInspector** - E17. Live GUI object inspection (UI Automation) -- hidden/disabled controls
- **Test-TcpkHandleEnumeration** - E11. Open handle counts and types for the process (triage summary).
- **Test-TcpkListeningPorts** - E03. TCP listeners + UDP endpoints owned by the process.
- **Test-TcpkLoadedModulePaths** - E10. Native modules loaded into the process from non-system paths. Checks BOTH the file ACL (module replaceable in place) and the parent directory ACL (a module can be planted). Program Files is intentionally in scope: installers routinely loosen ACLs on their own subdirectories.
- **Test-TcpkMemoryRegions** - E11. Virtual memory region protection (T1055 / T1620). Walks the process address space with VirtualQueryEx and reports RWX pages (writable and executable at once, so a memory write needs no DEP bypass) and executable memory not backed by a mapped image (the shape a manual-map or reflective loader produces). JIT-calibrated: .NET, V8/Node and the JVM generate code at runtime, so when one of those is loaded the finding is reported as posture rather than a defect. Read-only, opens with PROCESS_QUERY_INFORMATION only.
- **Test-TcpkThreadDacl** - E12. Running-thread DACL (T1055.003). Test-TcpkProcessDacl covers the process object; this covers the THREAD objects inside it. THREAD_SET_CONTEXT alone redirects execution by rewriting register state, with no process memory-write right needed, so a sound process DACL does not imply a sound thread one. Deduplicated per (account, rights) so a many-threaded process does not emit one finding per thread.
- **Test-TcpkTokenDacl** - E13. Access-token DACL (T1134.001). Test-TcpkProcessToken reports what the token CONTAINS; this reports who may OPERATE ON it. TOKEN_DUPLICATE on an elevated process is a direct escalation with no code injection: clone the token and CreateProcessAsUser. HIGH for DUPLICATE / IMPERSONATE / WRITE_DAC / ALL_ACCESS.
- **Test-TcpkProcessVirtualization** - E14. UAC file and registry virtualization state (T1548.002). Windows applies the shim only to 32-bit processes with no requestedExecutionLevel, so a modern app running virtualized is both unmanifested and writing security-relevant state into a user-writable VirtualStore. Reports enabled (MEDIUM) and allowed-but-not-enabled (LOW) separately.
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
- **Test-TcpkLogFiles** - H01. Log files under the target path: ACL + sensitive-content scan.
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

## K - Exploitation (GATED, off by default)  (14)

- **Get-TcpkCveMatches** - Match the target's shipped components against live CVE data (ONLINE-ONLY): OSV (NuGet/npm/Maven) + NVD (native libs by CPE); no offline catalog is bundled
- **Get-TcpkExploitPlan** - Build a unified, actionable exploit plan from CVE matches + exploitable findings.
- **Invoke-TcpkDpapiCrossUser** - K04. Attempt to decrypt a DPAPI blob under each available DPAPI scope.
- **Invoke-TcpkGuiUnlock** - K10. (GATED) Enable disabled controls / unmask password fields (Win32).
- **Invoke-TcpkInputFuzz** - K09. (GATED) Dumb file/argument fuzzer with crash capture.
- **Invoke-TcpkMemoryFlagFlip** - K07. (GATED) Locate and optionally patch an in-memory flag to prove bypass.
- **Invoke-TcpkPipeProbe** - K08. (GATED) Connect to a named pipe and send a benign probe.
- **New-TcpkComHijackTemplate** - K05. Generate a proxy-COM scaffold for a flagged COM-server CLSID.
- **New-TcpkFridaTlsBypass** - K02. Generate a Frida JS script template that bypasses a flagged TLS-pinning mechanism.
- **New-TcpkIlPatch** - K11. (GATED) IL binary patching via Mono.Cecil: ReturnTrue, ReturnFalse, ReturnNull, Nop, FlipBranch, StripSn.
- **New-TcpkRegistryHijackTemplate** - K12. (GATED) Registry-based persistence / hijack PoC artifacts (IFEO, RunKey, AppInitDlls).
- **New-TcpkPoisonedUpdateManifest** - K03. Generate a TEMPLATE update-manifest that demonstrates an unsigned-update hijack.
- **New-TcpkProxyDll** - K01. Generate a proxy-DLL source scaffold for a flagged phantom-import.
- **Start-TcpkPipeMitm** - K06. Local-loopback named-pipe MITM listener.

## Recon / target profiling  (4)

- **Get-TcpkAttackSurface** - R11. Synthesize a ranked attack-surface map from audit findings.
- **Get-TcpkExploitChains** - R12. Correlate individual findings into multi-step exploit CHAINS (emits CRITICAL/HIGH `chain.*` findings when co-occurring conditions form an attack path: unsigned-update+writable-dir, web-content+host-bridge, writable-privileged-binary, SYSTEM+IPC impersonation, URI-handler+dangerous-sink).
- **Get-TcpkReconStrings** - R11. Extract + categorize interesting literal strings from first-party binaries.
- **Get-TcpkTargetProfile** - R00. Recon / fingerprint pass. Builds a target-application profile for the

## Verify / triage  (6)

- **Confirm-TcpkCallsiteUsage** - Deterministic IL verification of callsites.* findings: is the flagged API actually invoked, reachable, and fed by external input? Refines Confidence to 'Confirmed (IL)' (reachable + dynamic argument) or 'Likely-FP (IL)' (no call site / constant-only argument). Runs in the audit before the LLM; no model needed.
- **Disable-TcpkExploit** - Turn off the Exploit bucket for this PowerShell session.
- **Enable-TcpkExploit** - Toggle on the Exploit bucket (K01-K06) for this PowerShell session.
- **Expand-TcpkSingleFile** - Extract the managed assemblies bundled inside a .NET single-file (PublishSingleFile) apphost so every static scanner can read them (the full audit auto-extracts + re-scans).
- **Invoke-TcpkDecompile** - Drive ILSpy CLI to decompile and return source context for a method.
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
**Total: 188 bucketed checks** documented here. Run `Get-TcpkInfo` for the authoritative live count (v2.7.1).
