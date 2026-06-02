# TCPK - Check Catalogue

Every public cmdlet, grouped by bucket. Run `Get-TcpkInfo` for live counts.
**GATED** cmdlets require `Enable-TcpkExploit -Acknowledge`.

## A - Static binary analysis  (31)

- **Get-TcpkPeHardening** - Per-DLL binary-hardening matrix (ASLR / DEP / CFG / HighEntropyVA / ...).
- **Test-TcpkAuthFlags** - A23. Client-side authentication / licensing boolean flags.
- **Test-TcpkCallsites** - A11. Static reference scan for dangerous .NET API patterns.
- **Test-TcpkCodeIntegrity** - A15. AppxMetadata\CodeIntegrity.cat signature status.
- **Test-TcpkCryptoMisuse** - A13. Crypto-misuse hunter -- hardcoded key material + weak KDF / padding.
- **Test-TcpkDebugFlags** - A16. Debug switches, security-disabling flags, and backdoor markers.
- **Test-TcpkDependencyCves** - A19. Parse *.deps.json and flag bundled NuGet deps with known CVEs.
- **Test-TcpkDeserialization** - A10. Static heuristic for unsafe .NET deserialization patterns.
- **Test-TcpkElectron** - A24. Electron / Chromium-embedded insecure configuration.
- **Test-TcpkEmbeddedScripts** - A20. Embedded script files shipped in the package.
- **Test-TcpkEndpoints** - A09 -- URL extraction + dev / qe / staging classifier.
- **Test-TcpkEntropySecrets** - A12. Entropy-based secret detection in text / config / source files.
- **Test-TcpkJavaBundle** - A35. Crack shipped Java archives (jar/war/ear) and scan entries for secrets + insecure-TLS markers.
- **Test-TcpkJwt** - A14. Embedded JSON Web Token (JWT) discovery + weakness analysis.
- **Test-TcpkNativeInterop** - A18. Native interop -- unsafe Marshal / pointer patterns.
- **Test-TcpkPackageManifests** - A34. CVE check for non-deps.json manifests (packages.config / *.csproj PackageReference / pom.xml / package.json / lockfiles) vs the offline catalog.
- **Test-TcpkPacker** - A22. Packer / obfuscator detection -- and the inverse: source-recoverable
- **Test-TcpkPeExports** - A04. PE export surface enumeration (for proxy-DLL planning).
- **Test-TcpkPeImports** - A03 -- Phantom DLL imports (DLL hijack candidates).
- **Test-TcpkPeMitigations** - A02 -- PE compile-time mitigations (ASLR, DEP, CFG, HighEntropyVA).
- **Test-TcpkPInvokeSurface** - A17. P/Invoke surface -- bare-name DllImport declarations.
- **Test-TcpkReflectionLoading** - A16. Dynamic code loading via reflection.
- **Test-TcpkResources** - A07. Embedded resource audit.
- **Test-TcpkSecrets** - A08 -- Hardcoded-secret scan (regex rules over UTF-8 + UTF-16LE views).
- **Test-TcpkSessionHandling** - A33. Session-handling hygiene (cookie HttpOnly/Secure/SameSite, token in URL, weak token generation, expiry) over shipped config / scripts / PE strings.
- **Test-TcpkSignature** - A01. Authenticode chain validation.
- **Test-TcpkStrings** - A06. Strings extraction with summary classification.
- **Test-TcpkStrongName** - A05. .NET assembly strong-name presence check.
- **Test-TcpkTlsBypass** - A12. TLS validation bypass patterns.
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

## C - OS integration  (23)

- **Expand-TcpkAsar** - Parse an Electron app.asar file-table, extract each module to disk, and scan the extracted JS/config for secrets + insecure Electron flags.
- **Get-TcpkTasvsMap** - Map findings / rule IDs to OWASP TASVS controls and the OWASP Desktop App Security Top 10 (report-time lookup; pipe findings, pass -RuleId, or dump the table).
- **Compare-TcpkFileSnapshot** - C19b. Diff two file-system snapshots -- files the app created/modified/deleted at runtime (exec drops HIGH).
- **Compare-TcpkRegistrySnapshot** - C18b. Diff two registry snapshots (Regshot-style) -- what the app changed.
- **Save-TcpkFileSnapshot** - C19a. Regshot-style file-system snapshot (path/size/mtime/SHA-256) for before/after diffing.
- **Save-TcpkRegistrySnapshot** - C18a. Regshot-style registry snapshot (before/after the app runs).
- **Test-TcpkAppPaths** - C10. App Paths registry entries.
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
- **Test-TcpkWmiPersistence** - C16. WMI permanent event subscriptions (persistence mechanism).

## D - Credential storage  (8)

- **Test-TcpkAppConfigSecrets** - D04. .NET Framework .config secrets (connection strings, machine keys).
- **Test-TcpkCredentialManager** - D02. Credential Manager entries belonging to the target.
- **Test-TcpkDpapiBlobs** - D01. DPAPI blobs in the target path.
- **Test-TcpkKeyMaterial** - D07. Private-key and certificate material inventory.
- **Test-TcpkLocalDb** - D07. Local databases at rest (SQLite / .db) -- unencrypted + world-readable.
- **Test-TcpkPlaintextConfigs** - D03. Token-shaped strings in small config files under the path.
- **Test-TcpkTokenCaches** - D05. MSAL / ADAL / custom OAuth token cache files.
- **Test-TcpkWebViewCreds** - D06. WebView2 Edge user profile -- saved login state.

## E - Runtime / live process  (19)

- **Test-TcpkChildProcesses** - E14. Direct child processes spawned by the target.
- **Test-TcpkComObjects** - E06. COM objects registered in HKCR\CLSID pointing at the target.
- **Test-TcpkDllSearchTrace** - E08. ETW capture of NAME NOT FOUND DLL probes during a window.
- **Test-TcpkGuiInspector** - E17. Live GUI object inspection (UI Automation) -- hidden/disabled controls
- **Test-TcpkHandleEnumeration** - E11. Open handle counts and types for the process (triage summary).
- **Test-TcpkListeningPorts** - E03. TCP listeners + UDP endpoints owned by the process.
- **Test-TcpkLoadedModulePaths** - E10. Native modules loaded into the process from non-system paths.
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
- **Test-TcpkWindowEnumeration** - E12. Top-level windows owned by the process (Shatter / UIA surface).

## F - Network  (8)

- **Test-TcpkBackendEndpoints** - F03. Inventory backend API endpoints + inferred auth model.
- **Test-TcpkCrlOcsp** - F06. CRL / OCSP revocation-checking behavior.
- **Test-TcpkDnsLeakage** - F05. DNS pre-resolution / hostname leakage indicators.
- **Test-TcpkInsecureSchemes** - F07. Cleartext network scheme references (http:// and ws://).
- **Test-TcpkSelfHostedServer** - F07. Self-hosted HTTP/web-server surface detection.
- **Test-TcpkTlsHandshake** - F09. ACTIVE (gated) per-version TLS handshake probe to backends + cert-validity result; flags negotiable SSL3/TLS1.0/1.1.
- **Test-TcpkTlsPinning** - F01. TLS certificate pinning detection.
- **Test-TcpkTlsProtocols** - F04. TLS protocol version markers (1.0 / 1.1 fallback?).
- **Test-TcpkUpdateFlow** - F02. Update mechanism: signed manifest? signed payload? downgrade defense?

## G - WebView2  (6)

- **Test-TcpkWv2DevTools** - G05. WebView2 DevTools enabled in shipped build.
- **Test-TcpkWv2HostObjects** - G01. AddHostObjectToScript -- .NET object exposure to JS.
- **Test-TcpkWv2ResourcePolicy** - G07. WebResourceRequested / external-resource fetch policy.
- **Test-TcpkWv2ScriptInjection** - G06. AddScriptToExecuteOnDocumentCreated -- script auto-injection.
- **Test-TcpkWv2VirtualHost** - G04. SetVirtualHostNameToFolderMapping (local content as a web origin).
- **Test-TcpkWv2WebMessage** - G02. WebMessageReceived handler presence (one-way JS-to-host bridge).

## H - Logging / telemetry  (4)

- **Test-TcpkEtwProviders** - H04. Custom ETW / EventSource providers (cross-process telemetry leak).
- **Test-TcpkLogFiles** - H01. Log files under the target path: ACL + sensitive-content scan.
- **Test-TcpkPiiInLogs** - H03. PII patterns in shipped logs / templates / data files.
- **Test-TcpkTelemetrySdks** - H02. Third-party telemetry SDK enumeration.

## I - Memory hygiene  (4)

- **Test-TcpkMemorySecrets** - I04. Live-memory secret scan (read-only) of a running process.
- **Test-TcpkPageFile** - I02. Page file / hibernation file secrecy hygiene.
- **Test-TcpkSecureStringUsage** - I03. SecureString / ProtectedData usage in first-party code.
- **Test-TcpkWerPolicy** - I01. Windows Error Reporting LocalDumps policy.

## J - Anti-debug  (4)

- **Test-TcpkAntiDebugRefs** - J01. Anti-debug API references (IsDebuggerPresent etc.).
- **Test-TcpkAntiInjection** - J03. Anti-injection / process-hollowing detection markers.
- **Test-TcpkSelfIntegrityCheck** - J02. Self-integrity verification markers.
- **Test-TcpkTimingAntiDebug** - J04. Timing-based anti-debug markers (RDTSC, QueryPerformanceCounter).

## K - Exploitation (GATED, off by default)  (12)

- **Get-TcpkCveMatches** - Match the target's shipped components against the offline CVE catalog
- **Get-TcpkExploitPlan** - Build a unified, actionable exploit plan from CVE matches + exploitable findings.
- **Invoke-TcpkDpapiCrossUser** - K04. Attempt to decrypt a DPAPI blob under each available DPAPI scope.
- **Invoke-TcpkGuiUnlock** - K10. (GATED) Enable disabled controls / unmask password fields (Win32).
- **Invoke-TcpkInputFuzz** - K09. (GATED) Dumb file/argument fuzzer with crash capture.
- **Invoke-TcpkMemoryFlagFlip** - K07. (GATED) Locate and optionally patch an in-memory flag to prove
- **Invoke-TcpkPipeProbe** - K08. (GATED) Connect to a named pipe and send a benign probe.
- **New-TcpkComHijackTemplate** - K05. Generate a proxy-COM scaffold for a flagged COM-server CLSID.
- **New-TcpkFridaTlsBypass** - K02. Generate a Frida JS script template that bypasses a flagged
- **New-TcpkPoisonedUpdateManifest** - K03. Generate a TEMPLATE update-manifest that demonstrates an
- **New-TcpkProxyDll** - K01. Generate a proxy-DLL source scaffold for a flagged phantom-import.
- **Start-TcpkPipeMitm** - K06. Local-loopback named-pipe MITM listener.

## Recon / target profiling  (4)

- **Get-TcpkAttackSurface** - R11. Synthesize a ranked attack-surface map from audit findings.
- **Get-TcpkExploitChains** - R12. Correlate individual findings into multi-step exploit CHAINS (emits CRITICAL/HIGH `chain.*` findings when co-occurring conditions form an attack path: unsigned-update+writable-dir, web-content+host-bridge, writable-privileged-binary, SYSTEM+IPC impersonation, URI-handler+dangerous-sink).
- **Get-TcpkReconStrings** - R11. Extract + categorize interesting literal strings from first-party binaries.
- **Get-TcpkTargetProfile** - R00. Recon / fingerprint pass. Builds a target-application profile for the

## Verify / triage  (4)

- **Disable-TcpkExploit** - Turn off the Exploit bucket for this PowerShell session.
- **Enable-TcpkExploit** - Toggle on the Exploit bucket (K01-K06) for this PowerShell session.
- **Invoke-TcpkDecompile** - Drive ILSpy CLI to decompile and return source context for a method.
- **Resolve-TcpkFindings** - Triage pipeline: dedupe + false-positive killers + confidence refinement.

## Reporting  (4)

- **Export-TcpkReportExcel** - Export a multi-sheet .xlsx report: Summary, Findings, DLL Hardening (+ CVEs).
- **Export-TcpkReportHtml** - Export TCPK findings as a self-contained, interactive HTML report.
- **Export-TcpkReportJson** - Export TCPK findings as JSON for CI / re-processing.
- **Export-TcpkSbom** - Export a CycloneDX 1.5 SBOM (software bill of materials) of bundled components.

## LLM (optional, local-first)  (6)

- **Disable-TcpkLlmCloud** - Turn off cloud LLM use for this session (reverts to local-only).
- **Enable-TcpkLlmCloud** - Allow TCPK to send findings to a CLOUD LLM backend for this session.
- **Get-TcpkLlmModels** - List the model IDs the configured provider + key can actually use (live).
- **Get-TcpkLlmProvider** - List the built-in LLM providers (for the GUI dropdown) or the current selection.
- **Invoke-TcpkLlmCodeJudgment** - L1 -- LLM-assisted verification of code-construct findings.
- **Test-TcpkLlm** - Connectivity + sanity check for the configured LLM provider.

---
**Total: 146 bucketed checks** (+ Invoke-TcpkAudit & Get-TcpkInfo = 148 public cmdlets).
