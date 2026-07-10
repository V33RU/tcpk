# Thick-client bug class reference

The 88 testcases TCPK covers, organized as a reading guide for engagement
scoping and post-audit triage.

## Bucket A. Static binary analysis (20 testcases)

What the binary itself reveals before it runs.

| Id  | Cmdlet | What it finds |
|-----|---|---|
| A01 | `Test-TcpkSignature` | Authenticode invalid / missing on PEs (MSIX-catalog-aware) |
| A02 | `Test-TcpkPeMitigations` | ASLR / DEP / CFG / HighEntropyVA flags missing from PE header |
| A03 | `Test-TcpkPeImports` | Phantom DLL imports (search-order hijack candidates) |
| A04 | `Test-TcpkPeExports` | Native export-table inventory |
| A05 | `Test-TcpkStrongName` | .NET assemblies without strong-name token |
| A06 | `Test-TcpkStrings` | Per-binary URL / path / IP triage summary |
| A07 | `Test-TcpkResources` | Embedded resources with URLs (data-fetch references) |
| A08 | `Test-TcpkSecrets` | Hardcoded secrets via 15+ regex rules |
| A09 | `Test-TcpkEndpoints` | Non-production URLs shipped to prod |
| A10 | `Test-TcpkDeserialization` | Unsafe-deserialization type references |
| A11 | `Test-TcpkCallsites` | Weak crypto, weak RNG, AES-ECB, insecure-temp |
| A12 | `Test-TcpkTlsBypass` | Custom TLS validation callbacks |
| A13 | `Test-TcpkXxe` | XXE patterns in code and shipped XML |
| A14 | `Test-TcpkWcfConfig` | Cleartext / unauthenticated WCF bindings |
| A15 | `Test-TcpkCodeIntegrity` | MSIX CodeIntegrity catalog status |
| A16 | `Test-TcpkReflectionLoading` | Assembly.LoadFrom from user paths |
| A17 | `Test-TcpkPInvokeSurface` | Bare-name DllImports (PATH-attackable) |
| A18 | `Test-TcpkNativeInterop` | Marshal / pointer / unsafe references |
| A20 | `Test-TcpkEmbeddedScripts` | Shipped PowerShell / JS / Python files |
| A21 | `Test-TcpkWebViewNavTargets` | URLs the embedded WebView2 will navigate to |

## Bucket B. MSIX manifest analysis (8 testcases)

What the package declares to the OS.

| Id  | Cmdlet | What it finds |
|-----|---|---|
| B01 | `Test-TcpkMsixCapabilities` | Risky declared capabilities (runFullTrust etc.) |
| B02 | `Test-TcpkMsixFrameworkDeps` | Missing VCLibs framework dependency |
| B03 | `Test-TcpkMsixProtocols` | URI scheme handlers registered |
| B04 | `Test-TcpkMsixFileAssocs` | File type associations |
| B05 | `Test-TcpkMsixAppInstaller` | Auto-update extension declared |
| B06 | `Test-TcpkMsixComServers` | Packaged COM server registrations |
| B07 | `Test-TcpkMsixExtensions` | fullTrustProcess / appExecutionAlias / contextMenu |
| B08 | `Test-TcpkMsixDeclaredVsUsed` | Capability declared but no first-party code marker |

## Bucket C. OS integration (11 testcases)

How the installed package sits in the OS.

| Id  | Cmdlet | What it finds |
|-----|---|---|
| C01 | `Test-TcpkInstallDirAcl` | Install dir files writable by non-admin |
| C02 | `Test-TcpkServicePermissions` | Service binary writable / weak SDDL |
| C03 | `Test-TcpkUnquotedServicePath` | Unquoted-service-path LPE primitive |
| C04 | `Test-TcpkAutoStart` | Run / RunOnce / scheduled-task autostart entries |
| C05 | `Test-TcpkFolderAcls` | Recursive user-writable items |
| C06 | `Test-TcpkRegistryFootprint` | HKCU / HKLM keys under vendor name |
| C07 | `Test-TcpkProtocolHandlers` | HKCR URI scheme handlers + unquoted %1 |
| C08 | `Test-TcpkShimCache` | AppCompat shim registrations |
| C09 | `Test-TcpkSxsManifests` | .manifest / .local files |
| C10 | `Test-TcpkAppPaths` | App Paths entries pointing to writable targets |
| C11 | `Test-TcpkIfeoHijack` | IFEO debugger-key persistence |

## Bucket D. Credential storage (6 testcases)

Where the app keeps secrets at rest.

| Id  | Cmdlet | What it finds |
|-----|---|---|
| D01 | `Test-TcpkDpapiBlobs` | DPAPI blobs decryptable as current user |
| D02 | `Test-TcpkCredentialManager` | Credential Manager entries |
| D03 | `Test-TcpkPlaintextConfigs` | Token-shaped strings in config files |
| D04 | `Test-TcpkAppConfigSecrets` | .NET .config connection strings / machine keys |
| D05 | `Test-TcpkTokenCaches` | MSAL / ADAL / custom OAuth caches |
| D06 | `Test-TcpkWebViewCreds` | WebView2 Edge profile saved logins |

## Bucket E. Live process / runtime (14 testcases)

What the running app exposes.

| Id  | Cmdlet | What it finds |
|-----|---|---|
| E01 | `Test-TcpkProcessMitigations` | DEP / ASLR / CFG enforced at runtime |
| E02 | `Test-TcpkLoadedModuleSignatures` | Loaded modules without Valid Authenticode |
| E03 | `Test-TcpkListeningPorts` | TCP listeners + UDP endpoints |
| E04 | `Test-TcpkNamedPipes` | Named pipes by name pattern |
| E05 | `Test-TcpkNamedPipeDacl` | Pipe DACL grants Write to non-admin |
| E06 | `Test-TcpkComObjects` | HKCR\CLSID entries pointing at target |
| E07 | `Test-TcpkMailslotsAlpc` | Mailslots (ALPC ports surfaced as gap) |
| E08 | `Test-TcpkDllSearchTrace` | Runtime NAME_NOT_FOUND DLL probes (ETW) |
| E09 | `Test-TcpkMemoryDump` | Secrets in process memory dump |
| E10 | `Test-TcpkLoadedModulePaths` | Modules from user-writable paths |
| E11 | `Test-TcpkHandleEnumeration` | Handle / thread / WS summary |
| E12 | `Test-TcpkWindowEnumeration` | Top-level windows (Shatter / UIA surface) |
| E13 | `Test-TcpkProcessToken` | Process owner + integrity level |
| E14 | `Test-TcpkChildProcesses` | Direct child processes |

## Bucket F. Network (6 testcases)

Outbound TLS / update / DNS posture.

| Id  | Cmdlet | What it finds |
|-----|---|---|
| F01 | `Test-TcpkTlsPinning` | Pinning markers present vs absent |
| F02 | `Test-TcpkUpdateFlow` | Update flow + signature-verification keyword presence |
| F03 | `Test-TcpkBackendEndpoints` | Backend host inventory + auth-marker contextualization |
| F04 | `Test-TcpkTlsProtocols` | Explicit weak TLS protocol enablement |
| F05 | `Test-TcpkDnsLeakage` | Pre-TLS hostname resolution |
| F06 | `Test-TcpkCrlOcsp` | Revocation-check disabled markers |

## Bucket G. WebView2 (7 testcases)

Embedded browser attack surface.

| Id  | Cmdlet | What it finds |
|-----|---|---|
| G01 | `Test-TcpkWv2HostObjects` | AddHostObjectToScript -- .NET to JS exposure |
| G02 | `Test-TcpkWv2WebMessage` | WebMessageReceived (narrower bridge) |
| G03 | `Test-TcpkWebViewNavTargets` | URLs the WebView navigates to (in bucket A) |
| G04 | `Test-TcpkWv2VirtualHost` | SetVirtualHostNameToFolderMapping |
| G05 | `Test-TcpkWv2DevTools` | DevTools enabled in shipped build |
| G06 | `Test-TcpkWv2ScriptInjection` | AddScriptToExecuteOnDocumentCreated |
| G07 | `Test-TcpkWv2ResourcePolicy` | WebResourceRequested filter handlers |

## Bucket H. Logging / telemetry (3 testcases)

Data flow disclosure and credential-in-logs hygiene.

| Id  | Cmdlet | What it finds |
|-----|---|---|
| H01 | `Test-TcpkLogFiles` | Log files + sensitive keyword scan |
| H02 | `Test-TcpkTelemetrySdks` | Third-party telemetry SDK integration |
| H03 | `Test-TcpkPiiInLogs` | PII patterns in shipped text files |

## Bucket I. Memory / crash hygiene (3 testcases)

| Id  | Cmdlet | What it finds |
|-----|---|---|
| I01 | `Test-TcpkWerPolicy` | WER LocalDumps policy (user-readable dumps?) |
| I02 | `Test-TcpkPageFile` | Pagefile-clear-at-shutdown + hiberfil presence |
| I03 | `Test-TcpkSecureStringUsage` | SecureString / ProtectedData markers |

## Bucket J. Anti-debug / self-integrity (4 testcases)

Informational hardening signals.

| Id  | Cmdlet | What it finds |
|-----|---|---|
| J01 | `Test-TcpkAntiDebugRefs` | IsDebuggerPresent / NtQueryInformationProcess refs |
| J02 | `Test-TcpkSelfIntegrityCheck` | Self-Authenticode / hash-compare markers |
| J03 | `Test-TcpkAntiInjection` | SetProcessMitigationPolicy / BlockNonMicrosoftBinaries |
| J04 | `Test-TcpkTimingAntiDebug` | High-resolution timing API references |

## Bucket K. Exploitation generation (6 testcases, opt-in)

Verification helpers that produce PoC artifacts. Gated behind
`Enable-TcpkExploit -Acknowledge` -- not enabled by default.

| Id  | Cmdlet | What it produces |
|-----|---|---|
| K01 | `New-TcpkProxyDll` | Proxy-DLL source scaffold (.def + dllmain.c + build.bat) for a flagged phantom import |
| K02 | `New-TcpkFridaTlsBypass` | Frida JS template hooking WinVerifyTrust + CertVerifyCertificateChainPolicy to force OK |
| K03 | `New-TcpkPoisonedUpdateManifest` | JSON manifest template demonstrating an unsigned-update finding |
| K04 | `Invoke-TcpkDpapiCrossUser` | Decrypt-attempt under CurrentUser + LocalMachine DPAPI scopes |
| K05 | `New-TcpkComHijackTemplate` | Proxy-COM C# scaffold + HKCU-scoped .reg for a flagged CLSID |
| K06 | `Start-TcpkPipeMitm` | Local-loopback named-pipe MITM relay with logging |

Outputs are PoC artifacts (source code, scripts, templates) -- not
turnkey weapons. The operator chooses to compile / deploy them, only
against authorized targets.

## Cross-bucket correlations (Verify layer)

The Verify layer flags combinations of findings that are individually unremarkable but together signal a serious issue:

- **Hardcoded secret + update flow + no sig verification** = supply-chain primitive
- **AddHostObjectToScript + SetVirtualHostNameToFolderMapping + user-writable mapped folder** = WebView2 origin escape
- **WeakDpapi + user-writable install dir + restart** = cross-user credential theft

Run `Resolve-TcpkFindings` against existing JSON to re-apply correlation logic
when you tune the rules.
