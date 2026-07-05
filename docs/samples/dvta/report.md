# TCPK Security Audit Report

- Target: `DVTA`
- Version: 1.0.0.0  |  Publisher: Microsoft  |  Type: Win32 application
- Generated: 2026-07-05 14:52:26Z UTC
- Findings: 35

## Executive summary

| Severity | Count |
|----------|-------|
| CRITICAL | 1 |
| HIGH | 3 |
| MEDIUM | 8 |
| LOW | 12 |
| INFO | 11 |

Evidence grade: proven (IL/dynamic) 3; confirmed 12; inferred -- verify 18; likely-FP / uncertain 2.

### Top findings

- **[CRITICAL]** Update flow present; NO signature-verification primitives in first-party code  (`update.no-signature-verification`, Inferred)
- **[HIGH]** Hardcoded credential in .NET config appSettings (+1 more affected)  (`secrets.config-hardcoded-secret`, Inferred)
- **[HIGH]** High-entropy base64 token in DVTA.exe.config  (`entropy.high-entropy-token`, Inferred)
- **[HIGH]** Hardcoded cryptographic key in .NET config appSettings (+1 more affected)  (`secrets.config-hardcoded-crypto-key`, Inferred)

## Findings

### CRITICAL (1)

#### 001. Update flow present; NO signature-verification primitives in first-party code

- Rule: `update.no-signature-verification`  |  Confidence: Inferred
- CVSS v4.0: 9.3 `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N`
- CWE: CWE-494, CWE-345, CWE-347
- OWASP TASVS: TASVS-NETWORK Network Communication
- Impact: Direct compromise: code execution, privilege escalation, or exposure of live credentials with little/no precondition.

If downloaded update content is not signature-verified before execution, anyone who can write to the update origin (or MITM the channel) achieves persistent RCE on every client. Confirm in ILSpy that DownloadUpdate / CheckForUpdate methods do not call any cryptographic verification path.

- File: `C:\ProgramData\DVTA\EntityFramework.dll`
- Evidence: `update keywords: CheckForUpdate,UpdateAvailable,UpdateUrl,UpdateManifest,DownloadUpdate,LatestVersion,update-manifest,/firmware | sig keywords absent`

Verify:
```
# WHAT THIS CHECKS: Inspects the app's update/download flow for missing integrity checks.
# STEP 1 - RUN THIS IN POWERSHELL:
Test-TcpkUpdateFlow -Path 'C:\ProgramData\DVTA'
# STEP 2 - READ THE OUTPUT:
#   VULNERABLE  if  it applies a downloaded update with NO signature or hash check (remote code execution via a poisoned update server).
#   OK          if  it verifies a signature or hash before extracting or running the payload.
# NOTE: decompile the update method to confirm the check actually runs.
# TOOL: PowerShell + a .NET decompiler
```

- Fix: Sign update manifests with an offline-keyed RSA signature; sign each downloaded payload (Authenticode or detached PKCS#7); verify before any extract/exec.

### HIGH (3)

#### 002. High-entropy base64 token in DVTA.exe.config

- Rule: `entropy.high-entropy-token`  |  Confidence: Inferred
- CVSS v4.0: 6.9 `CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N`
- CWE: CWE-798, CWE-312
- ATT&CK: T1552.001 Credentials In Files
- OWASP TASVS: TASVS-STORAGE Sensitive Data Storage
- OWASP Desktop Top 10: DA3 Sensitive Data Exposure
- Impact: Serious exposure: an attacker meeting a modest precondition can steal secrets, escalate, or bypass a security control.

A high-entropy string was found in a shipped text/config file. Such tokens are frequently API keys, bearer tokens, or symmetric keys that prefix-based rules miss. Confirm whether it is a live credential.

- File: `C:\ProgramData\DVTA\DVTA.exe.config`
- Evidence: `J8gLXc...v8k8 (len=32, H=4.539)`

Verify:
```
# WHAT THIS CHECKS: Surfaces long high-entropy strings in the file that might be embedded secrets.
# STEP 1 - RUN THIS IN POWERSHELL:
Select-String -Path 'C:\ProgramData\DVTA\DVTA.exe.config' -Pattern '[A-Za-z0-9+/_-]{24,}' -AllMatches | ForEach-Object { $_.Matches.Value }
# STEP 2 - READ THE OUTPUT:
#   VULNERABLE  if  a printed high-entropy string turns out to be a live key or secret.
#   OK          if  the strings are hashes, cache-busters, or asset IDs.
# TOOL: PowerShell
```

- Fix: Do not ship secrets in files. Load them from a protected store (DPAPI / OS keychain / server-issued token) at runtime and rotate any exposed value.

#### 003. Hardcoded cryptographic key in .NET config appSettings (+1 more affected)

- Rule: `secrets.config-hardcoded-crypto-key`  |  Confidence: Inferred
- CVSS v4.0: 8.5 `CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N`
- CWE: CWE-798, CWE-321
- ATT&CK: T1552.001 Credentials In Files
- OWASP TASVS: TASVS-STORAGE Sensitive Data Storage
- OWASP Desktop Top 10: DA3 Sensitive Data Exposure
- Impact: Serious exposure: an attacker meeting a modest precondition can steal secrets, escalate, or bypass a security control.

- File: `2 files`
- Affected (2):
  - `C:\ProgramData\DVTA\DVTA.exe.config`
  - `C:\ProgramData\DVTA\DVTA.vshost.exe.config`
- Evidence: `2 affected: C:\ProgramData\DVTA\DVTA.exe.config; C:\ProgramData\DVTA\DVTA.vshost.exe.config`

Verify:
```
# WHAT THIS CHECKS: Scans the file's text for things that look like LIVE secrets - Azure storage keys, connection strings, PEM private keys, AWS access keys, or JWT tokens.
# STEP 1 - RUN THIS IN POWERSHELL:
([regex]::Matches([Text.Encoding]::Unicode.GetString([IO.File]::ReadAllBytes('2 files')),'DefaultEndpointsProtocol=https?;[A-Za-z0-9=;._/+\-]{0,300}AccountKey=[A-Za-z0-9+/=]{20,}|AccountKey=[A-Za-z0-9+/=]{20,}|-----BEGIN [A-Z ]+KEY|AKIA[A-Z0-9]{16}|eyJ[A-Za-z0-9_-]{10,}')).Value
# STEP 2 - READ THE OUTPUT:
#   VULNERABLE  if  it prints a real secret - e.g. AccountKey=..., a DefaultEndpointsProtocol=... connection string, an AKIA... AWS key, an eyJ... JWT, or a -----BEGIN ... KEY----- block.
#   OK          if  it prints nothing (only placeholders, or there are no secrets in the file).
# NOTE: this reads the file as UTF-16 (Unicode) text. If the secret is stored as plain ASCII, change ::Unicode to ::UTF8 and run it again. To dump EVERY readable string instead: strings.exe -u '2 files'
# TOOL: PowerShell built-in (alternative: Sysinternals strings.exe)
```

- Fix: Never ship a symmetric or private key in config. Derive a per-user key (DPAPI) or fetch from a key vault; rotate the exposed key. With key+IV+ciphertext all present, the protected value is trivially decryptable.

#### 004. Hardcoded credential in .NET config appSettings (+1 more affected)

- Rule: `secrets.config-hardcoded-secret`  |  Confidence: Inferred
- CVSS v4.0: 8.5 `CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N`
- CWE: CWE-798, CWE-260
- ATT&CK: T1552.001 Credentials In Files
- OWASP TASVS: TASVS-STORAGE Sensitive Data Storage
- OWASP Desktop Top 10: DA3 Sensitive Data Exposure
- Impact: Serious exposure: an attacker meeting a modest precondition can steal secrets, escalate, or bypass a security control.

- File: `2 files`
- Affected (2):
  - `C:\ProgramData\DVTA\DVTA.exe.config`
  - `C:\ProgramData\DVTA\DVTA.vshost.exe.config`
- Evidence: `2 affected: C:\ProgramData\DVTA\DVTA.exe.config; C:\ProgramData\DVTA\DVTA.vshost.exe.config`

Verify:
```
# WHAT THIS CHECKS: Scans the file's text for things that look like LIVE secrets - Azure storage keys, connection strings, PEM private keys, AWS access keys, or JWT tokens.
# STEP 1 - RUN THIS IN POWERSHELL:
([regex]::Matches([Text.Encoding]::Unicode.GetString([IO.File]::ReadAllBytes('2 files')),'DefaultEndpointsProtocol=https?;[A-Za-z0-9=;._/+\-]{0,300}AccountKey=[A-Za-z0-9+/=]{20,}|AccountKey=[A-Za-z0-9+/=]{20,}|-----BEGIN [A-Z ]+KEY|AKIA[A-Z0-9]{16}|eyJ[A-Za-z0-9_-]{10,}')).Value
# STEP 2 - READ THE OUTPUT:
#   VULNERABLE  if  it prints a real secret - e.g. AccountKey=..., a DefaultEndpointsProtocol=... connection string, an AKIA... AWS key, an eyJ... JWT, or a -----BEGIN ... KEY----- block.
#   OK          if  it prints nothing (only placeholders, or there are no secrets in the file).
# NOTE: this reads the file as UTF-16 (Unicode) text. If the secret is stored as plain ASCII, change ::Unicode to ::UTF8 and run it again. To dump EVERY readable string instead: strings.exe -u '2 files'
# TOOL: PowerShell built-in (alternative: Sysinternals strings.exe)
```

- Fix: Do not store credentials/API keys in appSettings. Use DPAPI, Windows Credential Manager, or a key vault and inject at runtime; rotate the exposed secret.

### MEDIUM (8)

#### 005. DBAccess.dll is not Authenticode-signed (+2 more affected)

- Rule: `authenticode.pe-not-signed`  |  Confidence: Confirmed
- CVSS v4.0: 2.0 `CVSS:4.0/AV:L/AC:H/AT:P/PR:L/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N`
- CWE: CWE-347, CWE-494
- ATT&CK: T1553.002 Code Signing
- OWASP TASVS: TASVS-CODE Code Quality & Build Settings
- OWASP Desktop Top 10: DA8 Poor Code Quality
- Impact: Meaningful weakness that aids an attack chain or leaks sensitive information under some conditions.

- File: `3 files`
- Affected (3):
  - `C:\ProgramData\DVTA\DBAccess.dll`
  - `C:\ProgramData\DVTA\DVTA.exe`
  - `C:\ProgramData\DVTA\ExcelLibrary.dll`
- Evidence: `3 affected: C:\ProgramData\DVTA\DBAccess.dll; C:\ProgramData\DVTA\DVTA.exe; C:\ProgramData\DVTA\ExcelLibrary.dll`

Verify:
```
# WHAT THIS CHECKS: Checks the file's Authenticode digital signature.
# STEP 1 - RUN THIS IN POWERSHELL:
Get-AuthenticodeSignature -FilePath '3 files' | Format-List Status,StatusMessage,SignerCertificate
# STEP 2 - READ THE OUTPUT:
#   VULNERABLE  if  Status is NotSigned, HashMismatch, or Unknown (the file is unsigned, tampered, or untrusted).
#   OK          if  Status is Valid.
# TOOL: PowerShell
```

- Fix: Sign every shipped EXE/DLL with the company code-signing certificate.

#### 006. DVTA.vshost.exe signing certificate uses a weak hash (sha1RSA) (+1 more affected)

- Rule: `authenticode.weak-cert-hash`  |  Confidence: Confirmed
- CVSS v4.0: 2.0 `CVSS:4.0/AV:L/AC:H/AT:P/PR:L/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N`
- CWE: CWE-327, CWE-347
- ATT&CK: T1553.002 Code Signing
- OWASP TASVS: TASVS-CODE Code Quality & Build Settings
- OWASP Desktop Top 10: DA8 Poor Code Quality
- Impact: Meaningful weakness that aids an attack chain or leaks sensitive information under some conditions.

The signing certificate chain uses SHA-1/MD5, which are collision-prone and deprecated for code signing.

- File: `2 files`
- Affected (2):
  - `C:\ProgramData\DVTA\DVTA.vshost.exe`
  - `C:\ProgramData\DVTA\EntityFramework.dll`
- Evidence: `2 affected: C:\ProgramData\DVTA\DVTA.vshost.exe; C:\ProgramData\DVTA\EntityFramework.dll`

Verify:
```
# WHAT THIS CHECKS: Checks the file's Authenticode digital signature.
# STEP 1 - RUN THIS IN POWERSHELL:
Get-AuthenticodeSignature -FilePath '2 files' | Format-List Status,StatusMessage,SignerCertificate
# STEP 2 - READ THE OUTPUT:
#   VULNERABLE  if  Status is NotSigned, HashMismatch, or Unknown (the file is unsigned, tampered, or untrusted).
#   OK          if  Status is Valid.
# TOOL: PowerShell
```

- Fix: Obtain a SHA-256 (or stronger) code-signing certificate and re-sign.

#### 007. Raw ADO.NET command construction (verify SQL is parameterized) in DBAccess.dll

- Rule: `callsites.sql-command-construction`  |  Confidence: Confirmed (IL)
- CWE: CWE-89
- ATT&CK: T1059 Command and Scripting Interpreter
- OWASP TASVS: TASVS-CODE Code Quality
- OWASP Desktop Top 10: DA1 Injections
- Impact: Meaningful weakness that aids an attack chain or leaks sensitive information under some conditions.

Presence of a raw command object is not itself a bug. Decompile the call site: if the CommandText is built by string concatenation/interpolation with external input, this is SQL injection. Parameterized queries are safe.

- File: `C:\ProgramData\DVTA\DBAccess.dll`
- Evidence: `SqlCommand`

Verify:
```
# WHAT THIS CHECKS: Finds the exact code locations TCPK flagged so you can read the real logic in a decompiler.
# STEP 1 - RUN THIS IN POWERSHELL:
Test-TcpkCallsites -Path 'C:\ProgramData\DVTA\DBAccess.dll'
# STEP 2 - READ THE OUTPUT:
#   VULNERABLE  if  the flagged method returns a constant 'true' for certificate validation, or it deserializes/parses untrusted input with no checks.
#   OK          if  it builds an X509Chain, compares a certificate thumbprint, or validates the input before using it.
# NOTE: open the flagged method in a .NET decompiler (ILSpy or dnSpy) to read the method body.
# TOOL: PowerShell + a .NET decompiler (ILSpy / dnSpy)
```

- Fix: Decompile the method (ILSpy / dnSpy) to confirm whether this is a real bug or a safe context.

#### 008. Debug symbols shipped (2 affected)

- Rule: `devartifact.debug-symbols`  |  Confidence: Confirmed
- CVSS v4.0: 2.0 `CVSS:4.0/AV:L/AC:H/AT:P/PR:L/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N`
- CWE: CWE-489, CWE-540
- OWASP Desktop Top 10: DA3 Sensitive Data Exposure
- Impact: Meaningful weakness that aids an attack chain or leaks sensitive information under some conditions.

Debug symbol files (.pdb/.map) are present. They expose source file paths, type/method names, and line numbers - a reverse-engineering aid - and indicate debug metadata was not stripped from the release.

- File: `2 files`
- Affected (2):
  - `DBAccess.pdb`
  - `DVTA.pdb`
- Evidence: `2 affected: DBAccess.pdb; DVTA.pdb`

Verify:
```
# WHAT THIS CHECKS: Re-validate this finding using its reported File and Evidence values.
# STEP 1 - DO THIS MANUALLY:
#   - Re-run the TCPK check for rule 'devartifact.debug-symbols'.
#   - Inspect the reported File and Evidence; use the Evidence value as a search term.
# STEP 2 - READ THE OUTPUT:
#   VULNERABLE  if  the Evidence value is real, reachable, and does what the finding describes.
#   OK          if  the Evidence is a false positive (a placeholder, dead code, or unreachable).
# TOOL: TCPK / PowerShell
```

- Fix: Exclude .pdb/.map from the shipped artifact (publish without symbols, or strip them).

#### 009. EntityFramework.dll has client-side license/auth gate(s): IsPro

- Rule: `authflags.client-side-gate`  |  Confidence: Inferred
- CVSS v4.0: 6.8 `CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:N/VC:N/VI:H/VA:N/SC:N/SI:N/SA:N`
- CWE: CWE-602, CWE-603
- ATT&CK: T1078 Valid Accounts; T1211 Exploitation for Defense Evasion
- OWASP TASVS: TASVS-AUTH Authentication & Session
- OWASP Desktop Top 10: DA2 Broken Authentication and Session Management
- Impact: Meaningful weakness that aids an attack chain or leaks sensitive information under some conditions.

These boolean gates appear to run on the client. Decompile to confirm the feature/license is enforced LOCALLY -- if so, it is bypassable by patching the binary, flipping the value in memory, or returning true from the check.

- File: `C:\ProgramData\DVTA\EntityFramework.dll`
- Evidence: `IsPro`

Verify:
```
# WHAT THIS CHECKS: Re-validate this finding using its reported File and Evidence values.
# STEP 1 - DO THIS MANUALLY:
#   - Re-run the TCPK check for rule 'authflags.client-side-gate'.
#   - Inspect the reported File and Evidence; use the Evidence value as a search term.
# STEP 2 - READ THE OUTPUT:
#   VULNERABLE  if  the Evidence value is real, reachable, and does what the finding describes.
#   OK          if  the Evidence is a false positive (a placeholder, dead code, or unreachable).
# TOOL: TCPK / PowerShell
```

- Fix: Move authorization / licensing decisions server-side; never trust a client-side boolean for access control.

#### 010. Cleartext ftp:// endpoint: 192.168.56.110

- Rule: `scheme.cleartext-ftp`  |  Confidence: Inferred
- CVSS v4.0: 6.3 `CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N`
- CWE: CWE-319
- OWASP TASVS: TASVS-NETWORK Network Communication
- OWASP Desktop Top 10: DA7 Insecure Communication
- Impact: Meaningful weakness that aids an attack chain or leaks sensitive information under some conditions.

Non-TLS FTP reference in first-party code. FTP transmits commands, file contents, and any credentials in cleartext -- trivially intercepted or MITM-able. Confirm whether it is a live transfer, and check for hardcoded FTP credentials nearby.

- File: `C:\ProgramData\DVTA\DVTA.exe`
- Evidence: `ftp://192.168.56.110`

Verify:
```
# WHAT THIS CHECKS: Confirms whether a backend host the app talks to is reachable, and how the connection is secured.
# STEP 1 - RUN THIS IN POWERSHELL:
Test-NetConnection <host> -Port 443
# STEP 2 - READ THE OUTPUT:
#   VULNERABLE  if  the host is contacted over http:// (credentials sent in cleartext) or it accepts a forged/invalid certificate.
#   OK          if  it uses https with a valid, properly-validated certificate.
# NOTE: to see the real traffic, capture it with Burp or Fiddler while using the app.
# TOOL: PowerShell + an intercepting proxy (Burp / Fiddler)
```

- Fix: Use FTPS (FTP over TLS) or SFTP (SSH-based). Never send data or credentials over plain FTP, and never embed credentials in the URL.

#### 011. Cleartext http:// endpoint (2 affected)

- Rule: `scheme.cleartext-http`  |  Confidence: Inferred
- CVSS v4.0: 6.3 `CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N`
- CWE: CWE-319
- OWASP TASVS: TASVS-NETWORK Network Communication
- OWASP Desktop Top 10: DA7 Insecure Communication
- Impact: Meaningful weakness that aids an attack chain or leaks sensitive information under some conditions.

Non-TLS http:// reference in first-party code. If this host is contacted at runtime, traffic (and any credentials/tokens) is exposed to network attackers and is trivially MITM-able. Confirm whether it is a live call or a documentation link.

- File: `2 files`
- Affected (2):
  - `msdn.com`
  - `code.google.com`
- Evidence: `2 affected: msdn.com; code.google.com`

Verify:
```
# WHAT THIS CHECKS: Confirms whether a backend host the app talks to is reachable, and how the connection is secured.
# STEP 1 - RUN THIS IN POWERSHELL:
Test-NetConnection <host> -Port 443
# STEP 2 - READ THE OUTPUT:
#   VULNERABLE  if  the host is contacted over http:// (credentials sent in cleartext) or it accepts a forged/invalid certificate.
#   OK          if  it uses https with a valid, properly-validated certificate.
# NOTE: to see the real traffic, capture it with Burp or Fiddler while using the app.
# TOOL: PowerShell + an intercepting proxy (Burp / Fiddler)
```

- Fix: Use https:// with certificate validation. If the host is HTTP-only, proxy it through an authenticated TLS endpoint.

#### 012. Hardcoded AES/CBC initialization vector in config (+1 more affected)

- Rule: `secrets.config-hardcoded-iv`  |  Confidence: Inferred
- CVSS v4.0: 6.9 `CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N`
- CWE: CWE-329, CWE-798
- ATT&CK: T1552.001 Credentials In Files
- OWASP TASVS: TASVS-STORAGE Sensitive Data Storage
- OWASP Desktop Top 10: DA3 Sensitive Data Exposure
- Impact: Meaningful weakness that aids an attack chain or leaks sensitive information under some conditions.

- File: `2 files`
- Affected (2):
  - `C:\ProgramData\DVTA\DVTA.exe.config`
  - `C:\ProgramData\DVTA\DVTA.vshost.exe.config`
- Evidence: `2 affected: C:\ProgramData\DVTA\DVTA.exe.config; C:\ProgramData\DVTA\DVTA.vshost.exe.config`

Verify:
```
# WHAT THIS CHECKS: Scans the file's text for things that look like LIVE secrets - Azure storage keys, connection strings, PEM private keys, AWS access keys, or JWT tokens.
# STEP 1 - RUN THIS IN POWERSHELL:
([regex]::Matches([Text.Encoding]::Unicode.GetString([IO.File]::ReadAllBytes('2 files')),'DefaultEndpointsProtocol=https?;[A-Za-z0-9=;._/+\-]{0,300}AccountKey=[A-Za-z0-9+/=]{20,}|AccountKey=[A-Za-z0-9+/=]{20,}|-----BEGIN [A-Z ]+KEY|AKIA[A-Z0-9]{16}|eyJ[A-Za-z0-9_-]{10,}')).Value
# STEP 2 - READ THE OUTPUT:
#   VULNERABLE  if  it prints a real secret - e.g. AccountKey=..., a DefaultEndpointsProtocol=... connection string, an AKIA... AWS key, an eyJ... JWT, or a -----BEGIN ... KEY----- block.
#   OK          if  it prints nothing (only placeholders, or there are no secrets in the file).
# NOTE: this reads the file as UTF-16 (Unicode) text. If the secret is stored as plain ASCII, change ::Unicode to ::UTF8 and run it again. To dump EVERY readable string instead: strings.exe -u '2 files'
# TOOL: PowerShell built-in (alternative: Sysinternals strings.exe)
```

- Fix: Do not hardcode the IV. Generate a fresh random IV per encryption and store or transmit it alongside the ciphertext.

### LOW (12)

#### 013. Outbound HTTP request API (verify the target URL is not attacker-controlled) in DVTA.exe

- Rule: `callsites.ssrf-request-build`  |  Confidence: Confirmed (IL)
- CWE: CWE-918
- ATT&CK: T1059 Command and Scripting Interpreter
- OWASP TASVS: TASVS-CODE Code Quality
- OWASP Desktop Top 10: DA1 Injections
- Impact: Minor hardening gap / information useful to an attacker; low standalone risk.

Triage: if the request URL or host is built from external input (config, IPC, file, a prior server response) without an allowlist, this is SSRF / open-redirect surface. Decompile the call site to confirm the URL is constant or validated. (Backend-side SSRF is tested dynamically against the API.)

- File: `C:\ProgramData\DVTA\DVTA.exe`
- Evidence: `WebClient`

Verify:
```
# WHAT THIS CHECKS: Finds the exact code locations TCPK flagged so you can read the real logic in a decompiler.
# STEP 1 - RUN THIS IN POWERSHELL:
Test-TcpkCallsites -Path 'C:\ProgramData\DVTA\DVTA.exe'
# STEP 2 - READ THE OUTPUT:
#   VULNERABLE  if  the flagged method returns a constant 'true' for certificate validation, or it deserializes/parses untrusted input with no checks.
#   OK          if  it builds an X509Chain, compares a certificate thumbprint, or validates the input before using it.
# NOTE: open the flagged method in a .NET decompiler (ILSpy or dnSpy) to read the method body.
# TOOL: PowerShell + a .NET decompiler (ILSpy / dnSpy)
```

- Fix: Decompile the method (ILSpy / dnSpy) to confirm whether this is a real bug or a safe context.

#### 014. XmlSerializer reference

- Rule: `deser.xmlserializer`  |  Confidence: Confirmed (IL)
- CVSS v4.0: 9.3 `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N`
- CWE: CWE-502
- OWASP TASVS: TASVS-CODE Code Quality
- OWASP Desktop Top 10: DA1 Injections
- Impact: Minor hardening gap / information useful to an attacker; low standalone risk.

- File: `C:\ProgramData\DVTA\ExcelLibrary.dll`

Verify:
```
# WHAT THIS CHECKS: Finds the exact code locations TCPK flagged so you can read the real logic in a decompiler.
# STEP 1 - RUN THIS IN POWERSHELL:
Test-TcpkCallsites -Path 'C:\ProgramData\DVTA\ExcelLibrary.dll'
# STEP 2 - READ THE OUTPUT:
#   VULNERABLE  if  the flagged method returns a constant 'true' for certificate validation, or it deserializes/parses untrusted input with no checks.
#   OK          if  it builds an X509Chain, compares a certificate thumbprint, or validates the input before using it.
# NOTE: open the flagged method in a .NET decompiler (ILSpy or dnSpy) to read the method body.
# TOOL: PowerShell + a .NET decompiler (ILSpy / dnSpy)
```

- Fix: Use TypeNameHandling.None / allowlisted KnownTypes / System.Text.Json polymorphism. Confirm runtimeconfig.json EnableUnsafeBinaryFormatterSerialization=false.

#### 015. 5 first-party .NET assemblies are NOT obfuscated (source recoverable)

- Rule: `obfuscation.absent`  |  Confidence: Confirmed
- CVSS v4.0: 2.0 `CVSS:4.0/AV:L/AC:H/AT:P/PR:L/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N`
- CWE: CWE-656, CWE-1294
- ATT&CK: T1027.002 Software Packing
- OWASP TASVS: TASVS-CODE Code Quality & Build Settings
- OWASP Desktop Top 10: DA8 Poor Code Quality
- Impact: Minor hardening gap / information useful to an attacker; low standalone risk.

These managed assemblies have no packer and no obfuscator, so a decompiler (ILSpy/dnSpy) recovers near-original source: business logic, license checks, hardcoded values, and any embedded secrets are fully readable.

- File: `C:\ProgramData\DVTA`
- Evidence: `DBAccess.dll, DVTA.exe, DVTA.vshost.exe, EntityFramework.dll, ExcelLibrary.dll`

Verify:
```
# WHAT THIS CHECKS: Re-validate this finding using its reported File and Evidence values.
# STEP 1 - DO THIS MANUALLY:
#   - Re-run the TCPK check for rule 'obfuscation.absent'.
#   - Inspect the reported File and Evidence; use the Evidence value as a search term.
# STEP 2 - READ THE OUTPUT:
#   VULNERABLE  if  the Evidence value is real, reachable, and does what the finding describes.
#   OK          if  the Evidence is a false positive (a placeholder, dead code, or unreachable).
# TOOL: TCPK / PowerShell
```

- Fix: If the logic/IP or any client-side check matters, apply an obfuscator AND move trust decisions server-side. Never rely on obfuscation to hide secrets.

#### 016. Pagefile is NOT cleared at shutdown

- Rule: `pagefile.no-clear-at-shutdown`  |  Confidence: Confirmed
- CVSS v4.0: 2.0 `CVSS:4.0/AV:L/AC:H/AT:P/PR:L/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N`
- CWE: CWE-316
- OWASP Desktop Top 10: DA3 Sensitive Data Exposure
- Impact: Minor hardening gap / information useful to an attacker; low standalone risk.

The pagefile may contain copies of in-memory data from running processes after a clean shutdown.

- File: `HKLM:\System\CurrentControlSet\Control\Session Manager\Memory Management`
- Evidence: `ClearPageFileAtShutdown=0`

Verify:
```
# WHAT THIS CHECKS: Checks crash-dump and pagefile settings that could leak secrets to disk.
# STEP 1 - RUN THIS IN POWERSHELL:
reg query "HKLM\\SOFTWARE\\Microsoft\\Windows\\Windows Error Reporting"
# STEP 2 - READ THE OUTPUT:
#   VULNERABLE  if  full crash dumps are enabled, or the pagefile is not cleared at shutdown (in-memory secrets can reach disk).
#   OK          if  crash dumps are minidump-only AND ClearPageFileAtShutdown = 1.
# TOOL: reg.exe / PowerShell
```

- Fix: Set ClearPageFileAtShutdown=1 in the registry (or via Local Security Policy: Shutdown: Clear virtual memory pagefile).

#### 017. DBAccess.dll has no strong-name public key token (+2 more affected)

- Rule: `strongname.unsigned`  |  Confidence: Confirmed
- CVSS v4.0: 2.0 `CVSS:4.0/AV:L/AC:H/AT:P/PR:L/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N`
- ATT&CK: T1553.002 Code Signing
- OWASP TASVS: TASVS-CODE Code Quality & Build Settings
- OWASP Desktop Top 10: DA8 Poor Code Quality
- Impact: Minor hardening gap / information useful to an attacker; low standalone risk.

Assembly identity is name+version only -- weakens reflection-based assembly resolution.

- File: `3 files`
- Affected (3):
  - `C:\ProgramData\DVTA\DBAccess.dll`
  - `C:\ProgramData\DVTA\DVTA.exe`
  - `C:\ProgramData\DVTA\ExcelLibrary.dll`
- Evidence: `3 affected: C:\ProgramData\DVTA\DBAccess.dll; C:\ProgramData\DVTA\DVTA.exe; C:\ProgramData\DVTA\ExcelLibrary.dll`

Verify:
```
# WHAT THIS CHECKS: Checks whether a .NET assembly is strong-named (which makes it harder to silently replace).
# STEP 1 - RUN THIS IN POWERSHELL:
[Reflection.AssemblyName]::GetAssemblyName('3 files').GetPublicKeyToken()
# STEP 2 - READ THE OUTPUT:
#   VULNERABLE  if  the output is EMPTY - the assembly is not strong-named and can be modified or swapped out.
#   OK          if  a public-key token (a row of bytes) is printed.
# TOOL: PowerShell
```

- Fix: Sign the assembly during build (csc.exe /keyfile, or <SignAssembly>true</SignAssembly> in csproj).

#### 018. Base64 encoding (verify it is not used in place of encryption) in EntityFramework.dll

- Rule: `callsites.base64-as-encryption`  |  Confidence: Inferred
- CWE: CWE-326
- ATT&CK: T1059 Command and Scripting Interpreter
- OWASP TASVS: TASVS-CODE Code Quality; TASVS-CRYPTO Cryptography
- Impact: Minor hardening gap / information useful to an attacker; low standalone risk.

Base64 is encoding, not encryption. If a credential / token / PII field is base64-encoded and then stored or transmitted as if protected, the data is effectively cleartext. Confirm sensitive values are encrypted (DPAPI / AES-GCM), not merely base64-encoded.

- File: `C:\ProgramData\DVTA\EntityFramework.dll`
- Evidence: `ToBase64String`

Verify:
```
# WHAT THIS CHECKS: Finds the exact code locations TCPK flagged so you can read the real logic in a decompiler.
# STEP 1 - RUN THIS IN POWERSHELL:
Test-TcpkCallsites -Path 'C:\ProgramData\DVTA\EntityFramework.dll'
# STEP 2 - READ THE OUTPUT:
#   VULNERABLE  if  the flagged method returns a constant 'true' for certificate validation, or it deserializes/parses untrusted input with no checks.
#   OK          if  it builds an X509Chain, compares a certificate thumbprint, or validates the input before using it.
# NOTE: open the flagged method in a .NET decompiler (ILSpy or dnSpy) to read the method body.
# TOOL: PowerShell + a .NET decompiler (ILSpy / dnSpy)
```

- Fix: Decompile the method (ILSpy / dnSpy) to confirm whether this is a real bug or a safe context.

#### 019. Environment-variable lookup (verify not used for DLL/exe/config paths) in DVTA.exe

- Rule: `callsites.env-var-path-use`  |  Confidence: Inferred
- CWE: CWE-426, CWE-15
- ATT&CK: T1059 Command and Scripting Interpreter
- OWASP TASVS: TASVS-CODE Code Quality
- Impact: Minor hardening gap / information useful to an attacker; low standalone risk.

If an environment variable a standard user controls is used to build a DLL/EXE/config path that the app then loads or executes, a user can redirect it (DLL planting / path hijack). Decompile to see what the value feeds.

- File: `C:\ProgramData\DVTA\DVTA.exe`
- Evidence: `GetEnvironmentVariable`

Verify:
```
# WHAT THIS CHECKS: Finds the exact code locations TCPK flagged so you can read the real logic in a decompiler.
# STEP 1 - RUN THIS IN POWERSHELL:
Test-TcpkCallsites -Path 'C:\ProgramData\DVTA\DVTA.exe'
# STEP 2 - READ THE OUTPUT:
#   VULNERABLE  if  the flagged method returns a constant 'true' for certificate validation, or it deserializes/parses untrusted input with no checks.
#   OK          if  it builds an X509Chain, compares a certificate thumbprint, or validates the input before using it.
# NOTE: open the flagged method in a .NET decompiler (ILSpy or dnSpy) to read the method body.
# TOOL: PowerShell + a .NET decompiler (ILSpy / dnSpy)
```

- Fix: Decompile the method (ILSpy / dnSpy) to confirm whether this is a real bug or a safe context.

#### 020. Insecure-temp-file pattern reference in EntityFramework.dll

- Rule: `callsites.insecure-temp`  |  Confidence: Inferred
- CVSS v4.0: 2.0 `CVSS:4.0/AV:L/AC:H/AT:P/PR:L/UI:N/VC:N/VI:L/VA:N/SC:N/SI:N/SA:N`
- CWE: CWE-377
- ATT&CK: T1059 Command and Scripting Interpreter
- OWASP TASVS: TASVS-CODE Code Quality
- Impact: Minor hardening gap / information useful to an attacker; low standalone risk.

- File: `C:\ProgramData\DVTA\EntityFramework.dll`
- Evidence: `GetTempFileName`

Verify:
```
# WHAT THIS CHECKS: Finds the exact code locations TCPK flagged so you can read the real logic in a decompiler.
# STEP 1 - RUN THIS IN POWERSHELL:
Test-TcpkCallsites -Path 'C:\ProgramData\DVTA\EntityFramework.dll'
# STEP 2 - READ THE OUTPUT:
#   VULNERABLE  if  the flagged method returns a constant 'true' for certificate validation, or it deserializes/parses untrusted input with no checks.
#   OK          if  it builds an X509Chain, compares a certificate thumbprint, or validates the input before using it.
# NOTE: open the flagged method in a .NET decompiler (ILSpy or dnSpy) to read the method body.
# TOOL: PowerShell + a .NET decompiler (ILSpy / dnSpy)
```

- Fix: Decompile the method (ILSpy / dnSpy) to confirm whether this is a real bug or a safe context.

#### 021. CSV/Excel export without formula-injection neutralization

- Rule: `csv.formula-injection-risk`  |  Confidence: Inferred
- CWE: CWE-1236
- ATT&CK: T1059 Command and Scripting Interpreter; T1048 Exfiltration Over Alternative Protocol
- OWASP TASVS: TASVS-CODE Code Quality
- OWASP Desktop Top 10: DA1 Injections
- Impact: If an exported field is user-influenced and starts with a formula character, opening the file lets an attacker exfiltrate data (=WEBSERVICE / =HYPERLINK) or, in older Excel with DDE enabled, run commands on the reviewer machine. Risk depends on whether the exported fields are attacker-controlled.

The app exports data to CSV/Excel but no formula-character neutralization was seen. If any exported field can be user-controlled and starts with = + - @ (or tab/CR), a spreadsheet will execute it as a formula (=WEBSERVICE / =HYPERLINK for data exfiltration; =cmd|... for command execution in older Excel). Confirm the export path: are the fields user-influenced, and are leading formula characters escaped?

- File: `DVTA.exe`
- Evidence: `export sink present (1 file(s)); no formula-neutralization marker found`

Verify:
```
# WHAT THIS CHECKS: Checks whether data the app exports to CSV/Excel could be interpreted as a spreadsheet FORMULA (CSV/formula injection).
# STEP 1 - DO THIS MANUALLY:
#   - In the app, put a value that STARTS WITH = into a field that later gets exported -- e.g. type   =1+1   (or   =HYPERLINK('http://attacker/x','click')  ) into a name/comment/description field.
#   - Use the app's normal Export-to-CSV / Export-to-Excel feature to export that data.
#   - Open the exported .csv / .xlsx in Microsoft Excel and look at the cell you controlled.
# STEP 2 - READ THE OUTPUT:
#   VULNERABLE  if  Excel shows '2' (the formula ran) or a clickable hyperlink -- the leading '=' was NOT escaped, so =WEBSERVICE(...)/=HYPERLINK(...) can exfiltrate data and (older Excel) =cmd|... can run commands.
#   OK          if  Excel shows the literal text   =1+1   (the cell was prefixed with a single quote or the formula characters were neutralized).
# NOTE: Also try leading   +   -   @   tab and carriage-return; all are treated as formula starters by spreadsheet apps.
# TOOL: the app + Microsoft Excel
```

- Fix: Prefix any cell that starts with = + - @ (tab, CR) with a single quote, or enable the library's injection sanitisation (e.g. CsvHelper SanitizeForInjection).

#### 022. No SecureString / ProtectedData markers in any first-party PE

- Rule: `mem.hygiene-absent`  |  Confidence: Inferred
- CVSS v4.0: 2.0 `CVSS:4.0/AV:L/AC:H/AT:P/PR:L/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N`
- CWE: CWE-316
- OWASP Desktop Top 10: DA3 Sensitive Data Exposure
- Impact: Minor hardening gap / information useful to an attacker; low standalone risk.

Triage hint -- if this app handles passwords / tokens at runtime, those values may live in plain managed strings (GC-tracked, may persist in memory).

Verify:
```
# WHAT THIS CHECKS: Checks crash-dump and pagefile settings that could leak secrets to disk.
# STEP 1 - RUN THIS IN POWERSHELL:
reg query "HKLM\\SOFTWARE\\Microsoft\\Windows\\Windows Error Reporting"
# STEP 2 - READ THE OUTPUT:
#   VULNERABLE  if  full crash dumps are enabled, or the pagefile is not cleared at shutdown (in-memory secrets can reach disk).
#   OK          if  crash dumps are minidump-only AND ClearPageFileAtShutdown = 1.
# TOOL: reg.exe / PowerShell
```

- Fix: For password and token handling, use SecureString and Marshal.SecureStringToGlobalAllocUnicode / ZeroFreeGlobalAllocUnicode, or wrap in ProtectedMemory blocks.

#### 023. DVTA.exe writes to the registry and references credential fields (verify not stored in cleartext)

- Rule: `storage.registry-credential`  |  Confidence: Inferred
- CWE: CWE-312, CWE-522
- Impact: Minor hardening gap / information useful to an attacker; low standalone risk.

First-party code both writes to the Windows registry (RegistryKey.SetValue / CreateSubKey) and references credential fields (password / token / secret). Thick clients frequently persist login credentials to HKCU in cleartext. Decompile the SetValue call sites: if a password / token is written without DPAPI (ProtectedData / CryptProtectData) it is recoverable by any process running as that user. Runtime confirmation: run the app, then Test-TcpkRegistryValues scans the live keys for the stored secret.

- File: `C:\ProgramData\DVTA\DVTA.exe`
- Evidence: `registry write (SetValue/CreateSubKey) + credential token 'password'`

Verify:
```
# WHAT THIS CHECKS: Re-validate this finding using its reported File and Evidence values.
# STEP 1 - DO THIS MANUALLY:
#   - Re-run the TCPK check for rule 'storage.registry-credential'.
#   - Inspect the reported File and Evidence; use the Evidence value as a search term.
# STEP 2 - READ THE OUTPUT:
#   VULNERABLE  if  the Evidence value is real, reachable, and does what the finding describes.
#   OK          if  the Evidence is a false positive (a placeholder, dead code, or unreachable).
# TOOL: TCPK / PowerShell
```

- Fix: Never persist raw credentials to the registry. Protect them with DPAPI (ProtectedData) scoped to the current user, or use the Windows Credential Manager; store only non-reversible tokens where possible.

#### 024. HTTP client used; no cert-pinning markers found

- Rule: `tls.pinning-absent`  |  Confidence: Inferred
- CVSS v4.0: 6.3 `CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N`
- CWE: CWE-295
- OWASP TASVS: TASVS-NETWORK Network Communication
- OWASP Desktop Top 10: DA7 Insecure Communication
- Impact: Minor hardening gap / information useful to an attacker; low standalone risk.

App trusts the system root store. Acceptable for most consumer apps; raise to HIGH for high-value targets where corporate-CA MITM is in-threat-model.

- File: `C:\ProgramData\DVTA\DVTA.exe`
- Evidence: `uses WebClient; no pinning keywords`

Verify:
```
# WHAT THIS CHECKS: Tests whether the app pins or validates its TLS server certificates.
# STEP 1 - RUN THIS IN POWERSHELL:
Test-TcpkTlsPinning -Path 'C:\ProgramData\DVTA'
# STEP 2 - READ THE OUTPUT:
#   VULNERABLE  if  the app's HTTPS calls SUCCEED when routed through your forged-certificate proxy (no pinning / no validation).
#   OK          if  those calls FAIL through the proxy (pinning or validation is working).
# NOTE: to test live, MITM the running app with mitmproxy or Burp using a self-signed CA.
# TOOL: PowerShell + mitmproxy / Burp
```

- Fix: For sensitive backends, pin the leaf or root cert thumbprint via ServerCertificateCustomValidationCallback (and confirm the callback actually pins, not just returns true).

### INFO (11)

#### 025. ALPC ports enumerated; none matched the target

- Rule: `alpc.enumerated-clean`  |  Confidence: Confirmed
- Impact: Informational - triage context, not a vulnerability on its own.

ALPC enumeration succeeded; no port name matched this application. Informational.
- Evidence: `0 ALPC port(s) in \RPC Control; none matched the identity terms.`

Verify:
```
# WHAT THIS CHECKS: Re-validate this finding using its reported File and Evidence values.
# STEP 1 - DO THIS MANUALLY:
#   - Re-run the TCPK check for rule 'alpc.enumerated-clean'.
#   - Inspect the reported File and Evidence; use the Evidence value as a search term.
# STEP 2 - READ THE OUTPUT:
#   VULNERABLE  if  the Evidence value is real, reachable, and does what the finding describes.
#   OK          if  the Evidence is a false positive (a placeholder, dead code, or unreachable).
# TOOL: TCPK / PowerShell
```

#### 026. Attack surface: 2 entry point(s) across 2 categories

- Rule: `attacksurface.summary`  |  Confidence: Confirmed
- Impact: Informational - triage context, not a vulnerability on its own.

Synthesized map of how the app can be reached (protocols, IPC, listeners, exports, web bridges). See attack-surface.json.

- File: `C:\ProgramData\DVTA`
- Evidence: `Auth / trust surface=1; Mailslots / ALPC / objects=1`

Verify:
```
# WHAT THIS CHECKS: A map of the entry points TCPK found - protocols, pipes, COM, RPC, ports, listeners.
# STEP 1 - DO THIS MANUALLY:
#   - Open attack-surface.json in the output folder.
#   - Triage each entry point for authentication and input validation.
# STEP 2 - WHAT IT MEANS:
#   Informational map, not a vulnerability by itself. Use it to decide what to test next.
# TOOL: TCPK
```

#### 027. DVTA.vshost.exe signing certificate expired, but signature is timestamped (still valid) (+1 more affected)

- Rule: `authenticode.signer-expired`  |  Confidence: Confirmed
- CWE: CWE-347
- ATT&CK: T1553.002 Code Signing
- OWASP TASVS: TASVS-CODE Code Quality & Build Settings
- OWASP Desktop Top 10: DA8 Poor Code Quality
- Impact: Informational - triage context, not a vulnerability on its own.

The signing certificate is past its validity period, but the signature carries a trusted RFC3161 timestamp dated within that period, so it still establishes valid provenance. Informational only.

- File: `2 files`
- Affected (2):
  - `C:\ProgramData\DVTA\DVTA.vshost.exe`
  - `C:\ProgramData\DVTA\EntityFramework.dll`
- Evidence: `2 affected: C:\ProgramData\DVTA\DVTA.vshost.exe; C:\ProgramData\DVTA\EntityFramework.dll`

Verify:
```
# WHAT THIS CHECKS: Checks the file's Authenticode digital signature.
# STEP 1 - RUN THIS IN POWERSHELL:
Get-AuthenticodeSignature -FilePath '2 files' | Format-List Status,StatusMessage,SignerCertificate
# STEP 2 - READ THE OUTPUT:
#   VULNERABLE  if  Status is NotSigned, HashMismatch, or Unknown (the file is unsigned, tampered, or untrusted).
#   OK          if  Status is Valid.
# TOOL: PowerShell
```

- Fix: No immediate action. Re-sign at the next release to keep the chain current.

#### 028. No AppxMetadata\CodeIntegrity.cat present

- Rule: `codeintegrity.no-cat`  |  Confidence: Confirmed
- ATT&CK: T1553.002 Code Signing
- OWASP TASVS: TASVS-CODE Code Quality & Build Settings
- OWASP Desktop Top 10: DA8 Poor Code Quality
- Impact: Informational - triage context, not a vulnerability on its own.

- File: `C:\ProgramData\DVTA`

Verify:
```
# WHAT THIS CHECKS: Checks the file's Authenticode digital signature.
# STEP 1 - RUN THIS IN POWERSHELL:
Get-AuthenticodeSignature -FilePath 'C:\ProgramData\DVTA' | Format-List Status,StatusMessage,SignerCertificate
# STEP 2 - READ THE OUTPUT:
#   VULNERABLE  if  Status is NotSigned, HashMismatch, or Unknown (the file is unsigned, tampered, or untrusted).
#   OK          if  Status is Valid.
# TOOL: PowerShell
```

#### 029. DBAccess.dll contains URLs/paths/IPs (urls=0, paths=0, ips=4) (+4 more affected)

- Rule: `strings.summary`  |  Confidence: Confirmed
- OWASP Desktop Top 10: DA3 Sensitive Data Exposure
- Impact: Informational - triage context, not a vulnerability on its own.

Triage aid. See Test-TcpkEndpoints for non-prod classification and Test-TcpkSecrets for token-shaped strings.

- File: `5 files`
- Affected (5):
  - `C:\ProgramData\DVTA\DBAccess.dll`
  - `C:\ProgramData\DVTA\DVTA.exe`
  - `C:\ProgramData\DVTA\DVTA.vshost.exe`
  - `C:\ProgramData\DVTA\EntityFramework.dll`
  - `C:\ProgramData\DVTA\ExcelLibrary.dll`
- Evidence: `5 affected: C:\ProgramData\DVTA\DBAccess.dll; C:\ProgramData\DVTA\DVTA.exe; C:\ProgramData\DVTA\DVTA.vshost.exe; C:\ProgramData\DVTA\EntityFramework.dll; C:\ProgramData\DVTA\ExcelLibrary.dll`

Verify:
```
# WHAT THIS CHECKS: Re-validate this finding using its reported File and Evidence values.
# STEP 1 - DO THIS MANUALLY:
#   - Re-run the TCPK check for rule 'strings.summary'.
#   - Inspect the reported File and Evidence; use the Evidence value as a search term.
# STEP 2 - READ THE OUTPUT:
#   VULNERABLE  if  the Evidence value is real, reachable, and does what the finding describes.
#   OK          if  the Evidence is a false positive (a placeholder, dead code, or unreachable).
# TOOL: TCPK / PowerShell
```

#### 030. DVTA.vshost.exe.manifest (.manifest) present

- Rule: `sxs.manifest`  |  Confidence: Confirmed
- ATT&CK: T1574 Hijack Execution Flow
- OWASP TASVS: TASVS-PLATFORM Platform Interaction
- OWASP Desktop Top 10: DA6 Security Misconfiguration
- Impact: Informational - triage context, not a vulnerability on its own.

Interacts with the DLL search order. Cross-reference against the DLL-hijack analysis (Test-TcpkPInvokeSurface + Test-TcpkPeImports).

- File: `C:\ProgramData\DVTA\DVTA.vshost.exe.manifest`

Verify:
```
# WHAT THIS CHECKS: Re-validate this finding using its reported File and Evidence values.
# STEP 1 - DO THIS MANUALLY:
#   - Re-run the TCPK check for rule 'sxs.manifest'.
#   - Inspect the reported File and Evidence; use the Evidence value as a search term.
# STEP 2 - READ THE OUTPUT:
#   VULNERABLE  if  the Evidence value is real, reachable, and does what the finding describes.
#   OK          if  the Evidence is a false positive (a placeholder, dead code, or unreachable).
# TOOL: TCPK / PowerShell
```

#### 031. Backend host (2 affected)

- Rule: `backend.endpoint`  |  Confidence: Inferred
- OWASP TASVS: TASVS-NETWORK Network Communication
- OWASP Desktop Top 10: DA7 Insecure Communication
- Impact: Informational - triage context, not a vulnerability on its own.

Triage aid. Use the auth-marker list as a starting point for understanding how the app authenticates to this host.

- File: `2 files`
- Affected (2):
  - `code.google.com (URLs=2)`
  - `msdn.com (URLs=1)`
- Evidence: `2 affected: code.google.com (URLs=2); msdn.com (URLs=1)`

Verify:
```
# WHAT THIS CHECKS: Confirms whether a backend host the app talks to is reachable, and how the connection is secured.
# STEP 1 - RUN THIS IN POWERSHELL:
Test-NetConnection <host> -Port 443
# STEP 2 - READ THE OUTPUT:
#   VULNERABLE  if  the host is contacted over http:// (credentials sent in cleartext) or it accepts a forged/invalid certificate.
#   OK          if  it uses https with a valid, properly-validated certificate.
# NOTE: to see the real traffic, capture it with Burp or Fiddler while using the app.
# TOOL: PowerShell + an intercepting proxy (Burp / Fiddler)
```

#### 032. Raw ADO.NET command construction (verify SQL is parameterized) in EntityFramework.dll

- Rule: `callsites.sql-command-construction`  |  Confidence: Likely-FP (IL)
- CWE: CWE-89
- ATT&CK: T1059 Command and Scripting Interpreter
- OWASP TASVS: TASVS-CODE Code Quality
- OWASP Desktop Top 10: DA1 Injections
- Impact: Informational - triage context, not a vulnerability on its own.

Presence of a raw command object is not itself a bug. Decompile the call site: if the CommandText is built by string concatenation/interpolation with external input, this is SQL injection. Parameterized queries are safe.

- File: `C:\ProgramData\DVTA\EntityFramework.dll`
- Evidence: `SqlCommand`

Verify:
```
# WHAT THIS CHECKS: Finds the exact code locations TCPK flagged so you can read the real logic in a decompiler.
# STEP 1 - RUN THIS IN POWERSHELL:
Test-TcpkCallsites -Path 'C:\ProgramData\DVTA\EntityFramework.dll'
# STEP 2 - READ THE OUTPUT:
#   VULNERABLE  if  the flagged method returns a constant 'true' for certificate validation, or it deserializes/parses untrusted input with no checks.
#   OK          if  it builds an X509Chain, compares a certificate thumbprint, or validates the input before using it.
# NOTE: open the flagged method in a .NET decompiler (ILSpy or dnSpy) to read the method body.
# TOOL: PowerShell + a .NET decompiler (ILSpy / dnSpy)
```

- Fix: Decompile the method (ILSpy / dnSpy) to confirm whether this is a real bug or a safe context.

#### 033. BinaryFormatter reference

- Rule: `deser.binaryformatter`  |  Confidence: Likely-FP (IL)
- CWE: CWE-502
- OWASP TASVS: TASVS-CODE Code Quality
- OWASP Desktop Top 10: DA1 Injections
- Impact: Informational - triage context, not a vulnerability on its own.

BinaryFormatter is unsafe and obsolete (CWE-502). Confirm runtimeconfig EnableUnsafeBinaryFormatterSerialization=false.

- File: `C:\ProgramData\DVTA\ExcelLibrary.dll`

Verify:
```
# WHAT THIS CHECKS: Finds the exact code locations TCPK flagged so you can read the real logic in a decompiler.
# STEP 1 - RUN THIS IN POWERSHELL:
Test-TcpkCallsites -Path 'C:\ProgramData\DVTA\ExcelLibrary.dll'
# STEP 2 - READ THE OUTPUT:
#   VULNERABLE  if  the flagged method returns a constant 'true' for certificate validation, or it deserializes/parses untrusted input with no checks.
#   OK          if  it builds an X509Chain, compares a certificate thumbprint, or validates the input before using it.
# NOTE: open the flagged method in a .NET decompiler (ILSpy or dnSpy) to read the method body.
# TOOL: PowerShell + a .NET decompiler (ILSpy / dnSpy)
```

- Fix: Use TypeNameHandling.None / allowlisted KnownTypes / System.Text.Json polymorphism. Confirm runtimeconfig.json EnableUnsafeBinaryFormatterSerialization=false.

#### 034. EntityFramework.dll references self-integrity-check primitives

- Rule: `integrity.self-check-markers`  |  Confidence: Inferred
- OWASP Desktop Top 10: DA8 Poor Code Quality
- Impact: Informational - triage context, not a vulnerability on its own.

Confirm in ILSpy that the hash/signature is actually compared and the path acts on the result.

- File: `EntityFramework.dll`
- Evidence: `ComputeHash`

Verify:
```
# WHAT THIS CHECKS: These are anti-tamper / hardening signals, not vulnerabilities by themselves.
# STEP 1 - DO THIS MANUALLY:
#   - Decompile the flagged routine in a .NET or native decompiler.
#   - Check whether the anti-debug / integrity check actually gates execution.
# STEP 2 - WHAT IT MEANS:
#   Informational. It is GOOD if the check genuinely stops execution when triggered; it is WEAK (but still not a vuln) if the check is present but never enforced.
# TOOL: a .NET / native decompiler
```

#### 035. Sensitive-input UI with no screen-capture protection

- Rule: `ui.no-screen-capture-protection`  |  Confidence: Inferred
- CWE: CWE-200
- Impact: Informational - triage context, not a vulnerability on its own.

The app collects secret input (password box / SecureString / masked field) but no window calls SetWindowDisplayAffinity(WDA_EXCLUDEFROMCAPTURE). Screenshots, screen recorders, and remote-desktop / screen-share tools can capture the sensitive screen.

- File: `DVTA.exe`
- Evidence: `password / secret-input markers present; SetWindowDisplayAffinity not referenced`

Verify:
```
# WHAT THIS CHECKS: Re-validate this finding using its reported File and Evidence values.
# STEP 1 - DO THIS MANUALLY:
#   - Re-run the TCPK check for rule 'ui.no-screen-capture-protection'.
#   - Inspect the reported File and Evidence; use the Evidence value as a search term.
# STEP 2 - READ THE OUTPUT:
#   VULNERABLE  if  the Evidence value is real, reachable, and does what the finding describes.
#   OK          if  the Evidence is a false positive (a placeholder, dead code, or unreachable).
# TOOL: TCPK / PowerShell
```

- Fix: Call SetWindowDisplayAffinity(hwnd, WDA_EXCLUDEFROMCAPTURE) on windows that display secrets so they render blank to screen capture.

---

DISCLAIMER -- FOR AUTHORIZED TESTING ONLY. This report was produced by TCPK for
authorized security testing. Provided AS IS, without warranty of any kind; any
misuse is solely the responsibility of the user.
