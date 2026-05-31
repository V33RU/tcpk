# TCPK methodology

How to use TCPK in an actual thick-client engagement.

## Scope and authorization

Before running TCPK against any target, confirm:

1. **You are authorized.** Acme employee, contracted pentester, bug-bounty
   participant under written scope, software your organization owns, or a CTF /
   lab target.
2. **Cloud testing is in or out of scope.** TCPK's static checks never touch
   external infrastructure. The opt-in `-EnableDeepRuntime` switch starts
   kernel ETW and `procdump` -- both are local-only. But if static analysis
   surfaces a hardcoded cloud credential, exercising that credential against
   the actual cloud service is a separate authorization question.

## The four-phase engagement

### Phase 1. Survey (10 minutes)

Get the basics on the target.

```powershell
Import-Module .\TCPK\TCPK.psd1 -Force

# Resolve the target's package metadata if MSIX
Get-AppxPackage *YourApp*

# Confirm it's running if you want runtime checks
Get-Process | Where-Object Path -like '*YourApp*'
```

Note the install path, the process name, and the package family name.

### Phase 2. Audit (5-15 minutes for static; +1-2 min for runtime)

```powershell
Invoke-TcpkAudit `
    -Target            'C:\Program Files\WindowsApps\Vendor.App_x_y_z' `
    -ProcessName       'YourApp' `
    -PackageName       'YourApp' `
    -PackageFamilyName 'YourApp_xxxxxxxxxxxx' `
    -OutDir            .\out\YourApp `
    -Acknowledge
```

The orchestrator runs all 83 checks across 10 buckets, dedupes / triages via the
Verify layer, and writes:

- `out\YourApp\index.html`    -- the human-readable report
- `out\YourApp\findings.json` -- for CI / re-processing
- `out\YourApp\findings.md`   -- for tickets

### Phase 3. Triage (30-60 minutes)

Open `index.html`. Severity rules:

| Sev      | What to do |
|----------|---|
| CRITICAL | Investigate same-day. Get a code-line confirmation via ILSpy and prepare a vendor disclosure draft. |
| HIGH     | Confirm with one ILSpy decompile. Write up. |
| MEDIUM   | Bulk-triage. Many are hardening hygiene; some hide real issues. |
| LOW/INFO | Read once; spot the patterns; ignore individuals. |

For each CRITICAL or HIGH that has `Confidence=Inferred` or `Unverified`:

```powershell
# Use the Verify layer to drive ILSpy
Invoke-TcpkDecompile `
    -Dll    'C:\Program Files\WindowsApps\Vendor.App_x_y_z\YourApp.dll' `
    -Search 'ServerCertificateCustomValidationCallback'
```

This returns the decompiled C# (if ilspycmd installed) or byte context (fallback).

### Phase 4. Disclosure

See [disclosure-guide.md](disclosure-guide.md).

## When TCPK is wrong

- **False positive on signatures.** MSIX uses catalog signing
  (`AppxMetadata\CodeIntegrity.cat`). Internal PEs return `UnknownError` from
  Authenticode -- TCPK auto-handles this case. If you see catalog-related
  false positives, file a bug.
- **False positive on TLS callback.** A custom callback might pin certs
  correctly. Always decompile before reporting.
- **False positive on `BinaryFormatter`.** A `BinaryFormatter` substring in
  `runtimeconfig.json` is the name of the EnableUnsafeBinaryFormatterSerialization
  switch, not a call site. The Verify layer auto-demotes this.

## Tuning

Edit `TCPK\Data\secrets.json` to add new regex rules, CVE entries, or
deserialization tokens without changing code. Restart the module after edits.

## Performance notes

- The first audit run is slowest (cold disk). Subsequent runs are 2-3x faster.
- `Test-TcpkSecrets` is the long pole (~60s on a 200 MB install).
- `Test-TcpkProtocolHandlers` against a wildcard NameLike scans all of HKCR
  and takes ~7 minutes. Always pass a specific NameLike when you can.
- `Test-TcpkDllSearchTrace` requires admin and takes the configured `-Seconds`
  (default 30) plus a few seconds of post-processing.
