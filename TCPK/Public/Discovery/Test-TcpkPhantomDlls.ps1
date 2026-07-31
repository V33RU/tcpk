function Test-TcpkPhantomDlls {
<#
.SYNOPSIS
    Detect phantom DLL planting opportunities in PE import tables.

.DESCRIPTION
    Scans each first-party PE's import table for DLLs that do NOT exist
    anywhere in the application directory tree.  A missing imported DLL is
    a prime target for DLL planting: an attacker drops a malicious DLL with
    the expected name into the app directory (or a writable directory on
    the DLL search path) and the OS loader will happily load it the next
    time the application starts.

    Unlike DLL search-order tracing (Test-TcpkDllSearchTrace), this is a
    STATIC check -- it reads the PE import table and cross-references the
    filesystem without running the application, so it works on extracted
    packages and offline targets.

    BOTH import kinds are scanned:
      * dllsearch.phantom-dll       -- normal import table (data directory 1).
                                       Resolved once, at process load.
      * dllsearch.delayload-phantom -- delay-import table (data directory 13).
                                       Resolved at the FIRST CALL into the DLL,
                                       against the process state at that moment.
                                       Wider hijack window: the working directory
                                       may have changed, and resolution happens
                                       after any start-up integrity check.
    A name present in both tables is reported once, as the load-time case.

    Known system DLLs (kernel32, ntdll, user32, etc.) are excluded because
    they always resolve from System32; only application-scope DLLs that the
    developer intended to ship (but forgot, or that are optional) are flagged.

    CALIBRATION. A static "not present in the app tree" test alone over-reports,
    because a name absent from the app tree may still resolve before the loader
    ever consults the application directory. Three OS facts are applied to
    suppress those false positives and to rank what remains:

      * KnownDLLs      -- names mapped from the KnownDlls section are resolved
                          before the application directory is searched, so they
                          cannot be planted. Suppressed outright.
      * System32       -- a name that resolves in System32/SysWOW64 on the live
                          box is a Windows system DLL missing from the static
                          allowlist above, not a phantom import. Suppressed.
      * Root writable  -- a plant is only possible if some principal can write
                          the directory the DLL would load from. HIGH when the
                          install root is user-writable, MEDIUM when it is not
                          (still reportable: a writable directory elsewhere on
                          the search path, or a relative-path launch, revives it).

    The first two need a live Windows host. Off Windows (offline analysis of an
    extracted package) neither is knowable, so both are skipped and severity
    falls back to MEDIUM. Use -Verbose to see the suppression counts.

.PARAMETER Path
    File or directory to scan.

.OUTPUTS
    [TcpkFinding]
#>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    $knownSystemDlls = @(
        'advapi32.dll','bcrypt.dll','cfgmgr32.dll','crypt32.dll','comctl32.dll',
        'comdlg32.dll','dbghelp.dll','dwmapi.dll','gdi32.dll','gdiplus.dll',
        'imm32.dll','iphlpapi.dll','kernel32.dll','kernelbase.dll','mpr.dll',
        'mscoree.dll','msi.dll','msvcrt.dll','ncrypt.dll','netapi32.dll',
        'normaliz.dll','ntdll.dll','ole32.dll','oleaut32.dll','powrprof.dll',
        'psapi.dll','rpcrt4.dll','secur32.dll','setupapi.dll','shell32.dll',
        'shlwapi.dll','sspicli.dll','user32.dll','userenv.dll','uxtheme.dll',
        'version.dll','winhttp.dll','wininet.dll','winmm.dll','winspool.drv',
        'ws2_32.dll','wsock32.dll','wtsapi32.dll','dnsapi.dll','mswsock.dll',
        'pdh.dll','wintrust.dll','cabinet.dll','cryptui.dll','dxgi.dll',
        'd2d1.dll','d3d11.dll','d3d12.dll','dwrite.dll','shcore.dll',
        'authz.dll','wevtapi.dll','propsys.dll','profapi.dll','ucrtbase.dll',
        'vcruntime140.dll','vcruntime140_1.dll','msvcp140.dll',
        'vcruntime140d.dll','ucrtbased.dll','msvcp140d.dll',
        'api-ms-win-crt-runtime-l1-1-0.dll',
        'api-ms-win-crt-heap-l1-1-0.dll',
        'api-ms-win-crt-math-l1-1-0.dll',
        'api-ms-win-crt-stdio-l1-1-0.dll',
        'api-ms-win-crt-string-l1-1-0.dll',
        'api-ms-win-crt-locale-l1-1-0.dll',
        'api-ms-win-crt-convert-l1-1-0.dll',
        'api-ms-win-crt-environment-l1-1-0.dll',
        'api-ms-win-crt-filesystem-l1-1-0.dll',
        'api-ms-win-crt-time-l1-1-0.dll',
        'api-ms-win-crt-utility-l1-1-0.dll',
        'api-ms-win-crt-multibyte-l1-1-0.dll',
        'api-ms-win-crt-process-l1-1-0.dll',
        'api-ms-win-crt-private-l1-1-0.dll',
        'api-ms-win-core-synch-l1-2-0.dll'
    )
    $sysSet = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase)
    foreach ($s in $knownSystemDlls) { [void]$sysSet.Add($s) }

    $item = Get-Item -LiteralPath $Path -ErrorAction SilentlyContinue
    if (-not $item) { return }
    $root = if ($item.PSIsContainer) { $item.FullName } else { $item.DirectoryName }

    $appFiles = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase)
    Get-ChildItem -LiteralPath $root -Recurse -File -ErrorAction SilentlyContinue |
        ForEach-Object { [void]$appFiles.Add($_.Name) }

    # --- live-OS calibration (see CALIBRATION in the help above) ---------------
    $onWindows = ($env:OS -eq 'Windows_NT')

    # KnownDLLs: value data is the DLL file name (advapi32 -> advapi32.dll). The
    # DllDirectory/DllDirectory32 values are paths, not names, so skip them.
    $knownDllSet = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase)
    if ($onWindows) {
        try {
            $kd = Get-Item -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs' -ErrorAction Stop
            foreach ($n in $kd.GetValueNames()) {
                if ($n -match '^DllDirectory') { continue }
                $v = "$($kd.GetValue($n))".Trim()
                if ($v) { [void]$knownDllSet.Add($v) }
            }
        } catch {
            Write-Verbose "Test-TcpkPhantomDlls: KnownDLLs unreadable ($($_.Exception.Message)); skipping that suppression."
        }
    }

    # Probe both system directories rather than picking one by PE bitness: the
    # goal here is "is this a Windows system DLL name", and presence in either
    # answers that. Results are cached because an app can import the same name
    # from many binaries.
    $sysDirs = @()
    if ($onWindows -and $env:SystemRoot) {
        foreach ($d in @('System32', 'SysWOW64')) {
            $p = Join-Path $env:SystemRoot $d
            if (Test-Path -LiteralPath $p -PathType Container) { $sysDirs += $p }
        }
    }
    $sysProbe = @{}

    # A plant needs a writable target directory. Same principal/rights model as
    # Test-TcpkDllSideload so the two detectors rank consistently.
    $userPrincipals = '(?i)\b(Everyone|Authenticated Users|Users|INTERACTIVE|BUILTIN\\Users)\b'
    $writeRights    = 'Write|Modify|FullControl'
    $dirWritable    = $false
    if ($onWindows) {
        try {
            $acl = Get-Acl -LiteralPath $root -ErrorAction Stop
            $bad = $acl.Access | Where-Object {
                $_.IdentityReference.Value -match $userPrincipals -and
                $_.FileSystemRights -match $writeRights -and
                $_.AccessControlType -eq 'Allow'
            }
            $dirWritable = ($null -ne $bad -and @($bad).Count -gt 0)
        } catch {}
    }

    $supKnown = 0
    $supSystem = 0

    $seen = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase)

    foreach ($pe in Get-TcpkPeFiles -Path $Path) {
        if (Test-TcpkIsFrameworkFile $pe.Name) { continue }
        $info = Read-TcpkPe -Path $pe.FullName
        if (-not $info) { continue }

        # Normal imports first, then delay-load imports. Both are hijack candidates,
        # but a delay-load resolves at FIRST CALL from the process search path rather
        # than at load time, so it gets its own RuleId and its own wording. Order
        # matters: a name that is both a normal and a delay import is reported once,
        # as the normal (load-time) case.
        $candidates = New-Object 'System.Collections.Generic.List[object]'
        foreach ($imp in @($info.Imports))      { $candidates.Add([pscustomobject]@{ Name = "$imp"; Delay = $false }) }
        foreach ($imp in @($info.DelayImports)) { $candidates.Add([pscustomobject]@{ Name = "$imp"; Delay = $true  }) }

        foreach ($cand in $candidates) {
            $imp = $cand.Name
            if ([string]::IsNullOrWhiteSpace($imp)) { continue }
            $dll = $imp.Trim()
            if ($sysSet.Contains($dll)) { continue }
            if ($dll -match '^api-ms-win-|^ext-ms-') { continue }
            if ($appFiles.Contains($dll)) { continue }

            # Mapped from the KnownDlls section before the application directory
            # is ever searched, so this name cannot be planted.
            if ($knownDllSet.Contains($dll)) { $supKnown++; continue }

            $key = "$($pe.Name)|$dll"
            if (-not $seen.Add($key)) { continue }

            # Resolves in a live system directory -> a Windows system DLL that is
            # simply absent from $knownSystemDlls. Not a phantom import.
            if ($sysDirs.Count) {
                if (-not $sysProbe.ContainsKey($dll)) {
                    $found = $false
                    foreach ($d in $sysDirs) {
                        if (Test-Path -LiteralPath (Join-Path $d $dll) -PathType Leaf) { $found = $true; break }
                    }
                    $sysProbe[$dll] = $found
                }
                if ($sysProbe[$dll]) { $supSystem++; continue }
            }

            # Evidence must not assert a check that did not run: off Windows the
            # system probe and the ACL read are both skipped, and saying "false"
            # there would read as a negative result rather than an unknown.
            $sysNote = if ($sysDirs.Count) { 'system-resolved=false' } else { 'system-probe=skipped' }
            $aclNote = if ($onWindows) { "root writable=$dirWritable" } else { 'root writable=not-evaluated' }

            $sev = if ($dirWritable) { 'HIGH' } else { 'MEDIUM' }
            $writeNote = if ($dirWritable) {
                'The install root is user-writable, so the plant is directly achievable by a standard user.'
            } elseif ($onWindows) {
                'The install root is NOT user-writable, so a standard user cannot plant here directly. It remains reportable: any writable directory earlier on the DLL search path, or launching the binary from an attacker-controlled directory, still resolves the import to attacker content.'
            } else {
                'Install-root writability was not evaluated (calibration needs a live Windows host), so severity is held at MEDIUM.'
            }

            if ($cand.Delay) {
                $ruleId  = 'dllsearch.delayload-phantom'
                $kindTxt = 'delay-load imports'
                $kindDsc = ('This PE DELAY-loads a DLL that does not exist anywhere in the ' +
                    'application directory tree, is not a known Windows system DLL, is not ' +
                    'a KnownDLL, and does not resolve in System32/SysWOW64. A delay-load is ' +
                    'resolved at the FIRST CALL into the DLL, not at process start, so the ' +
                    'search runs against the process state at that moment. That is a wider ' +
                    'hijack window than a normal import: the working directory may have ' +
                    'changed, and the resolution happens long after any start-up integrity ' +
                    'check has completed. ')
                $fixTxt  = 'Ship the DLL with the application. Where the delay-load is intentional, pin resolution with a delay-load helper hook that loads by full path, or call SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32) at start-up so the late resolution cannot reach a writable directory.'
            } else {
                $ruleId  = 'dllsearch.phantom-dll'
                $kindTxt = 'imports'
                $kindDsc = ('This PE imports a DLL that does not exist anywhere in the ' +
                    'application directory tree, is not a known Windows system DLL, is not ' +
                    'a KnownDLL, and does not resolve in System32/SysWOW64. ')
                $fixTxt  = 'Ship the DLL with the application, use a full path in LoadLibrary, or call SetDefaultDllDirectories/AddDllDirectory to restrict the search path.'
            }

            New-TcpkFinding -Module 'static' -RuleId $ruleId `
                -Severity $sev -Confidence 'Confirmed' `
                -Title "Phantom DLL plantable: $dll ($kindTxt, in $($pe.Name))" `
                -File $pe.FullName `
                -Evidence "$kindTxt $dll; not found in $root; $aclNote; $sysNote" `
                -Cwe @('CWE-427','CWE-426') `
                -Description ($kindDsc +
                    'An attacker who can write to a directory the loader searches for this ' +
                    'name can plant a malicious DLL and execute code under the application ' +
                    'identity. ' + $writeNote) `
                -Fix $fixTxt
        }
    }

    if ($supKnown -or $supSystem) {
        Write-Verbose ("Test-TcpkPhantomDlls: calibration suppressed $supKnown KnownDLL import(s) " +
            "and $supSystem import(s) that resolve in System32/SysWOW64.")
    }
}
