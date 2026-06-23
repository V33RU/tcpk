function Test-TcpkAppStack {
<#
.SYNOPSIS
    A40. Application technology-stack fingerprint -- with an HONEST note on what
    TCPK's deep (managed-IL) analysis can and cannot reach for that stack.

.DESCRIPTION
    The recon profile (Get-TcpkTargetProfile) already fingerprints Electron, NW.js,
    Tauri, Flutter, Java, .NET vs native. This closes the remaining blind spots that
    otherwise make an audit silently shallow:

      * Python frozen (PyInstaller / cx_Freeze / py2exe)  -- logic is .pyc bytecode
      * Python compiled (Nuitka)                           -- compiled to native C
      * Go (statically-linked native)                      -- one fat binary, no DLLs
      * Rust (native, non-Tauri)
      * .NET MAUI / Avalonia / WinUI 3                      -- modern managed UI (IS analyzed)
      * Qt (C++)

    For each detected stack it emits an INFO finding stating the stack AND the
    coverage caveat -- e.g. "Python bytecode is NOT reached by the Mono.Cecil
    verifier; extract the .pyc and review". This makes the limits of a static audit
    explicit instead of leaving a Python/Go app looking 'clean' because nothing was
    actually decompiled. Detection is by shipped marker files plus first-party
    binary strings; INFO / Inferred (a fingerprint, not a vulnerability).

.PARAMETER Path
    File or directory.

.OUTPUTS
    [TcpkFinding]
#>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    $item = Get-Item -LiteralPath $Path -ErrorAction SilentlyContinue
    $dir  = if ($item -and $item.PSIsContainer) { $Path } elseif ($item) { Split-Path -Parent $item.FullName } else { $null }

    $names = @()
    if ($dir) {
        $names = @(Get-ChildItem -LiteralPath $dir -Recurse -File -ErrorAction SilentlyContinue |
                   ForEach-Object { $_.Name.ToLowerInvariant() })
    }
    function _has([string]$rx) { foreach ($n in $names) { if ($n -match $rx) { return $true } } return $false }

    $stacks = New-Object 'System.Collections.Generic.List[object]'

    # ---- file-marker stacks ----
    if ((_has '^python3?\d*\.dll$') -or ($names -contains 'python.exe') -or (_has '^base_library\.zip$') -or (_has '^library\.zip$')) {
        $stacks.Add([pscustomobject]@{ id='python-frozen'; name='Python (frozen: PyInstaller / cx_Freeze / py2exe)';
            note='Application logic is Python bytecode (.pyc), which TCPK''s managed-IL (Mono.Cecil) verifier does NOT reach. Extract with pyinstxtractor, decompile the .pyc (decompyle3 / uncompyle6), and review for hardcoded secrets, eval/exec, pickle.loads (deserialization), subprocess calls, and requests/urllib TLS verify=False.' })
    }
    if (_has '^qt[56]?core[d]?\.dll$') {
        $stacks.Add([pscustomobject]@{ id='qt'; name='Qt (C++ desktop framework)';
            note='Native Qt/C++ -- managed-IL analysis does not apply; review with a native disassembler (Ghidra / IDA / radare2). TCPK''s native unsafe-CRT and PE-hardening checks still apply.' })
    }
    if (_has '^microsoft\.maui') {
        $stacks.Add([pscustomobject]@{ id='dotnet-maui'; name='.NET MAUI';
            note='Cross-platform managed .NET UI -- the assemblies ARE analyzed by TCPK''s IL layer. Focus review on any embedded WebView (BlazorWebView / hybrid) and platform-handler bridges.' })
    }
    if (_has '^avalonia') {
        $stacks.Add([pscustomobject]@{ id='avalonia'; name='Avalonia UI (.NET)';
            note='Cross-platform managed .NET UI -- assemblies ARE analyzed by TCPK.' })
    }
    if ((_has '^microsoft\.winui\.dll$') -or (_has '^microsoft\.ui\.xaml')) {
        $stacks.Add([pscustomobject]@{ id='winui3'; name='WinUI 3 / Windows App SDK';
            note='Managed .NET UI -- assemblies ARE analyzed; review the WinRT / COM activation surface and any unpackaged full-trust capabilities.' })
    }

    # ---- string-marker stacks (first-party binaries) ----
    $go=$false; $rust=$false; $nuitka=$false; $pyi=$false
    # Bundled native third-party libraries are a common CVE source and are NOT reached by the
    # managed-IL analysis. Fingerprint the common ones by their embedded version string -- the
    # library NAME must be adjacent to the version, so this stays low-false-positive.
    $libRx = @(
        @{ id='openssl';  name='OpenSSL';  rx='OpenSSL\s+(\d+\.\d+\.\d+[a-z]?)' }
        @{ id='sqlite';   name='SQLite';   rx='SQLite\s+(?:version\s+)?(\d+\.\d+\.\d+)' }
        @{ id='zlib';     name='zlib';     rx='(?:in|de)flate\s+(\d+\.\d+\.\d+(?:\.\d+)?)\s+Copyright' }
        @{ id='libpng';   name='libpng';   rx='libpng\s+(?:version\s+)?(\d+\.\d+\.\d+)' }
        @{ id='libcurl';  name='libcurl';  rx='libcurl/(\d+\.\d+\.\d+)' }
        @{ id='freetype'; name='FreeType'; rx='FreeType\s+(\d+\.\d+\.\d+)' }
    )
    $nativeLibs = [ordered]@{}
    foreach ($pe in Get-TcpkPeFiles -Path $Path) {
        if (Test-TcpkIsFrameworkFile $pe.Name) { continue }
        $t = Read-TcpkAllText -Path $pe.FullName
        if (-not $t) { continue }
        if (-not $go     -and ($t.Contains('Go build ID:') -or ($t -match 'go1\.\d{1,2}\b'))) { $go = $true }
        if (-not $rust   -and ($t.Contains('/rustc/') -or $t.Contains('cargo/registry'))) { $rust = $true }
        if (-not $nuitka -and ($t.Contains('__nuitka') -or $t.Contains('Nuitka'))) { $nuitka = $true }
        if (-not $pyi    -and ($t.Contains('PyInstaller') -or $t.Contains('pyi-bootloader'))) { $pyi = $true }
        foreach ($lr in $libRx) {
            if (-not $nativeLibs.Contains($lr.id)) {
                $mm = [regex]::Match($t, $lr.rx, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
                if ($mm.Success) { $nativeLibs[$lr.id] = [pscustomobject]@{ Name=$lr.name; Ver=$mm.Groups[1].Value; File=$pe.Name } }
            }
        }
        if ($go -and $rust -and $nuitka -and $pyi -and $nativeLibs.Count -ge $libRx.Count) { break }
    }
    if ($go) {
        $stacks.Add([pscustomobject]@{ id='go-binary'; name='Go (statically-linked native binary)';
            note='A single statically-linked Go binary -- no managed IL and (usually) no separate DLLs, so TCPK''s deep static checks are blind. Pull strings, review with a Go-aware disassembler, and inspect embedded assets (go:embed) and net/http TLS config (InsecureSkipVerify).' })
    }
    if ($rust) {
        $stacks.Add([pscustomobject]@{ id='rust-native'; name='Rust (native binary)';
            note='Native Rust -- managed-IL analysis does not apply; review with a native disassembler. If this is a Tauri app, its WebView/IPC config is the primary surface (see Test-TcpkTauriConfig).' })
    }
    if ($nuitka) {
        $stacks.Add([pscustomobject]@{ id='python-nuitka'; name='Python (Nuitka-compiled to native)';
            note='Python compiled to a native binary via Nuitka -- source is not recoverable as .pyc; treat it as a native binary and review strings / imports / embedded data.' })
    }
    if ($pyi -and -not ($stacks | Where-Object { $_.id -eq 'python-frozen' })) {
        $stacks.Add([pscustomobject]@{ id='python-frozen'; name='Python (frozen: PyInstaller onefile)';
            note='A PyInstaller one-file build -- the .pyc archive is embedded in the .exe. Extract with pyinstxtractor, decompile the .pyc, and review for secrets, pickle.loads, eval/exec, and TLS verify=False.' })
    }

    foreach ($s in $stacks) {
        New-TcpkFinding -Module 'static' -RuleId "appstack.$($s.id)" `
            -Severity 'INFO' -Confidence 'Inferred' `
            -Title "Application stack: $($s.name)" -File $Path `
            -Evidence $s.name `
            -Description "Technology-stack fingerprint (so you know which TCPK checks actually apply). $($s.note)" `
            -Fix 'Informational. Use the noted tooling to cover the parts of this stack that TCPK''s managed-IL analysis does not reach.'
    }

    foreach ($k in $nativeLibs.Keys) {
        $nl = $nativeLibs[$k]
        New-TcpkFinding -Module 'static' -RuleId "appstack.native-$k" `
            -Severity 'INFO' -Confidence 'Inferred' `
            -Title "Bundled native library: $($nl.Name) $($nl.Ver)" -File $Path `
            -Evidence "$($nl.Name) $($nl.Ver) (in $($nl.File))" -Cwe @('CWE-1395') `
            -Description "A bundled native third-party library was fingerprinted by its embedded version string. Native C/C++ libraries are a common source of known CVEs and are NOT covered by the managed-IL analysis. Cross-check $($nl.Name) $($nl.Ver) against vendor advisories / OSV (run the audit with -OnlineCve, or Get-TcpkCveMatches) and keep bundled libraries patched." `
            -Fix "Track and patch bundled native libraries; verify $($nl.Name) $($nl.Ver) is not affected by known CVEs and update if so."
    }
}
