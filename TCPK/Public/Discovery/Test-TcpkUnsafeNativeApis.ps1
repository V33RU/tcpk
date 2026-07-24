function Test-TcpkUnsafeNativeApis {
<#
.SYNOPSIS
    A25. Dangerous C/C++ runtime functions in native binaries (overflow surface).

.DESCRIPTION
    Native (unmanaged) PEs that import classic unbounded string/format functions
    (strcpy, strcat, sprintf, gets, scanf, ...) carry buffer-overflow / format-
    string risk. The imported function names live in the PE import name table as
    ASCII, so we detect them by name. Managed (.NET) assemblies are skipped --
    they do not call the CRT directly.

    Triage aid: presence is not proof of a bug, but each call site warrants a
    bounds/format review.

.PARAMETER Path
    File or directory.

.OUTPUTS
    [TcpkFinding]
#>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    # name -> why it's dangerous. The PE import name table stores the EXACT exported
    # name, so the Win32 string helpers appear as their A/W-suffixed forms (lstrcpyW,
    # StrCatA, ...) and the no-terminate printf family as _snprintf/_vsnprintf -- the
    # bare 'lstrcpy' macro never appears, so those forms must be listed explicitly.
    $unsafe = @{
        'strcpy'='unbounded copy'; 'strcat'='unbounded concat'
        'wcscpy'='unbounded wide copy'; 'wcscat'='unbounded wide concat'; 'gets'='no bounds (banned)'
        'sprintf'='unbounded format'; 'vsprintf'='unbounded format'; 'swprintf'='unbounded wide format'
        'scanf'='format/overflow'; 'sscanf'='format/overflow'; 'strncpy'='no null-terminate'
        'memcpy'='unchecked length'; 'alloca'='stack exhaustion'; 'system'='shell exec'; '_wsystem'='shell exec'
        'WinExec'='process exec'
        # SDL-banned no-null-terminate-on-truncation printf family
        '_snprintf'='no null-terminate on truncation (banned)'; '_vsnprintf'='no null-terminate on truncation (banned)'
        '_snwprintf'='no null-terminate, wide (banned)'; '_vsnwprintf'='no null-terminate, wide (banned)'
        # SDL-banned Win32 unbounded format/copy/concat helpers (A/W decorated forms)
        'wsprintfA'='unbounded format (banned)'; 'wsprintfW'='unbounded wide format (banned)'
        'wvsprintfA'='unbounded format (banned)'; 'wvsprintfW'='unbounded wide format (banned)'
        'lstrcpyA'='unbounded copy (banned)'; 'lstrcpyW'='unbounded wide copy (banned)'
        'lstrcatA'='unbounded concat (banned)'; 'lstrcatW'='unbounded wide concat (banned)'
        'StrCpyA'='unbounded copy'; 'StrCpyW'='unbounded wide copy'
        'StrCatA'='unbounded concat'; 'StrCatW'='unbounded wide concat'
        # off-by-one / no-terminate prone bounded variants (evidence only)
        'strncat'='off-by-one prone'; 'wcsncpy'='no null-terminate, wide'; 'wcsncat'='off-by-one prone, wide'
    }
    $rx = [regex]('\b(' + (($unsafe.Keys | ForEach-Object { [regex]::Escape($_) }) -join '|') + ')\b')

    foreach ($pe in Get-TcpkPeFiles -Path $Path) {
        $info = Read-TcpkPe -Path $pe.FullName
        if (-not $info) { continue }
        # Skip non-first-party binaries: framework, bundled native runtimes, the Electron main
        # exe (banned CRT imports like gets/sprintf come from Chromium, not the app) and the NSIS
        # uninstaller (lstrcpy/wsprintf are stock NSIS) -- attributing these to the app is an FP.
        if (-not (Test-TcpkIsFirstParty -Name $pe.Name -SizeBytes $pe.Length -Path $pe.FullName)) { continue }
        $text = Read-TcpkAllText -Path $pe.FullName
        if (-not $text) { continue }
        if ($text.Contains('BSJB')) { continue }            # skip managed .NET

        $found = @()
        foreach ($m in $rx.Matches($text)) { if ($m.Value -and $found -notcontains $m.Value) { $found += $m.Value } }
        # Strong triggers = SPECIFIC unbounded string/format functions (rare as plain
        # words). 'system'/'memcpy' are excluded as triggers -- too common to confirm
        # by name alone -- but still listed in evidence if present.
        $strong = @($found | Where-Object { $_ -in @(
            'strcpy','strcat','sprintf','vsprintf','swprintf','gets','scanf','sscanf','wcscpy','wcscat',
            '_snprintf','_vsnprintf','_snwprintf','_vsnwprintf',
            'wsprintfA','wsprintfW','wvsprintfA','wvsprintfW',
            'lstrcpyA','lstrcpyW','lstrcatA','lstrcatW','StrCpyA','StrCpyW','StrCatA','StrCatW','strncat'
        ) })
        if ($strong.Count -eq 0) { continue }

        New-TcpkFinding -Module 'static' -RuleId 'native.unsafe-crt' `
            -Severity 'MEDIUM' -Confidence 'Inferred' `
            -Title "$($pe.Name) imports unsafe CRT functions: $(($strong | Select-Object -First 8) -join ', ')" `
            -File $pe.FullName -Evidence (($found | Select-Object -First 12) -join ', ') -Cwe @('CWE-120','CWE-134','CWE-787') `
            -Description 'Native binary references unbounded string / format / exec functions. Disassemble the call sites and confirm each has a bounded destination and a constant format string; attacker-controlled input here is a buffer-overflow or format-string vector.' `
            -Fix 'Replace with the bounded *_s variants (strcpy_s, sprintf_s), pass explicit sizes, and use constant format strings.'
    }
}
