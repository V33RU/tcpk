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
    # Allocation functions whose size argument may be the product of two integers.
    # If count * element_size overflows a 32-bit unsigned integer, the allocation is
    # smaller than expected and the subsequent fill overflows the heap buffer.
    # calloc() is the standard safe alternative (it does the overflow check internally).
    # reallocarray() is the POSIX equivalent for realloc. Neither is on Windows by default.
    $allocFns = @{
        'malloc'='size arg may be n*m with no overflow check; use calloc(n,size) instead'
        'GlobalAlloc'='size arg may be n*m with no overflow check'
        'LocalAlloc'='size arg may be n*m with no overflow check'
        'HeapAlloc'='size arg may be n*m with no overflow check'
        'VirtualAlloc'='size arg may be n*m with no overflow check'
        'CoTaskMemAlloc'='size arg may be n*m with no overflow check'
        'SysAllocStringLen'='size arg may be n*m with no overflow check'
        'realloc'='new size may be n*m with no overflow check; use reallocarray(p,n,size) instead'
    }
    $allocRx = [regex]('\b(' + (($allocFns.Keys | ForEach-Object { [regex]::Escape($_) }) -join '|') + ')\b')

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

        # Integer-overflow-before-allocation check.
        # Detect allocation functions imported alongside multiplication-capable arithmetic
        # without a safe alternative (calloc).  This is an import-level signal only;
        # disassembly is needed to confirm whether an unchecked multiply reaches the
        # size argument.  Report as Inferred LOW to direct the analyst to the call site.
        $allocFound = @()
        foreach ($m in $allocRx.Matches($text)) { if ($m.Value -and $allocFound -notcontains $m.Value) { $allocFound += $m.Value } }
        $hasMallocFamily = @($allocFound | Where-Object { $_ -in 'malloc','realloc','HeapAlloc','VirtualAlloc','GlobalAlloc','LocalAlloc','CoTaskMemAlloc','SysAllocStringLen' })
        $hasCalloc   = $text.Contains('calloc')        # safe alternative present?
        if ($hasMallocFamily.Count -gt 0 -and -not $hasCalloc) {
            New-TcpkFinding -Module 'static' -RuleId 'native.alloc-overflow-risk' `
                -Severity 'LOW' -Confidence 'Inferred' `
                -Title "$($pe.Name) uses allocation functions without calloc (integer-overflow-before-alloc risk)" `
                -File $pe.FullName `
                -Evidence "Allocation imports: $($hasMallocFamily -join ', '); calloc not found" `
                -Cwe @('CWE-190','CWE-122') `
                -Description ('The binary imports ' + ($hasMallocFamily -join ', ') + ' but does not import calloc. ' +
                    'If any call site passes the result of an integer multiplication (e.g. count * sizeof(T)) ' +
                    'as the size argument without an overflow check, a 32-bit wrap-around produces an ' +
                    'under-sized heap buffer and a subsequent fill overflows it. Disassemble the call ' +
                    'sites with IDA/Ghidra: if a MUL/IMUL result is passed directly to the size argument ' +
                    'without a preceding overflow check or without being constrained to a safe range, ' +
                    'this is a heap overflow primitive. calloc() performs the overflow check internally ' +
                    'and returns NULL on overflow, making it the safe default for array allocations.') `
                -Fix ('Replace malloc(count * sizeof(T)) with calloc(count, sizeof(T)). ' +
                    'For HeapAlloc/VirtualAlloc, add an explicit overflow check before the call: ' +
                    'if (count > SIZE_MAX / sizeof(T)) return ERROR_OVERFLOW; ' +
                    'DWORD bytes = count * sizeof(T); HeapAlloc(h, 0, bytes);')
        }
    }

    # ---- Source-level integer-overflow-before-allocation scan ----
    # If .c or .cpp source files are present in the scan path (dev environment or
    # app shipped with source), scan for the malloc(n * m) pattern without a
    # preceding overflow check on the same line or the line immediately above.
    $srcFiles = @(Get-ChildItem -Path $Path -Recurse -Include '*.c','*.cpp' -File `
                    -ErrorAction SilentlyContinue | Select-Object -First 200)
    if (-not $srcFiles.Count) { return }

    # Allocation with a multiplication as the size argument.
    # Matches: malloc(count * size)  malloc(n*sz)  HeapAlloc(h,0,n * m)  etc.
    $allocConcatRx = '(?i)\b(malloc|realloc|HeapAlloc|VirtualAlloc|GlobalAlloc|LocalAlloc|' +
                     'CoTaskMemAlloc|SysAllocStringLen)\s*\([^)]*\w+\s*\*\s*\w+[^)]*\)'
    # Safe: sizeof-only operands like malloc(sizeof(T)) are not overflow risks.
    $sizeofOnlyRx  = '(?i)\b(malloc|realloc|HeapAlloc|VirtualAlloc)\s*\(\s*sizeof\s*\('

    $seen = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

    foreach ($src in $srcFiles) {
        try { $lines = Get-Content $src.FullName -ErrorAction Stop } catch { continue }
        for ($i = 0; $i -lt $lines.Count; $i++) {
            $line = $lines[$i]
            if ($line -notmatch $allocConcatRx) { continue }
            if ($line -match $sizeofOnlyRx) { continue }   # malloc(sizeof(T)) alone is fine

            # Check whether the line or the immediately preceding line contains a
            # common overflow check pattern (> SIZE_MAX / n, > INT_MAX / n, FAILED(n*m), etc.)
            $prevLine = if ($i -gt 0) { $lines[$i-1] } else { '' }
            $hasCheck = ($line -match '(?i)(SIZE_MAX|INT_MAX|UINT_MAX|FAILED|overflow)') -or
                        ($prevLine -match '(?i)(SIZE_MAX|INT_MAX|UINT_MAX|FAILED|overflow|if\s*\(.*>\s*\w+\s*/)')

            if ($hasCheck) { continue }

            $loc = "$($src.FullName):$($i + 1)"
            if (-not $seen.Add($loc)) { continue }
            $snippet = $line.Trim(); if ($snippet.Length -gt 160) { $snippet = $snippet.Substring(0,160) + ' ...' }

            New-TcpkFinding -Module 'static' -RuleId 'native.alloc-overflow-source' `
                -Severity 'MEDIUM' -Confidence 'Confirmed' `
                -Title "Integer overflow before allocation: $($src.Name):$($i+1)" `
                -File $src.FullName `
                -Evidence "Line $($i+1): $snippet" `
                -Cwe @('CWE-190','CWE-122') `
                -Description ('An allocation function is called with a size argument that is the ' +
                    'product of two variables, and no overflow check was found on the preceding line. ' +
                    'If either variable is attacker-controlled (network input, file content, user field), ' +
                    'an attacker can supply values whose product wraps around a 32-bit integer, resulting ' +
                    'in an under-sized heap buffer. The subsequent fill (memcpy, strcpy, loop) then ' +
                    'overflows into adjacent heap memory, giving an attacker heap-layout control. ' +
                    'Confirm that at least one variable is attacker-influenced to promote to HIGH.') `
                -Fix ('Replace: malloc(count * sizeof(T))  with  calloc(count, sizeof(T)). ' +
                    'For custom sizes: check before multiplying: ' +
                    'if (count > SIZE_MAX / element_size) { return ENOMEM; } ' +
                    'size_t bytes = count * element_size; void* p = malloc(bytes);')
        }
    }
}
