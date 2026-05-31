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

    # name -> why it's dangerous
    $unsafe = @{
        'strcpy'='unbounded copy'; 'strcat'='unbounded concat'; 'lstrcpy'='unbounded copy'; 'lstrcat'='unbounded concat'
        'wcscpy'='unbounded wide copy'; 'wcscat'='unbounded wide concat'; 'gets'='no bounds (banned)'
        'sprintf'='unbounded format'; 'vsprintf'='unbounded format'; 'swprintf'='unbounded wide format'
        'scanf'='format/overflow'; 'sscanf'='format/overflow'; 'strncpy'='no null-terminate'
        'memcpy'='unchecked length'; 'alloca'='stack exhaustion'; 'system'='shell exec'; '_wsystem'='shell exec'
        'WinExec'='process exec'; 'StrCpyA'='unbounded copy'
    }
    $rx = [regex]('\b(' + (($unsafe.Keys | ForEach-Object { [regex]::Escape($_) }) -join '|') + ')\b')

    foreach ($pe in Get-TcpkPeFiles -Path $Path) {
        $info = Read-TcpkPe -Path $pe.FullName
        if (-not $info) { continue }
        if (Test-TcpkIsFrameworkFile $pe.Name) { continue } # skip Microsoft.* / framework native
        if (Test-TcpkIsNativeNoise $pe.Name)   { continue } # skip well-known runtimes
        $text = Read-TcpkAllText -Path $pe.FullName
        if (-not $text) { continue }
        if ($text.Contains('BSJB')) { continue }            # skip managed .NET

        $found = @()
        foreach ($m in $rx.Matches($text)) { if ($m.Value -and $found -notcontains $m.Value) { $found += $m.Value } }
        # Strong triggers = SPECIFIC unbounded string/format functions (rare as plain
        # words). 'system'/'memcpy' are excluded as triggers -- too common to confirm
        # by name alone -- but still listed in evidence if present.
        $strong = @($found | Where-Object { $_ -in 'strcpy','strcat','sprintf','vsprintf','swprintf','gets','scanf','sscanf','lstrcpy','lstrcat','wcscpy','wcscat' })
        if ($strong.Count -eq 0) { continue }

        New-TcpkFinding -Module 'static' -RuleId 'native.unsafe-crt' `
            -Severity 'MEDIUM' -Confidence 'Inferred' `
            -Title "$($pe.Name) imports unsafe CRT functions: $(($strong | Select-Object -First 8) -join ', ')" `
            -File $pe.FullName -Evidence (($found | Select-Object -First 12) -join ', ') -Cwe @('CWE-120','CWE-134','CWE-787') `
            -Description 'Native binary references unbounded string / format / exec functions. Disassemble the call sites and confirm each has a bounded destination and a constant format string; attacker-controlled input here is a buffer-overflow or format-string vector.' `
            -Fix 'Replace with the bounded *_s variants (strcpy_s, sprintf_s), pass explicit sizes, and use constant format strings.'
    }
}
