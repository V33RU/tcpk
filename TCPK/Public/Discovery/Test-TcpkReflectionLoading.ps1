function Test-TcpkReflectionLoading {
<#
.SYNOPSIS
    A16. Dynamic code loading via reflection.

.DESCRIPTION
    Scans first-party PEs for references to:
      - Assembly.LoadFrom / LoadFile / Load
      - AppDomain.Load
      - Activator.CreateInstanceFrom
      - AssemblyLoadContext
      - AssemblyResolve / add_AssemblyResolve event handlers

    Any of these is a hijack-via-managed-resolution candidate. Severity is
    MEDIUM by default -- low until combined with a writable plugin/extension
    directory, at which point it escalates to HIGH.

.PARAMETER Path
    File or directory.

.OUTPUTS
    [TcpkFinding]
#>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    $needles = @(
        'Assembly.LoadFrom','Assembly.LoadFile','Assembly.Load',
        'AppDomain.CurrentDomain.Load','Activator.CreateInstanceFrom',
        'AssemblyLoadContext','add_AssemblyResolve','ResolveEventHandler'
    )

    foreach ($pe in Get-TcpkPeFiles -Path $Path) {
        if (Test-TcpkIsFrameworkFile $pe.Name) { continue }
        $text = Read-TcpkAllText -Path $pe.FullName
        if (-not $text) { continue }

        $hits = @()
        foreach ($n in $needles) {
            $c = ([regex]::Matches($text, [regex]::Escape($n))).Count
            if ($c -gt 0) { $hits += "$n(x$c)" }
        }
        if ($hits.Count -eq 0) { continue }

        New-TcpkFinding -Module 'static' -RuleId 'reflection.dynamic-load' `
            -Severity 'MEDIUM' -Confidence 'Inferred' `
            -Title "$($pe.Name) references dynamic-load APIs" `
            -File $pe.FullName -Evidence ($hits -join ', ') `
            -Cwe @('CWE-470','CWE-427') `
            -Description 'Verify the source path/URL of the loaded assembly. If it can resolve to a user-writable location, this is a working hijack chain.' `
            -Fix 'Pin assembly identity via AssemblyName + public-key token; load only from package-relative paths.'
    }
}
