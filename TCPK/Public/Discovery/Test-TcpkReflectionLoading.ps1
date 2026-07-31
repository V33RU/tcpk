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
    always MEDIUM: this is a reference-level scan that proves the API is
    mentioned, not that the load path is attacker-controlled. It does not
    resolve the argument passed to the load call, so it cannot escalate on its
    own. Pair it with a writable-directory finding (acl.user-writable,
    install-dir.user-writable) to establish a working hijack chain.

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
