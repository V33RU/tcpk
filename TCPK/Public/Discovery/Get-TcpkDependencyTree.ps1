function Get-TcpkDependencyTree {
<#
.SYNOPSIS
    Recursive DLL dependency analysis -- Dependency Walker equivalent.

.DESCRIPTION
    Builds the full DLL dependency tree for a PE file, resolving each import
    against the Windows DLL search order and annotating every node with its
    resolution status and hijack risk position.

    Resolution order used (matching Windows loader behavior):
      1. Application directory  (same directory as the root PE)
      2. System32               (%SystemRoot%\System32)
      3. SysWOW64               (%SystemRoot%\SysWOW64)  -- if root PE is 32-bit
      4. Windows directory      (%SystemRoot%)
      5. PATH directories       ($env:PATH split)

    Resolution status per DLL node:
      FOUND-APPDIR   -- resolved to application directory
      FOUND-SYSTEM32 -- resolved to System32 or SysWOW64
      FOUND-WINDOWS  -- resolved to Windows directory
      FOUND-PATH     -- resolved to a PATH directory
      MISSING        -- not found in any search location

    Each node also reports:
      IsDelayLoad    -- true if the DLL is delay-imported (wider hijack window)
      HijackRisk     -- NONE / MEDIUM / HIGH based on resolution position + writability
                        HIGH   : MISSING, or FOUND-APPDIR and AppDir is writable by current user
                        MEDIUM : FOUND-PATH
                        NONE   : FOUND-SYSTEM32 or FOUND-WINDOWS (protected locations)

    The tree is built recursively up to $MaxDepth levels. Circular imports are
    detected and not followed again (marked Circular = true).

    Use Get-TcpkPeInfo to get the full PE header detail; this cmdlet focuses on
    the dependency graph for hijack analysis.

.PARAMETER Path
    The root PE file to analyze.

.PARAMETER MaxDepth
    Maximum recursion depth. Default 3 (covers most installer/app dependency trees).
    Set to 1 for a flat import list.

.PARAMETER ShowAll
    Include all nodes in the output, not just those with HijackRisk HIGH or MEDIUM.
    Default is to show all nodes.

.EXAMPLE
    Get-TcpkDependencyTree -Path .\app.exe | Format-Table -AutoSize
    Get-TcpkDependencyTree -Path .\app.exe -MaxDepth 2 |
        Where-Object { $_.HijackRisk -ne 'NONE' } |
        Sort-Object HijackRisk, DllName | Format-Table -AutoSize

.OUTPUTS
    [pscustomobject]  -- one per unique DLL node in the tree.
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [int]$MaxDepth   = 3,
        [switch]$ShowAll
    )

    if (-not (Assert-TcpkWindows 'Get-TcpkDependencyTree')) { return }

    $rootFile = Get-Item -LiteralPath $Path -ErrorAction SilentlyContinue
    if (-not $rootFile -or $rootFile.PSIsContainer) {
        Write-Warning "Get-TcpkDependencyTree: '$Path' is not a file."
        return
    }

    $appDir   = $rootFile.DirectoryName
    $sys32    = [IO.Path]::Combine($env:SystemRoot, 'System32')
    $wow64    = [IO.Path]::Combine($env:SystemRoot, 'SysWOW64')
    $winDir   = $env:SystemRoot
    $pathDirs = ($env:PATH -split ';') | Where-Object { $_ -and (Test-Path $_) }

    # Application directory writability (affects HijackRisk classification)
    $appDirWritable = $false
    try {
        $testFile = [IO.Path]::Combine($appDir, "_tcpk_wrtest_$(Get-Random).tmp")
        [IO.File]::WriteAllBytes($testFile, [byte[]]@())
        [IO.File]::Delete($testFile)
        $appDirWritable = $true
    } catch {}

    # ---- Parse imports and delay-imports from a PE file using Read-TcpkPe ----
    # Read-TcpkPe returns an object with Imports and DelayImports arrays.
    # Each element has a DllName property.
    function _GetImports([string]$filePath) {
        try {
            $pe = Read-TcpkPe -Path $filePath
            if (-not $pe) { return @() }
            $result = [System.Collections.Generic.List[hashtable]]::new()
            foreach ($imp in $pe.Imports) {
                if ($imp.DllName) { $result.Add(@{ Name=$imp.DllName.Trim(); IsDelay=$false }) }
            }
            foreach ($imp in $pe.DelayImports) {
                if ($imp.DllName) { $result.Add(@{ Name=$imp.DllName.Trim(); IsDelay=$true }) }
            }
            return $result.ToArray()
        } catch { return @() }
    }

    # ---- Resolve a DLL name to a physical path using the search order ----
    function _ResolveDll([string]$dllName) {
        $candidates = @(
            @{ Status='FOUND-APPDIR';   Dir=$appDir }
            @{ Status='FOUND-SYSTEM32'; Dir=$sys32  }
            @{ Status='FOUND-SYSTEM32'; Dir=$wow64  }
            @{ Status='FOUND-WINDOWS';  Dir=$winDir }
        )
        foreach ($c in $candidates) {
            $full = [IO.Path]::Combine($c.Dir, $dllName)
            if ([IO.File]::Exists($full)) {
                return @{ Status=$c.Status; ResolvedPath=$full }
            }
        }
        foreach ($pd in $pathDirs) {
            $full = [IO.Path]::Combine($pd, $dllName)
            if ([IO.File]::Exists($full)) {
                return @{ Status='FOUND-PATH'; ResolvedPath=$full }
            }
        }
        return @{ Status='MISSING'; ResolvedPath='' }
    }

    # ---- Classify hijack risk ----
    function _HijackRisk([string]$status, [bool]$isDelay) {
        switch ($status) {
            'MISSING'      { return 'HIGH'   }
            'FOUND-APPDIR' { if ($appDirWritable) { return 'HIGH' } else { return 'MEDIUM' } }
            'FOUND-PATH'   { return 'MEDIUM' }
            default        { return 'NONE'   }
        }
    }

    # Known OS / redistributable DLLs to skip recursion into (they have no app-specific imports)
    $skipRecurse = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase
    )
    foreach ($n in @(
        'ntdll.dll','kernel32.dll','kernelbase.dll','advapi32.dll','user32.dll',
        'gdi32.dll','ole32.dll','oleaut32.dll','comctl32.dll','shell32.dll',
        'shlwapi.dll','ws2_32.dll','rpcrt4.dll','sechost.dll','msvcrt.dll',
        'msvcp_win.dll','vcruntime140.dll','vcruntime140_1.dll',
        'msvcp140.dll','msvcp140_1.dll','api-ms-win-core-*.dll',
        'ucrtbase.dll','ucrtbased.dll','mfc140.dll','mfc140u.dll',
        'wldp.dll','crypt32.dll','bcrypt.dll','bcryptprimitives.dll',
        'wintrust.dll','version.dll','winmm.dll','imm32.dll','uxtheme.dll',
        'ntdll.dll','clr.dll','clrjit.dll','mscorwks.dll','mscoree.dll',
        'coreclr.dll','hostpolicy.dll','hostfxr.dll'
    )) { $null = $skipRecurse.Add($n) }

    # ---- BFS traversal ----
    $visited  = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $results  = [System.Collections.Generic.List[pscustomobject]]::new()

    # Queue entries: @{ FilePath; DllName; ParentName; Depth; IsDelay }
    $queue = [System.Collections.Generic.Queue[hashtable]]::new()
    $queue.Enqueue(@{
        FilePath   = $rootFile.FullName
        DllName    = $rootFile.Name
        ParentName = ''
        Depth      = 0
        IsDelay    = $false
    })

    while ($queue.Count -gt 0) {
        $node = $queue.Dequeue()
        $imports = _GetImports $node.FilePath

        foreach ($imp in $imports) {
            $dllName = $imp.Name
            $isDelay = $imp.IsDelay

            $resolution = _ResolveDll $dllName
            $risk       = _HijackRisk $resolution.Status $isDelay

            $alreadySeen = $visited.Contains($dllName)
            $null = $visited.Add($dllName)

            $entry = [pscustomobject]@{
                DllName      = $dllName
                ParentDll    = $node.DllName
                Depth        = $node.Depth + 1
                Status       = $resolution.Status
                ResolvedPath = $resolution.ResolvedPath
                IsDelayLoad  = $isDelay
                HijackRisk   = $risk
                Circular     = $alreadySeen
            }
            $results.Add($entry)

            # Recurse if: not seen before, within depth limit, has a resolved path,
            # and not in the OS skip list.
            if (-not $alreadySeen -and
                ($node.Depth + 1) -lt $MaxDepth -and
                $resolution.ResolvedPath -and
                -not $skipRecurse.Contains($dllName)) {
                $queue.Enqueue(@{
                    FilePath   = $resolution.ResolvedPath
                    DllName    = $dllName
                    ParentName = $node.DllName
                    Depth      = $node.Depth + 1
                    IsDelay    = $isDelay
                })
            }
        }
    }

    $results.ToArray()
}
