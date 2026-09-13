function Test-TcpkPInvokeImportMap {
<#
.SYNOPSIS
    A69. The assembly's real P/Invoke surface, read from the ImplMap metadata table.

.DESCRIPTION
    WHY THIS EXISTS. A managed assembly's native imports do NOT appear in the PE
    import table: the CLR resolves a DllImport lazily at first call, so the IAT is
    empty of them. Test-TcpkUnsafeNativeApis reads the PE import table and
    deliberately skips managed files for exactly this reason, which leaves the
    managed route to the same native functions uncovered. The authoritative record
    is the ImplMap table (what [DllImport] compiles into), and Cecil exposes it as
    MethodDefinition.PInvokeInfo.

    This reads every P/Invoke declaration in the assembly and reports three things.

      interop.pinvoke-surface            INFO    Inventory: which native modules the
                                                 assembly imports and how many entry
                                                 points from each. Scope information
                                                 for the reader, and the input for
                                                 marshalling review.

      interop.pinvoke-unsafe-native      LOW     Declarations that bind memory-unsafe
                                         MEDIUM  CRT string functions, or the Win32
                                                 APIs that perform cross-process
                                                 memory write and remote execution.
                                                 Escalates to MEDIUM when the full
                                                 remote-injection triad is declared
                                                 (allocate + write + execute), because
                                                 that combination has no purpose other
                                                 than running code in another process.

      interop.pinvoke-unqualified-module MEDIUM  A DllImport that names a module by
                                                 bare filename which is NOT a Windows
                                                 system DLL. The CLR resolves it
                                                 through the DLL search order, so a
                                                 planted file earlier in that order is
                                                 loaded instead. Pair with a writable
                                                 directory finding (acl.user-writable /
                                                 install-dir.user-writable) to close a
                                                 hijack chain.

    Declaring an API is not the same as reaching it with attacker input. These are
    surface observations at Confirmed (IL): the declaration is in the shipping
    metadata and re-reads identically. Escalation requires tracing the arguments.

.PARAMETER Path
    File or directory.

.OUTPUTS
    [TcpkFinding]
#>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path)) { return }

    # Windows system modules resolve from System32 under KnownDLLs / safe search
    # order and are not plantable by a non-admin, so a bare name here is normal.
    # Stored without the .dll suffix, lower case.
    $systemModules = @(
        'kernel32','kernelbase','user32','gdi32','gdiplus','advapi32','shell32','shlwapi',
        'ole32','oleaut32','comctl32','comdlg32','ntdll','psapi','version','ws2_32','wininet',
        'winhttp','crypt32','bcrypt','ncrypt','secur32','sspicli','wtsapi32','userenv','netapi32',
        'iphlpapi','dnsapi','mpr','setupapi','cfgmgr32','dwmapi','uxtheme','msimg32','winmm',
        'winspool.drv','winspool','imm32','oleacc','propsys','dbghelp','wevtapi','powrprof',
        'msvcrt','ucrtbase','rpcrt4','authz','credui','wldap32','activeds','taskschd','xmllite',
        'd3d9','d3d11','d3d12','dxgi','opengl32','avrt','mf','mfplat','mfreadwrite','dsound'
    )

    # Native functions worth calling out when bound through managed P/Invoke.
    # Keyed lower-case, without an A/W suffix (stripped before lookup).
    $unsafeCrt = @('strcpy','strcat','sprintf','vsprintf','gets','wcscpy','wcscat','swprintf',
                   'lstrcpy','lstrcat','strncpy','strcpyn','memmove','alloca','_alloca')
    $remoteAlloc = @('virtualallocex','ntallocatevirtualmemory','zwallocatevirtualmemory')
    $remoteWrite = @('writeprocessmemory','ntwritevirtualmemory','zwwritevirtualmemory')
    $remoteExec  = @('createremotethread','createremotethreadex','ntcreatethreadex',
                     'rtlcreateuserthread','queueuserapc','ntqueueapcthread','setthreadcontext',
                     'setwindowshookex')

    foreach ($pe in Get-TcpkPeFiles -Path $Path) {
        if (Test-TcpkIsFrameworkFile $pe.Name) { continue }

        $asm = Get-TcpkCecilAssembly -DllPath $pe.FullName
        if (-not $asm) { continue }
        $mod = $null
        try { $mod = $asm.MainModule } catch { $mod = $null }
        if (-not $mod) { continue }

        $types = @()
        try { $types = @($mod.GetTypes()) } catch { $types = @() }
        if ($types.Count -eq 0) { continue }

        $byModule    = @{}                                              # module -> entry count
        $entries     = New-Object 'System.Collections.Generic.List[string]'
        $unsafeHits  = New-Object 'System.Collections.Generic.List[string]'
        $plantable   = @{}                                              # module -> sample entry
        $sawAlloc = $false; $sawWrite = $false; $sawExec = $false
        $total = 0

        foreach ($t in $types) {
            $methods = @()
            try { $methods = @($t.Methods) } catch { continue }
            foreach ($m in $methods) {
                if (-not $m.HasPInvokeInfo) { continue }
                $pi = $null
                try { $pi = $m.PInvokeInfo } catch { continue }
                if (-not $pi) { continue }

                $modName = ''
                try { $modName = "$($pi.Module.Name)" } catch { }
                $entry = ''
                try { $entry = "$($pi.EntryPoint)" } catch { }
                if (-not $entry) { $entry = "$($m.Name)" }
                if (-not $modName) { continue }
                $total++

                if ($byModule.ContainsKey($modName)) { $byModule[$modName]++ } else { $byModule[$modName] = 1 }
                if ($entries.Count -lt 10) { $entries.Add("$modName!$entry") }

                # --- plantable module target ---------------------------------
                # Only a BARE filename is search-order resolved. A rooted or
                # relative path is a different (and separately reviewable) case,
                # so it is not reported here.
                $hasPathSep = ($modName.Contains('\') -or $modName.Contains('/'))
                if (-not $hasPathSep) {
                    $stem = $modName.ToLowerInvariant()
                    if ($stem.EndsWith('.dll')) { $stem = $stem.Substring(0, $stem.Length - 4) }
                    if ($systemModules -notcontains $stem -and -not $plantable.ContainsKey($modName)) {
                        $plantable[$modName] = "$modName!$entry"
                    }
                }

                # --- dangerous native binding --------------------------------
                $fn = $entry.ToLowerInvariant()
                if ($fn.Length -gt 1) {
                    $last = $fn.Substring($fn.Length - 1, 1)
                    if ($last -eq 'a' -or $last -eq 'w') {
                        $trimmed = $fn.Substring(0, $fn.Length - 1)
                        # Only strip the suffix when the trimmed form is a known API;
                        # blindly trimming would turn 'gdipcreatebitmapfromscan0w' style
                        # names into noise and could mis-key a legitimate function.
                        if ($unsafeCrt -contains $trimmed -or $remoteAlloc -contains $trimmed -or
                            $remoteWrite -contains $trimmed -or $remoteExec -contains $trimmed) {
                            $fn = $trimmed
                        }
                    }
                }
                if ($unsafeCrt -contains $fn) {
                    if ($unsafeHits.Count -lt 12) { $unsafeHits.Add("$modName!$entry (memory-unsafe CRT)") }
                }
                if ($remoteAlloc -contains $fn) {
                    $sawAlloc = $true
                    if ($unsafeHits.Count -lt 12) { $unsafeHits.Add("$modName!$entry (remote allocate)") }
                }
                if ($remoteWrite -contains $fn) {
                    $sawWrite = $true
                    if ($unsafeHits.Count -lt 12) { $unsafeHits.Add("$modName!$entry (remote write)") }
                }
                if ($remoteExec -contains $fn) {
                    $sawExec = $true
                    if ($unsafeHits.Count -lt 12) { $unsafeHits.Add("$modName!$entry (remote execute)") }
                }
            }
        }

        if ($total -eq 0) { continue }

        # ---- inventory -------------------------------------------------------
        $modTxt = (($byModule.Keys | Sort-Object) | ForEach-Object { "$_ x$($byModule[$_])" }) -join ', '
        New-TcpkFinding -Module 'static' -RuleId 'interop.pinvoke-surface' `
            -Severity 'INFO' -Confidence 'Confirmed (IL)' `
            -Title "$($pe.Name) declares $total P/Invoke entry point(s) across $($byModule.Count) native module(s)" `
            -File $pe.FullName `
            -Evidence ("$modTxt | e.g. " + ($entries -join ', ')) `
            -Description ('The assembly''s native import surface, read from the ImplMap metadata table ' +
                '(what [DllImport] compiles into). These imports do not appear in the PE import table ' +
                'because the CLR resolves them lazily at first call, so a PE-import scan does not see ' +
                'them. This is scope information: it defines which native code the managed target can ' +
                'reach, and it is the input list for marshalling and buffer-size review.') `
            -Fix 'No action required for the inventory itself. Use it to scope interop review: check the size and length arguments on any entry that takes a buffer, and confirm SetLastError/CharSet match the native contract.'

        # ---- dangerous native bindings ---------------------------------------
        if ($unsafeHits.Count -gt 0) {
            $triad = ($sawAlloc -and $sawWrite -and $sawExec)
            $sev = 'LOW'
            if ($triad) { $sev = 'MEDIUM' }
            $triadNote = ''
            if ($triad) {
                $triadNote = ' The full remote-injection triad is declared in this one assembly: ' +
                    'allocate memory in another process, write to it, and start execution there. That ' +
                    'combination has no purpose other than running code inside a process the assembly ' +
                    'does not own, and it is worth confirming against the product''s stated behaviour.'
            }
            New-TcpkFinding -Module 'static' -RuleId 'interop.pinvoke-unsafe-native' `
                -Severity $sev -Confidence 'Confirmed (IL)' `
                -Title "$($pe.Name) P/Invokes memory-unsafe or cross-process native APIs" `
                -File $pe.FullName -Evidence ($unsafeHits -join '; ') `
                -Cwe @('CWE-119', 'CWE-787') `
                -Description ('The assembly binds native functions that are either memory-unsafe by ' +
                    'construction (CRT string copies with no destination bound) or operate on another ' +
                    'process''s address space. A PE import-table scan cannot see these because the CLR ' +
                    'resolves a DllImport lazily, so this route is invisible to native-import tooling.' +
                    $triadNote + ' Declaring an API is not the same as reaching it with attacker input: ' +
                    'the next step is tracing whether the buffer, length or target-process arguments are ' +
                    'caller-influenced.') `
                -Fix 'Replace memory-unsafe CRT bindings with bounded managed equivalents (the BCL string and Span<T> APIs) rather than marshalling to strcpy/strcat/sprintf. For cross-process APIs, confirm each is required by a documented product feature, and restrict the target-process selection so it cannot be redirected by configuration or user input.'
        }

        # ---- search-order plantable module targets ---------------------------
        if ($plantable.Count -gt 0) {
            $sample = (($plantable.Keys | Sort-Object) | ForEach-Object { $plantable[$_] }) -join '; '
            New-TcpkFinding -Module 'static' -RuleId 'interop.pinvoke-unqualified-module' `
                -Severity 'MEDIUM' -Confidence 'Confirmed (IL)' `
                -Title "$($pe.Name) P/Invokes $($plantable.Count) non-system module(s) by bare name" `
                -File $pe.FullName -Evidence $sample `
                -Cwe @('CWE-427', 'CWE-426') `
                -Description ('A [DllImport] names its native module by bare filename and that module is ' +
                    'not a Windows system DLL, so it is not protected by KnownDLLs. The CLR resolves it ' +
                    'through the standard DLL search order, which includes the application directory. A ' +
                    'file of that name planted earlier in the search order is loaded and executed inside ' +
                    'the target process. This is the managed half of a DLL-hijack chain; it becomes a ' +
                    'confirmed hijack when paired with a writable directory on the search path.') `
                -Fix 'Load the library explicitly from a known absolute path before first use (LoadLibraryEx with LOAD_WITH_ALTERED_SEARCH_PATH, or a NativeLibrary resolver), or ship it under a path that only administrators can write. Do not rely on the ambient DLL search order for a private native dependency.'
        }
    }
}
