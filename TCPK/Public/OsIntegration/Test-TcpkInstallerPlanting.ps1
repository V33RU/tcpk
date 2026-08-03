function Test-TcpkInstallerPlanting {
<#
.SYNOPSIS
    C27. Installer / setup binary DLL planting -- a setup executable that resolves DLLs
    from its own directory, where the user's browser already dropped it.

.DESCRIPTION
    Every other DLL check in TCPK looks at an INSTALLED application. This one looks at the
    installer, which is a different and historically productive target: a setup .exe runs
    from wherever the browser saved it, usually %USERPROFILE%\Downloads, and that directory
    is writable by any process running as that user. Windows resolves a DLL from the
    executable's own directory before System32, so a DLL the installer imports but does not
    ship next to itself is loaded from the download folder if one is sitting there.

    The attacker does not need to touch the installer. They need one earlier write into the
    Downloads directory -- a second download, an archive that extracts there, any prior
    code execution as that user -- and then they wait for the victim to run a setup binary
    they downloaded themselves. Installers are commonly run elevated, so the payload lands
    with Administrator rights.

    This is a disclosed, paid bug class: an installer loading dwmapi.dll from the Downloads
    folder, and another loading shfolder.dll from its own directory. Both are exactly this
    shape, and neither is visible to a check that only inspects an installed tree.

    WHAT IS FLAGGED. A file that looks like an installer (name or PE characteristics), which
    imports a DLL that is NOT present beside it and NOT a known API-set or system-forwarder.
    Each such import is a name an attacker can satisfy from the same directory.

    ATTRIBUTION. Reported against the installer, which is the vendor's artifact and the
    vendor's fix (full-path loads, SetDefaultDllDirectories, or shipping the dependency).
    The Downloads directory being writable is a property of Windows, not of the vendor, and
    is not itself reported here.

    Static and read-only. The installer is never executed.

.PARAMETER Path
    File or directory to scan. A directory is searched for installer-shaped executables.

.PARAMETER MaxFiles
    Cap on installer binaries inspected (default 40).

.OUTPUTS
    [TcpkFinding]
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [ValidateRange(1, 500)][int]$MaxFiles = 40
    )

    if (-not (Assert-TcpkWindows 'Test-TcpkInstallerPlanting')) { return }

    $item = Get-Item -LiteralPath $Path -ErrorAction SilentlyContinue
    if (-not $item) { return }

    # Installer-shaped names. Deliberately a NAME heuristic plus a size floor rather than a
    # deep NSIS/Inno/MSI signature parse: the point is to notice that the artifact under
    # audit is a setup binary at all, and a false positive here only means one extra PE gets
    # its imports checked, which is harmless.
    $installerRx = '(?i)(^|[\\/_.-])(setup|install(er)?|update(r)?|bootstrap(per)?|websetup|vc_redist)([\\/_.-]|\d|$)'

    $candidates = @()
    if ($item.PSIsContainer) {
        $candidates = @(Get-TcpkChildItemSafe -Path $item.FullName -File |
            Where-Object { $_.Extension -ieq '.exe' -and $_.Name -match $installerRx } |
            Select-Object -First $MaxFiles)
    } elseif ($item.Extension -ieq '.exe') {
        # An explicitly named target is inspected whether or not the name looks like a setup
        # binary -- the analyst pointed at it deliberately.
        $candidates = @($item)
    }
    if (-not $candidates.Count) { return }

    # Names that legitimately do not sit beside the binary. api-ms-win-* and ext-ms-* are
    # API sets resolved by the loader from a schema, never from disk, so treating them as
    # plantable would flag essentially every modern PE.
    $apiSetRx = '(?i)^(api-ms-win-|ext-ms-)'

    $inspected = 0
    $flagged = 0
    foreach ($exe in $candidates) {
        $inspected++
        $dir = $exe.DirectoryName
        if (-not $dir) { continue }

        $pe = $null
        try { $pe = Read-TcpkPe -Path $exe.FullName } catch { }
        if (-not $pe) { continue }

        # Delay imports count too: the loader resolves them on first use, through the same
        # search order, so they are just as plantable as a static import.
        $imports = @()
        try { $imports = @($pe.Imports) + @($pe.DelayImports) } catch { }
        $imports = @($imports | Where-Object { $_ } | Select-Object -Unique)
        if (-not $imports.Count) { continue }

        $missing = New-Object 'System.Collections.Generic.List[string]'
        foreach ($imp in $imports) {
            $name = "$imp"
            if (-not $name) { continue }
            if ($name -match $apiSetRx) { continue }
            # Present beside the installer -> the loader takes that copy, nothing to plant.
            if (Test-Path -LiteralPath (Join-Path $dir $name)) { continue }
            # Shipped by Windows in System32 -> the app directory still wins in the default
            # search order, so this IS plantable. Recorded, but separated below so the
            # non-system ones (a dependency the vendor forgot to ship) rank first.
            $missing.Add($name)
        }
        if (-not $missing.Count) { continue }

        $sys32 = Join-Path $env:SystemRoot 'System32'
        $notInSystem = @($missing | Where-Object { -not (Test-Path -LiteralPath (Join-Path $sys32 $_)) })
        $inSystem    = @($missing | Where-Object { Test-Path -LiteralPath (Join-Path $sys32 $_) })

        # A dependency that exists NOWHERE is the strongest case: the loader is guaranteed to
        # walk the search order and find nothing, so a planted file is loaded every time.
        if ($notInSystem.Count) {
            $flagged++
            $sample = (@($notInSystem) | Select-Object -First 8) -join ', '
            $more = if ($notInSystem.Count -gt 8) { " (+$($notInSystem.Count - 8) more)" } else { '' }
            New-TcpkFinding -Module 'os' -RuleId 'installer.plantable-import' `
                -Severity 'HIGH' -Confidence 'Confirmed' `
                -Title "Installer $($exe.Name) imports $($notInSystem.Count) DLL(s) that exist neither beside it nor in System32" `
                -File $exe.FullName `
                -Evidence "dir=$dir; missing=$sample$more" `
                -Cwe @('CWE-427','CWE-426') `
                -Description ('This setup binary imports DLLs that are not shipped alongside it and ' +
                    'are not present in System32, so the loader will search and find nothing. Windows ' +
                    "searches the executable's OWN directory first, and a setup binary runs from " +
                    'wherever the browser saved it, typically the user Downloads folder, which any ' +
                    'process running as that user can write to. An attacker who can drop one file ' +
                    'there before the victim runs the installer gets code execution -- with ' +
                    'Administrator rights whenever the installer is elevated, which is the norm. ' +
                    'The attacker never modifies the installer itself, so its signature stays valid.') `
                -Fix ('Ship every dependency next to the installer, or load it with an absolute path. ' +
                    'Call SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32) as the first ' +
                    'instruction in the entry point so the current directory leaves the search order. ' +
                    'For a single-file bootstrapper, prefer a statically linked build.')
        }

        # System-resident, but the application directory still precedes System32 in the
        # default search order, so these remain plantable. Lower severity because the
        # legitimate copy exists and a defence such as SafeDllSearchMode may already cover it.
        if ($inSystem.Count) {
            $flagged++
            $sample = (@($inSystem) | Select-Object -First 8) -join ', '
            $more = if ($inSystem.Count -gt 8) { " (+$($inSystem.Count - 8) more)" } else { '' }
            New-TcpkFinding -Module 'os' -RuleId 'installer.searchorder-import' `
                -Severity 'MEDIUM' -Confidence 'Inferred' `
                -Title "Installer $($exe.Name) resolves $($inSystem.Count) system DLL(s) from its own directory first" `
                -File $exe.FullName `
                -Evidence "dir=$dir; system-resident=$sample$more" `
                -Cwe @('CWE-427') `
                -Description ('These DLLs exist in System32, but the executable directory precedes ' +
                    'System32 in the default search order, so a copy planted beside the installer ' +
                    'wins. Disclosed cases in this class used exactly such names (for example ' +
                    'dwmapi.dll and shfolder.dll) planted into a Downloads folder. Inferred rather ' +
                    'than Confirmed: SafeDllSearchMode and a manifest-declared dependency can ' +
                    'change the outcome, so verify with Process Monitor which copy actually loads.') `
                -Fix ('Call SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32) at entry, or load ' +
                    'these by absolute System32 path. Do not rely on SafeDllSearchMode, which does ' +
                    'not remove the application directory from the search order.')
        }
    }

    # Coverage record: silence here must mean "looked and found nothing", not "never looked".
    if ($inspected -gt 0 -and $flagged -eq 0) {
        New-TcpkFinding -Module 'os' -RuleId 'installer.imports-resolved' `
            -Severity 'INFO' -Confidence 'Confirmed' `
            -Title "$inspected installer binary(ies) checked; every import resolves beside them or in System32" `
            -File $item.FullName `
            -Evidence "inspected=$inspected" `
            -Description ('No plantable import was found in the setup binaries examined. This says ' +
                'nothing about DLLs loaded dynamically at run time via LoadLibrary, which a static ' +
                'import walk cannot see.')
    }
}
