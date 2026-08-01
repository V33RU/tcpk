function Test-TcpkDllSideload {
<#
.SYNOPSIS
    Detect DLL side-loading opportunities via known target DLL names.

.DESCRIPTION
    DLL side-loading exploits the Windows loader's search order: when an
    application loads a DLL by name (without a full path), the loader checks
    the application directory first.  Certain DLL names are well-known
    side-loading targets because they are commonly loaded by legitimate
    applications but often not shipped in the app directory:

      version.dll, winmm.dll, dbghelp.dll, dwmapi.dll, uxtheme.dll,
      crypt32.dll, wintrust.dll, profapi.dll, shcore.dll, propsys.dll, etc.

    If a first-party PE imports one of these DLLs AND the application
    directory is user-writable, an attacker can drop a proxy DLL that
    forwards all exports to the real system DLL while executing payload code.

    This check identifies:
      1. Known sideload-target DLL imports from first-party PEs where the
         DLL is NOT shipped in the app directory (the attacker plants it).
      2. The application directory's writability (needed to exploit).

    SCOPE. Every first-party PE module is examined, not just .exe files:
    DLL-to-DLL side-loading is common, and a shipped DLL importing an
    unshipped sideload target is the same primitive as an EXE doing it.
    Delay-load imports (PE data directory 13) count as well, and are the
    stronger case because they resolve at first call rather than at load.

    One finding is emitted per sideload-target DLL, listing the modules that
    import it, rather than one finding per importing module. That keeps the
    count bounded on large applications while still telling the vendor every
    place the name is reachable from.

    Unlike Test-TcpkPhantomDlls (which flags ANY missing import),
    this specifically targets the well-researched sideload DLL names
    used in real-world campaigns (APT29, Lazarus, etc.).

    MITRE ATT&CK T1574.002 (DLL Side-Loading).

.PARAMETER Path
    File or directory to scan.

.OUTPUTS
    [TcpkFinding]
#>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    $sideloadTargets = @(
        'version.dll','winmm.dll','dbghelp.dll','dwmapi.dll','uxtheme.dll',
        'crypt32.dll','wintrust.dll','profapi.dll','shcore.dll','propsys.dll',
        'cryptsp.dll','cryptbase.dll','msasn1.dll','dpapi.dll','rsaenh.dll',
        'ntmarta.dll','ntshrui.dll','srvcli.dll','cscapi.dll','wkscli.dll',
        'netutils.dll','samcli.dll','samlib.dll','logoncli.dll','dxgi.dll',
        'dxcore.dll','d3d11.dll','d3d9.dll','d3d12.dll','d3dcompiler_47.dll',
        'dwrite.dll','d2d1.dll','textinputframework.dll','coreuicomponents.dll',
        'coremessaging.dll','wintypes.dll','twinapi.appcore.dll',
        'textshaping.dll','msftedit.dll','edputil.dll','urlmon.dll',
        'iertutil.dll','winsta.dll','wtsapi32.dll','pcacli.dll','sxs.dll',
        'userenv.dll','mpr.dll','netapi32.dll','cabinet.dll','apphelp.dll',
        'cryptui.dll','msimg32.dll','oledlg.dll','oleacc.dll',
        'coloradapterclient.dll','fltlib.dll','bcrypt.dll'
    )
    $sideloadSet = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase)
    foreach ($s in $sideloadTargets) { [void]$sideloadSet.Add($s) }

    $item = Get-Item -LiteralPath $Path -ErrorAction SilentlyContinue
    if (-not $item) { return }
    $root = if ($item.PSIsContainer) { $item.FullName } else { $item.DirectoryName }

    $appFiles = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase)
    Get-ChildItem -LiteralPath $root -Recurse -File -ErrorAction SilentlyContinue |
        ForEach-Object { [void]$appFiles.Add($_.Name) }

    $userPrincipals = '(?i)\b(Everyone|Authenticated Users|Users|INTERACTIVE|BUILTIN\\Users)\b'
    $writeRights    = 'Write|Modify|FullControl'
    $dirWritable    = $false
    if ($env:OS -eq 'Windows_NT') {
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

    # Pass 1: collect which first-party modules import each unshipped sideload target.
    # Keyed by DLL name so the finding count stays bounded on large applications.
    $hits = [ordered]@{}
    foreach ($pe in Get-TcpkPeFiles -Path $Path) {
        if ($pe.Extension.ToLowerInvariant() -notin @('.exe', '.dll', '.node', '.pyd')) { continue }
        if (Test-TcpkIsFrameworkFile $pe.Name) { continue }
        $info = Read-TcpkPe -Path $pe.FullName
        if (-not $info) { continue }

        $cands = New-Object 'System.Collections.Generic.List[object]'
        foreach ($imp in @($info.Imports))      { $cands.Add([pscustomobject]@{ N = "$imp"; Delay = $false }) }
        foreach ($imp in @($info.DelayImports)) { $cands.Add([pscustomobject]@{ N = "$imp"; Delay = $true  }) }

        foreach ($c in $cands) {
            if ([string]::IsNullOrWhiteSpace($c.N)) { continue }
            $dll = $c.N.Trim()
            if (-not $sideloadSet.Contains($dll)) { continue }
            if ($appFiles.Contains($dll)) { continue }

            if (-not $hits.Contains($dll)) {
                $hits[$dll] = [pscustomobject]@{
                    Importers = (New-Object 'System.Collections.Generic.List[string]')
                    AnyDelay  = $false
                    FirstFile = $pe.FullName
                }
            }
            $label = $pe.Name
            if ($c.Delay) { $label = "$($pe.Name) [delay-load]"; $hits[$dll].AnyDelay = $true }
            if (-not $hits[$dll].Importers.Contains($label)) { $hits[$dll].Importers.Add($label) }
        }
    }

    # Pass 2: one finding per sideload-target DLL.
    foreach ($dll in @($hits.Keys)) {
        $h = $hits[$dll]
        $imps = @($h.Importers)
        $impTxt = ($imps | Select-Object -First 6) -join ', '
        if ($imps.Count -gt 6) { $impTxt = "$impTxt (+$($imps.Count - 6) more)" }

        $sev = if ($dirWritable) { 'HIGH' } else { 'MEDIUM' }

        $writeNote = 'The application directory is not currently writable by non-admin users, but this should be verified on all deployment targets.'
        if ($dirWritable) { $writeNote = 'The application directory IS writable by non-admin users, so exploitation is straightforward.' }

        $delayNote = ''
        if ($h.AnyDelay) {
            $delayNote = ' At least one importer DELAY-loads this DLL, which resolves at the first call rather than at process start, so the search runs against the process state at that moment and after any start-up integrity check.'
        }

        New-TcpkFinding -Module 'static' -RuleId 'dllsearch.sideload-candidate' `
            -Severity $sev -Confidence 'Confirmed' `
            -Title "DLL sideload target: $dll (imported by $($imps.Count) module(s))" `
            -File $h.FirstFile `
            -Evidence "$dll not shipped in app dir; importers: $impTxt; dir writable=$dirWritable" `
            -Cwe @('CWE-427') `
            -Description ('A first-party module imports a DLL that is a well-known side-loading ' +
                'target (used in real APT campaigns). The DLL is not shipped in the ' +
                'application directory, so an attacker can plant a proxy DLL that loads the ' +
                'real system DLL while executing arbitrary code. ' + $writeNote + $delayNote +
                ' (ATT&CK T1574.002 DLL Side-Loading).') `
            -Fix 'Ship the DLL with the application, use SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32), or sign the application and enforce code integrity.'
    }
}
