function Test-TcpkPeImports {
<#
.SYNOPSIS
    A03 - Phantom DLL imports (DLL hijack candidates).

.DESCRIPTION
    For every PE under the path, lists its native imports and flags any DLL
    that is NOT a Windows Known DLL AND NOT shipped in the same folder.
    These are candidates for runtime hijack via PATH / current-directory.

.PARAMETER Path
    File or directory.

.OUTPUTS
    [TcpkFinding]
#>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    # The standard Windows "Known DLLs" set, plus common always-present-from-System32
    # DLLs. NOTE: this static list is a fast-path; the authoritative check below also
    # tests System32 / SysWOW64 existence at scan time so the list never needs to be
    # exhaustive.
    $known = @(
        'advapi32.dll','clbcatq.dll','combase.dll','comdlg32.dll','coml2.dll',
        'difxapi.dll','gdi32.dll','imagehlp.dll','imm32.dll','kernel32.dll','kernelbase.dll',
        'msasn1.dll','msctf.dll','msvcp_win.dll','msvcrt.dll','normaliz.dll','ntdll.dll',
        'ole32.dll','oleaut32.dll','psapi.dll','rpcrt4.dll','sechost.dll','setupapi.dll',
        'shcore.dll','shell32.dll','shlwapi.dll','user32.dll','ucrtbase.dll','win32u.dll',
        'wininet.dll','ws2_32.dll',
        # crypto / trust / security
        'crypt32.dll','cryptbase.dll','cryptsp.dll','bcrypt.dll','bcryptprimitives.dll',
        'ncrypt.dll','wintrust.dll','secur32.dll','sspicli.dll','cryptui.dll',
        # user profile / shell / networking / misc system
        'userenv.dll','profapi.dll','iphlpapi.dll','dnsapi.dll','winhttp.dll',
        'mswsock.dll','version.dll','dbghelp.dll','dbgcore.dll','propsys.dll',
        'dwmapi.dll','uxtheme.dll','wtsapi32.dll','netapi32.dll','dhcpcsvc.dll',
        'msi.dll','msvcp140.dll','wevtapi.dll','powrprof.dll','cfgmgr32.dll',
        'devobj.dll','gdiplus.dll','windowscodecs.dll','d3d11.dll','dxgi.dll',
        'oleacc.dll','comctl32.dll','winmm.dll','urlmon.dll','wininet.dll',
        'mpr.dll','rasapi32.dll','activeds.dll','wlanapi.dll','fwpuclnt.dll'
    )

    # Resolve System32 / SysWOW64 paths once for the dynamic existence check.
    $systemDirs = @(
        [Environment]::GetFolderPath('System'),                    # System32
        [Environment]::GetFolderPath('SystemX86'),                 # SysWOW64 (on x64) or System32 (on x86)
        "$env:windir\System32",
        "$env:windir\SysWOW64"
    ) | Where-Object { $_ -and (Test-Path $_) } | Select-Object -Unique
    $sysCache = @{}
    function Test-TcpkInSystemDir([string]$dllName) {
        if ($sysCache.ContainsKey($dllName)) { return $sysCache[$dllName] }
        $found = $false
        foreach ($d in $systemDirs) {
            if (Test-Path (Join-Path $d $dllName)) { $found = $true; break }
        }
        $sysCache[$dllName] = $found
        return $found
    }
    # VC++ runtime - special-cased because MSIX apps frequently miss VCLibs dep.
    $vcRuntime = @(
        'msvcp140.dll','msvcp140_1.dll','vcruntime140.dll','vcruntime140_1.dll',
        'concrt140.dll','vccorlib140.dll'
    )

    $item = Get-Item -LiteralPath $Path
    $folder = if ($item.PSIsContainer) { $item.FullName } else { $item.DirectoryName }

    # Is the target an MSIX/AppX package? The VCRuntime/VCLibs reasoning only
    # applies to packaged apps. For classic Win32 installs, a VCRuntime DLL that
    # resolves from System32 (system-wide VCRedist) is benign, not a finding.
    $isMsix = $false
    if ($item.PSIsContainer) {
        $isMsix = Test-Path (Join-Path $item.FullName 'AppxManifest.xml')
    } elseif ($item.Extension.ToLowerInvariant() -in '.msix','.appx','.msixbundle','.appxbundle') {
        $isMsix = $true
    }

    # Build set of DLLs shipped ANYWHERE under the target (recursive), so a DLL in
    # a subfolder importing a runtime shipped in the root is correctly seen as shipped.
    $shipped = @{}
    foreach ($f in (Get-ChildItem -LiteralPath $folder -Recurse -Filter *.dll -File -ErrorAction SilentlyContinue)) {
        $shipped[$f.Name.ToLowerInvariant()] = $true
    }

    foreach ($pe in Get-TcpkPeFiles -Path $Path) {
        $info = Read-TcpkPe -Path $pe.FullName
        if (-not $info -or -not $info.Imports) { continue }

        foreach ($imp in $info.Imports) {
            if ($imp -in $known) { continue }
            if ($imp.StartsWith('api-ms-win-') -or $imp.StartsWith('ext-ms-win-')) { continue }
            if ($shipped.ContainsKey($imp)) { continue }

            $isVc = $imp -in $vcRuntime

            # Authoritative System32 check: if the DLL exists in System32/SysWOW64
            # it resolves there and is not a hijack candidate. VCRuntime DLLs are
            # only exempt from this skip for MSIX targets (where VCLibs must be
            # declared); for classic Win32 they are treated like any system DLL.
            if (Test-TcpkInSystemDir $imp) {
                if (-not ($isVc -and $isMsix)) { continue }
            }

            $sev   = 'MEDIUM'
            $title = "$($pe.Name) imports $imp -- not shipped, not a Known DLL"
            $fix   = 'Ship the DLL alongside the executable, or use LoadLibraryEx + LOAD_LIBRARY_SEARCH_SYSTEM32.'

            if ($isVc -and $isMsix) {
                $sev   = 'HIGH'
                $title = "$($pe.Name) imports VC runtime $imp -- verify VCLibs declared in MSIX manifest"
                $fix   = "Declare Microsoft.VCLibs.140.00.UWPDesktop in AppxManifest.xml or static-link the runtime."
            }

            New-TcpkFinding -Module 'static' -RuleId 'pe-imports.phantom' `
                -Severity $sev -Confidence 'Confirmed' `
                -Title $title -File $pe.FullName -Evidence "import=$imp" `
                -Cwe @('CWE-427') -Fix $fix
        }
    }
}
