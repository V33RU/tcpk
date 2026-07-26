function Test-TcpkPhantomDlls {
<#
.SYNOPSIS
    Detect phantom DLL planting opportunities in PE import tables.

.DESCRIPTION
    Scans each first-party PE's import table for DLLs that do NOT exist
    anywhere in the application directory tree.  A missing imported DLL is
    a prime target for DLL planting: an attacker drops a malicious DLL with
    the expected name into the app directory (or a writable directory on
    the DLL search path) and the OS loader will happily load it the next
    time the application starts.

    Unlike DLL search-order tracing (Test-TcpkDllSearchTrace), this is a
    STATIC check -- it reads the PE import table and cross-references the
    filesystem without running the application, so it works on extracted
    packages and offline targets.

    Known system DLLs (kernel32, ntdll, user32, etc.) are excluded because
    they always resolve from System32; only application-scope DLLs that the
    developer intended to ship (but forgot, or that are optional) are flagged.

.PARAMETER Path
    File or directory to scan.

.OUTPUTS
    [TcpkFinding]
#>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    $knownSystemDlls = @(
        'advapi32.dll','bcrypt.dll','cfgmgr32.dll','crypt32.dll','comctl32.dll',
        'comdlg32.dll','dbghelp.dll','dwmapi.dll','gdi32.dll','gdiplus.dll',
        'imm32.dll','iphlpapi.dll','kernel32.dll','kernelbase.dll','mpr.dll',
        'mscoree.dll','msi.dll','msvcrt.dll','ncrypt.dll','netapi32.dll',
        'normaliz.dll','ntdll.dll','ole32.dll','oleaut32.dll','powrprof.dll',
        'psapi.dll','rpcrt4.dll','secur32.dll','setupapi.dll','shell32.dll',
        'shlwapi.dll','sspicli.dll','user32.dll','userenv.dll','uxtheme.dll',
        'version.dll','winhttp.dll','wininet.dll','winmm.dll','winspool.drv',
        'ws2_32.dll','wsock32.dll','wtsapi32.dll','dnsapi.dll','mswsock.dll',
        'pdh.dll','wintrust.dll','cabinet.dll','cryptui.dll','dxgi.dll',
        'd2d1.dll','d3d11.dll','d3d12.dll','dwrite.dll','shcore.dll',
        'authz.dll','wevtapi.dll','propsys.dll','profapi.dll','ucrtbase.dll',
        'vcruntime140.dll','vcruntime140_1.dll','msvcp140.dll',
        'vcruntime140d.dll','ucrtbased.dll','msvcp140d.dll',
        'api-ms-win-crt-runtime-l1-1-0.dll',
        'api-ms-win-crt-heap-l1-1-0.dll',
        'api-ms-win-crt-math-l1-1-0.dll',
        'api-ms-win-crt-stdio-l1-1-0.dll',
        'api-ms-win-crt-string-l1-1-0.dll',
        'api-ms-win-crt-locale-l1-1-0.dll',
        'api-ms-win-crt-convert-l1-1-0.dll',
        'api-ms-win-crt-environment-l1-1-0.dll',
        'api-ms-win-crt-filesystem-l1-1-0.dll',
        'api-ms-win-crt-time-l1-1-0.dll',
        'api-ms-win-crt-utility-l1-1-0.dll',
        'api-ms-win-crt-multibyte-l1-1-0.dll',
        'api-ms-win-crt-process-l1-1-0.dll',
        'api-ms-win-crt-private-l1-1-0.dll',
        'api-ms-win-core-synch-l1-2-0.dll'
    )
    $sysSet = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase)
    foreach ($s in $knownSystemDlls) { [void]$sysSet.Add($s) }

    $item = Get-Item -LiteralPath $Path -ErrorAction SilentlyContinue
    if (-not $item) { return }
    $root = if ($item.PSIsContainer) { $item.FullName } else { $item.DirectoryName }

    $appFiles = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase)
    Get-ChildItem -LiteralPath $root -Recurse -File -ErrorAction SilentlyContinue |
        ForEach-Object { [void]$appFiles.Add($_.Name) }

    $seen = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase)

    foreach ($pe in Get-TcpkPeFiles -Path $Path) {
        if (Test-TcpkIsFrameworkFile $pe.Name) { continue }
        $info = Read-TcpkPe -Path $pe.FullName
        if (-not $info) { continue }

        foreach ($imp in @($info.Imports)) {
            if ([string]::IsNullOrWhiteSpace($imp)) { continue }
            $dll = $imp.Trim()
            if ($sysSet.Contains($dll)) { continue }
            if ($dll -match '^api-ms-win-|^ext-ms-') { continue }
            if ($appFiles.Contains($dll)) { continue }
            $key = "$($pe.Name)|$dll"
            if (-not $seen.Add($key)) { continue }

            New-TcpkFinding -Module 'static' -RuleId 'dllsearch.phantom-dll' `
                -Severity 'HIGH' -Confidence 'Confirmed' `
                -Title "Phantom DLL plantable: $dll (imported by $($pe.Name))" `
                -File $pe.FullName `
                -Evidence "imports $dll; not found in $root" `
                -Cwe @('CWE-427','CWE-426') `
                -Description ('This PE imports a DLL that does not exist anywhere in the ' +
                    'application directory tree and is not a known Windows system DLL. ' +
                    'An attacker with write access to the application directory (or a ' +
                    'directory on the DLL search path) can plant a malicious DLL with ' +
                    'this name to achieve code execution under the application identity.') `
                -Fix 'Ship the DLL with the application, use a full path in LoadLibrary, or call SetDefaultDllDirectories/AddDllDirectory to restrict the search path.'
        }
    }
}
