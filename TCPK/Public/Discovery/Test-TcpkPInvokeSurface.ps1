function Test-TcpkPInvokeSurface {
<#
.SYNOPSIS
    A17. P/Invoke surface -- bare-name DllImport declarations.

.DESCRIPTION
    Scans first-party PEs for DllImport-shaped metadata that references a
    DLL by bare filename (subject to the OS DLL search order). If the
    referenced DLL is NOT in the standard Known DLLs list, the call is a
    candidate for DLL hijack via PATH precedence.

.PARAMETER Path
    File or directory.

.OUTPUTS
    [TcpkFinding]
#>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    $known = @(
        'kernel32.dll','user32.dll','advapi32.dll','ntdll.dll','ole32.dll',
        'oleaut32.dll','shell32.dll','shlwapi.dll','crypt32.dll','wininet.dll',
        'ws2_32.dll','iphlpapi.dll','gdi32.dll','rpcrt4.dll','setupapi.dll',
        'msvcrt.dll','ucrtbase.dll','combase.dll','psapi.dll','version.dll',
        'msi.dll','dbghelp.dll','propsys.dll','dwmapi.dll','uxtheme.dll',
        'kernelbase.dll','win32u.dll','sechost.dll','bcrypt.dll','ncrypt.dll',
        'mscoree.dll','clr.dll','coreclr.dll'
    )
    $rx = [regex]'DllImport[^"]{0,80}"([A-Za-z0-9._\-]+\.dll)"'

    foreach ($pe in Get-TcpkPeFiles -Path $Path) {
        if (Test-TcpkIsFrameworkFile $pe.Name) { continue }
        $text = Read-TcpkAllText -Path $pe.FullName
        if (-not $text) { continue }

        $bare = @{}
        foreach ($m in $rx.Matches($text)) {
            $dll = $m.Groups[1].Value.ToLowerInvariant()
            if ($dll -match '[\\/]' -or $dll -match '^[a-z]:') { continue }
            $bare[$dll] = $true
        }

        $suspect = $bare.Keys |
            Where-Object { $_ -notin $known } |
            Where-Object { $_ -notmatch '^(api-ms-win-|ext-ms-win-)' }

        foreach ($s in $suspect) {
            New-TcpkFinding -Module 'static' -RuleId 'pinvoke.bare-name' `
                -Severity 'LOW' -Confidence 'Inferred' `
                -Title "$($pe.Name) DllImports '$s' by bare name" `
                -File $pe.FullName -Evidence "DllImport(`"$s`")" `
                -Cwe @('CWE-427') `
                -Description 'If the bare-name DLL is not in System32 and the app does not call SetDefaultDllDirectories, this is search-order-attackable.' `
                -Fix 'Use full path, or call SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32 | LOAD_LIBRARY_SEARCH_APPLICATION_DIR) at startup.'
        }
    }
}
