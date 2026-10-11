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

        # Does this binary neutralise the default DLL search order? SetDefaultDllDirectories
        # (with LOAD_LIBRARY_SEARCH_SYSTEM32) is the fix that makes a bare-name import safe.
        # If the binary references it at all, keep bare-name at LOW; if it does not, the
        # insecure default order applies and a bare-name import is genuinely search-order
        # attackable, so raise to MEDIUM.
        $hardenedSearch = $text.Contains('SetDefaultDllDirectories')

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
            $sev = if ($hardenedSearch) { 'LOW' } else { 'MEDIUM' }
            $ev  = "DllImport(`"$s`")" + $(if ($hardenedSearch) { ' | SetDefaultDllDirectories referenced' } else { ' | no SetDefaultDllDirectories call -- default search order applies' })
            New-TcpkFinding -Module 'static' -RuleId 'pinvoke.bare-name' `
                -Severity $sev -Confidence 'Inferred' `
                -Title "$($pe.Name) DllImports '$s' by bare name" `
                -File $pe.FullName -Evidence $ev `
                -Cwe @('CWE-427') `
                -Description 'The binary imports this DLL by bare filename, so it is resolved through the OS DLL search order. When the binary does not call SetDefaultDllDirectories (raised to MEDIUM here), a non-System32 DLL of this name planted earlier on the search path -- the application directory, a writable PATH entry, or the current directory -- loads instead, which is DLL search-order hijacking. Confirm the DLL is not shipped in System32 and that no writable directory precedes it on the search path.' `
                -Fix 'Use a full path, or call SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32 | LOAD_LIBRARY_SEARCH_APPLICATION_DIR) at startup so bare-name imports resolve only from trusted directories.'
        }

        # SetDllDirectory with a RELATIVE literal path widens the search order with a
        # current-directory-relative folder (read from IL; the empty-string hardening form and
        # rooted/absolute paths are not flagged).
        foreach ($v in (Get-TcpkDllSearchWidenVerdicts -DllPath $pe.FullName)) {
            $ev2 = New-Object 'System.Collections.Generic.List[string]'
            $ev2.Add("SetDllDirectory('$($v.PathArg)') adds a relative directory to the DLL search order.")
            $ev2.Add('')
            $ev2.Add('LOCATION (open THIS assembly in ILSpy/dnSpy):')
            $ev2.Add("  Assembly : $($v.Assembly)")
            $ev2.Add("  Namespace: $($v.Namespace)")
            $ev2.Add("  Type     : $($v.Type)")
            $ev2.Add("  Method   : $($v.Method)")
            $ev2.Add("  MD token : $($v.Token)")
            $ev2.Add('')
            $ev2.Add('IL PROOF (the path literal fed to SetDllDirectory):')
            $ev2.Add($v.Il)
            New-TcpkFinding -Module 'static' -RuleId 'dllsearch.setdlldirectory-relative' `
                -Severity 'MEDIUM' -Confidence 'Confirmed (IL)' `
                -Title "$($pe.Name) adds a relative directory to the DLL search path: '$($v.PathArg)'" `
                -File $pe.FullName -Evidence ($ev2 -join "`n") `
                -Cwe @('CWE-427','CWE-426') `
                -AttributionBasis 'established-code' -Subject $pe.FullName `
                -Description 'The binary calls SetDllDirectory with a relative path literal, inserting a current-directory-relative folder into the DLL search order for every subsequent load in the process. The current directory is often attacker-influenceable (a working directory, a download or share path), so a DLL planted there under the name of a later import loads into the process. The empty-string form SetDllDirectory("") is the safe call (it removes the current directory) and is not flagged; this is a non-empty relative path.' `
                -Fix 'Pass an absolute, admin-only path to SetDllDirectory, or call SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32 | LOAD_LIBRARY_SEARCH_APPLICATION_DIR) and AddDllDirectory with a full path instead.'
        }
    }
}
