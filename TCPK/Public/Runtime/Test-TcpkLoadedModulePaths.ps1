function Test-TcpkLoadedModulePaths {
<#
.SYNOPSIS
    E10. Native modules loaded into the process from non-system paths.

.DESCRIPTION
    For every loaded module, classify the source directory (System32 /
    SysWOW64 / WinSxS / WindowsApps / Program Files / user-writable).
    User-writable paths are HIGH (runtime DLL hijack working confirmation).
    Non-system paths outside expected installer locations are MEDIUM
    (review for legitimacy).

.OUTPUTS
    [TcpkFinding]
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ParameterSetName='ByName')][string]$ProcessName,
        [Parameter(Mandatory, ParameterSetName='ById')][int]$ProcessId
    )

    if (-not (Assert-TcpkWindows 'Test-TcpkLoadedModulePaths')) { return }
    $procs = if ($PSCmdlet.ParameterSetName -eq 'ByName') {
        Get-TcpkProcess -ProcessName $ProcessName
    } else {
        Get-TcpkProcess -ProcessId $ProcessId
    }

    foreach ($p in $procs) {
        try { $mods = $p.Modules } catch { continue }
        # The process's OWN main module (the .exe) always sits in the app dir and is NOT a
        # DLL-search-order hijack candidate -- excluding it removes a guaranteed false positive on
        # every per-user-installed app. Its path/signature posture is already covered statically
        # (authenticode.pe-not-signed / DLL hardening matrix). Dependency DLLs stay in scope.
        $mainPath = $null; try { $mainPath = $p.MainModule.FileName } catch { }
        foreach ($m in $mods) {
            $path = $m.FileName
            if ($mainPath -and $path -eq $mainPath) { continue }
            if ($path -match '\\(System32|SysWOW64|WinSxS|Microsoft\.NET|WindowsApps)\\') { continue }
            if ($path -match '\\Program Files( \(x86\))?\\') { continue }

            $sev = 'MEDIUM'
            $writable = $false
            try {
                $acl = Get-Acl -LiteralPath $path -ErrorAction Stop
                $writable = $acl.Access | Where-Object {
                    $_.IdentityReference.Value -match '(?i)\b(Everyone|Authenticated Users|Users|INTERACTIVE)\b' -and
                    $_.FileSystemRights -match 'Write|Modify|FullControl' -and
                    $_.AccessControlType -eq 'Allow'
                }
            } catch { }
            if ($writable) { $sev = 'HIGH' }

            New-TcpkFinding -Module 'runtime' -RuleId 'loaded.non-system-path' `
                -Severity $sev -Confidence 'Confirmed' `
                -Title "$($p.Name) loaded $(Split-Path $path -Leaf) from non-system path$(if ($writable) {' (user-writable)'} else {''})" `
                -File $path -Evidence "PID=$($p.Id)" `
                -Cwe @('CWE-427')
        }
    }
}
