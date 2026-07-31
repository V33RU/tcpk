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
            # OS-owned, ACL-protected locations. These are genuinely not plantable by a
            # standard user, so skipping them removes noise rather than coverage.
            if ($path -match '\\(System32|SysWOW64|WinSxS|Microsoft\.NET|WindowsApps)\\') { continue }

            # NOTE: Program Files is deliberately NOT skipped. It is protected by DEFAULT,
            # but installers routinely loosen ACLs on their own subdirectories, and a
            # user-writable directory under Program Files feeding a module into a
            # privileged process is one of the most common real thick-client LPE findings.
            # Skipping the whole tree discarded that entire class. The ACL check below is
            # what decides, not the path.

            $writable = $false
            $dirWritable = $false
            $userRx = '(?i)\b(Everyone|Authenticated Users|Users|INTERACTIVE|BUILTIN\\Users)\b'
            $rightsRx = 'Write|Modify|FullControl|TakeOwnership|ChangePermissions'

            # The FILE ACL covers overwriting this module in place (substitution). The
            # DIRECTORY ACL covers planting a DIFFERENT module that resolves earlier in
            # the search order. They are separate primitives and both matter; checking
            # only the file missed the planting case entirely.
            try {
                $acl = Get-Acl -LiteralPath $path -ErrorAction Stop
                $writable = @($acl.Access | Where-Object {
                    $_.IdentityReference.Value -match $userRx -and
                    $_.FileSystemRights -match $rightsRx -and
                    $_.AccessControlType -eq 'Allow'
                }).Count -gt 0
            } catch { }
            try {
                $dacl = Get-Acl -LiteralPath (Split-Path $path -Parent) -ErrorAction Stop
                $dirWritable = @($dacl.Access | Where-Object {
                    $_.IdentityReference.Value -match $userRx -and
                    $_.FileSystemRights -match $rightsRx -and
                    $_.AccessControlType -eq 'Allow'
                }).Count -gt 0
            } catch { }

            $sev = if ($writable -or $dirWritable) { 'HIGH' } else { 'MEDIUM' }

            # Plain if/elseif statements rather than an if-expression: a newline can
            # terminate an assignment expression, so the multi-line expression form is
            # not reliably parseable across PowerShell versions.
            $how = ''
            if ($writable -and $dirWritable) { $how = ' (file and directory user-writable)' }
            elseif ($writable)    { $how = ' (file user-writable: replaceable in place)' }
            elseif ($dirWritable) { $how = ' (directory user-writable: a module can be planted)' }

            New-TcpkFinding -Module 'runtime' -RuleId 'loaded.non-system-path' `
                -Severity $sev -Confidence 'Confirmed' `
                -Title "$($p.Name) loaded $(Split-Path $path -Leaf) from non-system path$how" `
                -File $path -Evidence "PID=$($p.Id); file-writable=$writable; dir-writable=$dirWritable" `
                -Cwe @('CWE-427')
        }
    }
}
