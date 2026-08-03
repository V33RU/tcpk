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
        $nonWritable = New-Object 'System.Collections.Generic.List[string]'
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

            # NOT WRITABLE MEANS NOT HIJACKABLE, so it is not a finding. This used to emit
            # MEDIUM for every module regardless, and on a self-contained .NET app that is
            # ~76 MEDIUM findings for the app loading its own runtime out of its own install
            # directory -- all of them reading file-writable=False; dir-writable=False. The
            # handful of genuinely interesting results in the same run were buried under it.
            # Writability is the entire point of this check, so it now decides whether there
            # is a finding at all, not just how severe it is.
            if (-not ($writable -or $dirWritable)) {
                $nonWritable.Add((Split-Path $path -Leaf))
                continue
            }

            # Plain if/elseif statements rather than an if-expression: a newline can
            # terminate an assignment expression, so the multi-line expression form is
            # not reliably parseable across PowerShell versions.
            $how = ''
            if ($writable -and $dirWritable) { $how = ' (file and directory user-writable)' }
            elseif ($writable)    { $how = ' (file user-writable: replaceable in place)' }
            elseif ($dirWritable) { $how = ' (directory user-writable: a module can be planted)' }

            New-TcpkFinding -Module 'runtime' -RuleId 'loaded.non-system-path' `
                -Severity 'HIGH' -Confidence 'Confirmed' `
                -Title "$($p.Name) loaded $(Split-Path $path -Leaf) from a USER-WRITABLE path$how" `
                -File $path -Evidence "PID=$($p.Id); file-writable=$writable; dir-writable=$dirWritable" `
                -Cwe @('CWE-427') `
                -Description ('This module was loaded from a location a non-admin user can write to, ' +
                    'so it can be replaced in place or shadowed by a planted copy that resolves ' +
                    'earlier in the search order. The loading process then executes attacker code ' +
                    'with its own privileges.') `
                -Fix ('Restrict the ACL on the module and its directory to Administrators/SYSTEM, and ' +
                    'load dependencies by full path.')
        }

        # One aggregated INFO for everything checked and found NOT writable. Keeps the
        # coverage visible -- silence would otherwise be indistinguishable from "never
        # looked" -- without emitting a finding per DLL.
        if ($nonWritable.Count) {
            $sample = (@($nonWritable) | Select-Object -First 10) -join ', '
            $more = if ($nonWritable.Count -gt 10) { " (+$($nonWritable.Count - 10) more)" } else { '' }
            New-TcpkFinding -Module 'runtime' -RuleId 'loaded.non-system-path-checked' `
                -Severity 'INFO' -Confidence 'Confirmed' `
                -Title "$($p.Name): $($nonWritable.Count) module(s) loaded from outside the system directories, none user-writable" `
                -File "$($p.Name) (PID $($p.Id))" `
                -Evidence "not-writable=$($nonWritable.Count); $sample$more" `
                -Description ('Every one of these was ACL-checked and is not writable by a non-admin ' +
                    'user, so none is a DLL-hijack candidate. A self-contained .NET or Electron app ' +
                    'loading its own runtime from its own install directory is the normal case and ' +
                    'produces this list. Recorded so the check is visibly complete rather than silent.')
        }
    }
}
