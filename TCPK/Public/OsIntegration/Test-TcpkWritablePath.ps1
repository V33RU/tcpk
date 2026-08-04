function Test-TcpkWritablePath {
<#
.SYNOPSIS
    Detect writable directories in the system PATH (binary planting surface).

.DESCRIPTION
    The system and user PATH environment variable determines where Windows
    searches for executables.  If any directory in the PATH is writable by
    non-admin users, an attacker can plant a malicious binary with the same
    name as a legitimate tool (e.g. python.exe, git.exe, curl.exe) and it
    will be executed instead of the real one whenever the application or any
    child process resolves that name.

    This is particularly dangerous for thick-client applications that shell
    out to external tools via Process.Start without a full path.

    MITRE ATT&CK T1574.007 (Path Interception by PATH Environment Variable).

.PARAMETER Path
    File or directory to scan (used to identify application-specific PATH
    entries; also checks the system PATH).

.OUTPUTS
    [TcpkFinding]
#>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    if (-not (Assert-TcpkWindows 'Test-TcpkWritablePath')) { return }

    # Resolve the target install directory for relevance filtering
    $tgtItem = Get-Item -LiteralPath $Path -ErrorAction SilentlyContinue
    if (-not $tgtItem) { return }
    $targetDir = if ($tgtItem.PSIsContainer) { $tgtItem.FullName } else { $tgtItem.DirectoryName }
    $targetDir = $targetDir.TrimEnd('\')

    $userPrincipals = '(?i)\b(Everyone|Authenticated Users|Users|INTERACTIVE|BUILTIN\\Users)\b'
    $writeRights    = 'Write|Modify|FullControl'

    $pathDirs = @()
    $sysPath = [System.Environment]::GetEnvironmentVariable('PATH', 'Machine')
    if ($sysPath) { $pathDirs += $sysPath.Split(';', [System.StringSplitOptions]::RemoveEmptyEntries) }
    $usrPath = [System.Environment]::GetEnvironmentVariable('PATH', 'User')
    if ($usrPath) { $pathDirs += $usrPath.Split(';', [System.StringSplitOptions]::RemoveEmptyEntries) }

    # PATH entries that are user-writable BY DESIGN, not by vendor mistake. These live in
    # the user's own profile, so the user can always write to them, and an elevated process
    # launched from that user's session inherits the user PATH -- which is precisely the
    # privilege crossing. %LOCALAPPDATA%\Microsoft\WindowsApps is the sink in several of the
    # publicly disclosed DLL-hijack reports in this class.
    #
    # They must bypass the target-relevance filter below. That filter keeps this check
    # attributable by only reporting PATH directories at or around the install tree -- but
    # WindowsApps sits nowhere near an install dir, so the single highest-yield hijack sink
    # on Windows was structurally unreachable by this check.
    $knownSinks = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    if ($env:LOCALAPPDATA) { [void]$knownSinks.Add((Join-Path $env:LOCALAPPDATA 'Microsoft\WindowsApps').TrimEnd('\')) }

    $seen = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase)

    foreach ($dir in $pathDirs) {
        $d = $dir.Trim().TrimEnd('\')
        if (-not $d) { continue }
        if (-not $seen.Add($d)) { continue }
        if (-not (Test-Path -LiteralPath $d -PathType Container)) { continue }

        if ($d -match '(?i)^C:\\Windows') { continue }

        $isKnownSink = $knownSinks.Contains($d)

        # Only report PATH dirs related to the target: dir is a parent of
        # the target, dir is inside the target, or dir equals the target.
        $dNorm = $d.ToLower()
        $tNorm = $targetDir.ToLower()
        $isParent = $tNorm.StartsWith($dNorm + '\')
        $isChild  = $dNorm.StartsWith($tNorm + '\')
        $isEqual  = $dNorm -eq $tNorm
        if (-not ($isParent -or $isChild -or $isEqual -or $isKnownSink)) { continue }

        try { $acl = Get-Acl -LiteralPath $d -ErrorAction Stop } catch { continue }
        $bad = @($acl.Access | Where-Object {
            $_.IdentityReference.Value -match $userPrincipals -and
            $_.FileSystemRights -match $writeRights -and
            $_.AccessControlType -eq 'Allow'
        })
        # A profile-local sink usually grants the OWNING USER rather than a well-known group,
        # so the group match above legitimately finds nothing. Writability is structural
        # there -- it is the user's own directory -- so do not require a group ACE for it.
        if ($bad.Count -eq 0 -and -not $isKnownSink) { continue }

        $ev = if ($bad.Count) {
            ($bad | ForEach-Object { "$($_.IdentityReference) -> $($_.FileSystemRights)" }) -join '; '
        } else {
            'user-writable by design (directory lives in the current user profile)'
        }
        $inSystem = $false
        if ($sysPath) {
            foreach ($sp in $sysPath.Split(';', [System.StringSplitOptions]::RemoveEmptyEntries)) {
                if ($sp.Trim().TrimEnd('\') -ieq $d) { $inSystem = $true; break }
            }
        }
        $scope = if ($inSystem) { 'system' } else { 'user' }

        if ($isKnownSink) {
            # Severity is deliberately MEDIUM on its own. The directory existing is a Windows
            # default and not a vulnerability; it becomes one when this application also
            # searches for a name it will not find, and the attack graph raises that pair
            # (prim.hijackname + prim.loaddir) to a reachable goal. Reporting it HIGH standalone
            # would fire on every Windows box and be an attribution error.
            New-TcpkFinding -Module 'os' -RuleId 'path.writable-entry' `
                -Severity 'MEDIUM' -Confidence 'Confirmed' `
                -Title "Known user-writable PATH sink on the search path: $d" `
                -File $d `
                -Evidence "$scope PATH; $ev" `
                -Cwe @('CWE-427','CWE-426') `
                -Description ('This directory is in the ' + $scope + ' PATH and sits in the ' +
                    'current user profile, so any non-admin user can write to it. It is a ' +
                    'Windows default, NOT a vendor mistake -- but an elevated process launched ' +
                    'from this user session inherits the user PATH, so anything this application ' +
                    'resolves by NAME rather than by full path can be satisfied from here. That ' +
                    'is the privilege crossing behind the publicly disclosed DLL-hijack reports ' +
                    'in this class, where a missing DLL (for example tcmalloc.dll, providers.dll, ' +
                    'perf.dll) was planted in this exact directory and loaded by an elevated ' +
                    'process. On its own this is only the SINK: it matters when paired with a ' +
                    'name this application searches for and does not find.') `
                -Fix ('The vendor cannot remove this directory from PATH, and does not need to. ' +
                    'Fix the loading side instead: load DLLs by full path, call ' +
                    'SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32) at startup, remove ' +
                    'imports of DLLs that are not shipped, and launch child processes with a ' +
                    'fully qualified path rather than a bare name.')
        } else {
            New-TcpkFinding -Module 'os' -RuleId 'path.writable-entry' `
                -Severity 'HIGH' -Confidence 'Confirmed' `
                -Title "Writable $scope PATH directory: $d" `
                -File $d `
                -Evidence "$scope PATH; $ev" `
                -Cwe @('CWE-427','CWE-426') `
                -Description ('This directory is in the ' + $scope + ' PATH and is writable by ' +
                    'non-admin users. An attacker can plant a malicious executable here with the ' +
                    'same name as a legitimate tool. When the application (or any process on the ' +
                    'system) resolves that tool name, the planted binary runs instead ' +
                    '(ATT&CK T1574.007 Path Interception).') `
                -Fix "Remove the directory from PATH or restrict its ACL to administrators/SYSTEM only."
        }
    }
}
