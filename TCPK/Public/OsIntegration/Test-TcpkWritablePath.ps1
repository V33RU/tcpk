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

    $seen = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase)

    foreach ($dir in $pathDirs) {
        $d = $dir.Trim().TrimEnd('\')
        if (-not $d) { continue }
        if (-not $seen.Add($d)) { continue }
        if (-not (Test-Path -LiteralPath $d -PathType Container)) { continue }

        if ($d -match '(?i)^C:\\Windows') { continue }

        # Only report PATH dirs related to the target: dir is a parent of
        # the target, dir is inside the target, or dir equals the target.
        $dNorm = $d.ToLower()
        $tNorm = $targetDir.ToLower()
        $isParent = $tNorm.StartsWith($dNorm + '\')
        $isChild  = $dNorm.StartsWith($tNorm + '\')
        $isEqual  = $dNorm -eq $tNorm
        if (-not ($isParent -or $isChild -or $isEqual)) { continue }

        try { $acl = Get-Acl -LiteralPath $d -ErrorAction Stop } catch { continue }
        $bad = @($acl.Access | Where-Object {
            $_.IdentityReference.Value -match $userPrincipals -and
            $_.FileSystemRights -match $writeRights -and
            $_.AccessControlType -eq 'Allow'
        })
        if ($bad.Count -eq 0) { continue }

        $ev = ($bad | ForEach-Object { "$($_.IdentityReference) -> $($_.FileSystemRights)" }) -join '; '
        $inSystem = $false
        if ($sysPath) {
            foreach ($sp in $sysPath.Split(';', [System.StringSplitOptions]::RemoveEmptyEntries)) {
                if ($sp.Trim().TrimEnd('\') -ieq $d) { $inSystem = $true; break }
            }
        }
        $scope = if ($inSystem) { 'system' } else { 'user' }

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
