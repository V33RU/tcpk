function Test-TcpkServiceBinaryAcl {
<#
.SYNOPSIS
    C18. Non-admin-writable service / scheduled-task BINARY (EoP).

.DESCRIPTION
    Complements Test-TcpkServicePermissions (which checks the service *config*
    SDDL). This checks the actual EXECUTABLE the service / task launches: if a
    non-admin can overwrite that file -- or its containing directory -- they
    control code that runs as the service account (often LocalSystem) at next
    start. That is a direct local privilege escalation.

.PARAMETER NameLike
    Service/task name substring (default '*').

.OUTPUTS
    [TcpkFinding]
#>
    [CmdletBinding()]
    param([string[]]$NameLike = @())

    if (-not (Assert-TcpkWindows 'Test-TcpkServiceBinaryAcl')) { return }

    $terms = Get-TcpkNameTerms -NameLike $NameLike

    $riskyId    = '(?i)\b(Everyone|Authenticated Users|Users|INTERACTIVE|BUILTIN\\Users)\b'
    $riskyRights = 'Write|Modify|FullControl|WriteData|CreateFiles|AppendData|ChangePermissions|TakeOwnership'

    function _CheckFileAcl([string]$file, [string]$ctx, [string]$ruleId) {
        if (-not $file -or -not (Test-Path -LiteralPath $file)) { return }
        $targets = @($file)
        $dir = Split-Path -Parent $file
        if ($dir) { $targets += $dir }
        foreach ($t in $targets) {
            try { $acl = Get-Acl -LiteralPath $t -ErrorAction Stop } catch { continue }
            $bad = $acl.Access | Where-Object {
                $_.AccessControlType -eq 'Allow' -and
                $_.IdentityReference.Value -match $riskyId -and
                $_.FileSystemRights -match $riskyRights
            }
            if ($bad) {
                $grant = ($bad | ForEach-Object { "$($_.IdentityReference) -> $($_.FileSystemRights)" } | Select-Object -Unique) -join '; '
                $what = if ($t -eq $file) { 'binary' } else { 'binary directory' }
                New-TcpkFinding -Module 'os' -RuleId $ruleId `
                    -Severity 'HIGH' -Confidence 'Confirmed' `
                    -Title "$ctx $what is non-admin writable: $(Split-Path -Leaf $t)" `
                    -File $t -Evidence "$grant | $ctx" -Cwe @('CWE-732','CWE-276','CWE-269') `
                    -Description 'A non-admin principal can replace the executable (or drop a planted DLL into its directory) that this service/task runs with elevated privileges. Overwriting it yields code execution as the service account at next launch.' `
                    -Fix 'Restrict the binary and its directory to admin-only write (inherit from Program Files); remove explicit grants to non-admin groups.'
            }
        }
    }

    # extract an .exe path from a service PathName / command line
    function _ExePath([string]$cmd) {
        if (-not $cmd) { return $null }
        $cmd = $cmd.Trim()
        if ($cmd.StartsWith('"')) {
            $end = $cmd.IndexOf('"', 1)
            if ($end -gt 1) { return $cmd.Substring(1, $end - 1) }
        }
        $m = [regex]::Match($cmd, '(?i)^(.*?\.exe)\b')
        if ($m.Success) { return $m.Groups[1].Value }
        return $null
    }

    # ---- services ----
    try {
        $svcs = Get-CimInstance Win32_Service -ErrorAction Stop
        foreach ($s in $svcs) {
            if ($terms.Count -and -not (
                    (Test-TcpkTermMatch -Text $s.Name -Terms $terms) -or
                    (Test-TcpkTermMatch -Text $s.DisplayName -Terms $terms) -or
                    (Test-TcpkTermMatch -Text "$($s.PathName)" -Terms $terms))) { continue }
            $exe = _ExePath $s.PathName
            if ($exe) { _CheckFileAcl $exe "Service '$($s.Name)'" 'servicebin.user-writable' }
        }
    } catch { }

    # ---- scheduled tasks (binary the action launches) ----
    try {
        $csv = & schtasks.exe /query /v /fo CSV 2>$null | ConvertFrom-Csv
        $seen = @{}
        foreach ($row in $csv) {
            $tn = "$($row.TaskName)"
            $run = "$($row.'Task To Run')"
            if (-not $run) { continue }
            if ($terms.Count -and -not ((Test-TcpkTermMatch -Text $tn -Terms $terms) -or (Test-TcpkTermMatch -Text $run -Terms $terms))) { continue }
            $exe = _ExePath $run
            if (-not $exe) { continue }
            if ($seen.ContainsKey($exe)) { continue }
            $seen[$exe] = $true
            _CheckFileAcl $exe "Task '$tn'" 'taskbin.user-writable'
        }
    } catch { }
}
