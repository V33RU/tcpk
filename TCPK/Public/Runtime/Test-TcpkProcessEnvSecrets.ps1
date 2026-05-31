function Test-TcpkProcessEnvSecrets {
<#
.SYNOPSIS
    E16. Secrets in a running process's environment block (read-only).

.DESCRIPTION
    Walks the target process PEB (x64) to its environment block and scans the
    NAME=VALUE pairs for secret patterns. Apps frequently pass API keys, tokens
    and connection strings via environment variables -- which are readable by
    the same user and inherited by child processes.

    Read-only. Variables whose NAME looks sensitive (KEY/TOKEN/SECRET/PASSWORD/
    CONN...) and whose VALUE is non-trivial are flagged even if no regex matches.

.PARAMETER ProcessName
    Running process name (no .exe).

.OUTPUTS
    [TcpkFinding]
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ParameterSetName='ByName')][string]$ProcessName,
        [Parameter(Mandatory, ParameterSetName='ById')][int]$ProcessId
    )

    if (-not (Assert-TcpkWindows 'Test-TcpkProcessEnvSecrets')) { return }
    if (-not ('Tcpk.MemRead' -as [type])) { return }

    $procs = if ($PSCmdlet.ParameterSetName -eq 'ByName') { Get-TcpkProcess -ProcessName $ProcessName } else { Get-TcpkProcess -ProcessId $ProcessId }
    if (-not $procs) { return }

    $rules = Get-TcpkSecretRegexRules
    $rxSensitiveName = [regex]'(?i)(password|passwd|secret|token|apikey|api_key|access_key|client_secret|conn_?str|connectionstring|private_?key|credential|bearer|sas_?token)'
    # working-dir / shell vars that look credential-ish by substring but are not secrets
    $rxBenignName = [regex]'^(PWD|OLDPWD|PROMPT|PATHEXT|PSModulePath|HOMEPATH|HOMEDRIVE)$'

    foreach ($p in $procs) {
        $env = $null
        try { $env = [Tcpk.MemRead]::GetEnv($p.Id) } catch { $env = $null }
        if (-not $env) {
            New-TcpkSkippedFinding -RuleId 'env.unreadable' -Title "Cannot read environment of $($p.Name) (PID $($p.Id))" -Reason 'PEB read denied -- run elevated if target is elevated.'
            continue
        }

        $seen = @{}
        foreach ($pair in ($env -split "`0")) {
            if (-not $pair -or $pair.IndexOf('=') -lt 1) { continue }
            $eq = $pair.IndexOf('=')
            $name = $pair.Substring(0, $eq)
            $val  = $pair.Substring($eq + 1)
            if ($name.StartsWith('=')) { continue }            # drive-letter pseudo-vars (=C:)
            if ($val.Length -lt 4) { continue }
            if ($rxBenignName.IsMatch($name)) { continue }
            if ($seen.ContainsKey($name)) { continue }
            $seen[$name] = $true

            $matched = $false
            foreach ($r in $rules) { if ($r._RX.IsMatch($pair)) { $matched = $true; break } }
            $sensitiveName = $rxSensitiveName.IsMatch($name)
            if (-not ($matched -or $sensitiveName)) { continue }
            # name-only hits: require a non-trivial, non-path value
            if (-not $matched) {
                if ($val.Length -lt 8) { continue }
                if ($val -match '^[A-Za-z]:[\\/]' -or $val -match '^[\\/]') { continue }   # filesystem path
            }

            $red = if ($val.Length -gt 12) { $val.Substring(0,4) + '...' + $val.Substring($val.Length-4) + " (len=$($val.Length))" } else { '(short)' }
            $sev = if ($matched) { 'HIGH' } else { 'MEDIUM' }
            New-TcpkFinding -Module 'runtime' -RuleId 'env.secret' `
                -Severity $sev -Confidence $(if ($matched){'Confirmed'}else{'Inferred'}) `
                -Title "Sensitive environment variable in $($p.Name): $name" `
                -File "$($p.Name) (PID $($p.Id))" `
                -Evidence "$name=$red" -Cwe @('CWE-526','CWE-214') `
                -Description 'A secret-looking environment variable is set on the running process. Environment variables are readable by the same user, visible in process dumps, and inherited by every child process the app spawns.' `
                -Fix 'Do not pass secrets via environment variables. Use a protected secret store and inject at the point of use; clear the variable after reading.'
        }
    }
}
