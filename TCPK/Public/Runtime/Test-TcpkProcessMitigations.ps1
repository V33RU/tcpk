function Test-TcpkProcessMitigations {
<#
.SYNOPSIS
    E01. Runtime process mitigations (DEP, ASLR, CFG, SEHOP, etc.).

.PARAMETER ProcessName
.PARAMETER ProcessId
.OUTPUTS
    [TcpkFinding]
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ParameterSetName='ByName')][string]$ProcessName,
        [Parameter(Mandatory, ParameterSetName='ById')][int]$ProcessId
    )

    if (-not (Assert-TcpkWindows 'Test-TcpkProcessMitigations')) { return }
    if (-not (Get-Command Get-ProcessMitigation -ErrorAction SilentlyContinue)) {
        New-TcpkSkippedFinding -RuleId 'procmit.unavailable' `
            -Title 'Get-ProcessMitigation not available on this PS host' `
            -Reason 'Module ProcessMitigations is not loaded.'
        return
    }

    $procs = if ($PSCmdlet.ParameterSetName -eq 'ByName') {
        Get-TcpkProcess -ProcessName $ProcessName
    } else {
        Get-TcpkProcess -ProcessId $ProcessId
    }
    if (-not $procs) { return }

    $checks = @(
        @{ Path='DEP.Enable';                              Sev='HIGH';   Name='DEP' }
        @{ Path='ASLR.BottomUp';                           Sev='HIGH';   Name='ASLR.BottomUp' }
        @{ Path='ASLR.ForceRelocateImages';                Sev='MEDIUM'; Name='ASLR.ForceRelocateImages' }
        @{ Path='ASLR.HighEntropy';                        Sev='MEDIUM'; Name='ASLR.HighEntropy' }
        @{ Path='CFG.Enable';                              Sev='MEDIUM'; Name='CFG' }
        @{ Path='SEHOP.Enable';                            Sev='MEDIUM'; Name='SEHOP' }
        @{ Path='ChildProcess.DisallowChildProcessCreation';Sev='LOW';   Name='NoChildProcess' }
    )
    foreach ($p in $procs) {
        $m = Get-ProcessMitigation -Id $p.Id -ErrorAction SilentlyContinue
        if (-not $m) { continue }
        foreach ($c in $checks) {
            $val = $m
            foreach ($seg in ($c.Path -split '\.')) {
                if ($null -eq $val) { break }
                $val = $val.PSObject.Properties[$seg] | ForEach-Object Value
            }
            if ($null -eq $val) { continue }
            if (([string]$val).ToUpper() -notin 'ON','TRUE','ENABLE','NOTSET') {
                New-TcpkFinding -Module 'runtime' -RuleId "procmit.$($c.Name)" `
                    -Severity $c.Sev -Confidence 'Confirmed' `
                    -Title "$($p.Name): $($c.Name) is not ON ($val)" `
                    -File "$($p.Name) (PID $($p.Id))" `
                    -Evidence "$($c.Path)=$val" `
                    -Cwe @('CWE-1037') `
                    -Fix 'Enable via Set-ProcessMitigation or rebuild with the right compiler/linker flags.'
            }
        }
    }
}
