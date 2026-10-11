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
        # Image-load policy: the direct defence against DLL search-order hijack / sideload.
        # PreferSystem32 resolves system DLLs from System32 first; BlockRemoteImageLoads
        # refuses DLLs from UNC/remote paths; BlockLowLabelImageLoads refuses low-integrity
        # images. A wrong property name just resolves to $null and is skipped, never errors.
        @{ Path='ImageLoad.PreferSystem32';          Sev='MEDIUM'; Name='ImageLoad.PreferSystem32';   Cwe=@('CWE-427') }
        @{ Path='ImageLoad.BlockRemoteImageLoads';   Sev='MEDIUM'; Name='ImageLoad.BlockRemoteImages'; Cwe=@('CWE-427','CWE-114') }
        @{ Path='ImageLoad.BlockLowLabelImageLoads'; Sev='LOW';    Name='ImageLoad.BlockLowLabelImages'; Cwe=@('CWE-427') }
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
                    -Cwe ($(if ($c.Cwe) { $c.Cwe } else { @('CWE-1037') })) `
                    -Fix 'Enable via Set-ProcessMitigation or rebuild with the right compiler/linker flags.'
            }
        }
    }
}
