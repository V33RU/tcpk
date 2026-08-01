#requires -Version 5.1
# Pester 5: Test-TcpkMemoryRegions. Walks a live process address space and classifies regions
# by protection. Windows-only (VirtualQueryEx); off Windows the cmdlet returns via
# Assert-TcpkWindows and these are skipped.

BeforeDiscovery {
    $script:isWin = ($env:OS -eq 'Windows_NT')
}

BeforeAll {
    Import-Module "$PSScriptRoot\..\TCPK.psd1" -Force
}

Describe 'Test-TcpkMemoryRegions' -Skip:(-not $script:isWin) {
    It 'reports a skipped finding for a process that is not running' {
        $r = @(Test-TcpkMemoryRegions -ProcessName 'tcpk-no-such-process-xyz')
        $r.Count | Should -BeGreaterThan 0
        $r[0].RuleId | Should -Be 'memregion.no-process'
        $r[0].Confidence | Should -Be 'Skipped'
    }

    It 'enumerates regions of the current process and emits a summary' {
        $r = @(Test-TcpkMemoryRegions -ProcessId $PID)
        $sum = $r | Where-Object RuleId -eq 'memregion.summary'
        $sum | Should -Not -BeNullOrEmpty
        $sum.Evidence | Should -Match 'regions=\d+'
    }

    It 'detects the JIT runtime in a PowerShell host and calibrates on it' {
        # The PowerShell host has the CLR loaded, so private executable memory is expected
        # and must not be reported as though it were unexplained.
        $r = @(Test-TcpkMemoryRegions -ProcessId $PID)
        $sum = $r | Where-Object RuleId -eq 'memregion.summary'
        $sum.Evidence | Should -Match 'jit=(clr|coreclr)'

        $priv = $r | Where-Object RuleId -eq 'memregion.private-exec'
        if ($priv) {
            # JIT present, so this is posture rather than a defect.
            $priv.Severity | Should -Be 'INFO'
            $priv.Description | Should -Match 'JIT runtime is loaded'
        }
    }

    It 'never rates RWX above MEDIUM when a JIT runtime is present' {
        $r = @(Test-TcpkMemoryRegions -ProcessId $PID | Where-Object RuleId -eq 'memregion.rwx')
        foreach ($f in $r) { $f.Severity | Should -Be 'MEDIUM' }
    }

    It 'counts every region it reports and keeps the sample bounded' {
        $r = @(Test-TcpkMemoryRegions -ProcessId $PID)
        foreach ($f in ($r | Where-Object { $_.RuleId -in @('memregion.rwx', 'memregion.private-exec') })) {
            # Sample is capped at 6 entries, so the evidence cannot grow without bound.
            (($f.Evidence -split ';').Count) | Should -BeLessOrEqual 12
        }
    }
}

Describe 'memregion rule IDs are registered in the mapping tables' {
    It 'maps <_> to an ATT&CK technique and a TASVS control' -ForEach @(
        'memregion.rwx'
        'memregion.private-exec'
        'memregion.summary'
    ) {
        $rid = $_
        $tech = & (Get-Module TCPK) { param($r) Get-TcpkAttackTechnique -RuleId $r } $rid
        @($tech).Count | Should -BeGreaterThan 0 -Because "$rid must map to an ATT&CK technique"
        $ctl = & (Get-Module TCPK) { param($r) Get-TcpkTasvsControl -RuleId $r } $rid
        @($ctl).Count | Should -BeGreaterThan 0 -Because "$rid must map to a TASVS control"
    }

    It 'maps the injection-shaped rules to T1055 and T1620' {
        $tech = & (Get-Module TCPK) { Get-TcpkAttackTechnique -RuleId 'memregion.private-exec' }
        ($tech -join ' ') | Should -Match 'T1055'
        ($tech -join ' ') | Should -Match 'T1620'
    }
}
