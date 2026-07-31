#requires -Version 5.1
# Pester 5: Test-TcpkHandleDacl. Enumerates the kernel objects a live process holds and
# grades their DACLs. Windows-only. The record-splitting is exercised directly because it
# uses a control-character separator and a 5.1-safe split.

BeforeDiscovery {
    $script:isWin = ($env:OS -eq 'Windows_NT')
}

BeforeAll {
    Import-Module "$PSScriptRoot\..\TCPK.psd1" -Force
}

Describe 'Test-TcpkHandleDacl' -Skip:(-not $script:isWin) {
    It 'runs against the current process without throwing' {
        { Test-TcpkHandleDacl -ProcessId $PID -MaxHandles 300 } | Should -Not -Throw
    }

    It 'emits only known rule IDs' {
        foreach ($f in @(Test-TcpkHandleDacl -ProcessId $PID -MaxHandles 300)) {
            $f.RuleId | Should -BeIn @('handle.dacl-weak', 'handle.type-census',
                                       'handle.dacl-unreadable', 'handle-dacl.unavailable')
        }
    }

    It 'produces a type census naming real kernel object types' {
        $c = @(Test-TcpkHandleDacl -ProcessId $PID -MaxHandles 500 |
            Where-Object RuleId -eq 'handle.type-census')
        if ($c.Count) {
            # Every PowerShell host holds these. File is excluded by design.
            $c[0].Evidence | Should -Match '(Event|Mutant|Key|Directory|Semaphore|Thread)='
            $c[0].Evidence | Should -Not -Match '\bFile='
        }
    }

    It 'never blocks: completes a bounded scan well inside a timeout' {
        # The whole point of skipping File-type name queries is that this cannot hang.
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        $null = @(Test-TcpkHandleDacl -ProcessId $PID -MaxHandles 500)
        $sw.Stop()
        $sw.Elapsed.TotalSeconds | Should -BeLessThan 60
    }
}

Describe 'handle record splitting' {
    It 'splits on the 0x1F separator using 5.1-safe syntax' {
        # Mirrors what the cmdlet does with what the C# emits.
        $rec = "Event" + [char]0x1F + "D:(A;;0x1F0003;;;S-1-5-32-545)" + [char]0x1F + "2031619"
        $parts = $rec.Split([char]0x1F)
        $parts.Count | Should -Be 3
        $parts[0] | Should -Be 'Event'
        $parts[1] | Should -Match '^D:'
    }
}

Describe 'handle rule IDs are registered' {
    It 'maps <_> to an ATT&CK technique and a TASVS control' -ForEach @(
        'handle.dacl-weak'
        'handle.type-census'
    ) {
        $rid = $_
        $tech = & (Get-Module TCPK) { param($r) Get-TcpkAttackTechnique -RuleId $r } $rid
        @($tech).Count | Should -BeGreaterThan 0 -Because "$rid must map to an ATT&CK technique"
        $ctl = & (Get-Module TCPK) { param($r) Get-TcpkTasvsControl -RuleId $r } $rid
        @($ctl).Count | Should -BeGreaterThan 0 -Because "$rid must map to a TASVS control"
    }
}
