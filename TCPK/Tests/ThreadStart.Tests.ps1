#requires -Version 5.1
# Pester 5: Test-TcpkThreadStart. Reads each thread's Win32 start address with
# NtQueryInformationThread and reports the ones that fall outside every loaded module.
# Windows-only (OpenThread + ntdll); off Windows the cmdlet returns via Assert-TcpkWindows.
#
# The tests below deliberately target the FALSE-POSITIVE boundaries rather than the happy
# path, because the happy path on a clean host is "emit nothing":
#   * the PowerShell host has the CLR loaded, so any unbacked start address there MUST be
#     downgraded to INFO posture and MUST say why;
#   * nothing may be reported when fewer than two module ranges were readable, since a
#     partial module list makes backed threads look unbacked;
#   * the inspected-thread count must respect -MaxThreads and must stay distinct from the
#     process's real thread total.

BeforeDiscovery {
    $script:isWin = ($env:OS -eq 'Windows_NT')
}

BeforeAll {
    Import-Module "$PSScriptRoot\..\TCPK.psd1" -Force

    # Pull "checked=N of M" out of an evidence string. Returns $null when absent.
    function script:Get-CheckedPair {
        param([string]$Evidence)
        if ($Evidence -match 'checked=(\d+) of (\d+)') {
            return [pscustomobject]@{ Checked = [int]$matches[1]; Total = [int]$matches[2] }
        }
        return $null
    }
}

Describe 'Test-TcpkThreadStart' -Skip:(-not $script:isWin) {

    It 'reports a skipped finding when the named process is not running' {
        $r = @(Test-TcpkThreadStart -ProcessName 'tcpk-no-such-process-xyz')
        $r.Count | Should -BeGreaterThan 0
        $r[0].RuleId | Should -Be 'thread-start.unavailable'
        $r[0].Confidence | Should -Be 'Skipped'
    }

    It 'reports a skipped finding when the PID does not exist' {
        $r = @(Test-TcpkThreadStart -ProcessId 999999)
        $r.Count | Should -BeGreaterThan 0
        $r[0].RuleId | Should -Be 'thread-start.unavailable'
        $r[0].Confidence | Should -Be 'Skipped'
    }

    It 'runs against the current process without throwing' {
        { Test-TcpkThreadStart -ProcessId $PID } | Should -Not -Throw
    }

    It 'emits only the three declared rule IDs' {
        $r = @(Test-TcpkThreadStart -ProcessId $PID)
        foreach ($f in $r) {
            $f.RuleId | Should -BeIn @('thread.unbacked-start', 'thread.start-unreadable', 'thread-start.unavailable')
        }
    }

    It 'downgrades an unbacked start address to INFO when a JIT runtime is loaded' {
        # The PowerShell host has clr/coreclr mapped, so runtime-generated code is expected
        # here and an unbacked start address must not be presented as a defect.
        $r = @(Test-TcpkThreadStart -ProcessId $PID | Where-Object RuleId -eq 'thread.unbacked-start')
        foreach ($f in $r) {
            $f.Evidence | Should -Match 'jit=(clr|coreclr|clrjit|mscorwks)'
            $f.Severity | Should -Be 'INFO'
            $f.Description | Should -Match 'JIT runtime is loaded'
        }
    }

    It 'never rates an unbacked start MEDIUM while a JIT runtime is reported in the evidence' {
        # The severity decision and the evidence line must agree. If they ever diverge the
        # calibration has been broken.
        $r = @(Test-TcpkThreadStart -ProcessId $PID | Where-Object RuleId -eq 'thread.unbacked-start')
        foreach ($f in $r) {
            if ($f.Evidence -notmatch 'jit=none') { $f.Severity | Should -Be 'INFO' }
        }
    }

    It 'never reports against a partial module list' {
        # Fewer than two readable module ranges means the comparison base is unusable, and
        # the cmdlet must emit a Skipped finding instead of flagging backed threads.
        $r = @(Test-TcpkThreadStart -ProcessId $PID | Where-Object RuleId -eq 'thread.unbacked-start')
        foreach ($f in $r) {
            $f.Evidence | Should -Match 'modules=(\d+)'
            [int]($f.Evidence -replace '(?s).*modules=(\d+).*', '$1') | Should -BeGreaterThan 1
        }
    }

    It 'honours -MaxThreads and keeps the inspected count separate from the thread total' {
        $r = @(Test-TcpkThreadStart -ProcessId $PID -MaxThreads 2)
        foreach ($f in ($r | Where-Object RuleId -eq 'thread.unbacked-start')) {
            $pair = Get-CheckedPair -Evidence $f.Evidence
            $pair | Should -Not -BeNullOrEmpty
            $pair.Checked | Should -BeLessOrEqual 2
            # The real thread total must still be carried, so a capped run cannot be read
            # as a full sweep of the process.
            $pair.Total | Should -BeGreaterOrEqual $pair.Checked
        }
    }

    It 'clamps a nonsensical -MaxThreads instead of throwing' {
        { Test-TcpkThreadStart -ProcessId $PID -MaxThreads 0 } | Should -Not -Throw
        { Test-TcpkThreadStart -ProcessId $PID -MaxThreads -5 } | Should -Not -Throw
        { Test-TcpkThreadStart -ProcessId $PID -MaxThreads 99999 } | Should -Not -Throw
    }

    It 'deduplicates by region so one region yields at most one finding' {
        $r = @(Test-TcpkThreadStart -ProcessId $PID | Where-Object RuleId -eq 'thread.unbacked-start')
        $regions = @($r | ForEach-Object {
            if ($_.Evidence -match 'region=(0x[0-9A-F]+)') { $matches[1] }
        })
        if ($regions.Count -gt 0) {
            @($regions | Sort-Object -Unique).Count | Should -Be $regions.Count
        }
    }

    It 'bounds the emitted findings and the per-finding thread sample' {
        $r = @(Test-TcpkThreadStart -ProcessId $PID | Where-Object RuleId -eq 'thread.unbacked-start')
        # At most 10 regions reported per process.
        $r.Count | Should -BeLessOrEqual 10
        foreach ($f in $r) {
            $tids = ''
            if ($f.Evidence -match 'tids=([\d,]*)') { $tids = $matches[1] }
            @($tids -split ',' | Where-Object { $_ }).Count | Should -BeLessOrEqual 8
        }
    }

    It 'attributes every finding to the inspected process' {
        $r = @(Test-TcpkThreadStart -ProcessId $PID | Where-Object RuleId -eq 'thread.unbacked-start')
        foreach ($f in $r) {
            $f.File | Should -Match "PID $PID"
            $f.Module | Should -Be 'runtime'
        }
    }

    It 'loads the Tcpk.ThreadStart primitive under a distinct type name' {
        # Must not be bolted onto Tcpk.ObjSec or Tcpk.MemRegions: those are guarded by an
        # -as [type] check, so a new method on an already-loaded type is ignored silently.
        $null = Test-TcpkThreadStart -ProcessId $PID
        ('Tcpk.ThreadStart' -as [type]) | Should -Not -BeNullOrEmpty
    }

    It 'returns a sentinel rather than throwing for a thread ID that does not exist' {
        $null = Test-TcpkThreadStart -ProcessId $PID
        $v = [Tcpk.ThreadStart]::GetStart(999999)
        # -1 OpenThread denied / no such thread, -2 query failed. Never a positive address.
        $v | Should -BeLessThan 0
    }

    It 'reads a real start address for a thread of the current process' {
        $null = Test-TcpkThreadStart -ProcessId $PID
        $tid = (Get-Process -Id $PID).Threads[0].Id
        $v = [Tcpk.ThreadStart]::GetStart([int]$tid)
        # Either a genuine address, or one of the DOCUMENTED sentinels. 0 (query
        # succeeded, null address) is one of them: the earlier form of this test
        # excluded 0 and so would have failed on a return the code calls legal.
        ($v -gt 0 -or $v -eq 0 -or $v -eq -1 -or $v -eq -2 -or $v -eq -3) | Should -BeTrue
    }

    It 'rejects a thread ID owned by another process instead of reading it' {
        # Thread IDs are recycled. If a TID captured in the snapshot has been reused by
        # another process by the time it is opened, its start address must NOT be read
        # and compared against this process's modules -- that manufactures an unbacked
        # thread out of nothing. The owner-scoped overload must return the -3 sentinel.
        $null = Test-TcpkThreadStart -ProcessId $PID
        $tid = [int](Get-Process -Id $PID).Threads[0].Id
        # Any value other than the real owner works: the check compares the owner
        # GetProcessIdOfThread reports against the one asked for, so whether this
        # number happens to be a live PID is irrelevant.
        $notOurPid = $PID + 1000000
        $v = [Tcpk.ThreadStart]::GetStart($tid, $notOurPid)
        $v | Should -Be -3
    }

    It 'reads the same address through the owner-scoped overload as the plain one' {
        # The owner check must gate the read, not alter it.
        $null = Test-TcpkThreadStart -ProcessId $PID
        $tid = [int](Get-Process -Id $PID).Threads[0].Id
        $plain = [Tcpk.ThreadStart]::GetStart($tid)
        $owned = [Tcpk.ThreadStart]::GetStart($tid, $PID)
        if ($plain -gt 0) { $owned | Should -Be $plain }
    }

    It 'labels counts as scoped to the inspected threads, never as process totals' {
        # A capped sweep must not present its own numbers as the process's numbers,
        # because an inflated count reads as a bigger problem than was observed.
        $r = @(Test-TcpkThreadStart -ProcessId $PID -MaxThreads 3 |
            Where-Object RuleId -eq 'thread.unbacked-start')
        foreach ($f in $r) {
            $f.Evidence | Should -Match 'unbacked-in-checked=\d+'
            $f.Evidence | Should -Match 'regions-in-checked=\d+'
            # The old 'unbacked-total' / 'regions-total' labels were counts over the
            # capped sample wearing the name of a process-wide total.
            $f.Evidence | Should -Not -Match 'unbacked-total'
            $f.Evidence | Should -Not -Match 'regions-total'
        }
    }

    It 'records whether the candidate survived the refreshed-module-list re-test' {
        $r = @(Test-TcpkThreadStart -ProcessId $PID |
            Where-Object RuleId -eq 'thread.unbacked-start')
        foreach ($f in $r) {
            $f.Evidence | Should -Match 'retested=(yes|no)'
        }
    }

    It 'accounts for threads whose start address could not be read' {
        $r = @(Test-TcpkThreadStart -ProcessId $PID |
            Where-Object RuleId -eq 'thread.unbacked-start')
        foreach ($f in $r) {
            $f.Evidence | Should -Match 'unreadable=\d+'
            $f.Evidence | Should -Match 'stale-tid=\d+'
            # Sentinels are counted, never turned into a reported address. -1/-2/-3
            # formatted with {0:X} as a [long] are the three values below.
            $f.Evidence | Should -Not -Match 'addrs=.*0xFFFFFFFFFFFFFFF[DEF]'
        }
    }

    It 'never reports more regions than it says it reported' {
        $r = @(Test-TcpkThreadStart -ProcessId $PID |
            Where-Object RuleId -eq 'thread.unbacked-start')
        foreach ($f in $r) {
            $f.Evidence | Should -Match 'regions-reported=(\d+) of (\d+)'
            $reported = [int]($f.Evidence -replace '(?s).*regions-reported=(\d+) of \d+.*', '$1')
            $reported | Should -BeLessOrEqual 10
            $reported | Should -Be $r.Count
        }
    }
}

Describe 'Test-TcpkThreadStart contract' {

    It 'is exported by the module' {
        Get-Command Test-TcpkThreadStart -Module TCPK -ErrorAction SilentlyContinue |
            Should -Not -BeNullOrEmpty
    }

    It 'exposes ByName and ById parameter sets plus MaxThreads' {
        $cmd = Get-Command Test-TcpkThreadStart -Module TCPK
        $cmd.Parameters.Keys | Should -Contain 'ProcessName'
        $cmd.Parameters.Keys | Should -Contain 'ProcessId'
        $cmd.Parameters.Keys | Should -Contain 'MaxThreads'
        @($cmd.ParameterSets.Name) | Should -Contain 'ByName'
        @($cmd.ParameterSets.Name) | Should -Contain 'ById'
    }

    It 'defaults MaxThreads to 200' {
        $src = Get-Content "$PSScriptRoot\..\Public\Runtime\Test-TcpkThreadStart.ps1" -Raw
        $src | Should -Match '\$MaxThreads\s*=\s*200'
    }

    It 'source is pure ASCII' {
        $bytes = [System.IO.File]::ReadAllBytes("$PSScriptRoot\..\Public\Runtime\Test-TcpkThreadStart.ps1")
        (@($bytes | Where-Object { $_ -gt 127 }).Count) | Should -Be 0
    }

    It 'documents the limits it cannot see past' {
        # The docstring overstating the code is the failure mode this guards against.
        $src = Get-Content "$PSScriptRoot\..\Public\Runtime\Test-TcpkThreadStart.ps1" -Raw
        $src | Should -Match 'THREAD_SET_INFORMATION'
        $src | Should -Match 'does not read the memory at the start address'
        $src | Should -Match 'not proof of a clean process'
    }

    It 'documents the reporting caps rather than silently truncating' {
        # The 10-region cap was applied in code but absent from the docstring, which
        # left a truncated report readable as a complete one.
        $src = Get-Content "$PSScriptRoot\..\Public\Runtime\Test-TcpkThreadStart.ps1" -Raw
        $src | Should -Match 'At most 10 regions are reported'
        $src | Should -Match 'unbacked-in-checked'
    }

    It 'documents the runtimes its JIT calibration does not cover' {
        # The JIT list is shared with Test-TcpkMemoryRegions so the two cannot drift.
        # That is a real false-positive gap and must be named, not left implied.
        $src = Get-Content "$PSScriptRoot\..\Public\Runtime\Test-TcpkThreadStart.ps1" -Raw
        $src | Should -Match 'mono-2\.0'
        $src | Should -Match 'jscript9\.dll'
        $src | Should -Match 'NOT calibrated'
    }

    It 'documents the thread-ID recycling guard' {
        $src = Get-Content "$PSScriptRoot\..\Public\Runtime\Test-TcpkThreadStart.ps1" -Raw
        $src | Should -Match 'GetProcessIdOfThread'
        $src | Should -Match 'recycles thread ID'
    }

    It 'keeps the JIT module list identical to Test-TcpkMemoryRegions' {
        # A divergence here means the two checks can disagree about whether a process
        # is a JIT host, which is exactly what the shared list exists to prevent.
        $mine  = Get-Content "$PSScriptRoot\..\Public\Runtime\Test-TcpkThreadStart.ps1" -Raw
        $other = Get-Content "$PSScriptRoot\..\Public\Runtime\Test-TcpkMemoryRegions.ps1" -Raw
        foreach ($m in @('clr.dll','coreclr.dll','clrjit.dll','mscorwks.dll','jvm.dll','node.dll','libnode.dll','libcef.dll','chrome_elf.dll')) {
            $q = "'" + $m + "'"
            $mine  | Should -BeLike "*$q*"
            $other | Should -BeLike "*$q*"
        }
    }

    It 'does not splice both parameters into the not-running title' {
        # "$ProcessName$ProcessId" renders as "notepad0" in the ByName set, because an
        # unbound [int] parameter is 0.
        $src = Get-Content "$PSScriptRoot\..\Public\Runtime\Test-TcpkThreadStart.ps1" -Raw
        $src | Should -Not -Match '\$ProcessName\$ProcessId'
    }

    It 'does not use loop flow control from inside a catch block' {
        $src = Get-Content "$PSScriptRoot\..\Public\Runtime\Test-TcpkThreadStart.ps1" -Raw
        $src | Should -Not -Match 'catch\s*\{\s*(continue|break)\s*\}'
    }

    It 'source has no PowerShell 6+ only syntax' {
        # Target is Windows PowerShell 5.1. These all parse-fail or misbehave there.
        $src = Get-Content "$PSScriptRoot\..\Public\Runtime\Test-TcpkThreadStart.ps1" -Raw
        $src | Should -Not -Match '\?\?'
        $src | Should -Not -Match '(?m)^\s*[^#]*-Parallel\b'
        $src | Should -Not -Match '\.Where\{'
        $src | Should -Not -Match '\.ForEach\{'
    }

    It 'assigns no automatic variable' {
        $src = Get-Content "$PSScriptRoot\..\Public\Runtime\Test-TcpkThreadStart.ps1" -Raw
        # $host is read-only and assigning it throws. This has bitten the codebase before.
        $src | Should -Not -Match '(?i)\$(host|input|error|args|matches|this|pwd|home|pid)\s*='
    }

    It 'parses under the PowerShell parser with no errors' {
        $path = "$PSScriptRoot\..\Public\Runtime\Test-TcpkThreadStart.ps1"
        $errs = $null
        $null = [System.Management.Automation.Language.Parser]::ParseFile($path, [ref]$null, [ref]$errs)
        @($errs).Count | Should -Be 0
    }
}

Describe 'Test-TcpkThreadStart off Windows' -Skip:($env:OS -eq 'Windows_NT') {
    It 'emits nothing and does not throw' {
        $r = @(Test-TcpkThreadStart -ProcessId 1 -WarningAction SilentlyContinue)
        $r.Count | Should -Be 0
    }
}
