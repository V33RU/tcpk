#requires -Version 5.1
# Pester 5: thread DACL, token DACL and UAC virtualization checks. All three read kernel
# object security descriptors, so they are Windows-only and skip cleanly elsewhere.
# The SDDL parsing helper is tested directly with synthetic descriptors, which is the part
# that decides whether a finding fires at all.

BeforeDiscovery {
    $script:isWin = ($env:OS -eq 'Windows_NT')
}

BeforeAll {
    Import-Module "$PSScriptRoot\..\TCPK.psd1" -Force
}

Describe 'Get-TcpkSddlLowPrivGrants' {
    It 'flags a grant to a low-privilege well-known SID' {
        InModuleScope TCPK {
            # D:(A;;0x0010;;;S-1-5-32-545)  = allow Users THREAD_SET_CONTEXT
            $g = @(Get-TcpkSddlLowPrivGrants -Sddl 'D:(A;;0x00000010;;;S-1-5-32-545)' `
                    -RightsMap ([ordered]@{ SET_CONTEXT = 0x0010 }))
            $g.Count | Should -Be 1
            $g[0].Sid | Should -Be 'S-1-5-32-545'
            $g[0].Granted | Should -Contain 'SET_CONTEXT'
        }
    }

    It 'ignores a grant to a non low-privilege SID' {
        InModuleScope TCPK {
            # SYSTEM holding full control is normal, not a finding.
            $g = @(Get-TcpkSddlLowPrivGrants -Sddl 'D:(A;;0x001F03FF;;;S-1-5-18)' `
                    -RightsMap ([ordered]@{ ALL_ACCESS = 0x1F03FF }))
            $g.Count | Should -Be 0
        }
    }

    It 'ignores a low-privilege grant that carries none of the dangerous rights' {
        InModuleScope TCPK {
            # 0x00020000 is READ_CONTROL only.
            $g = @(Get-TcpkSddlLowPrivGrants -Sddl 'D:(A;;0x00020000;;;S-1-5-32-545)' `
                    -RightsMap ([ordered]@{ SET_CONTEXT = 0x0010; ALL_ACCESS = 0x1F03FF }))
            $g.Count | Should -Be 0
        }
    }

    It 'ignores DENY aces' {
        InModuleScope TCPK {
            $g = @(Get-TcpkSddlLowPrivGrants -Sddl 'D:(D;;0x001F03FF;;;S-1-5-32-545)' `
                    -RightsMap ([ordered]@{ ALL_ACCESS = 0x1F03FF }))
            $g.Count | Should -Be 0
        }
    }

    It 'returns empty rather than throwing on malformed or empty SDDL' {
        InModuleScope TCPK {
            @(Get-TcpkSddlLowPrivGrants -Sddl '' -RightsMap ([ordered]@{ X = 1 })).Count | Should -Be 0
            @(Get-TcpkSddlLowPrivGrants -Sddl 'not-an-sddl' -RightsMap ([ordered]@{ X = 1 })).Count | Should -Be 0
        }
    }
}

Describe 'Test-TcpkThreadDacl' -Skip:(-not $script:isWin) {
    It 'runs against the current process without throwing' {
        { Test-TcpkThreadDacl -ProcessId $PID } | Should -Not -Throw
    }

    It 'emits only known rule IDs' {
        foreach ($f in @(Test-TcpkThreadDacl -ProcessId $PID)) {
            $f.RuleId | Should -BeIn @('thread.dacl-hijackable', 'thread.dacl-unreadable', 'thread-dacl.unavailable')
        }
    }
}

Describe 'Test-TcpkTokenDacl' -Skip:(-not $script:isWin) {
    It 'runs against the current process without throwing' {
        { Test-TcpkTokenDacl -ProcessId $PID } | Should -Not -Throw
    }

    It 'emits only known rule IDs' {
        foreach ($f in @(Test-TcpkTokenDacl -ProcessId $PID)) {
            $f.RuleId | Should -BeIn @('token.dacl-weak', 'token.dacl-unreadable', 'token-dacl.unavailable')
        }
    }
}

Describe 'Test-TcpkProcessVirtualization' -Skip:(-not $script:isWin) {
    It 'reads the virtualization state of the current process' {
        $r = @(Test-TcpkProcessVirtualization -ProcessId $PID)
        foreach ($f in $r) {
            $f.RuleId | Should -BeIn @('virtualization.enabled', 'virtualization.allowed',
                                       'virtualization.unreadable', 'virtualization.unavailable')
        }
    }

    It 'does not report virtualization enabled for a 64-bit manifested host' {
        # PowerShell ships a manifest with a requestedExecutionLevel, so the shim must not
        # apply. A hit here would mean the packed return value is being decoded wrong.
        if ([Environment]::Is64BitProcess) {
            $r = @(Test-TcpkProcessVirtualization -ProcessId $PID | Where-Object RuleId -eq 'virtualization.enabled')
            $r.Count | Should -Be 0
        }
    }
}

Describe 'thread / token / virtualization rule IDs are registered' {
    It 'maps <_> to an ATT&CK technique and a TASVS control' -ForEach @(
        'thread.dacl-hijackable'
        'token.dacl-weak'
        'virtualization.enabled'
        'virtualization.allowed'
    ) {
        $rid = $_
        $tech = & (Get-Module TCPK) { param($r) Get-TcpkAttackTechnique -RuleId $r } $rid
        @($tech).Count | Should -BeGreaterThan 0 -Because "$rid must map to an ATT&CK technique"
        $ctl = & (Get-Module TCPK) { param($r) Get-TcpkTasvsControl -RuleId $r } $rid
        @($ctl).Count | Should -BeGreaterThan 0 -Because "$rid must map to a TASVS control"
    }

    It 'maps thread hijacking to T1055.003 and token abuse to T1134' {
        $t = & (Get-Module TCPK) { Get-TcpkAttackTechnique -RuleId 'thread.dacl-hijackable' }
        ($t -join ' ') | Should -Match 'T1055\.003'
        $k = & (Get-Module TCPK) { Get-TcpkAttackTechnique -RuleId 'token.dacl-weak' }
        ($k -join ' ') | Should -Match 'T1134'
    }
}
