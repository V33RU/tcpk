#requires -Version 5.1
# ATT&CK / OWASP-TASVS map refresh + new exploit chains for the v2.6.x detection rule
# families (process token privileges, Electron IPC->sink, intercept response mining +
# tamper, URI activation, browser store decryption).

BeforeAll {
    $psd1 = Join-Path (Split-Path (Split-Path $PSCommandPath -Parent) -Parent) 'TCPK.psd1'
    Import-Module $psd1 -Force
}

Describe 'ATT&CK mapping for new rule families' {
    It 'maps <RuleId> to a technique containing <Tid>' -ForEach @(
        @{ RuleId = 'process.impactful-privileges'; Tid = 'T1134' }
        @{ RuleId = 'electron.ipc-handler-sink';    Tid = 'T1059' }
        @{ RuleId = 'intercept.token-in-response';  Tid = 'T1539' }
        @{ RuleId = 'intercept.tamper-accepted';    Tid = 'T1565' }
        @{ RuleId = 'protocol-handler';             Tid = 'T1204' }
        @{ RuleId = 'browser.master-key-recovered'; Tid = 'T1555.003' }
    ) {
        InModuleScope TCPK -Parameters @{ RuleId = $RuleId; Tid = $Tid } {
            param($RuleId, $Tid)
            (Get-TcpkAttackText -RuleId $RuleId) | Should -Match ([regex]::Escape($Tid))
        }
    }
}

Describe 'OWASP Desktop Top 10 mapping for new rule families' {
    It 'maps <RuleId> to <Da>' -ForEach @(
        @{ RuleId = 'electron.ipc-handler-sink';       Da = 'DA1' }
        @{ RuleId = 'process.impactful-privileges';    Da = 'DA5' }
        @{ RuleId = 'intercept.secret-in-response';    Da = 'DA7' }
        @{ RuleId = 'intercept.tamper-accepted';       Da = 'DA5' }
        @{ RuleId = 'protocol-handler';                Da = 'DA6' }
        @{ RuleId = 'browser.master-key-recovered';    Da = 'DA3' }
        @{ RuleId = 'crypto.hardcoded-key';            Da = 'DA4' }
    ) {
        InModuleScope TCPK -Parameters @{ RuleId = $RuleId; Da = $Da } {
            param($RuleId, $Da)
            (Get-TcpkOwaspDa -RuleId $RuleId) | Should -Match $Da
        }
    }
}

Describe 'New exploit chains' {
    BeforeAll {
        function New-F($rid, $sev) {
            & (Get-Module TCPK) { param($r, $s) New-TcpkFinding -Module 'x' -RuleId $r -Severity $s -Confidence 'Confirmed' -Title $r -File 'f' } $rid $sev
        }
    }

    It 'raises chain.impactful-priv-to-system from an impactful privilege + a code-exec sink' {
        $findings = @((New-F 'process.impactful-privileges' 'MEDIUM'), (New-F 'callsites.command-execution' 'HIGH'))
        $chains = $findings | Get-TcpkExploitChains
        ($chains | Where-Object { $_.RuleId -eq 'chain.impactful-priv-to-system' }) | Should -Not -BeNullOrEmpty
    }

    It 'raises chain.browser-store-session-theft from a recovered master key + a known backend' {
        $findings = @((New-F 'browser.master-key-recovered' 'HIGH'), (New-F 'intercept.endpoint-confirmed' 'INFO'))
        $chains = $findings | Get-TcpkExploitChains
        ($chains | Where-Object { $_.RuleId -eq 'chain.browser-store-session-theft' }) | Should -Not -BeNullOrEmpty
    }

    It 'raises chain.electron-renderer-to-main-rce from an IPC sink + weak isolation' {
        $findings = @((New-F 'electron.ipc-handler-sink' 'CRITICAL'), (New-F 'electron.insecure-default-nodeIntegration' 'CRITICAL'))
        $chains = $findings | Get-TcpkExploitChains
        $c = $chains | Where-Object { $_.RuleId -eq 'chain.electron-renderer-to-main-rce' }
        $c | Should -Not -BeNullOrEmpty
        $c.Severity | Should -Be 'CRITICAL'
    }

    It 'does NOT raise the Electron chain from an IPC sink alone (no weak-isolation link)' {
        $findings = @((New-F 'electron.ipc-handler-sink' 'CRITICAL'), (New-F 'electron.runtime-version' 'INFO'))
        $chains = $findings | Get-TcpkExploitChains
        ($chains | Where-Object { $_.RuleId -eq 'chain.electron-renderer-to-main-rce' }) | Should -BeNullOrEmpty
    }
}
