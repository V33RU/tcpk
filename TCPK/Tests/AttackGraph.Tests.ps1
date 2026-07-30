#requires -Version 5.1
# Pester 5: Get-TcpkAttackGraph correlates findings into entry->primitive->goal paths and a
# Mermaid diagram, including the GhostTree evasion path. Offline, reasons over findings only.

BeforeAll {
    $psd1 = Join-Path (Split-Path (Split-Path $PSCommandPath -Parent) -Parent) 'TCPK.psd1'
    Import-Module $psd1 -Force
    function New-F($rid, $sev) {
        & (Get-Module TCPK) { param($r, $s) New-TcpkFinding -Module 'x' -RuleId $r -Severity $s -Confidence 'Confirmed' -Title $r -File 'f' } $rid $sev
    }
}

Describe 'Get-TcpkAttackGraph' {
    It 'reaches RCE from a URI handler + a code-exec sink' {
        $g = @(@((New-F 'protocol-handler.registered' 'MEDIUM'), (New-F 'callsites.command-execution' 'HIGH')) | Get-TcpkAttackGraph)
        $rce = $g | Where-Object { $_.RuleId -eq 'attackgraph.reachable-goal' -and $_.Title -match 'Code execution' }
        $rce | Should -Not -BeNullOrEmpty
        $rce.Severity | Should -Be 'CRITICAL'
    }
    It 'reaches SYSTEM from a writable privileged binary alone' {
        $g = @(@((New-F 'service.writable-binary' 'HIGH')) | Get-TcpkAttackGraph)
        ($g | Where-Object { $_.RuleId -eq 'attackgraph.reachable-goal' -and $_.Title -match 'SYSTEM' }) | Should -Not -BeNullOrEmpty
    }
    It 'reaches credential theft from an exposed secret + a reachable backend' {
        $g = @(@((New-F 'browser.master-key-recovered' 'HIGH'), (New-F 'intercept.endpoint-confirmed' 'INFO')) | Get-TcpkAttackGraph)
        ($g | Where-Object { $_.RuleId -eq 'attackgraph.reachable-goal' -and $_.Title -match 'Credential' }) | Should -Not -BeNullOrEmpty
    }
    It 'models the GhostTree evasion path (writable load dir + recursive junction -> RCE, hides edge)' {
        $g = @(@((New-F 'acl.user-writable' 'MEDIUM'), (New-F 'reparse.recursive-junction' 'HIGH')) | Get-TcpkAttackGraph)
        ($g | Where-Object { $_.RuleId -eq 'attackgraph.reachable-goal' -and $_.Title -match 'Code execution' }) | Should -Not -BeNullOrEmpty
        $render = $g | Where-Object RuleId -eq 'attackgraph.render'
        $render.Description | Should -Match 'GhostTree'
        $render.Description | Should -Match '-\.->\|hides\|'          # the dashed evasion edge
        $render.Description | Should -Match 'flowchart'
    }
    It 'emits attackgraph.no-path when nothing correlates end to end' {
        $g = @(@((New-F 'entropy.high-entropy-string' 'LOW')) | Get-TcpkAttackGraph)
        ($g | Where-Object RuleId -eq 'attackgraph.reachable-goal') | Should -BeNullOrEmpty
        ($g | Where-Object RuleId -eq 'attackgraph.no-path') | Should -Not -BeNullOrEmpty
    }
    It 'does not build a path on a link the verifiers demoted to Likely-FP' {
        $demoted = & (Get-Module TCPK) { New-TcpkFinding -Module 'x' -RuleId 'callsites.command-execution' -Severity 'HIGH' -Confidence 'Likely-FP (LLM)' -Title 't' }
        $g = @(@((New-F 'protocol-handler.registered' 'MEDIUM'), $demoted) | Get-TcpkAttackGraph)
        ($g | Where-Object { $_.RuleId -eq 'attackgraph.reachable-goal' -and $_.Title -match 'Code execution' }) | Should -BeNullOrEmpty
    }
}
