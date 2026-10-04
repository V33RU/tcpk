#requires -Version 5.1
# Pester 5: Get-TcpkAttackGraph correlates findings into entry->primitive->goal paths and a
# Mermaid diagram, including the GhostTree evasion path. Offline, reasons over findings only.

BeforeAll {
    $psd1 = Join-Path (Split-Path (Split-Path $PSCommandPath -Parent) -Parent) 'TCPK.psd1'
    Import-Module $psd1 -Force
    function New-F($rid, $sev) {
        & (Get-Module TCPK) { param($r, $s) New-TcpkFinding -Module 'x' -RuleId $r -Severity $s -Confidence 'Confirmed' -Title $r -File 'f' } $rid $sev
    }
    function New-FP($rid, $sev, $file, $subject) {
        & (Get-Module TCPK) { param($r,$s,$fl,$su) New-TcpkFinding -Module 'x' -RuleId $r -Severity $s -Confidence 'Confirmed' -Title $r -File $fl -Subject $su } $rid $sev $file $subject
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

Describe 'Privileged-writer join (relational, not presence)' {

    # The sound half of the arbitrary-file-write class: a SYSTEM process whose image sits in
    # a user-writable directory. Proven by path containment, so co-presence of an unrelated
    # ProgramData folder does NOT trigger it.

    It 'raises CRITICAL when the SYSTEM image is inside a user-writable dir' {
        $priv = New-FP 'process.running-as-system' 'HIGH' 'svc.exe (PID 4)' 'C:\Program Files\App\svc.exe'
        $wr   = New-FP 'install-dir.user-writable' 'MEDIUM' 'C:\Program Files\App' 'C:\Program Files\App'
        $g = @(@($priv, $wr) | Get-TcpkAttackGraph)
        ($g | Where-Object { $_.RuleId -eq 'attackgraph.privileged-writable-image' }) | Should -Not -BeNullOrEmpty
        ($g | Where-Object { $_.RuleId -eq 'attackgraph.privileged-writable-image' })[0].Severity | Should -Be 'CRITICAL'
    }

    It 'does NOT fire for a SYSTEM process + an unrelated writable ProgramData dir' {
        # The flood case the presence recipe was kept from doing. No containment -> no match.
        $priv = New-FP 'process.running-as-system' 'HIGH' 'svc.exe (PID 4)' 'C:\Program Files\App\svc.exe'
        $wr   = New-FP 'acl.programdata-user-writable' 'HIGH' 'C:\ProgramData\Other' 'C:\ProgramData\Other'
        $g = @(@($priv, $wr) | Get-TcpkAttackGraph)
        ($g | Where-Object { $_.RuleId -eq 'attackgraph.privileged-writable-image' }) | Should -BeNullOrEmpty
    }

    It 'does NOT fire when the privileged finding has no image path' {
        $priv = New-F 'process.running-as-system' 'HIGH'
        $wr   = New-FP 'install-dir.user-writable' 'MEDIUM' 'C:\Program Files\App' 'C:\Program Files\App'
        $g = @(@($priv, $wr) | Get-TcpkAttackGraph)
        ($g | Where-Object { $_.RuleId -eq 'attackgraph.privileged-writable-image' }) | Should -BeNullOrEmpty
    }
}
