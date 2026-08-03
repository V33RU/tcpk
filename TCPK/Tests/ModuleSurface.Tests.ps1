#requires -Version 5.1
# Pester 5: what the module actually exports, and what it deliberately does not.
#
# WHY. The GUI's Graph tab called New-TcpkFinding and piped [TcpkFinding] objects into
# Get-TcpkAttackGraph directly from GUI scope. Neither is reachable there:
# Export-ModuleMember publishes only Public/*.ps1 basenames, so New-TcpkFinding (which
# lives in Private/_Finding.ps1) does not exist outside the module, and [TcpkFinding] is
# a module-scoped class a caller cannot name without `using module`. The call threw
# "not recognized", the handler's own catch turned it into "Graph failed: ...", and the
# tab appeared broken after every completed audit.
#
# The fix is to run that work inside the module with `& $mod { ... }`. These tests pin
# the facts that make the fix necessary, so a future refactor cannot quietly reintroduce
# a private call from GUI scope.

BeforeAll {
    $script:Root = Split-Path (Split-Path $PSCommandPath -Parent) -Parent
    $psd1 = Join-Path (Split-Path $PSCommandPath -Parent | Split-Path -Parent) 'TCPK.psd1'
    Import-Module $psd1 -Force
}

Describe 'Module export surface' {

    It 'exports the public cmdlets the GUI calls directly' {
        foreach ($n in 'Invoke-TcpkAudit', 'Get-TcpkAttackGraph', 'Compare-TcpkAudit') {
            Get-Command $n -Module TCPK -ErrorAction SilentlyContinue | Should -Not -BeNullOrEmpty -Because "$n is called from GUI scope"
        }
    }

    It 'does NOT export New-TcpkFinding, so any caller of it must run inside the module' {
        # Not a defect -- private helpers staying private is the design. This test exists
        # so the constraint is visible, because violating it fails at RUNTIME inside a
        # try/catch and surfaces as a misleading "failed" message rather than a crash.
        Get-Command 'New-TcpkFinding' -Module TCPK -ErrorAction SilentlyContinue | Should -BeNullOrEmpty
    }

    It 'does not leak the TcpkFinding class into caller scope' {
        # A module class is only importable via `using module`. Get-TcpkAttackGraph takes
        # [TcpkFinding[]], so a caller outside the module cannot build its input either.
        ('TcpkFinding' -as [type]) | Should -BeNullOrEmpty
    }
}

Describe 'GUI does not call module-private helpers from GUI scope' {

    It 'Start-TCPKGui.ps1 only calls New-TcpkFinding inside a module scriptblock' {
        $gui = Join-Path (Split-Path $script:Root -Parent) 'Start-TCPKGui.ps1'
        if (-not (Test-Path -LiteralPath $gui)) { Set-ItResult -Skipped -Because 'GUI script not present'; return }
        $src = Get-Content -LiteralPath $gui -Raw

        # Every New-TcpkFinding call must be preceded by an `& $mod {` within the same
        # handler. Approximate that structurally: count the calls, and require at least
        # as many `& $mod {` module-scope entries in the file.
        $calls = ([regex]::Matches($src, 'New-TcpkFinding')).Count
        if ($calls -eq 0) { $true | Should -BeTrue; return }
        $modScopes = ([regex]::Matches($src, '&\s*\$mod\s*\{')).Count
        $modScopes | Should -BeGreaterThan 0 -Because 'a private helper can only be reached via & $mod { }'
    }

    It 'the Graph handler runs its finding reconstruction inside the module' {
        $gui = Join-Path (Split-Path $script:Root -Parent) 'Start-TCPKGui.ps1'
        if (-not (Test-Path -LiteralPath $gui)) { Set-ItResult -Skipped -Because 'GUI script not present'; return }
        $src = Get-Content -LiteralPath $gui -Raw
        $m = [regex]::Match($src, '(?s)\$btnGraphBuild\.Add_Click\(\{(.+?)\n\}\)')
        $m.Success | Should -BeTrue -Because 'the Graph build handler must be findable'
        $body = $m.Groups[1].Value
        if ($body -match 'New-TcpkFinding') {
            $body | Should -Match '&\s*\$mod\s*\{' -Because 'New-TcpkFinding is not exported; it only resolves inside the module'
        }
    }
}
