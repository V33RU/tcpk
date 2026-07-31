#requires -Version 5.1
# Pester 5: scan-coverage accounting. The safe walker drops unreadable, depth-capped and
# reparse subtrees. Before this existed all three were silent, so a scan that read a fraction
# of the target was indistinguishable from a complete one. These tests prove the counters
# move and that the finding only appears when something was actually skipped.

BeforeDiscovery {
    # Reparse assertions need the ability to create a link. Linux always can; Windows needs
    # Developer Mode or admin for symlinks. Probe at discovery time because -Skip is
    # evaluated then.
    $script:hasLink = $false
    $t = Join-Path ([System.IO.Path]::GetTempPath()) ('tcpk-cov-t-' + [guid]::NewGuid().ToString('N').Substring(0, 6))
    $p = Join-Path ([System.IO.Path]::GetTempPath()) ('tcpk-cov-p-' + [guid]::NewGuid().ToString('N').Substring(0, 6))
    New-Item -ItemType Directory -Path $t -Force | Out-Null
    try { New-Item -ItemType SymbolicLink -Path $p -Target $t -ErrorAction Stop | Out-Null; $script:hasLink = $true } catch {}
    Remove-Item -LiteralPath $p -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $t -Recurse -Force -ErrorAction SilentlyContinue
}

BeforeAll {
    Import-Module "$PSScriptRoot\..\TCPK.psd1" -Force
}

Describe 'scan-coverage counters' {
    It 'counts directories walked on a clean tree and skips nothing' {
        $root = Join-Path ([System.IO.Path]::GetTempPath()) ('tcpk-cov-clean-' + [guid]::NewGuid().ToString('N').Substring(0, 8))
        New-Item -ItemType Directory -Path (Join-Path $root 'a\b') -Force | Out-Null
        Set-Content -LiteralPath (Join-Path $root 'a\b\f.txt') -Value 'x'
        try {
            InModuleScope TCPK -Parameters @{ r = $root } {
                param($r)
                Reset-TcpkScanStats
                $null = @(Get-TcpkChildItemSafe -Path $r -File)
                $s = Get-TcpkScanStats
                $s.DirsWalked         | Should -BeGreaterThan 0
                $s.UnreadableCount    | Should -Be 0
                $s.DepthSkippedCount  | Should -Be 0
            }
        } finally { Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue }
    }

    It 'counts subtrees dropped by the depth cap' {
        $root = Join-Path ([System.IO.Path]::GetTempPath()) ('tcpk-cov-depth-' + [guid]::NewGuid().ToString('N').Substring(0, 8))
        New-Item -ItemType Directory -Path (Join-Path $root 'l1\l2\l3') -Force | Out-Null
        try {
            InModuleScope TCPK -Parameters @{ r = $root } {
                param($r)
                Reset-TcpkScanStats
                # MaxDepth 1 means the walk stops before descending past the first level.
                $null = @(Get-TcpkChildItemSafe -Path $r -File -MaxDepth 1)
                (Get-TcpkScanStats).DepthSkippedCount | Should -BeGreaterThan 0
            }
        } finally { Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue }
    }

    It 'counts reparse points it refuses to follow' -Skip:(-not $script:hasLink) {
        $root = Join-Path ([System.IO.Path]::GetTempPath()) ('tcpk-cov-rp-' + [guid]::NewGuid().ToString('N').Substring(0, 8))
        New-Item -ItemType Directory -Path (Join-Path $root 'real') -Force | Out-Null
        New-Item -ItemType SymbolicLink -Path (Join-Path $root 'link') -Target (Join-Path $root 'real') -ErrorAction SilentlyContinue | Out-Null
        try {
            InModuleScope TCPK -Parameters @{ r = $root } {
                param($r)
                Reset-TcpkScanStats
                $null = @(Get-TcpkChildItemSafe -Path $r -File)
                (Get-TcpkScanStats).ReparseSkippedCount | Should -BeGreaterThan 0
            }
        } finally { Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue }
    }

    It 'caps the stored sample so a pathological tree cannot balloon memory' {
        InModuleScope TCPK {
            Reset-TcpkScanStats
            for ($i = 0; $i -lt 200; $i++) { Add-TcpkScanSkip -Kind 'Unreadable' -ItemPath "C:\fake\$i" }
            $s = Get-TcpkScanStats
            $s.UnreadableCount        | Should -Be 200
            $s.UnreadableSample.Count | Should -BeLessOrEqual 25
        }
    }
}

Describe 'Test-TcpkScanCoverage' {
    It 'emits nothing when the walk skipped nothing' {
        InModuleScope TCPK { Reset-TcpkScanStats }
        @(Test-TcpkScanCoverage).Count | Should -Be 0
    }

    It 'reports LOW with the count when directories were unreadable' {
        InModuleScope TCPK {
            Reset-TcpkScanStats
            Add-TcpkScanSkip -Kind 'Unreadable' -ItemPath 'C:\Program Files\WindowsApps\Some.Pkg'
        }
        $f = @(Test-TcpkScanCoverage)
        $f.Count            | Should -Be 1
        $f[0].RuleId        | Should -Be 'scan.incomplete-coverage'
        $f[0].Severity      | Should -Be 'LOW'
        $f[0].Evidence      | Should -Match 'unreadable'
    }

    It 'stays INFO when only deliberate limits fired' {
        InModuleScope TCPK {
            Reset-TcpkScanStats
            Add-TcpkScanSkip -Kind 'Reparse' -ItemPath 'C:\App\link'
        }
        $f = @(Test-TcpkScanCoverage)
        $f.Count       | Should -Be 1
        $f[0].Severity | Should -Be 'INFO'
    }
}

Describe 'scan rule ID is registered in the mapping tables' {
    It 'maps scan.incomplete-coverage to an ATT&CK technique and a TASVS control' {
        $tech = & (Get-Module TCPK) { Get-TcpkAttackTechnique -RuleId 'scan.incomplete-coverage' }
        @($tech).Count | Should -BeGreaterThan 0
        $ctl = & (Get-Module TCPK) { Get-TcpkTasvsControl -RuleId 'scan.incomplete-coverage' }
        @($ctl).Count | Should -BeGreaterThan 0
    }
}
