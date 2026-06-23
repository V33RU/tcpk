#requires -Version 5.1
# Detection benchmark gate (v1.8.x credibility slice): runs the curated corpus in bench/ and
# asserts precision/recall stay perfect on it -- so a regression that starts missing a planted
# bug (recall drop) or flagging a clean/placeholder fixture (precision drop) fails the suite.

BeforeAll {
    # ...\TCPK\Tests\Benchmark.Tests.ps1 -> repo root is three levels up
    $repoRoot = Split-Path (Split-Path (Split-Path $PSCommandPath -Parent) -Parent) -Parent
    $script:bench = Join-Path $repoRoot 'bench\Invoke-TcpkBenchmark.ps1'
    $script:res = & $script:bench
}

Describe 'TCPK detection benchmark' {
    It 'runs the curated corpus' {
        $script:res.Cases | Should -BeGreaterThan 0
    }
    It 'catches every planted vulnerability (recall = 1.0)' {
        $script:res.FN | Should -Be 0
        $script:res.Recall | Should -Be 1.0
    }
    It 'flags nothing on clean / placeholder fixtures (precision = 1.0)' {
        $script:res.FP | Should -Be 0
        $script:res.Precision | Should -Be 1.0
    }
    It 'writes a scorecard' {
        Test-Path -LiteralPath $script:res.Scorecard | Should -BeTrue
    }
}
