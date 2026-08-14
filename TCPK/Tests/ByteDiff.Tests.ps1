#requires -Version 5.1
# Pester 5: whole-file byte diff and difference navigation.
#
# The behaviour being pinned is the one the page-local overlay could not give: telling the
# difference between "no differences on this page" and "no differences in this file". The
# size-mismatch handling matters as much, because folding a length delta into the byte
# count would both drown a real difference and park Next-diff at the truncation point.

BeforeAll {
    $psd1 = Join-Path (Split-Path (Split-Path $PSCommandPath -Parent) -Parent) 'TCPK.psd1'
    Import-Module $psd1 -Force

    $script:work = Join-Path ([IO.Path]::GetTempPath()) ('tcpk-bdiff-' + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Force -Path $script:work | Out-Null

    function script:New-Bin([string]$name, [byte[]]$bytes) {
        $p = Join-Path $script:work $name
        [IO.File]::WriteAllBytes($p, $bytes)
        return $p
    }

    $base = New-Object 'byte[]' 4096
    for ($i = 0; $i -lt 4096; $i++) { $base[$i] = [byte]($i % 251) }

    $script:a = script:New-Bin 'a.bin' $base

    # Same length, differing at four known offsets.
    $mod = [byte[]]$base.Clone()
    foreach ($o in 5, 1000, 1001, 4095) { $mod[$o] = [byte](($mod[$o] + 1) % 256) }
    $script:b = script:New-Bin 'b.bin' $mod

    $script:same    = script:New-Bin 'same.bin' $base
    $script:longer  = script:New-Bin 'longer.bin'  ($base + (New-Object 'byte[]' 512))
    $script:shorter = script:New-Bin 'shorter.bin' $base[0..2047]
}

AfterAll {
    if ($script:work -and (Test-Path $script:work)) {
        Remove-Item $script:work -Recurse -Force -ErrorAction SilentlyContinue
    }
}

Describe 'Get-TcpkFileDiffSummary: identical files' {
    It 'reports Identical only when length AND content match' {
        InModuleScope TCPK -Parameters @{ a = $script:a; s = $script:same } {
            param($a, $s)
            $r = Get-TcpkFileDiffSummary -PathA $a -PathB $s
            $r.Identical | Should -BeTrue
            $r.DifferingBytes | Should -Be 0
            $r.FirstDifference | Should -Be ([int64]-1)
            $r.LengthDelta | Should -Be 0
        }
    }
}

Describe 'Get-TcpkFileDiffSummary: same length, real differences' {
    It 'counts every differing byte across the whole file' {
        InModuleScope TCPK -Parameters @{ a = $script:a; b = $script:b } {
            param($a, $b)
            $r = Get-TcpkFileDiffSummary -PathA $a -PathB $b
            $r.DifferingBytes | Should -Be 4
            $r.Identical | Should -BeFalse
        }
    }

    It 'reports the FIRST difference, not merely that one exists' {
        InModuleScope TCPK -Parameters @{ a = $script:a; b = $script:b } {
            param($a, $b)
            (Get-TcpkFileDiffSummary -PathA $a -PathB $b).FirstDifference | Should -Be 5
        }
    }

    It 'finds a difference that is nowhere near the first page' {
        # The page-local overlay reported "diff: 0 bytes" for every page before the change.
        InModuleScope TCPK -Parameters @{ w = $script:work } {
            param($w)
            $x = New-Object 'byte[]' 100000
            $y = [byte[]]$x.Clone()
            $y[90000] = 1
            $px = Join-Path $w 'far-a.bin'; $py = Join-Path $w 'far-b.bin'
            [IO.File]::WriteAllBytes($px, $x); [IO.File]::WriteAllBytes($py, $y)
            $r = Get-TcpkFileDiffSummary -PathA $px -PathB $py
            $r.DifferingBytes | Should -Be 1
            $r.FirstDifference | Should -Be 90000
            $r.Identical | Should -BeFalse
        }
    }
}

Describe 'Get-TcpkFileDiffSummary: size mismatch is its own fact' {
    It 'does NOT count the tail of the longer file as differing bytes' {
        InModuleScope TCPK -Parameters @{ a = $script:a; l = $script:longer } {
            param($a, $l)
            $r = Get-TcpkFileDiffSummary -PathA $a -PathB $l
            $r.DifferingBytes | Should -Be 0        # the common 4096 bytes are identical
            $r.LengthDelta | Should -Be 512
            $r.CommonLength | Should -Be 4096
            $r.Identical | Should -BeFalse          # still not the same file
        }
    }

    It 'reports a negative delta when the comparison file is shorter' {
        InModuleScope TCPK -Parameters @{ a = $script:a; sh = $script:shorter } {
            param($a, $sh)
            $r = Get-TcpkFileDiffSummary -PathA $a -PathB $sh
            $r.LengthDelta | Should -Be -2048
            $r.CommonLength | Should -Be 2048
            $r.DifferingBytes | Should -Be 0
        }
    }

    It 'flags a truncated scan rather than presenting it as complete' {
        InModuleScope TCPK -Parameters @{ a = $script:a; b = $script:b } {
            param($a, $b)
            $r = Get-TcpkFileDiffSummary -PathA $a -PathB $b -MaxScan 100
            $r.Truncated | Should -BeTrue
            $r.Identical | Should -BeFalse    # never "identical" off a partial scan
            $r.Scanned | Should -Be 100
        }
    }
}

Describe 'Find-TcpkByteDifference: forward' {
    It 'finds each difference in turn when stepping from current+1' {
        InModuleScope TCPK -Parameters @{ a = $script:a; b = $script:b } {
            param($a, $b)
            $o1 = Find-TcpkByteDifference -PathA $a -PathB $b -From 0
            $o2 = Find-TcpkByteDifference -PathA $a -PathB $b -From ($o1 + 1)
            $o3 = Find-TcpkByteDifference -PathA $a -PathB $b -From ($o2 + 1)
            $o4 = Find-TcpkByteDifference -PathA $a -PathB $b -From ($o3 + 1)
            $o1 | Should -Be 5
            $o2 | Should -Be 1000
            $o3 | Should -Be 1001
            $o4 | Should -Be 4095
        }
    }

    It 'returns -1 once past the last difference' {
        InModuleScope TCPK -Parameters @{ a = $script:a; b = $script:b } {
            param($a, $b)
            Find-TcpkByteDifference -PathA $a -PathB $b -From 4096 | Should -Be ([int64]-1)
        }
    }

    It 'returns -1 for identical files' {
        InModuleScope TCPK -Parameters @{ a = $script:a; s = $script:same } {
            param($a, $s)
            Find-TcpkByteDifference -PathA $a -PathB $s -From 0 | Should -Be ([int64]-1)
        }
    }
}

Describe 'Find-TcpkByteDifference: backward' {
    It 'finds the NEAREST preceding difference, not the earliest' {
        InModuleScope TCPK -Parameters @{ a = $script:a; b = $script:b } {
            param($a, $b)
            Find-TcpkByteDifference -PathA $a -PathB $b -From 4095 -Backward | Should -Be 4095
            Find-TcpkByteDifference -PathA $a -PathB $b -From 4094 -Backward | Should -Be 1001
            Find-TcpkByteDifference -PathA $a -PathB $b -From 1000 -Backward | Should -Be 1000
            Find-TcpkByteDifference -PathA $a -PathB $b -From 999  -Backward | Should -Be 5
        }
    }

    It 'returns -1 before the first difference' {
        InModuleScope TCPK -Parameters @{ a = $script:a; b = $script:b } {
            param($a, $b)
            Find-TcpkByteDifference -PathA $a -PathB $b -From 4 -Backward | Should -Be ([int64]-1)
        }
    }

    It 'crosses chunk windows to find a distant preceding difference' {
        # >1 MB apart, so the backward walk must step through several windows and still
        # return the nearest one rather than the first it stumbles on.
        InModuleScope TCPK -Parameters @{ w = $script:work } {
            param($w)
            $n = 3000000
            $x = New-Object 'byte[]' $n
            $y = [byte[]]$x.Clone()
            $y[100] = 1; $y[2500000] = 1
            $px = Join-Path $w 'wide-a.bin'; $py = Join-Path $w 'wide-b.bin'
            [IO.File]::WriteAllBytes($px, $x); [IO.File]::WriteAllBytes($py, $y)
            Find-TcpkByteDifference -PathA $px -PathB $py -From ($n - 1) -Backward | Should -Be 2500000
            Find-TcpkByteDifference -PathA $px -PathB $py -From 2499999 -Backward | Should -Be 100
        }
    }
}

Describe 'Find-TcpkByteDifference: never navigates into the size-mismatch tail' {
    It 'ignores bytes past the shorter file rather than stopping there forever' {
        InModuleScope TCPK -Parameters @{ a = $script:a; l = $script:longer } {
            param($a, $l)
            # common prefix is identical, so there is NO difference to navigate to even
            # though the files are 512 bytes apart in length
            Find-TcpkByteDifference -PathA $a -PathB $l -From 0 | Should -Be ([int64]-1)
            Find-TcpkByteDifference -PathA $a -PathB $l -From 5000 -Backward | Should -Be ([int64]-1)
        }
    }
}

Describe 'Find-TcpkByteDifference: bad input' {
    It 'returns -1 for a missing file instead of throwing' {
        InModuleScope TCPK -Parameters @{ a = $script:a; w = $script:work } {
            param($a, $w)
            Find-TcpkByteDifference -PathA $a -PathB (Join-Path $w 'nope.bin') -From 0 | Should -Be ([int64]-1)
        }
    }
}
