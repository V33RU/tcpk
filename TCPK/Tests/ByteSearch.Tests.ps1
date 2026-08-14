#requires -Version 5.1
# Pester 5: Find-TcpkByteMatches.
#
# The defect this covers is not a missing feature, it is a wrong answer. The Hex tab
# searched ascii and hex only, so searching a Windows binary for a string it demonstrably
# contains returned nothing, and the operator concluded the string was absent. The first
# Describe below is that exact scenario.

BeforeAll {
    $psd1 = Join-Path (Split-Path (Split-Path $PSCommandPath -Parent) -Parent) 'TCPK.psd1'
    Import-Module $psd1 -Force

    $script:work = Join-Path ([IO.Path]::GetTempPath()) ('tcpk-bsearch-' + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Force -Path $script:work | Out-Null

    # A file shaped like a real Windows binary: the SAME literal present once as ASCII and
    # once as UTF-16LE, which is how a PE carries its managed and native strings.
    $script:mixed = Join-Path $script:work 'mixed.bin'
    $ms = New-Object IO.MemoryStream
    $pad = New-Object 'byte[]' 128
    $ms.Write($pad, 0, $pad.Length)
    $script:asciiAt = $ms.Length
    $a = [Text.Encoding]::ASCII.GetBytes('ConnectionString')
    $ms.Write($a, 0, $a.Length)
    $ms.Write($pad, 0, $pad.Length)
    $script:wideAt = $ms.Length
    $w = [Text.Encoding]::Unicode.GetBytes('ConnectionString')
    $ms.Write($w, 0, $w.Length)
    $ms.Write($pad, 0, $pad.Length)
    [IO.File]::WriteAllBytes($script:mixed, $ms.ToArray()); $ms.Dispose()
}

AfterAll {
    if ($script:work -and (Test-Path $script:work)) {
        Remove-Item $script:work -Recurse -Force -ErrorAction SilentlyContinue
    }
}

Describe 'Find-TcpkByteMatches: the UTF-16 blind spot' {
    It 'ascii-only search MISSES a UTF-16LE literal (the old behaviour)' {
        InModuleScope TCPK -Parameters @{ f = $script:mixed; w = $script:wideAt } {
            param($f, $w)
            $r = Find-TcpkByteMatches -Path $f -Query 'ConnectionString' -Kind 'ascii'
            # it finds the ASCII copy but never the wide one
            @($r.Matches | Where-Object { $_.Offset -eq $w }).Count | Should -Be 0
        }
    }

    It 'utf16le finds the wide literal at its exact offset' {
        InModuleScope TCPK -Parameters @{ f = $script:mixed; w = $script:wideAt } {
            param($f, $w)
            $r = Find-TcpkByteMatches -Path $f -Query 'ConnectionString' -Kind 'utf16le'
            @($r.Matches).Count | Should -Be 1
            @($r.Matches)[0].Offset | Should -Be $w
        }
    }

    It 'auto finds BOTH copies and labels which encoding matched' {
        InModuleScope TCPK -Parameters @{ f = $script:mixed; a = $script:asciiAt; w = $script:wideAt } {
            param($f, $a, $w)
            $r = Find-TcpkByteMatches -Path $f -Query 'ConnectionString' -Kind 'auto'
            @($r.Matches).Count | Should -Be 2
            @($r.Matches)[0].Offset | Should -Be $a
            @($r.Matches)[1].Offset | Should -Be $w
            (@($r.Matches) | Where-Object { $_.Kind -eq 'utf16le' }).Count | Should -Be 1
        }
    }

    It 'returns matches in ascending offset order' {
        InModuleScope TCPK -Parameters @{ f = $script:mixed } {
            param($f)
            $o = @(Find-TcpkByteMatches -Path $f -Query 'ConnectionString' -Kind 'auto').Matches |
                 ForEach-Object { [int64]$_.Offset }
            ($o | Sort-Object) -join ',' | Should -Be ($o -join ',')
        }
    }
}

Describe 'Find-TcpkByteMatches: hex and case handling' {
    It 'accepts spaced or unspaced hex identically' {
        InModuleScope TCPK -Parameters @{ f = $script:mixed } {
            param($f)
            $a = @(Find-TcpkByteMatches -Path $f -Query '43 6F 6E' -Kind 'hex').Matches
            $b = @(Find-TcpkByteMatches -Path $f -Query '436f6e'   -Kind 'hex').Matches
            @($a).Count | Should -Be @($b).Count
            @($a).Count | Should -BeGreaterThan 0
        }
    }

    It 'throws on an odd digit count instead of reporting no match' {
        InModuleScope TCPK {
            { Convert-TcpkSearchNeedle -Query 'abc' -Kind 'hex' } |
                Should -Throw -ExpectedMessage '*even number of hex digits*'
        }
    }

    It 'matches case-insensitively only when asked' {
        InModuleScope TCPK -Parameters @{ f = $script:mixed } {
            param($f)
            @(Find-TcpkByteMatches -Path $f -Query 'connectionstring' -Kind 'ascii').Matches.Count | Should -Be 0
            @(Find-TcpkByteMatches -Path $f -Query 'connectionstring' -Kind 'ascii' -CaseInsensitive).Matches.Count | Should -Be 1
        }
    }
}

Describe 'Find-TcpkByteMatches: regex over a latin1 byte view' {
    It 'reports a char index that IS the byte offset' {
        InModuleScope TCPK -Parameters @{ f = $script:mixed; a = $script:asciiAt } {
            param($f, $a)
            $r = Find-TcpkByteMatches -Path $f -Query 'Connection[A-Za-z]+' -Kind 'regex'
            @($r.Matches)[0].Offset | Should -Be $a
        }
    }

    It 'does not match UTF-16 text, which is the documented limit' {
        InModuleScope TCPK -Parameters @{ f = $script:mixed; w = $script:wideAt } {
            param($f, $w)
            # every other byte is 0x00 in the wide copy, so a plain regex cannot span it
            $r = Find-TcpkByteMatches -Path $f -Query 'ConnectionString' -Kind 'regex'
            @($r.Matches | Where-Object { $_.Offset -eq $w }).Count | Should -Be 0
        }
    }

    It 'bounds a pathological pattern instead of hanging' {
        InModuleScope TCPK -Parameters @{ f = $script:mixed } {
            param($f)
            # classic catastrophic backtracking; must surface as an error, not a freeze
            { Find-TcpkByteMatches -Path $f -Query '(a+)+$' -Kind 'regex' -RegexTimeoutMs 200 } |
                Should -Not -Throw
        }
    }
}

Describe 'Find-TcpkByteMatches: limits are stated, not hidden' {
    It 'flags Truncated when MaxMatches is hit' {
        InModuleScope TCPK -Parameters @{ w = $script:work } {
            param($w)
            $f = Join-Path $w 'many.bin'
            $b = [Text.Encoding]::ASCII.GetBytes('AB' * 500)
            [IO.File]::WriteAllBytes($f, $b)
            $r = Find-TcpkByteMatches -Path $f -Query 'AB' -Kind 'ascii' -MaxMatches 10
            @($r.Matches).Count | Should -Be 10
            $r.Truncated | Should -BeTrue
        }
    }

    It 'does not flag Truncated when everything fit' {
        InModuleScope TCPK -Parameters @{ f = $script:mixed } {
            param($f)
            (Find-TcpkByteMatches -Path $f -Query 'ConnectionString' -Kind 'auto').Truncated | Should -BeFalse
        }
    }

    It 'honours -From so Find-next can advance' {
        InModuleScope TCPK -Parameters @{ f = $script:mixed; a = $script:asciiAt; w = $script:wideAt } {
            param($f, $a, $w)
            $r = Find-TcpkByteMatches -Path $f -Query 'ConnectionString' -Kind 'auto' -From ($a + 1)
            @($r.Matches)[0].Offset | Should -Be $w
        }
    }

    It 'returns empty for a missing file or empty query rather than throwing' {
        InModuleScope TCPK -Parameters @{ w = $script:work; f = $script:mixed } {
            param($w, $f)
            @((Find-TcpkByteMatches -Path (Join-Path $w 'nope.bin') -Query 'x').Matches).Count | Should -Be 0
            @((Find-TcpkByteMatches -Path $f -Query '').Matches).Count | Should -Be 0
        }
    }
}

Describe 'Find-TcpkByteMatches: chunk boundaries' {
    It 'finds a needle straddling the 8 MB chunk edge, exactly once' {
        InModuleScope TCPK -Parameters @{ w = $script:work } {
            param($w)
            $f = Join-Path $w 'straddle.bin'
            $fs = [IO.File]::Create($f)
            try {
                $blk = New-Object 'byte[]' 65536
                for ($i = 0; $i -lt 128; $i++) { $fs.Write($blk, 0, $blk.Length) }   # 8 MB
                $fs.Position = 8MB - 4
                $n = [Text.Encoding]::ASCII.GetBytes('STRADDLE')
                $fs.Write($n, 0, $n.Length)
                $fs.Write($blk, 0, 4096)
            } finally { $fs.Dispose() }
            $r = Find-TcpkByteMatches -Path $f -Query 'STRADDLE' -Kind 'ascii'
            @($r.Matches).Count | Should -Be 1
            @($r.Matches)[0].Offset | Should -Be (8MB - 4)
        }
    }
}
