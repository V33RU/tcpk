#requires -Version 5.1
# Pester 5: the byte-map sampler.
#
# The rendering is not testable and does not need to be. What is testable, and is the part
# that would quietly ruin the view, is the arithmetic: how a span maps to pixels, and how a
# clicked pixel maps back to a file offset. A byte map that jumps to the wrong offset is
# worse than no byte map, because it looks authoritative.

BeforeAll {
    $psd1 = Join-Path (Split-Path (Split-Path $PSCommandPath -Parent) -Parent) 'TCPK.psd1'
    Import-Module $psd1 -Force

    $script:work = Join-Path ([IO.Path]::GetTempPath()) ('tcpk-bmap-' + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Force -Path $script:work | Out-Null

    # 1024 bytes, value == offset mod 256. Every pixel's value therefore states which byte
    # it came from, so an off-by-one in the mapping shows up as a wrong VALUE, not just a
    # wrong count.
    $script:ramp = Join-Path $script:work 'ramp.bin'
    $b = New-Object 'byte[]' 1024
    for ($i = 0; $i -lt 1024; $i++) { $b[$i] = [byte]($i % 256) }
    [IO.File]::WriteAllBytes($script:ramp, $b)

    # Not a multiple of the column count, to exercise the ragged final row.
    $script:ragged = Join-Path $script:work 'ragged.bin'
    [IO.File]::WriteAllBytes($script:ragged, $b[0..999])

    # Big enough to force block mode.
    $script:big = Join-Path $script:work 'big.bin'
    $fs = [IO.File]::Create($script:big)
    try {
        $blk = New-Object 'byte[]' 65536
        for ($i = 0; $i -lt 65536; $i++) { $blk[$i] = 200 }
        for ($i = 0; $i -lt 32; $i++) { $fs.Write($blk, 0, $blk.Length) }   # 2 MB of 200
    } finally { $fs.Dispose() }
}

AfterAll {
    if ($script:work -and (Test-Path $script:work)) {
        Remove-Item $script:work -Recurse -Force -ErrorAction SilentlyContinue
    }
}

Describe 'Get-TcpkByteMapSamples: exact mode' {
    It 'maps one pixel per byte when the span fits' {
        InModuleScope TCPK -Parameters @{ f = $script:ramp } {
            param($f)
            $m = Get-TcpkByteMapSamples -Path $f -Columns 256 -MaxRows 512
            $m.Mode | Should -Be 'exact'
            $m.BytesPerPixel | Should -Be 1
            $m.RowCount | Should -Be 4
            $m.LastRowValid | Should -Be 256
        }
    }

    It 'each pixel holds the byte that is actually at that offset' {
        InModuleScope TCPK -Parameters @{ f = $script:ramp } {
            param($f)
            $m = Get-TcpkByteMapSamples -Path $f -Columns 256 -MaxRows 512
            # value == offset mod 256 by construction
            $m.Rows[0][0]   | Should -Be 0
            $m.Rows[0][255] | Should -Be 255
            $m.Rows[1][0]   | Should -Be 0
            $m.Rows[3][17]  | Should -Be 17
        }
    }

    It 'reports a ragged final row instead of padding it silently' {
        InModuleScope TCPK -Parameters @{ f = $script:ragged } {
            param($f)
            $m = Get-TcpkByteMapSamples -Path $f -Columns 256 -MaxRows 512
            $m.RowCount | Should -Be 4
            $m.LastRowValid | Should -Be 232      # 1000 - 3*256
            $m.Rows[3].Length | Should -Be 256    # the array is full width...
        }
    }
}

Describe 'Get-TcpkByteMapSamples: block mode' {
    It 'switches to block mode and states the ratio' {
        InModuleScope TCPK -Parameters @{ f = $script:big } {
            param($f)
            $m = Get-TcpkByteMapSamples -Path $f -Columns 256 -MaxRows 512
            $m.Mode | Should -Be 'block'
            $m.BytesPerPixel | Should -BeGreaterThan 1
            $m.RowCount | Should -BeLessOrEqual 512
        }
    }

    It 'averages rather than sampling, so a constant region stays its own value' {
        InModuleScope TCPK -Parameters @{ f = $script:big } {
            param($f)
            $m = Get-TcpkByteMapSamples -Path $f -Columns 256 -MaxRows 512
            $m.Rows[0][0] | Should -Be 200
            $m.Rows[10][100] | Should -Be 200
        }
    }

    It 'never produces more rows than MaxRows, whatever the file size' {
        InModuleScope TCPK -Parameters @{ f = $script:big } {
            param($f)
            (Get-TcpkByteMapSamples -Path $f -Columns 64 -MaxRows 100).RowCount | Should -BeLessOrEqual 100
            (Get-TcpkByteMapSamples -Path $f -Columns 256 -MaxRows 8).RowCount  | Should -BeLessOrEqual 8
        }
    }
}

Describe 'Get-TcpkByteMapSamples: zooming to a region' {
    It 'maps a window exactly when Offset and Length are given' {
        InModuleScope TCPK -Parameters @{ f = $script:ramp } {
            param($f)
            $m = Get-TcpkByteMapSamples -Path $f -Columns 16 -MaxRows 512 -Offset 512 -Length 32
            $m.Mode | Should -Be 'exact'
            $m.RowCount | Should -Be 2
            $m.Offset | Should -Be 512
            $m.Length | Should -Be 32
            $m.Rows[0][0] | Should -Be 0     # byte at 512 is 512 % 256 = 0
            $m.Rows[0][5] | Should -Be 5
        }
    }

    It 'clamps a Length that runs past the end of the file' {
        InModuleScope TCPK -Parameters @{ f = $script:ramp } {
            param($f)
            $m = Get-TcpkByteMapSamples -Path $f -Columns 16 -MaxRows 512 -Offset 1000 -Length 999999
            $m.Length | Should -Be 24        # 1024 - 1000
        }
    }

    It 'returns empty for an offset at or past EOF rather than throwing' {
        InModuleScope TCPK -Parameters @{ f = $script:ramp } {
            param($f)
            (Get-TcpkByteMapSamples -Path $f -Offset 1024).RowCount | Should -Be 0
            (Get-TcpkByteMapSamples -Path $f -Offset 99999).RowCount | Should -Be 0
        }
    }

    It 'returns empty for a missing or zero-length file' {
        InModuleScope TCPK -Parameters @{ w = $script:work } {
            param($w)
            (Get-TcpkByteMapSamples -Path (Join-Path $w 'nope.bin')).RowCount | Should -Be 0
            $z = Join-Path $w 'zero.bin'
            [IO.File]::WriteAllBytes($z, (New-Object 'byte[]' 0))
            (Get-TcpkByteMapSamples -Path $z).RowCount | Should -Be 0
        }
    }
}

Describe 'Get-TcpkByteMapOffset: a click must land on the right byte' {
    It 'maps pixel (0,0) to the span start' {
        InModuleScope TCPK -Parameters @{ f = $script:ramp } {
            param($f)
            $m = Get-TcpkByteMapSamples -Path $f -Columns 256 -MaxRows 512
            Get-TcpkByteMapOffset -Map $m -Column 0 -Row 0 | Should -Be 0
        }
    }

    It 'maps row/column to the exact offset in exact mode' {
        InModuleScope TCPK -Parameters @{ f = $script:ramp } {
            param($f)
            $m = Get-TcpkByteMapSamples -Path $f -Columns 256 -MaxRows 512
            Get-TcpkByteMapOffset -Map $m -Column 5   -Row 0 | Should -Be 5
            Get-TcpkByteMapOffset -Map $m -Column 0   -Row 1 | Should -Be 256
            Get-TcpkByteMapOffset -Map $m -Column 255 -Row 3 | Should -Be 1023
        }
    }

    It 'returns the FIRST byte of the block in block mode' {
        InModuleScope TCPK -Parameters @{ f = $script:big } {
            param($f)
            $m = Get-TcpkByteMapSamples -Path $f -Columns 256 -MaxRows 512
            Get-TcpkByteMapOffset -Map $m -Column 0 -Row 0 | Should -Be 0
            Get-TcpkByteMapOffset -Map $m -Column 1 -Row 0 | Should -Be ([int64]$m.BytesPerPixel)
            Get-TcpkByteMapOffset -Map $m -Column 0 -Row 1 | Should -Be ([int64]$m.BytesPerPixel * $m.Columns)
        }
    }

    It 'adds the window Offset when zoomed' {
        InModuleScope TCPK -Parameters @{ f = $script:ramp } {
            param($f)
            $m = Get-TcpkByteMapSamples -Path $f -Columns 16 -MaxRows 512 -Offset 512 -Length 32
            Get-TcpkByteMapOffset -Map $m -Column 0 -Row 0 | Should -Be 512
            Get-TcpkByteMapOffset -Map $m -Column 3 -Row 1 | Should -Be 531
        }
    }

    It 'refuses padding in the ragged final row instead of jumping past EOF' {
        InModuleScope TCPK -Parameters @{ f = $script:ragged } {
            param($f)
            $m = Get-TcpkByteMapSamples -Path $f -Columns 256 -MaxRows 512
            # 232 real pixels in the last row; 231 is the final valid one
            Get-TcpkByteMapOffset -Map $m -Column 231 -Row 3 | Should -Be 999
            Get-TcpkByteMapOffset -Map $m -Column 232 -Row 3 | Should -Be ([int64]-1)
            Get-TcpkByteMapOffset -Map $m -Column 255 -Row 3 | Should -Be ([int64]-1)
        }
    }

    It 'refuses out-of-grid coordinates' {
        InModuleScope TCPK -Parameters @{ f = $script:ramp } {
            param($f)
            $m = Get-TcpkByteMapSamples -Path $f -Columns 256 -MaxRows 512
            Get-TcpkByteMapOffset -Map $m -Column -1  -Row 0 | Should -Be ([int64]-1)
            Get-TcpkByteMapOffset -Map $m -Column 256 -Row 0 | Should -Be ([int64]-1)
            Get-TcpkByteMapOffset -Map $m -Column 0   -Row 4 | Should -Be ([int64]-1)
        }
    }

    It 'never returns an offset past the end of the mapped span' {
        InModuleScope TCPK -Parameters @{ f = $script:big } {
            param($f)
            $m = Get-TcpkByteMapSamples -Path $f -Columns 256 -MaxRows 512
            $end = $m.Offset + $m.Length
            for ($r = 0; $r -lt $m.RowCount; $r += 97) {
                for ($c = 0; $c -lt $m.Columns; $c += 61) {
                    $o = Get-TcpkByteMapOffset -Map $m -Column $c -Row $r
                    if ($o -ge 0) { $o | Should -BeLessThan $end }
                }
            }
        }
    }
}
