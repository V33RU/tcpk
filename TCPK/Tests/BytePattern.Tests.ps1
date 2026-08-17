#requires -Version 5.1
# Pester 5: the byte-pattern engine.
#
# Two things are being pinned. First that the decoders are right, checked against real
# files built at run time rather than against hand-typed expectations. Second, and more
# important, that a field which does NOT fit the file is reported as out-of-range instead
# of being rendered from whatever bytes happened to be in the buffer. A pattern that
# silently produces plausible values for the wrong file is worse than one that fails.

BeforeAll {
    $psd1 = Join-Path (Split-Path (Split-Path $PSCommandPath -Parent) -Parent) 'TCPK.psd1'
    Import-Module $psd1 -Force
    $script:root = Split-Path (Split-Path $PSCommandPath -Parent) -Parent
    $script:patterns = Join-Path $script:root 'Data\patterns'

    $script:work = Join-Path ([IO.Path]::GetTempPath()) ('tcpk-bpat-' + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Force -Path $script:work | Out-Null

    # A real 44.1 kHz / mono / 16-bit WAV header, so the shipped pattern is checked against
    # bytes rather than against what I believed the layout to be.
    $script:wav = Join-Path $script:work 'a.wav'
    $ms = New-Object IO.MemoryStream
    $bw = New-Object IO.BinaryWriter($ms)
    $bw.Write([Text.Encoding]::ASCII.GetBytes('RIFF'))
    $bw.Write([uint32]264228)
    $bw.Write([Text.Encoding]::ASCII.GetBytes('WAVE'))
    $bw.Write([Text.Encoding]::ASCII.GetBytes('fmt '))
    $bw.Write([uint32]16)
    $bw.Write([uint16]1)        # PCM
    $bw.Write([uint16]1)        # mono
    $bw.Write([uint32]44100)
    $bw.Write([uint32]88200)    # byte rate = 44100 * 1 * 16/8
    $bw.Write([uint16]2)        # block align
    $bw.Write([uint16]16)       # bits per sample
    $bw.Write([Text.Encoding]::ASCII.GetBytes('data'))
    $bw.Write([uint32]264192)
    $bw.Flush()
    [IO.File]::WriteAllBytes($script:wav, $ms.ToArray())
    $bw.Dispose(); $ms.Dispose()
}

AfterAll {
    if ($script:work -and (Test-Path $script:work)) {
        Remove-Item $script:work -Recurse -Force -ErrorAction SilentlyContinue
    }
}

Describe 'Read-TcpkBytePattern: validation refuses rather than renders blanks' {
    It 'accepts a well-formed pattern' {
        InModuleScope TCPK {
            $r = Read-TcpkBytePattern -Json '[{"name":"A","offset":0,"size":4,"type":"string"}]'
            $r.Errors.Count | Should -Be 0
            $r.Fields.Count | Should -Be 1
        }
    }

    It 'names the offending field on an unknown type' {
        InModuleScope TCPK {
            $r = Read-TcpkBytePattern -Json '[{"name":"BAD","offset":0,"size":4,"type":"nope"}]'
            ($r.Errors -join ' ') | Should -Match 'BAD'
            ($r.Errors -join ' ') | Should -Match 'unknown type'
        }
    }

    It 'rejects an integer size that has no decoder' {
        InModuleScope TCPK {
            $r = Read-TcpkBytePattern -Json '[{"name":"X","offset":0,"size":3,"type":"leuint"}]'
            ($r.Errors -join ' ') | Should -Match '1, 2, 4 or 8'
        }
    }

    It 'rejects a size that contradicts a fixed-width type instead of silently overriding' {
        InModuleScope TCPK {
            $r = Read-TcpkBytePattern -Json '[{"name":"G","offset":0,"size":8,"type":"guid"}]'
            ($r.Errors -join ' ') | Should -Match 'always 16 bytes'
        }
    }

    It 'rejects a negative offset' {
        InModuleScope TCPK {
            $r = Read-TcpkBytePattern -Json '[{"name":"N","offset":-4,"size":2,"type":"leuint"}]'
            ($r.Errors -join ' ') | Should -Match 'non-negative'
        }
    }

    It 'reports invalid JSON as such, not as an empty pattern' {
        InModuleScope TCPK {
            $r = Read-TcpkBytePattern -Json '{not json'
            $r.Errors.Count | Should -BeGreaterThan 0
            ($r.Errors -join ' ') | Should -Match 'not valid JSON'
        }
    }

    It 'assigns a stable colour when none is given' {
        InModuleScope TCPK {
            $a = (Read-TcpkBytePattern -Json '[{"name":"A","offset":0,"size":1,"type":"leuint"}]').Fields[0]
            $b = (Read-TcpkBytePattern -Json '[{"name":"A","offset":0,"size":1,"type":"leuint"}]').Fields[0]
            "$($a.R),$($a.G),$($a.B)" | Should -Be "$($b.R),$($b.G),$($b.B)"
        }
    }

    It 'parses an explicit #RRGGBB colour' {
        InModuleScope TCPK {
            $f = (Read-TcpkBytePattern -Json '[{"name":"A","offset":0,"size":1,"type":"leuint","color":"#3A7BD5"}]').Fields[0]
            $f.R | Should -Be 58; $f.G | Should -Be 123; $f.B | Should -Be 213
        }
    }
}

Describe 'Resolve-TcpkBytePattern: the shipped WAV pattern against a real WAV' {
    It 'decodes every field to the value the file actually holds' {
        InModuleScope TCPK -Parameters @{ pat = (Join-Path $script:patterns 'wav-header.json'); wav = $script:wav } {
            param($pat, $wav)
            $p = Read-TcpkBytePattern -Path $pat
            $p.Errors.Count | Should -Be 0
            $rows = Resolve-TcpkBytePattern -Path $wav -Fields $p.Fields
            $get = { param($n) ($rows | Where-Object { $_.Name -eq $n }).Value }

            & $get 'MAGIC'           | Should -Be 'RIFF'
            & $get 'HEADER'          | Should -Be 'WAVE'
            & $get 'SAMPLE_RATE'     | Should -Be '44100'
            & $get 'BYTE_RATE'       | Should -Be '88200'
            & $get 'CHANNELS'        | Should -Be '1'
            & $get 'BITS_PER_SAMPLE' | Should -Be '16'
            & $get 'BLOCK_ALIGN'     | Should -Be '2'
            & $get 'DATA_HEADER'     | Should -Be 'data'
            & $get 'DATA_SIZE'       | Should -Be '264192'
        }
    }

    It 'marks every row ok on a file the pattern fits' {
        InModuleScope TCPK -Parameters @{ pat = (Join-Path $script:patterns 'wav-header.json'); wav = $script:wav } {
            param($pat, $wav)
            $p = Read-TcpkBytePattern -Path $pat
            $rows = Resolve-TcpkBytePattern -Path $wav -Fields $p.Fields
            @($rows | Where-Object { $_.Status -ne 'ok' }).Count | Should -Be 0
        }
    }
}

Describe 'Resolve-TcpkBytePattern: a pattern that does not fit says so' {
    It 'marks fields past EOF out-of-range instead of decoding stale bytes' {
        InModuleScope TCPK -Parameters @{ w = $script:work } {
            param($w)
            $tiny = Join-Path $w 'tiny.bin'
            [IO.File]::WriteAllBytes($tiny, [Text.Encoding]::ASCII.GetBytes('RIFF'))
            $p = Read-TcpkBytePattern -Json '[
                {"name":"MAGIC","offset":0,"size":4,"type":"string"},
                {"name":"PAST_END","offset":100,"size":4,"type":"leuint"}]'
            $rows = Resolve-TcpkBytePattern -Path $tiny -Fields $p.Fields
            ($rows | Where-Object { $_.Name -eq 'MAGIC' }).Value | Should -Be 'RIFF'
            $pe = $rows | Where-Object { $_.Name -eq 'PAST_END' }
            $pe.Status | Should -Be 'out-of-range'
            $pe.Value | Should -BeNullOrEmpty
        }
    }

    It 'keeps the out-of-range row rather than dropping it from the table' {
        InModuleScope TCPK -Parameters @{ w = $script:work } {
            param($w)
            $tiny = Join-Path $w 'tiny.bin'
            $p = Read-TcpkBytePattern -Json '[{"name":"A","offset":0,"size":4,"type":"string"},{"name":"B","offset":900,"size":4,"type":"leuint"}]'
            @(Resolve-TcpkBytePattern -Path $tiny -Fields $p.Fields).Count | Should -Be 2
        }
    }
}

Describe 'Resolve-TcpkBytePattern: decoders' {
    It 'reads big-endian and little-endian differently, as the SQLite spec requires' {
        InModuleScope TCPK -Parameters @{ w = $script:work } {
            param($w)
            $f = Join-Path $w 'endian.bin'
            [IO.File]::WriteAllBytes($f, [byte[]]@(0x10, 0x00))   # BE 4096, LE 16
            $p = Read-TcpkBytePattern -Json '[
                {"name":"BE","offset":0,"size":2,"type":"beuint"},
                {"name":"LE","offset":0,"size":2,"type":"leuint"}]'
            $rows = Resolve-TcpkBytePattern -Path $f -Fields $p.Fields
            ($rows | Where-Object { $_.Name -eq 'BE' }).Value | Should -Be '4096'
            ($rows | Where-Object { $_.Name -eq 'LE' }).Value | Should -Be '16'
        }
    }

    It 'decodes a GUID in the Windows mixed-endian layout' {
        InModuleScope TCPK -Parameters @{ w = $script:work } {
            param($w)
            $f = Join-Path $w 'guid.bin'
            [IO.File]::WriteAllBytes($f, [byte[]](0..15))
            $p = Read-TcpkBytePattern -Json '[{"name":"G","offset":0,"type":"guid"}]'
            $rows = Resolve-TcpkBytePattern -Path $f -Fields $p.Fields
            $rows[0].Value | Should -Be '{03020100-0504-0706-0809-0A0B0C0D0E0F}'
        }
    }

    It 'trims a NUL-padded fixed-width string' {
        InModuleScope TCPK -Parameters @{ w = $script:work } {
            param($w)
            $f = Join-Path $w 'padded.bin'
            [IO.File]::WriteAllBytes($f, ([Text.Encoding]::ASCII.GetBytes('fmt') + [byte[]]@(0, 0, 0, 0, 0)))
            $p = Read-TcpkBytePattern -Json '[{"name":"S","offset":0,"size":8,"type":"string"}]'
            (Resolve-TcpkBytePattern -Path $f -Fields $p.Fields)[0].Value | Should -Be 'fmt'
        }
    }

    It 'rejects a non-FILETIME rather than printing a year-1601 date' {
        InModuleScope TCPK -Parameters @{ w = $script:work } {
            param($w)
            $f = Join-Path $w 'ft.bin'
            [IO.File]::WriteAllBytes($f, [byte[]]@(1, 0, 0, 0, 0, 0, 0, 0))   # 1 tick
            $p = Read-TcpkBytePattern -Json '[{"name":"T","offset":0,"type":"filetime"}]'
            (Resolve-TcpkBytePattern -Path $f -Fields $p.Fields)[0].Value | Should -Match 'not a FILETIME'
        }
    }
}

Describe 'Resolve-TcpkBytePattern: BaseOffset' {
    It 'applies a header pattern at an arbitrary position' {
        InModuleScope TCPK -Parameters @{ w = $script:work } {
            param($w)
            $f = Join-Path $w 'offset.bin'
            $pad = New-Object 'byte[]' 512
            [IO.File]::WriteAllBytes($f, ($pad + [Text.Encoding]::ASCII.GetBytes('RIFF')))
            $p = Read-TcpkBytePattern -Json '[{"name":"MAGIC","offset":0,"size":4,"type":"string"}]'
            $rows = Resolve-TcpkBytePattern -Path $f -Fields $p.Fields -BaseOffset 512
            $rows[0].Value | Should -Be 'RIFF'
            $rows[0].Offset | Should -Be 512
        }
    }
}

Describe 'The shipped patterns all load clean' {
    It 'every JSON in Data\patterns validates with zero errors' {
        InModuleScope TCPK -Parameters @{ dir = $script:patterns } {
            param($dir)
            $files = @(Get-ChildItem -LiteralPath $dir -Filter '*.json' -File)
            $files.Count | Should -BeGreaterThan 0
            foreach ($f in $files) {
                $r = Read-TcpkBytePattern -Path $f.FullName
                if ($r.Errors.Count) { throw "$($f.Name): $($r.Errors -join '; ')" }
                $r.Fields.Count | Should -BeGreaterThan 0
            }
        }
    }
}

Describe 'Get-TcpkFileStructure: the public entry point' {
    It 'lists the shipped patterns, all error-free' {
        $l = @(Get-TcpkFileStructure -ListPatterns)
        $l.Count | Should -BeGreaterThan 0
        @($l | Where-Object { $_.Errors -gt 0 }).Count | Should -Be 0
        @($l | Where-Object { $_.Name -eq 'wav-header' }).Count | Should -Be 1
    }

    It 'resolves a pattern by bare name' {
        $r = @(Get-TcpkFileStructure -Path $script:wav -Pattern 'wav-header')
        ($r | Where-Object { $_.Name -eq 'SAMPLE_RATE' }).Value | Should -Be '44100'
    }

    It 'names the shipped set when the pattern is unknown' {
        { Get-TcpkFileStructure -Path $script:wav -Pattern 'no-such-pattern' } |
            Should -Throw -ExpectedMessage '*Shipped:*'
    }

    It 'refuses a whole invalid pattern rather than rendering the rows that parsed' {
        $bad = Join-Path $script:work 'bad.json'
        '[{"name":"OK","offset":0,"size":4,"type":"string"},{"name":"BAD","offset":0,"size":3,"type":"leuint"}]' |
            Set-Content -LiteralPath $bad -Encoding UTF8
        { Get-TcpkFileStructure -Path $script:wav -Pattern $bad } | Should -Throw -ExpectedMessage '*is invalid*'
    }

    It 'hands ONE row per field to a downstream pipeline, not the whole array at once' {
        # Regression. Resolve-TcpkBytePattern comma-returns its rows so a one-field pattern
        # stays an array, and a comma-protected array is not unrolled by the pipeline: the
        # agentic UI piped this call straight into ForEach-Object and got every field in a
        # SINGLE iteration, where [int64]$_.Offset threw on an Object[] and the panel came
        # back as an error. Callers must assign first; this pins which shape they get.
        $names = @(Get-TcpkFileStructure -Path $script:wav -Pattern 'wav-header' |
                   ForEach-Object { "$($_.Name)" })
        $names.Count | Should -BeGreaterThan 1
        $names | Should -Contain 'SAMPLE_RATE'
        # Each element is one field name, never several joined by the array's ToString.
        @($names | Where-Object { $_ -match ' ' }).Count | Should -Be 0
    }

    It 'parses a structure at an offset reported by the embedded-blob scanner' {
        $host2 = Join-Path $script:work 'embedded.bin'
        $pad = New-Object 'byte[]' 777
        [IO.File]::WriteAllBytes($host2, ($pad + [IO.File]::ReadAllBytes($script:wav)))
        $r = @(Get-TcpkFileStructure -Path $host2 -Pattern 'wav-header' -BaseOffset 777)
        ($r | Where-Object { $_.Name -eq 'MAGIC' }).Value | Should -Be 'RIFF'
        ($r | Where-Object { $_.Name -eq 'MAGIC' }).Offset | Should -Be 777
    }
}

