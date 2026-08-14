#requires -Version 5.1
# Pester 5: Test-TcpkEmbeddedBlobs.
#
# The point of this cmdlet is that a magic-byte match is NOT a finding, so most of these
# tests are about what it REFUSES to report. Measured justification: the shipped
# Mono.Cecil.dll, one legitimate 350 KB assembly, contains four bare 'MZ' sequences. A
# match-only scanner reports three embedded executables in a clean file. Structural
# validation is the whole cmdlet.

BeforeAll {
    $psd1 = Join-Path (Split-Path (Split-Path $PSCommandPath -Parent) -Parent) 'TCPK.psd1'
    Import-Module $psd1 -Force

    $script:work = Join-Path ([IO.Path]::GetTempPath()) ('tcpk-blobs-' + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Force -Path $script:work | Out-Null

    # A minimal but STRUCTURALLY VALID PE stub: MZ, e_lfanew at 0x3C pointing to 'PE\0\0'.
    function script:New-PeStub([int]$lfanew = 0x80) {
        $b = New-Object 'byte[]' ($lfanew + 64)
        $b[0] = 0x4D; $b[1] = 0x5A                                   # MZ
        [Array]::Copy([BitConverter]::GetBytes([int]$lfanew), 0, $b, 0x3C, 4)
        $b[$lfanew] = 0x50; $b[$lfanew + 1] = 0x45                   # PE
        $b[$lfanew + 2] = 0; $b[$lfanew + 3] = 0                     # \0\0
        return $b
    }

    # 'MZ' with a broken e_lfanew: the exact false positive a match-only scan produces.
    function script:New-FakeMz {
        $b = New-Object 'byte[]' 512
        $b[0] = 0x4D; $b[1] = 0x5A
        [Array]::Copy([BitConverter]::GetBytes([int]0x7FFFFF00), 0, $b, 0x3C, 4)  # points nowhere
        return $b
    }

    $script:host1 = Join-Path $script:work 'host-with-pe.bin'
    $pad = New-Object 'byte[]' 4096
    (New-Object Random 7).NextBytes($pad)
    $ms = New-Object IO.MemoryStream
    $ms.Write($pad, 0, $pad.Length)
    $script:peOffset = $ms.Length
    $pe = script:New-PeStub
    $ms.Write($pe, 0, $pe.Length)
    $ms.Write($pad, 0, $pad.Length)
    [IO.File]::WriteAllBytes($script:host1, $ms.ToArray()); $ms.Dispose()

    # A file whose only 'MZ' hits are structurally bogus.
    $script:noiseFile = Join-Path $script:work 'noise.bin'
    $ms2 = New-Object IO.MemoryStream
    $ms2.Write($pad, 0, $pad.Length)
    $fake = script:New-FakeMz
    $ms2.Write($fake, 0, $fake.Length)
    [IO.File]::WriteAllBytes($script:noiseFile, $ms2.ToArray()); $ms2.Dispose()

    # SQLite: a 16-byte signature, long enough to need no validator.
    $script:dbFile = Join-Path $script:work 'host-with-db.bin'
    $ms3 = New-Object IO.MemoryStream
    $ms3.Write($pad, 0, 1024)
    $sq = [Text.Encoding]::ASCII.GetBytes('SQLite format 3') + [byte[]]@(0)
    $ms3.Write($sq, 0, $sq.Length)
    $ms3.Write($pad, 0, 256)
    [IO.File]::WriteAllBytes($script:dbFile, $ms3.ToArray()); $ms3.Dispose()

    # A shipped private key inside a blob.
    $script:keyFile = Join-Path $script:work 'host-with-key.bin'
    $ms4 = New-Object IO.MemoryStream
    $ms4.Write($pad, 0, 512)
    $pem = [Text.Encoding]::ASCII.GetBytes("-----BEGIN RSA PRIVATE KEY-----`nMIIEow...`n")
    $ms4.Write($pem, 0, $pem.Length)
    [IO.File]::WriteAllBytes($script:keyFile, $ms4.ToArray()); $ms4.Dispose()
}

AfterAll {
    if ($script:work -and (Test-Path $script:work)) {
        Remove-Item $script:work -Recurse -Force -ErrorAction SilentlyContinue
    }
}

Describe 'Test-TcpkEmbeddedBlobs: finds what is really there' {
    It 'reports a structurally valid PE at its true offset' {
        $f = @(Test-TcpkEmbeddedBlobs -Path $script:host1)
        $e = @($f | Where-Object { $_.RuleId -eq 'embedded.executable' })
        $e.Count | Should -Be 1
        "$($e[0].Evidence)" | Should -Match ("offset=0x" + $script:peOffset.ToString('x'))
    }

    It 'cites the structural check, not the magic bytes' {
        $f = @(Test-TcpkEmbeddedBlobs -Path $script:host1)
        $e = @($f | Where-Object { $_.RuleId -eq 'embedded.executable' })
        "$($e[0].Evidence)" | Should -Match 'e_lfanew='
    }

    It 'finds an embedded SQLite database' {
        $f = @(Test-TcpkEmbeddedBlobs -Path $script:dbFile)
        @($f | Where-Object { $_.RuleId -eq 'embedded.database' }).Count | Should -Be 1
    }

    It 'rates an embedded private key higher than an archive' {
        $f = @(Test-TcpkEmbeddedBlobs -Path $script:keyFile)
        $k = @($f | Where-Object { $_.RuleId -eq 'embedded.key' })
        $k.Count | Should -Be 1
        $k[0].Severity | Should -Be 'HIGH'
    }
}

Describe 'Test-TcpkEmbeddedBlobs: refuses what only looks right' {
    It 'does NOT report an MZ whose e_lfanew points outside the file' {
        $f = @(Test-TcpkEmbeddedBlobs -Path $script:noiseFile)
        @($f | Where-Object { $_.RuleId -eq 'embedded.executable' }).Count | Should -Be 0
    }

    It 'counts the rejected candidate rather than hiding it' {
        $f = @(Test-TcpkEmbeddedBlobs -Path $script:noiseFile)
        $s = @($f | Where-Object { $_.RuleId -eq 'embedded.scan' })
        $s.Count | Should -Be 1
        "$($s[0].Evidence)" | Should -Match 'rejected-candidates=[1-9]'
    }

    It 'ignores the host file own header via -MinOffset' {
        # The PE stub written on its own: its MZ is at offset 0, which is not "embedded".
        $solo = Join-Path $script:work 'solo.exe'
        [IO.File]::WriteAllBytes($solo, (script:New-PeStub))
        $f = @(Test-TcpkEmbeddedBlobs -Path $solo)
        @($f | Where-Object { $_.RuleId -eq 'embedded.executable' }).Count | Should -Be 0
    }

    It 'does not raise media by default, but does with -IncludeMedia' {
        $png = Join-Path $script:work 'host-with-png.bin'
        $ms = New-Object IO.MemoryStream
        $z = New-Object 'byte[]' 256
        $ms.Write($z, 0, $z.Length)
        $sig = [byte[]]@(0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A)
        $ms.Write($sig, 0, $sig.Length)
        [IO.File]::WriteAllBytes($png, $ms.ToArray()); $ms.Dispose()

        @(Test-TcpkEmbeddedBlobs -Path $png | Where-Object { $_.RuleId -eq 'embedded.media' }).Count | Should -Be 0
        @(Test-TcpkEmbeddedBlobs -Path $png -IncludeMedia | Where-Object { $_.RuleId -eq 'embedded.media' }).Count | Should -Be 1
    }
}

Describe 'Test-TcpkEmbeddedBlobs: coverage is always stated' {
    It 'emits the scan record even when nothing is found' {
        $empty = Join-Path $script:work 'plain.bin'
        [IO.File]::WriteAllBytes($empty, (New-Object 'byte[]' 2048))
        $f = @(Test-TcpkEmbeddedBlobs -Path $empty)
        $s = @($f | Where-Object { $_.RuleId -eq 'embedded.scan' })
        $s.Count | Should -Be 1
        "$($s[0].Title)" | Should -Match '0 found'
    }

    It 'names any file it could not scan in full, and raises severity for it' {
        $f = @(Test-TcpkEmbeddedBlobs -Path $script:host1 -MaxFileBytes 512)
        $s = @($f | Where-Object { $_.RuleId -eq 'embedded.scan' })
        $s[0].Severity | Should -Be 'LOW'
        "$($s[0].Evidence)" | Should -Match 'TRUNCATED'
        "$($s[0].Title)" | Should -Match 'TRUNCATED'
    }

    It 'scans a folder recursively and aggregates one scan record' {
        $f = @(Test-TcpkEmbeddedBlobs -Path $script:work)
        @($f | Where-Object { $_.RuleId -eq 'embedded.scan' }).Count | Should -Be 1
    }
}

Describe 'Find-TcpkEmbeddedSignature: chunk-boundary correctness' {
    It 'finds a PE that straddles the 1 MB chunk boundary' {
        # The regression this guards: the overlap must cover what the VALIDATOR reads
        # (e_lfanew + 4, i.e. 0x84 bytes), not just the 2-byte signature. Sized at
        # maxSig-1 the match here is bounds-rejected and then never rescanned.
        $straddle = Join-Path $script:work 'straddle.bin'
        $fs = [IO.File]::Create($straddle)
        try {
            $blk = New-Object 'byte[]' 65536
            for ($i = 0; $i -lt 16; $i++) { $fs.Write($blk, 0, $blk.Length) }   # 1 MB exactly
            $fs.Position = 1048576 - 0x40                                        # start just before the edge
            $pe = script:New-PeStub
            $fs.Write($pe, 0, $pe.Length)
            $fs.Write($blk, 0, 4096)
        } finally { $fs.Dispose() }

        $f = @(Test-TcpkEmbeddedBlobs -Path $straddle)
        @($f | Where-Object { $_.RuleId -eq 'embedded.executable' }).Count | Should -Be 1
    }

    It 'reports a straddling match once, not twice' {
        $f = @(Test-TcpkEmbeddedBlobs -Path (Join-Path $script:work 'straddle.bin'))
        @($f | Where-Object { $_.RuleId -eq 'embedded.executable' }).Count | Should -Be 1
    }
}
