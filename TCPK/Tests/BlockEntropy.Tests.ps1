#requires -Version 5.1
# Pester 5: Get-TcpkBlockEntropy.
#
# This exists because the version that lived in Start-TCPKGui.ps1 could not be tested. It
# was a script-local function inside a 7500-line WinForms file, and it silently read only
# the first 10 MB while its caller had sized blocks to span the whole file. The Hex tab's
# entropy strip therefore coloured one byte range and its click handler jumped to another
# on any target over 10 MB, which for thick clients is the normal case, not an edge case.
#
# The 11 MB fixture below is deliberate: it is the smallest file that would have exposed
# that bug. Under the old code every block past 10 MB simply did not exist.

BeforeAll {
    $psd1 = Join-Path (Split-Path (Split-Path $PSCommandPath -Parent) -Parent) 'TCPK.psd1'
    Import-Module $psd1 -Force

    $script:work = Join-Path ([IO.Path]::GetTempPath()) ('tcpk-entropy-' + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Force -Path $script:work | Out-Null

    # 11 MB: 10 MB of zeros, then 1 MB of high-entropy bytes. The tail sits PAST the old
    # 10 MB read cap, so a regression reintroducing the cap loses it entirely.
    $script:big = Join-Path $script:work 'big.bin'
    $zeros = New-Object 'byte[]' (1MB)
    $rand  = New-Object 'byte[]' (1MB)
    (New-Object Random 1234).NextBytes($rand)     # seeded: same bytes every run
    $fs = [IO.File]::Create($script:big)
    try {
        for ($i = 0; $i -lt 10; $i++) { $fs.Write($zeros, 0, $zeros.Length) }
        $fs.Write($rand, 0, $rand.Length)
    } finally { $fs.Dispose() }
    $script:bigLen = [int64](Get-Item $script:big).Length

    # A small file whose length is deliberately NOT a multiple of the block size.
    $script:ragged = Join-Path $script:work 'ragged.bin'
    $rb = New-Object 'byte[]' 1000
    (New-Object Random 99).NextBytes($rb)
    [IO.File]::WriteAllBytes($script:ragged, $rb)
}

AfterAll {
    if ($script:work -and (Test-Path $script:work)) {
        Remove-Item $script:work -Recurse -Force -ErrorAction SilentlyContinue
    }
}

Describe 'Get-TcpkBlockEntropy: covers the whole file' {
    It 'returns blocks spanning the entire file, not a capped prefix' {
        $bs = 64KB
        $e = Get-TcpkBlockEntropy -Path $script:big -BlockSize $bs
        $expected = [int][Math]::Ceiling($script:bigLen / [double]$bs)
        $e.Count | Should -Be $expected
        # the array must reach past where the old 10 MB cap stopped
        ($e.Count * $bs) | Should -BeGreaterOrEqual $script:bigLen
    }

    It 'sees the high-entropy tail that sits PAST the old 10 MB cap' {
        $bs = 64KB
        $e = Get-TcpkBlockEntropy -Path $script:big -BlockSize $bs
        # last block is inside the random megabyte
        $e[$e.Count - 1] | Should -BeGreaterThan 7.0
    }

    It 'still reports the zero-filled head as near-zero entropy' {
        $e = Get-TcpkBlockEntropy -Path $script:big -BlockSize 64KB
        $e[0] | Should -Be 0.0
        $e[10] | Should -Be 0.0
    }
}

Describe 'Get-TcpkBlockEntropy: values are bits per byte' {
    It 'gives 0.0 for a single repeated byte' {
        $f = Join-Path $script:work 'flat.bin'
        [IO.File]::WriteAllBytes($f, (New-Object 'byte[]' 8192))
        (Get-TcpkBlockEntropy -Path $f -BlockSize 4096)[0] | Should -Be 0.0
    }

    It 'gives exactly 8.0 for a block containing each byte value once' {
        $f = Join-Path $script:work 'uniform.bin'
        $b = New-Object 'byte[]' 256
        for ($i = 0; $i -lt 256; $i++) { $b[$i] = [byte]$i }
        [IO.File]::WriteAllBytes($f, $b)
        $e = Get-TcpkBlockEntropy -Path $f -BlockSize 256
        [Math]::Round($e[0], 6) | Should -Be 8.0
    }

    It 'gives 1.0 for a block of two equally frequent values' {
        $f = Join-Path $script:work 'twovals.bin'
        $b = New-Object 'byte[]' 1024
        for ($i = 0; $i -lt 1024; $i++) { $b[$i] = [byte]($i % 2) }
        [IO.File]::WriteAllBytes($f, $b)
        [Math]::Round((Get-TcpkBlockEntropy -Path $f -BlockSize 1024)[0], 6) | Should -Be 1.0
    }
}

Describe 'Get-TcpkBlockEntropy: MaxBlocks trades resolution, never coverage' {
    It 'raises the block size instead of dropping the tail' {
        $e = Get-TcpkBlockEntropy -Path $script:big -BlockSize 4096 -MaxBlocks 50
        $e.Count | Should -BeLessOrEqual 50
        # coverage preserved: the last block must still contain the random tail
        $e[$e.Count - 1] | Should -BeGreaterThan 0.0
    }
}

Describe 'Get-TcpkBlockEntropy: edges' {
    It 'handles a final short block using only the bytes that exist' {
        # 1000 bytes with a 256-byte block: the 4th block holds 232 bytes, not 256. If the
        # reusable buffer were not accounted for, it would count 24 stale bytes from the
        # previous block and skew the value.
        $e = Get-TcpkBlockEntropy -Path $script:ragged -BlockSize 256
        $e.Count | Should -Be 4
        $e[3] | Should -BeGreaterThan 0.0
        $e[3] | Should -BeLessOrEqual 8.0
    }

    It 'returns empty for a missing file rather than throwing' {
        $e = Get-TcpkBlockEntropy -Path (Join-Path $script:work 'nope.bin')
        @($e).Count | Should -Be 0
    }

    It 'returns empty for a zero-length file' {
        $f = Join-Path $script:work 'empty.bin'
        [IO.File]::WriteAllBytes($f, (New-Object 'byte[]' 0))
        @(Get-TcpkBlockEntropy -Path $f).Count | Should -Be 0
    }

    It 'raises an absurdly small block size to a usable one' {
        # A 16-byte block cannot exceed 4.0 bits/byte however random it is, so a tiny block
        # size would make everything look structured. Values under 64 are raised to 256.
        $e = Get-TcpkBlockEntropy -Path $script:ragged -BlockSize 8
        $e.Count | Should -Be ([int][Math]::Ceiling(1000 / 256.0))
    }
}
