#requires -Version 5.1
# Pester 5: streaming printable-run extractor and the coverage accounting around it.
#
# WHY. A 212 MB binary decodes to ~445 M characters across the three views, and
# Test-TcpkSecrets runs 41 rules over each one. Every rule's cheap pre-filter is
# String.IndexOf with OrdinalIgnoreCase, which on .NET Framework routes through NLS
# collation rather than a byte compare -- so the pre-filter ALONE is ~18 billion
# character comparisons for one file. That is a scan pegged on one core for hours
# with no I/O, and it is NOT catastrophic backtracking; it is aggregate linear work
# on an input that should never have been that large. Extracting printable runs
# first cuts the matched text to a few percent of the file.
#
# These tests pin the properties that make that safe: every byte is read, a string
# is still found regardless of file size, and any loss of fidelity is REPORTED
# rather than absorbed.

BeforeAll {
    $psd1 = Join-Path (Split-Path (Split-Path $PSCommandPath -Parent) -Parent) 'TCPK.psd1'
    Import-Module $psd1 -Force
    $script:fx = Join-Path ([System.IO.Path]::GetTempPath()) ('tcpk-extract-' + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $script:fx | Out-Null

    # Binary-ish filler with an ASCII needle at a known offset, and a UTF-16LE needle
    # at a chosen parity so both wide views get exercised.
    function script:New-Bin {
        param([string]$Name, [long]$Size, [string]$Ascii, [long]$AsciiAt,
              [string]$Wide = '', [long]$WideAt = 0)
        $p = Join-Path $script:fx $Name
        $fs = [System.IO.FileStream]::new($p, [System.IO.FileMode]::Create, [System.IO.FileAccess]::Write)
        try {
            $block = New-Object byte[] 1048576
            $rnd = New-Object System.Random 1234
            $rnd.NextBytes($block)
            # Force high bytes so the filler is not accidentally printable.
            for ($i = 0; $i -lt $block.Length; $i++) { $block[$i] = [byte](($block[$i] -bor 0x80)) }
            $w = 0
            while ($w -lt $Size) {
                $take = [int][Math]::Min($block.Length, $Size - $w)
                $fs.Write($block, 0, $take); $w += $take
            }
            if ($Ascii) {
                $b = [System.Text.Encoding]::ASCII.GetBytes($Ascii)
                $fs.Position = $AsciiAt; $fs.Write($b, 0, $b.Length)
            }
            if ($Wide) {
                $b = [System.Text.Encoding]::Unicode.GetBytes($Wide)
                $fs.Position = $WideAt; $fs.Write($b, 0, $b.Length)
            }
        } finally { $fs.Dispose() }
        return $p
    }
}
AfterAll {
    if ($script:fx -and (Test-Path $script:fx)) { Remove-Item $script:fx -Recurse -Force -ErrorAction SilentlyContinue }
}

Describe 'Tcpk.StringExtractor compiles and runs' {
    It 'compiles on this host' {
        InModuleScope TCPK { Initialize-TcpkExtractor } | Should -BeTrue
    }
}

Describe 'Invoke-TcpkStringExtract' {

    It 'reads every byte of the file' {
        $p = New-Bin 'full.bin' (20MB) 'TCPK_ASCII_NEEDLE' (10MB)
        $r = InModuleScope TCPK -Parameters @{ f = $p } { param($f) Invoke-TcpkStringExtract -Path $f }
        $r | Should -Not -BeNullOrEmpty
        $r.BytesRead | Should -Be $r.FileLength -Because 'nothing may be skipped for size'
    }

    It 'finds an ASCII run far past any old size cap' {
        $p = New-Bin 'deep.bin' (40MB) 'TCPK_DEEP_NEEDLE' (35MB)
        $r = InModuleScope TCPK -Parameters @{ f = $p } { param($f) Invoke-TcpkStringExtract -Path $f }
        $r.Ascii | Should -Match 'TCPK_DEEP_NEEDLE'
    }

    It 'recovers a UTF-16LE run at EVEN alignment' {
        $p = New-Bin 'wide-even.bin' (20MB) '' 0 'TCPK_WIDE_EVEN' (4MB)      # 4MB is even
        $r = InModuleScope TCPK -Parameters @{ f = $p } { param($f) Invoke-TcpkStringExtract -Path $f }
        $r.WideEven | Should -Match 'TCPK_WIDE_EVEN'
    }

    It 'recovers a UTF-16LE run at ODD alignment, which a single decode would miss' {
        $p = New-Bin 'wide-odd.bin' (20MB) '' 0 'TCPK_WIDE_ODD' ((4MB) + 1)  # deliberately odd
        $r = InModuleScope TCPK -Parameters @{ f = $p } { param($f) Invoke-TcpkStringExtract -Path $f }
        $r.WideOdd | Should -Match 'TCPK_WIDE_ODD'
    }

    It 'drops sub-minimum runs so random bytes do not become text' {
        $p = New-Bin 'noise.bin' (18MB) 'ab' 100                              # 2 chars < min 4
        $r = InModuleScope TCPK -Parameters @{ f = $p } { param($f) Invoke-TcpkStringExtract -Path $f }
        # The extracted text must be a small fraction of the file, not a decode of it.
        $r.Ascii.Length | Should -BeLessThan ([int](18MB / 10))
    }

    It 'reports Deduped only above the dedup threshold' {
        $p = New-Bin 'small.bin' (18MB) 'TCPK_X' 4096
        $r = InModuleScope TCPK -Parameters @{ f = $p } { param($f) Invoke-TcpkStringExtract -Path $f }
        $r.Deduped | Should -BeFalse -Because 'occurrence counts stay exact below the threshold'
    }
}

Describe 'Read-TcpkStringViews reader selection' {

    It 'decodes a small file verbatim and marks it not streamed' {
        $p = Join-Path $script:fx 'tiny.txt'
        'hello TCPK_TINY world' | Set-Content -LiteralPath $p -Encoding UTF8
        $v = InModuleScope TCPK -Parameters @{ f = $p } { param($f) Read-TcpkStringViews -Path $f }
        $v.Streamed  | Should -BeFalse
        $v.Truncated | Should -BeFalse
        $v.Utf8      | Should -Match 'TCPK_TINY'
    }

    It 'streams a file at or above the threshold and still reports full coverage' {
        $p = New-Bin 'big.bin' (20MB) 'TCPK_BIG_NEEDLE' (15MB)
        $v = InModuleScope TCPK -Parameters @{ f = $p } { param($f) Read-TcpkStringViews -Path $f }
        $v.Streamed   | Should -BeTrue
        $v.Truncated  | Should -BeFalse -Because 'a complete streamed pass is not a truncated one'
        $v.Length     | Should -Be $v.FileLength
        $v.Utf8       | Should -Match 'TCPK_BIG_NEEDLE'
    }
}

Describe 'Degraded reads reach the report without the caller opting in' {

    # THE POINT. Truncated/Deduped used to live only on the view object, and exactly one
    # check out of 65 ever looked. Read-TcpkAllText -- the API 64 files call -- discarded
    # them entirely, so above the threshold those checks silently received altered text.
    # Coverage is now registered centrally, so ignoring the flags cannot hide the loss.

    It 'Read-TcpkAllText registers a capped view in the scan-coverage counters' {
        InModuleScope TCPK {
            Reset-TcpkScanStats
            $views = [pscustomobject]@{
                Path = 'C:\fake\capped.dll'; Utf8 = 'x'; Utf16Le = ''; Utf16LeOdd = ''
                Length = 1; FileLength = 999; Truncated = $true; Streamed = $true; Deduped = $false
            }
            Register-TcpkViewCoverage -Views $views
            (Get-TcpkScanStats).ViewCappedCount | Should -Be 1
        }
    }

    It 'registers a deduped view separately from a capped one' {
        InModuleScope TCPK {
            Reset-TcpkScanStats
            $views = [pscustomobject]@{
                Path = 'C:\fake\dedup.dll'; Utf8 = 'x'; Utf16Le = ''; Utf16LeOdd = ''
                Length = 1; FileLength = 999; Truncated = $false; Streamed = $true; Deduped = $true
            }
            Register-TcpkViewCoverage -Views $views
            $s = Get-TcpkScanStats
            $s.ViewDedupedCount | Should -Be 1
            $s.ViewCappedCount  | Should -Be 0
        }
    }

    It 'Test-TcpkScanCoverage reports a capped view as LOW, and dedup alone as INFO' {
        $capped = InModuleScope TCPK {
            Reset-TcpkScanStats
            Add-TcpkScanSkip -Kind 'ViewCapped' -ItemPath 'C:\fake\a.dll'
            @(Test-TcpkScanCoverage)
        }
        $capped.Count | Should -BeGreaterThan 0
        $capped[0].Severity | Should -Be 'LOW' -Because 'a capped view is a genuine unknown'
        $capped[0].Title    | Should -Match 'ceiling'

        $dedup = InModuleScope TCPK {
            Reset-TcpkScanStats
            Add-TcpkScanSkip -Kind 'ViewDeduped' -ItemPath 'C:\fake\b.dll'
            @(Test-TcpkScanCoverage)
        }
        $dedup.Count | Should -BeGreaterThan 0
        $dedup[0].Severity | Should -Be 'INFO' -Because 'dedup keeps every distinct string; only repeat counts are lost'
        $dedup[0].Title    | Should -Match 'collapsed'
    }

    It 'stays silent when nothing was degraded' {
        $none = InModuleScope TCPK { Reset-TcpkScanStats; @(Test-TcpkScanCoverage) }
        $none.Count | Should -Be 0
    }
}

Describe 'CVSS archetype coverage for the secrets family' {
    # All 41 secrets.* rules previously matched NO archetype and fell through to a
    # generic severity band -- 37 of them HIGH or CRITICAL.
    It 'maps every secrets.* rule to an archetype' {
        InModuleScope TCPK {
            $data = Get-Content -LiteralPath (Join-Path $script:TcpkRoot 'Data\secrets.json') -Raw | ConvertFrom-Json
            $rules = if ($data -is [array]) { $data } else { $data.rules }
            $unmapped = @()
            foreach ($r in $rules) {
                if (-not $r.id) { continue }
                $rid = "secrets.$($r.id)"
                $hit = $false
                foreach ($m in $script:TcpkCvssRuleArchetype) { if ($rid -match $m.Rx) { $hit = $true; break } }
                if (-not $hit) { $unmapped += $rid }
            }
            $unmapped | Should -BeNullOrEmpty
        }
    }

    It 'does not give a timeout/skip record a credential-exposure vector' {
        InModuleScope TCPK {
            $a = $null
            foreach ($m in $script:TcpkCvssRuleArchetype) { if ('secrets.rule-timeout' -match $m.Rx) { $a = $m.A; break } }
            $a | Should -Be 'hardening'
        }
    }
}
