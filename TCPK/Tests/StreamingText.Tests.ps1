#requires -Version 5.1
# Pester 5: streaming text access. No file is skipped for being large.
#
# WHY. Eight checks used to drop a file above a size threshold with no report, and
# eleven others had no threshold and loaded a 200 MB file whole (~2 GB of Large Object
# Heap per call, re-done by every caller because the view cache stops admitting at
# ~44 MB). Invoke-TcpkOnFileText replaces both behaviours: small files decode whole as
# before, large files walk in bounded overlapping chunks. These tests pin the property
# that actually matters -- a match is found regardless of file size, INCLUDING when it
# straddles a chunk boundary, which is the one thing chunking can silently break.

BeforeAll {
    $psd1 = Join-Path (Split-Path (Split-Path $PSCommandPath -Parent) -Parent) 'TCPK.psd1'
    Import-Module $psd1 -Force
    $script:fx = Join-Path ([System.IO.Path]::GetTempPath()) ('tcpk-stream-' + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $script:fx | Out-Null

    # Build a file with a known needle at a known byte offset, padded to $SizeBytes.
    function script:New-BigFile {
        param([string]$Name, [long]$SizeBytes, [string]$Needle, [long]$NeedleAt)
        $p = Join-Path $script:fx $Name
        $fs = [System.IO.FileStream]::new($p, [System.IO.FileMode]::Create, [System.IO.FileAccess]::Write)
        try {
            $filler = New-Object byte[] 1048576
            for ($i = 0; $i -lt $filler.Length; $i++) { $filler[$i] = [byte]0x41 }   # 'A'
            $written = 0
            while ($written -lt $SizeBytes) {
                $take = [int][Math]::Min($filler.Length, $SizeBytes - $written)
                $fs.Write($filler, 0, $take); $written += $take
            }
            if ($Needle) {
                $nb = [System.Text.Encoding]::ASCII.GetBytes($Needle)
                $fs.Position = $NeedleAt
                $fs.Write($nb, 0, $nb.Length)
            }
        } finally { $fs.Dispose() }
        return $p
    }
}
AfterAll {
    if ($script:fx -and (Test-Path $script:fx)) { Remove-Item $script:fx -Recurse -Force -ErrorAction SilentlyContinue }
}

Describe 'Invoke-TcpkOnFileText' {

    It 'decodes a small file whole and reports the three views' {
        $p = Join-Path $script:fx 'small.txt'
        'hello TCPK_MARKER world' | Set-Content -LiteralPath $p -Encoding UTF8
        $srcs = InModuleScope TCPK -Parameters @{ f = $p } {
            param($f)
            $st = @{ Stop = $false; Seen = (New-Object 'System.Collections.Generic.List[string]') }
            Invoke-TcpkOnFileText -Path $f -State $st -OnText { param($t, $s, $x) $x.Seen.Add($s) }
            @($st.Seen.ToArray())
        }
        $srcs | Should -Contain 'utf8'
        $srcs | Should -Contain 'utf16le'
        $srcs | Should -Contain 'utf16le-odd'
        # A small file is one pass per view, never chunked.
        ($srcs | Where-Object { $_ -like '*#*' }).Count | Should -Be 0
    }

    It 'chunks a file above the whole-file threshold instead of loading it whole' {
        # 48 MB > the 40 MB threshold, so this must arrive as numbered chunks.
        $p = New-BigFile 'big.bin' (48MB) 'TCPK_MARKER_A' 1024
        $srcs = InModuleScope TCPK -Parameters @{ f = $p } {
            param($f)
            $st = @{ Stop = $false; Seen = (New-Object 'System.Collections.Generic.List[string]') }
            Invoke-TcpkOnFileText -Path $f -State $st -OnText { param($t, $s, $x) $x.Seen.Add($s) }
            @($st.Seen.ToArray())
        }
        ($srcs | Where-Object { $_ -like 'utf8#*' }).Count | Should -BeGreaterThan 1
        # Chunk ordinals must be distinct and sequential, not the byte count.
        $srcs | Should -Contain 'utf8#1'
        $srcs | Should -Contain 'utf8#2'
    }

    It 'never returns without reading, whatever the size' {
        $p = New-BigFile 'huge.bin' (70MB) 'TCPK_MARKER_B' (65MB)
        $calls = InModuleScope TCPK -Parameters @{ f = $p } {
            param($f)
            $st = @{ Stop = $false; N = 0 }
            Invoke-TcpkOnFileText -Path $f -State $st -OnText { param($t, $s, $x) $x.N++ }
            $st.N
        }
        $calls | Should -BeGreaterThan 0
    }

    It 'honours an early stop so a short-circuit does not read the whole file' {
        $p = New-BigFile 'stop.bin' (60MB) 'TCPK_MARKER_C' 512
        $calls = InModuleScope TCPK -Parameters @{ f = $p } {
            param($f)
            $st = @{ Stop = $false; N = 0 }
            Invoke-TcpkOnFileText -Path $f -State $st -OnText { param($t, $s, $x) $x.N++; $x.Stop = $true }
            $st.N
        }
        $calls | Should -Be 1
    }
}

Describe 'Test-TcpkFileContainsAny' {

    It 'finds a needle in a file far above any old size cap' {
        # 150 MB: above the 150MB CVE cap, the 50MB decompiler cap and the 5MB Electron cap.
        $p = New-BigFile 'over-caps.bin' (150MB) 'TCPK_NEEDLE_XYZ' (100MB)
        $hit = InModuleScope TCPK -Parameters @{ f = $p } { param($f) Test-TcpkFileContainsAny -Path $f -Needles @('TCPK_NEEDLE_XYZ') }
        $hit | Should -BeTrue
    }

    It 'finds a needle that STRADDLES a chunk boundary' {
        # The 16 MB chunk boundary is the one place chunking can silently lose a match.
        # Place the needle so it spans it.
        $needle = 'TCPK_BOUNDARY_NEEDLE'
        $at = (16MB) - 8
        $p = New-BigFile 'boundary.bin' (48MB) $needle $at
        $hit = InModuleScope TCPK -Parameters @{ f = $p; n = $needle } { param($f, $n) Test-TcpkFileContainsAny -Path $f -Needles @($n) }
        $hit | Should -BeTrue -Because 'the 64 KB overlap exists precisely to catch this'
    }

    It 'returns false for an absent needle without throwing' {
        $p = New-BigFile 'absent.bin' (45MB) '' 0
        $hit = InModuleScope TCPK -Parameters @{ f = $p } { param($f) Test-TcpkFileContainsAny -Path $f -Needles @('NOT_PRESENT_ANYWHERE') }
        $hit | Should -BeFalse
    }

    It 'is case-insensitive by default and exact with -CaseSensitive' {
        $p = Join-Path $script:fx 'case.txt'
        'MixedCaseToken' | Set-Content -LiteralPath $p -Encoding UTF8
        (InModuleScope TCPK -Parameters @{ f = $p } { param($f) Test-TcpkFileContainsAny -Path $f -Needles @('mixedcasetoken') }) | Should -BeTrue
        (InModuleScope TCPK -Parameters @{ f = $p } { param($f) Test-TcpkFileContainsAny -Path $f -Needles @('mixedcasetoken') -CaseSensitive }) | Should -BeFalse
    }
}

Describe 'Select-TcpkFileMatch' {

    It 'deduplicates a match re-presented by the chunk overlap' {
        # A needle inside the overlap region is decoded twice by design. If dedup were
        # missing, the count would be inflated and any severity derived from it wrong.
        $needle = 'TCPK_DUP_NEEDLE'
        $p = New-BigFile 'dup.bin' (48MB) $needle ((16MB) - 16)
        $m = InModuleScope TCPK -Parameters @{ f = $p; n = $needle } {
            param($f, $n) @(Select-TcpkFileMatch -Path $f -Pattern ([regex]::Escape($n)))
        }
        $m.Count | Should -Be 1
    }

    It 'bounds the RESULT SET without bounding the read' {
        $p = Join-Path $script:fx 'many.txt'
        (1..50 | ForEach-Object { "TOKEN_$_" }) -join "`n" | Set-Content -LiteralPath $p -Encoding UTF8
        $m = InModuleScope TCPK -Parameters @{ f = $p } { param($f) @(Select-TcpkFileMatch -Path $f -Pattern 'TOKEN_\d+' -MaxMatches 5) }
        $m.Count | Should -Be 5
    }

    It 'returns an empty array for an invalid pattern instead of throwing' {
        $p = Join-Path $script:fx 'bad.txt'
        'x' | Set-Content -LiteralPath $p -Encoding UTF8
        $m = InModuleScope TCPK -Parameters @{ f = $p } { param($f) @(Select-TcpkFileMatch -Path $f -Pattern '([unclosed') }
        $m.Count | Should -Be 0
    }
}

Describe 'Get-TcpkFirstFileMatch' {
    It 'returns the first match, or empty string when there is none' {
        $p = Join-Path $script:fx 'first.txt'
        'ver=1.2.3 and ver=9.9.9' | Set-Content -LiteralPath $p -Encoding UTF8
        (InModuleScope TCPK -Parameters @{ f = $p } { param($f) Get-TcpkFirstFileMatch -Path $f -Pattern 'ver=\d+\.\d+\.\d+' }) | Should -Be 'ver=1.2.3'
        (InModuleScope TCPK -Parameters @{ f = $p } { param($f) Get-TcpkFirstFileMatch -Path $f -Pattern 'nothing\d+' }) | Should -Be ''
    }
}

Describe 'Get-TcpkSubstringCount streams rather than skipping' {
    It 'counts occurrences in a file above the whole-file threshold' {
        $p = New-BigFile 'count.bin' (45MB) 'TCPK_COUNT_ME' 2048
        $c = InModuleScope TCPK -Parameters @{ f = $p } { param($f) Get-TcpkSubstringCount -Path $f -Needle 'TCPK_COUNT_ME' }
        $c | Should -BeGreaterThan 0
    }
}
