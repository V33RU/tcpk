#requires -Version 5.1
# Pester 5: the three conditions under which every check runs to completion and the
# results still are not evidence -- a packed binary, a single-file bundle above the
# extractor ceiling, and a non-managed stack. Each one used to be silent, which made
# the audit output identical to a genuinely clean target.
#
# Fixtures are REAL PE files built here byte by byte, not stubs: Read-TcpkPe parses
# them and returns their section names, which is what Test-TcpkPacker keys on. If the
# PE layout below were wrong the parser would return $null and these tests would fail
# rather than silently pass.

BeforeAll {
    $psd1 = Join-Path (Split-Path (Split-Path $PSCommandPath -Parent) -Parent) 'TCPK.psd1'
    Import-Module $psd1 -Force

    $script:work = Join-Path ([IO.Path]::GetTempPath()) ("tcpk-reliab-" + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Force -Path $script:work | Out-Null

    # Minimal but structurally valid PE32. Layout: DOS stub with e_lfanew at 0x3C ->
    # 'PE\0\0' -> COFF header -> 224-byte optional header (magic 0x10B) -> section table.
    function script:New-TestPe {
        param([string]$Path, [string[]]$Sections)
        $PEOFF = 0x80
        $ms = New-Object System.IO.MemoryStream
        $bw = New-Object System.IO.BinaryWriter($ms)

        $dos = New-Object byte[] $PEOFF
        $dos[0] = 0x4D; $dos[1] = 0x5A                                   # 'MZ'
        [Array]::Copy([BitConverter]::GetBytes([int]$PEOFF), 0, $dos, 0x3C, 4)
        $bw.Write($dos)

        $bw.Write([byte[]]@(0x50, 0x45, 0x00, 0x00))                     # 'PE\0\0'
        $OPT = 224
        $bw.Write([uint16]0x14C)                 # Machine i386
        $bw.Write([uint16]$Sections.Count)       # NumberOfSections
        $bw.Write([uint32]0)                     # TimeDateStamp
        $bw.Write([uint32]0)                     # PointerToSymbolTable
        $bw.Write([uint32]0)                     # NumberOfSymbols
        $bw.Write([uint16]$OPT)                  # SizeOfOptionalHeader
        $bw.Write([uint16]0x0102)                # Characteristics

        $opt = New-Object byte[] $OPT
        [Array]::Copy([BitConverter]::GetBytes([uint16]0x10B), 0, $opt, 0,  2)   # PE32
        [Array]::Copy([BitConverter]::GetBytes([uint32]0x1000), 0, $opt, 4,  4)  # SizeOfCode
        [Array]::Copy([BitConverter]::GetBytes([uint16]0x0140), 0, $opt, 70, 2)  # DllCharacteristics
        [Array]::Copy([BitConverter]::GetBytes([uint32]16),    0, $opt, 92, 4)   # NumberOfRvaAndSizes
        $bw.Write($opt)

        $i = 0
        foreach ($n in $Sections) {
            $nm = New-Object byte[] 8
            $nb = [Text.Encoding]::ASCII.GetBytes($n)
            [Array]::Copy($nb, 0, $nm, 0, [Math]::Min(8, $nb.Length))
            $bw.Write($nm)
            $bw.Write([uint32]0x1000)                # VirtualSize
            $bw.Write([uint32](0x1000 * ($i + 1)))   # VirtualAddress
            $bw.Write([uint32]0x200)                 # SizeOfRawData
            $bw.Write([uint32](0x400 * ($i + 1)))    # PointerToRawData
            $bw.Write([uint32]0); $bw.Write([uint32]0)
            $bw.Write([uint16]0); $bw.Write([uint16]0)
            # 0xE0000020 as a decimal literal: PowerShell reads the hex form as a signed
            # Int32 first, which is negative, and the cast to UInt32 then throws.
            $bw.Write([uint32]3758096416)            # Characteristics: CODE|EXECUTE|READ|WRITE
            $i++
        }
        $bw.Flush()
        $bytes = $ms.ToArray()
        if ($bytes.Length -lt 0x600) { $bytes += (New-Object byte[] (0x600 - $bytes.Length)) }
        [IO.File]::WriteAllBytes($Path, $bytes)
        $bw.Dispose(); $ms.Dispose()
    }
}

AfterAll {
    if ($script:work -and (Test-Path $script:work)) {
        Remove-Item $script:work -Recurse -Force -ErrorAction SilentlyContinue
    }
}

Describe 'Scan reliability: the PE fixtures are real' {
    It 'builds a PE that the production parser actually reads' {
        $p = Join-Path $script:work 'parsecheck.exe'
        script:New-TestPe -Path $p -Sections @('UPX0', 'UPX1', '.rsrc')
        $info = & (Get-Module TCPK) { param($x) Read-TcpkPe -Path $x } $p
        $info | Should -Not -BeNullOrEmpty
        $info.SectionNames | Should -Contain 'UPX0'
    }
}

Describe 'Scan reliability: packed binary is not reported as clean' {
    BeforeAll {
        $script:pdir = Join-Path $script:work 'packed'
        New-Item -ItemType Directory -Force -Path $script:pdir | Out-Null
        script:New-TestPe -Path (Join-Path $script:pdir 'app.exe') -Sections @('UPX0', 'UPX1', '.rsrc')
        & (Get-Module TCPK) { Reset-TcpkScanStats }
        $script:pf  = @(Test-TcpkPacker -Path $script:pdir)
        $script:pst = & (Get-Module TCPK) { Get-TcpkScanStats }
        $script:pcov = @(Test-TcpkScanCoverage)
    }

    It 'detects the packer' {
        @($script:pf | Where-Object { $_.RuleId -eq 'packer.detected' }).Count | Should -BeGreaterThan 0
    }

    It 'registers the coverage consequence, not just the packer fact' {
        [int]$script:pst.PackedOpaqueCount | Should -BeGreaterThan 0
    }

    It 'raises a coverage finding at MEDIUM, because a whole check family is invalidated' {
        $c = @($script:pcov | Where-Object { $_.RuleId -eq 'scan.incomplete-coverage' })
        $c.Count | Should -Be 1
        $c[0].Severity | Should -Be 'MEDIUM'
    }

    It 'says in the title that the results are unreliable, so a title-only reader is warned' {
        $c = @($script:pcov | Where-Object { $_.RuleId -eq 'scan.incomplete-coverage' })
        "$($c[0].Title)" | Should -Match 'UNRELIABLE'
        "$($c[0].Title)" | Should -Match 'packed'
    }

    It 'tells the operator the low finding count is not evidence of a clean target' {
        $c = @($script:pcov | Where-Object { $_.RuleId -eq 'scan.incomplete-coverage' })
        "$($c[0].Fix)" | Should -Match 'NOT evidence'
        "$($c[0].Fix)" | Should -Match 'Unpack'
    }
}

Describe 'Scan reliability: a clean binary stays silent (no false positive)' {
    It 'registers nothing and emits no coverage finding' {
        $cdir = Join-Path $script:work 'clean'
        New-Item -ItemType Directory -Force -Path $cdir | Out-Null
        script:New-TestPe -Path (Join-Path $cdir 'app.exe') -Sections @('.text', '.data', '.rsrc')
        & (Get-Module TCPK) { Reset-TcpkScanStats }
        $null = @(Test-TcpkPacker -Path $cdir)
        $st = & (Get-Module TCPK) { Get-TcpkScanStats }
        [int]$st.PackedOpaqueCount | Should -Be 0
        @(Test-TcpkScanCoverage).Count | Should -Be 0
    }
}

Describe 'Scan reliability: oversized single-file bundle is not silently skipped' {
    BeforeAll {
        $script:big = Join-Path $script:work 'bigapp.exe'
        [IO.File]::WriteAllBytes($script:big, (New-Object byte[] 200000))
        & (Get-Module TCPK) { Reset-TcpkScanStats }
        # The real production function, with the ceiling lowered so the test does not
        # need a 700 MB file on disk. The size branch under test is the same one.
        $script:bigRet = & (Get-Module TCPK) { param($p) Test-TcpkSingleFileExe -Path $p -MaxBytes 1000 } $script:big
        $script:bst    = & (Get-Module TCPK) { Get-TcpkScanStats }
        $script:bcov   = @(Test-TcpkScanCoverage)
    }

    It 'still returns null, so existing callers are unchanged' {
        $script:bigRet | Should -BeNullOrEmpty
    }

    It 'records the skip, which is what distinguishes it from "not a bundle"' {
        [int]$script:bst.BundleTooLargeCount | Should -Be 1
    }

    It 'reports the real byte size rather than a rounded zero' {
        $s = (@($script:bst.BundleTooLargeSample) -join ' ')
        $s | Should -Match '200000 bytes'
        $s | Should -Match 'ceiling 1000 bytes'
    }

    It 'states in the title that the managed assemblies were never scanned' {
        $c = @($script:bcov | Where-Object { $_.RuleId -eq 'scan.incomplete-coverage' })
        $c.Count | Should -Be 1
        $c[0].Severity | Should -Be 'MEDIUM'
        "$($c[0].Title)" | Should -Match 'INCOMPLETE'
        "$($c[0].Fix)"   | Should -Match 'Expand-TcpkSingleFile'
    }
}

Describe 'Scan reliability: non-managed stack declares the IL limit' {
    BeforeAll {
        $script:qdir = Join-Path $script:work 'qtapp'
        New-Item -ItemType Directory -Force -Path $script:qdir | Out-Null
        script:New-TestPe -Path (Join-Path $script:qdir 'app.exe')     -Sections @('.text', '.data')
        script:New-TestPe -Path (Join-Path $script:qdir 'qt6core.dll') -Sections @('.text', '.data')
        & (Get-Module TCPK) { Reset-TcpkScanStats }
        $script:qf   = @(Test-TcpkAppStack -Path $script:qdir)
        $script:qst  = & (Get-Module TCPK) { Get-TcpkScanStats }
        $script:qcov = @(Test-TcpkScanCoverage)
    }

    It 'fingerprints the Qt stack' {
        @($script:qf | Where-Object { $_.RuleId -eq 'appstack.qt' }).Count | Should -Be 1
    }

    It 'registers that the IL provers could not read this target' {
        [int]$script:qst.NativeOnlyCount | Should -BeGreaterThan 0
    }

    It 'reports at LOW, because native checks did run and their results stand' {
        $c = @($script:qcov | Where-Object { $_.RuleId -eq 'scan.incomplete-coverage' })
        $c.Count | Should -Be 1
        $c[0].Severity | Should -Be 'LOW'
        "$($c[0].Title)" | Should -Match 'PARTIAL'
        "$($c[0].Fix)"   | Should -Match 'capability limit'
    }
}

Describe 'Scan reliability: a failed CVE lookup is not a clean supply chain' {
    BeforeAll {
        & (Get-Module TCPK) { Reset-TcpkScanStats }
        # Force a REAL network failure by pointing the OSV endpoint at an unroutable host,
        # rather than mocking the transport. The .invalid TLD is reserved by RFC 2606 and
        # can never resolve, so this exercises the actual catch block.
        $script:osvMatches = & (Get-Module TCPK) {
            $orig = $script:TcpkOsvBatchUri
            $script:TcpkOsvBatchUri = 'https://osv-does-not-exist.invalid/v1/querybatch'
            Reset-TcpkOsvQueryStatus
            $comp = @(
                [pscustomobject]@{ Name = 'Newtonsoft.Json'; Version = '9.0.1'; File = 'deps.json' },
                [pscustomobject]@{ Name = 'log4net';         Version = '2.0.8'; File = 'deps.json' }
            )
            $r = @(Get-TcpkOsvQueryNet -Components $comp -Ecosystem 'NuGet' -TimeoutSec 5 -WarningAction SilentlyContinue)
            $script:TcpkOsvBatchUri = $orig
            , $r
        }
        $script:cveStats = & (Get-Module TCPK) { Get-TcpkScanStats }
        $script:cveCov   = @(Test-TcpkScanCoverage)
    }

    It 'returns no CVE matches, which on its own looks like a clean supply chain' {
        @($script:osvMatches).Count | Should -Be 0
    }

    It 'registers the failed lookup instead of leaving it to a console warning' {
        [int]$script:cveStats.CveLookupFailedCount | Should -BeGreaterThan 0
    }

    It 'names the component count and the transport error in the sample' {
        (@($script:cveStats.CveLookupFailedSample) -join ' ') | Should -Match '2 component'
    }

    It 'reports at MEDIUM and says the dependency surface was NOT tested' {
        $c = @($script:cveCov | Where-Object { $_.RuleId -eq 'scan.incomplete-coverage' })
        $c.Count | Should -Be 1
        $c[0].Severity   | Should -Be 'MEDIUM'
        "$($c[0].Title)" | Should -Match 'NOT tested'
    }

    It 'states there is no offline database to fall back to' {
        $c = @($script:cveCov | Where-Object { $_.RuleId -eq 'scan.incomplete-coverage' })
        "$($c[0].Fix)" | Should -Match 'NO offline CVE database'
        "$($c[0].Fix)" | Should -Match 'UNTESTED for this run, not clean'
    }
}

Describe 'Scan reliability: a managed stack does NOT trigger the native limit' {
    It 'stays silent for an Avalonia/.NET target' {
        $mdir = Join-Path $script:work 'managed'
        New-Item -ItemType Directory -Force -Path $mdir | Out-Null
        script:New-TestPe -Path (Join-Path $mdir 'Avalonia.Base.dll') -Sections @('.text', '.data')
        & (Get-Module TCPK) { Reset-TcpkScanStats }
        $null = @(Test-TcpkAppStack -Path $mdir)
        $st = & (Get-Module TCPK) { Get-TcpkScanStats }
        [int]$st.NativeOnlyCount | Should -Be 0
    }
}
