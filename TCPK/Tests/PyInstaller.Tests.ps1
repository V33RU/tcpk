#requires -Version 5.1
# Pester 5: Expand-TcpkPyInstaller must carve a PyInstaller CArchive back to disk.
#
# Every fixture here is built programmatically in the temp dir from the documented
# format: big-endian cookie and table-of-contents fields written with [BitConverter]
# plus [Array]::Reverse. No captured real-world bytes.
#
# Covered:
#   * a modern (88-byte, pylibname) cookie with a compressed 'm' entry, an 's' entry
#     and a PYZ entry -> all three recovered, bytecode-only MEDIUM fires
#   * a legacy 24-byte cookie (no pylibname) -> still parses
#   * a plaintext .py data entry -> source-recovered fires
#   * a '..\..\evil.txt' entry -> refused, nothing written outside OutDir
#   * a file with no cookie -> a Skipped finding, never silence
#   * a cx_Freeze library.zip -> extracted

BeforeAll {
    $psd1 = Join-Path (Split-Path (Split-Path $PSCommandPath -Parent) -Parent) 'TCPK.psd1'
    Import-Module $psd1 -Force

    Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction SilentlyContinue

    $script:tmp = Join-Path ([System.IO.Path]::GetTempPath()) ('tcpk-pyitest-' + [guid]::NewGuid().ToString('N').Substring(0, 8))
    New-Item -ItemType Directory -Path $script:tmp -Force | Out-Null

    # --- fixture builders -----------------------------------------------------
    function _Be32Bytes([int64]$v) {
        $b = [System.BitConverter]::GetBytes([uint32]$v)
        if ([System.BitConverter]::IsLittleEndian) { [Array]::Reverse($b) }
        return , $b
    }

    # zlib container: 0x78 0x9C + raw deflate + a 4-byte adler slot (the reader skips
    # the header and stops at the end of the deflate stream, so the slot may be zero).
    function _Zlib([byte[]]$Data) {
        $o  = New-Object System.IO.MemoryStream
        $ds = New-Object System.IO.Compression.DeflateStream($o, [System.IO.Compression.CompressionMode]::Compress, $true)
        $ds.Write($Data, 0, $Data.Length)
        $ds.Dispose()
        $raw = $o.ToArray(); $o.Dispose()
        $ms = New-Object System.IO.MemoryStream
        $ms.WriteByte(0x78); $ms.WriteByte(0x9C)
        $ms.Write($raw, 0, $raw.Length)
        $ms.Write([byte[]]@(0, 0, 0, 0), 0, 4)
        $r = $ms.ToArray(); $ms.Dispose()
        return , $r
    }

    # Entries: @{ Name=<string>; Type=<char>; Data=<byte[]>; Compress=<bool> }
    function _BuildPyiExe {
        param(
            [string]$OutFile,
            [object[]]$Entries,
            [int]$PyVer = 311,
            [bool]$OldCookie = $false
        )
        $stub = [System.Text.Encoding]::ASCII.GetBytes('MZ' + ('P' * 254))   # 256-byte stand-in bootloader

        $dataMs = New-Object System.IO.MemoryStream
        $recs = New-Object System.Collections.Generic.List[object]
        foreach ($e in $Entries) {
            $payload = $e.Data
            $flag = 0
            if ($e.Compress) { $payload = _Zlib $e.Data; $flag = 1 }
            $pos = [int]$dataMs.Position
            $dataMs.Write($payload, 0, $payload.Length)
            # BadPos records an offset that points past the end of the file, so the
            # reader has to reject the entry instead of reading garbage.
            if ($null -ne $e.BadPos) { $pos = [int]$e.BadPos }
            $recs.Add([pscustomobject]@{
                Name = $e.Name; Type = $e.Type; Pos = $pos
                CSize = $payload.Length; USize = $e.Data.Length; Flag = $flag
            })
        }
        $dataBytes = $dataMs.ToArray(); $dataMs.Dispose()

        $tocMs = New-Object System.IO.MemoryStream
        foreach ($r in $recs) {
            $nb  = [System.Text.Encoding]::UTF8.GetBytes($r.Name)
            $len = 18 + $nb.Length
            $pad = (16 - ($len % 16)) % 16      # PyInstaller NUL-pads the name slot
            $len += $pad
            $b = _Be32Bytes $len;     $tocMs.Write($b, 0, 4)
            $b = _Be32Bytes $r.Pos;   $tocMs.Write($b, 0, 4)
            $b = _Be32Bytes $r.CSize; $tocMs.Write($b, 0, 4)
            $b = _Be32Bytes $r.USize; $tocMs.Write($b, 0, 4)
            $tocMs.WriteByte([byte]$r.Flag)
            $tocMs.WriteByte([byte][char]$r.Type)
            $tocMs.Write($nb, 0, $nb.Length)
            for ($i = 0; $i -lt $pad; $i++) { $tocMs.WriteByte(0) }
        }
        $tocBytes = $tocMs.ToArray(); $tocMs.Dispose()

        $cookieSize = 88
        if ($OldCookie) { $cookieSize = 24 }
        $lengthofPackage = $dataBytes.Length + $tocBytes.Length + $cookieSize

        $out = New-Object System.IO.MemoryStream
        $out.Write($stub, 0, $stub.Length)
        $out.Write($dataBytes, 0, $dataBytes.Length)
        $out.Write($tocBytes, 0, $tocBytes.Length)
        $magic = [byte[]]@(0x4D, 0x45, 0x49, 0x0C, 0x0B, 0x0A, 0x0B, 0x0E)   # 'MEI' + 0C 0B 0A 0B 0E
        $out.Write($magic, 0, 8)
        $b = _Be32Bytes $lengthofPackage;  $out.Write($b, 0, 4)
        $b = _Be32Bytes $dataBytes.Length; $out.Write($b, 0, 4)   # toc offset from archive base
        $b = _Be32Bytes $tocBytes.Length;  $out.Write($b, 0, 4)
        $b = _Be32Bytes $PyVer;            $out.Write($b, 0, 4)
        if (-not $OldCookie) {
            $lib = New-Object byte[] 64
            $ln = [System.Text.Encoding]::ASCII.GetBytes('python311.dll')
            [Array]::Copy($ln, 0, $lib, 0, $ln.Length)
            $out.Write($lib, 0, 64)
        }
        [System.IO.File]::WriteAllBytes($OutFile, $out.ToArray())
        $out.Dispose()
    }

    function _Ascii([string]$s) { return , ([System.Text.Encoding]::ASCII.GetBytes($s)) }

    # === fixture A: bytecode-only archive, modern cookie =======================
    $script:scriptBody = 'MARSHALLED-ENTRY-SCRIPT-FIXTURE'
    $script:moduleBody = 'MARSHALLED-MODULE-FIXTURE'
    $script:pyzBody    = 'PYZ-CONTAINER-FIXTURE'
    $script:exeA = Join-Path $script:tmp 'appa.exe'
    _BuildPyiExe -OutFile $script:exeA -PyVer 311 -Entries @(
        @{ Name = 'myscript';      Type = 's'; Data = (_Ascii $script:scriptBody); Compress = $true  },
        @{ Name = 'app.mymodule';  Type = 'm'; Data = (_Ascii $script:moduleBody); Compress = $false },
        @{ Name = 'PYZ-00.pyz';    Type = 'z'; Data = (_Ascii $script:pyzBody);    Compress = $false }
    )
    $script:outA  = Join-Path $script:tmp 'outA'
    $script:rootA = Join-Path $script:outA 'appa'
    $script:fA = @(Expand-TcpkPyInstaller -Path $script:exeA -OutDir $script:outA -WarningAction SilentlyContinue)

    # === fixture B: legacy 24-byte cookie + a plaintext .py data entry =========
    $script:exeB = Join-Path $script:tmp 'appb.exe'
    _BuildPyiExe -OutFile $script:exeB -PyVer 27 -OldCookie $true -Entries @(
        @{ Name = 'config/settings.py'; Type = 'x'; Data = (_Ascii "value = 1`n"); Compress = $false },
        @{ Name = 'legacymod';          Type = 'm'; Data = (_Ascii 'LEGACY-MODULE-FIXTURE'); Compress = $true }
    )
    $script:outB  = Join-Path $script:tmp 'outB'
    $script:rootB = Join-Path $script:outB 'appb'
    $script:fB = @(Expand-TcpkPyInstaller -Path $script:exeB -OutDir $script:outB -WarningAction SilentlyContinue)

    # === fixture C: zip-slip ==================================================
    $script:exeC = Join-Path $script:tmp 'appc.exe'
    _BuildPyiExe -OutFile $script:exeC -PyVer 311 -Entries @(
        @{ Name = 'ok.txt';           Type = 'x'; Data = (_Ascii 'INROOT'); Compress = $false },
        @{ Name = '..\..\evil.txt';   Type = 'x'; Data = (_Ascii 'EVIL');   Compress = $false },
        @{ Name = '../../evil2.txt';  Type = 'x'; Data = (_Ascii 'EVIL2');  Compress = $false }
    )
    $script:outC  = Join-Path $script:tmp 'outC'
    $script:rootC = Join-Path $script:outC 'appc'
    $script:warnC = @()
    $script:fC = @(Expand-TcpkPyInstaller -Path $script:exeC -OutDir $script:outC -WarningVariable +script:warnC -WarningAction SilentlyContinue)

    # === fixture D: not a PyInstaller archive =================================
    $script:exeD = Join-Path $script:tmp 'plain.exe'
    $rnd = New-Object byte[] 4096
    (New-Object System.Random 1337).NextBytes($rnd)
    # make sure the random filler cannot accidentally contain the cookie magic
    for ($i = 0; $i -lt $rnd.Length; $i++) { if ($rnd[$i] -eq 0x4D) { $rnd[$i] = 0x41 } }
    [System.IO.File]::WriteAllBytes($script:exeD, $rnd)
    $script:outD = Join-Path $script:tmp 'outD'
    $script:fD = @(Expand-TcpkPyInstaller -Path $script:exeD -OutDir $script:outD -WarningAction SilentlyContinue)

    # === fixture E: cx_Freeze library.zip =====================================
    $script:dirE = Join-Path $script:tmp 'cxapp'
    New-Item -ItemType Directory -Path $script:dirE -Force | Out-Null
    $script:libZip = Join-Path $script:dirE 'library.zip'
    $zfs = [System.IO.File]::Open($script:libZip, [System.IO.FileMode]::Create)
    $za  = New-Object System.IO.Compression.ZipArchive($zfs, [System.IO.Compression.ZipArchiveMode]::Create)
    $ze  = $za.CreateEntry('pkg/mymod.pyc')
    $zw  = $ze.Open()
    $zb  = [System.Text.Encoding]::ASCII.GetBytes('CXFREEZE-MODULE-FIXTURE')
    $zw.Write($zb, 0, $zb.Length); $zw.Dispose()
    $za.Dispose(); $zfs.Dispose()
    $script:outE = Join-Path $script:tmp 'outE'
    $script:fE = @(Expand-TcpkPyInstaller -Path $script:dirE -OutDir $script:outE -WarningAction SilentlyContinue)

    # === fixture G: an entry whose recorded offset runs past the file =========
    $script:exeG = Join-Path $script:tmp 'appg.exe'
    _BuildPyiExe -OutFile $script:exeG -PyVer 311 -Entries @(
        @{ Name = 'good.txt'; Type = 'x'; Data = (_Ascii 'GOOD'); Compress = $false },
        @{ Name = 'torn.txt'; Type = 'x'; Data = (_Ascii 'TORN'); Compress = $false; BadPos = 900000000 }
    )
    $script:outG  = Join-Path $script:tmp 'outG'
    $script:rootG = Join-Path $script:outG 'appg'
    $script:fG = @(Expand-TcpkPyInstaller -Path $script:exeG -OutDir $script:outG -WarningAction SilentlyContinue)

    # === fixture H: the same archive as A, but with the entry cap set to 1 ====
    $script:outH = Join-Path $script:tmp 'outH'
    $script:fH = @(Expand-TcpkPyInstaller -Path $script:exeA -OutDir $script:outH -MaxEntries 1 -WarningAction SilentlyContinue)

    # === fixture F: directory with nothing frozen in it =======================
    $script:dirF = Join-Path $script:tmp 'emptyapp'
    New-Item -ItemType Directory -Path $script:dirF -Force | Out-Null
    [System.IO.File]::WriteAllText((Join-Path $script:dirF 'readme.txt'), 'nothing frozen here')
    $script:outF = Join-Path $script:tmp 'outF'
    $script:fF = @(Expand-TcpkPyInstaller -Path $script:dirF -OutDir $script:outF -WarningAction SilentlyContinue)
}

AfterAll {
    if ($script:tmp) { Remove-Item -LiteralPath $script:tmp -Recurse -Force -ErrorAction SilentlyContinue }
}

Describe 'Expand-TcpkPyInstaller CArchive extraction' {
    It 'recovers every table-of-contents entry to disk' {
        (Join-Path $script:rootA 'myscript.pyc')     | Should -Exist
        (Join-Path $script:rootA 'app.mymodule.pyc') | Should -Exist
        (Join-Path $script:rootA 'PYZ-00.pyz')       | Should -Exist
    }

    It 'inflates a zlib-compressed entry back to the original bytes' {
        $t = [System.IO.File]::ReadAllText((Join-Path $script:rootA 'myscript.pyc'))
        $t | Should -Be $script:scriptBody
    }

    It 'writes an uncompressed entry verbatim' {
        $t = [System.IO.File]::ReadAllText((Join-Path $script:rootA 'app.mymodule.pyc'))
        $t | Should -Be $script:moduleBody
    }

    It 'emits an inventory finding with the entry count' {
        $inv = @($script:fA | Where-Object { $_.RuleId -eq 'pyfrozen.expanded' })
        $inv.Count | Should -Be 1
        $inv[0].Severity   | Should -Be 'INFO'
        $inv[0].Confidence | Should -Be 'Confirmed'
        $inv[0].Title      | Should -Match 'Extracted 3 entries'
        $inv[0].Evidence   | Should -Match 'entries=3'
    }

    It 'reports the Python version decoded from the cookie' {
        $inv = @($script:fA | Where-Object { $_.RuleId -eq 'pyfrozen.expanded' })
        $inv[0].Evidence | Should -Match 'python=3\.11'
    }

    It 'records bytecode-only recovery as a coverage limit, not a weakness' {
        $bc = @($script:fA | Where-Object { $_.RuleId -eq 'pyfrozen.bytecode-only' })
        $bc.Count | Should -Be 1
        # Every PyInstaller build ships .pyc and no .py, so this is the normal shape of the
        # format and not a defect in the application. It is INFO / Skipped because it states
        # that the text-level checks could not read the logic, which is a coverage limit.
        $bc[0].Severity   | Should -Be 'INFO'
        $bc[0].Confidence | Should -Be 'Skipped'
        $bc[0].Evidence   | Should -Match 'pyc=2'
        # honesty: the fix text must point at decompilation as a manual follow-up
        $bc[0].Fix | Should -Match 'decompyle3|uncompyle6'
        # and it must NOT assert what the unread bytecode contains
        "$($bc[0].Impact)" | Should -Not -Match 'pickle\.loads|eval/exec|verify=False'
    }

    It 'states that the PYZ container was recovered but not unpacked' {
        $pz = @($script:fA | Where-Object { $_.RuleId -eq 'pyfrozen.pyz-not-unpacked' })
        $pz.Count | Should -Be 1
        $pz[0].Confidence | Should -Be 'Skipped'
    }

    It 'reports no unreadable entries for a well-formed archive' {
        @($script:fA | Where-Object { $_.RuleId -eq 'pyfrozen.entry-unreadable' }).Count | Should -Be 0
        @($script:fA | Where-Object { $_.RuleId -eq 'pyfrozen.parse-failed' }).Count     | Should -Be 0
    }
}

Describe 'Expand-TcpkPyInstaller legacy 24-byte cookie' {
    It 'parses an archive whose cookie has no pylibname field' {
        $inv = @($script:fB | Where-Object { $_.RuleId -eq 'pyfrozen.expanded' })
        $inv.Count | Should -Be 1
        $inv[0].Evidence | Should -Match 'entries=2'
        $inv[0].Evidence | Should -Match 'python=2\.7'
    }

    It 'preserves the relative path of a nested entry name' {
        (Join-Path (Join-Path $script:rootB 'config') 'settings.py') | Should -Exist
    }

    It 'reports the recovered plaintext source separately' {
        $src = @($script:fB | Where-Object { $_.RuleId -eq 'pyfrozen.source-recovered' })
        $src.Count | Should -Be 1
        $src[0].Cwe | Should -Contain 'CWE-540'
    }

    It 'does not claim bytecode-only when source was recovered' {
        @($script:fB | Where-Object { $_.RuleId -eq 'pyfrozen.bytecode-only' }).Count | Should -Be 0
    }
}

Describe 'Expand-TcpkPyInstaller zip-slip guard' {
    It 'writes the in-root entry' {
        (Join-Path $script:rootC 'ok.txt') | Should -Exist
        [System.IO.File]::ReadAllText((Join-Path $script:rootC 'ok.txt')) | Should -Be 'INROOT'
    }

    It 'writes nothing outside the extraction root' {
        (Join-Path $script:tmp 'evil.txt')   | Should -Not -Exist
        (Join-Path $script:tmp 'evil2.txt')  | Should -Not -Exist
        (Join-Path $script:outC 'evil.txt')  | Should -Not -Exist
        (Join-Path $script:outC 'evil2.txt') | Should -Not -Exist
    }

    It 'contains only the single in-root file under the extraction root' {
        $names = @(Get-ChildItem -LiteralPath $script:rootC -Recurse -File | ForEach-Object { $_.Name })
        $names.Count | Should -Be 1
        $names[0] | Should -Be 'ok.txt'
    }

    It 'reports the refused traversal entries' {
        $zs = @($script:fC | Where-Object { $_.RuleId -eq 'pyfrozen.zipslip-blocked' })
        $zs.Count | Should -Be 1
        $zs[0].Severity | Should -Be 'MEDIUM'
        $zs[0].Cwe | Should -Contain 'CWE-22'
        $zs[0].Title | Should -Match '2 entry names'
    }

    It 'warns on each refused entry' {
        ($script:warnC -join ' ') | Should -Match 'zip-slip|escapes'
    }
}

Describe 'Expand-TcpkPyInstaller non-PyInstaller input' {
    It 'emits a Skipped finding instead of returning silently' {
        $script:fD.Count | Should -BeGreaterThan 0
        $sk = @($script:fD | Where-Object { $_.RuleId -eq 'pyfrozen.not-pyinstaller' })
        $sk.Count | Should -Be 1
        $sk[0].Confidence | Should -Be 'Skipped'
        $sk[0].Severity   | Should -Be 'INFO'
    }

    It 'does not claim the file is clean' {
        $sk = @($script:fD | Where-Object { $_.RuleId -eq 'pyfrozen.not-pyinstaller' })
        $sk[0].Description | Should -Match 'NOT a statement that the file is clean'
    }

    It 'emits a Skipped finding for a directory with nothing frozen in it' {
        $script:fF.Count | Should -BeGreaterThan 0
        @($script:fF | Where-Object { $_.RuleId -eq 'pyfrozen.not-pyinstaller' -and $_.Confidence -eq 'Skipped' }).Count | Should -Be 1
    }
}

Describe 'Expand-TcpkPyInstaller coverage gaps are reported, not hidden' {
    It 'reports an entry it could not recover' {
        (Join-Path $script:rootG 'good.txt') | Should -Exist
        (Join-Path $script:rootG 'torn.txt') | Should -Not -Exist
        $ue = @($script:fG | Where-Object { $_.RuleId -eq 'pyfrozen.entry-unreadable' })
        $ue.Count | Should -Be 1
        $ue[0].Confidence | Should -Be 'Skipped'
        $ue[0].Title | Should -Match '^1 PyInstaller entries could not be recovered'
    }

    It 'reports that extraction stopped at the entry cap' {
        $ch = @($script:fH | Where-Object { $_.RuleId -eq 'pyfrozen.cap-hit' })
        $ch.Count | Should -Be 1
        $ch[0].Confidence | Should -Be 'Skipped'
        $ch[0].Evidence   | Should -Match 'entry cap 1 reached'
        # and the inventory finding must show the truncated count, not the full one
        $inv = @($script:fH | Where-Object { $_.RuleId -eq 'pyfrozen.expanded' })
        $inv[0].Evidence | Should -Match 'entries=1'
    }
}

Describe 'Expand-TcpkPyInstaller cx_Freeze library.zip' {
    It 'extracts the module archive' {
        $inv = @($script:fE | Where-Object { $_.RuleId -eq 'pyfrozen.libzip-expanded' })
        $inv.Count | Should -Be 1
        $inv[0].Evidence | Should -Match 'entries=1'
        $extracted = @(Get-ChildItem -LiteralPath $script:outE -Recurse -File | Where-Object { $_.Name -eq 'mymod.pyc' })
        $extracted.Count | Should -Be 1
        [System.IO.File]::ReadAllText($extracted[0].FullName) | Should -Be 'CXFREEZE-MODULE-FIXTURE'
    }

    It 'does not also report the directory as having no frozen archive' {
        @($script:fE | Where-Object { $_.RuleId -eq 'pyfrozen.not-pyinstaller' }).Count | Should -Be 0
    }
}
