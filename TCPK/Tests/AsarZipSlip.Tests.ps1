#requires -Version 5.1
# Pester 5: Expand-TcpkAsar must not let a malicious asar entry name (a ../ traversal in the
# header file-table) write outside the extraction root. Builds a minimal valid asar with an
# in-root file plus a "../pwned.txt" entry and asserts only the in-root file lands.

BeforeAll {
    $psd1 = Join-Path (Split-Path (Split-Path $PSCommandPath -Parent) -Parent) 'TCPK.psd1'
    Import-Module $psd1 -Force

    $script:tmp = Join-Path ([System.IO.Path]::GetTempPath()) ('tcpk-asartest-' + [guid]::NewGuid().ToString('N').Substring(0, 8))
    New-Item -ItemType Directory -Path $script:tmp -Force | Out-Null

    # header file-table: good.txt in-root, plus a ".." dir holding pwned.txt -> "../pwned.txt"
    $json = '{"files":{"good.txt":{"offset":"0","size":4},"..":{"files":{"pwned.txt":{"offset":"4","size":4}}}}}'
    $jsonBytes = [System.Text.Encoding]::UTF8.GetBytes($json)
    $data = [System.Text.Encoding]::UTF8.GetBytes('GOODEVIL')   # good.txt=GOOD @0, pwned.txt=EVIL @4
    $ms = [System.IO.MemoryStream]::new(); $bw = [System.IO.BinaryWriter]::new($ms)
    $bw.Write([uint32]4)                          # pickle: size-of-size (always 4)
    $bw.Write([uint32](4 + $jsonBytes.Length))    # header pickle size (jsonLen field + json)
    $bw.Write([uint32]$jsonBytes.Length)          # json string length
    $bw.Write($jsonBytes)
    $bw.Write($data)
    $bw.Flush()
    $script:asar = Join-Path $script:tmp 'malicious.asar'
    [System.IO.File]::WriteAllBytes($script:asar, $ms.ToArray()); $bw.Dispose()

    $script:outDir = Join-Path $script:tmp 'out'
    New-Item -ItemType Directory -Path $script:outDir -Force | Out-Null
    $script:outRoot = Join-Path $script:outDir 'malicious'
}
AfterAll { if ($script:tmp) { Remove-Item -LiteralPath $script:tmp -Recurse -Force -ErrorAction SilentlyContinue } }

Describe 'Expand-TcpkAsar zip-slip guard' {
    It 'extracts in-root files but blocks a ../ traversal entry' {
        $null = Expand-TcpkAsar -Path $script:asar -OutDir $script:outDir -WarningAction SilentlyContinue
        (Join-Path $script:outRoot 'good.txt') | Should -Exist
        [System.IO.File]::ReadAllText((Join-Path $script:outRoot 'good.txt')) | Should -Be 'GOOD'
        # the traversal target must NOT have been written one level up (outside the root)
        (Join-Path $script:outDir 'pwned.txt') | Should -Not -Exist
    }
    It 'warns that the escaping entry was skipped' {
        $w = @()
        $null = Expand-TcpkAsar -Path $script:asar -OutDir $script:outDir -WarningVariable +w -WarningAction SilentlyContinue
        ($w -join ' ') | Should -Match 'zip-slip|escapes'
    }
}
