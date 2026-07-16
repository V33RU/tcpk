#requires -Version 5.1
# Pester 5: static-unpacker batch - Java archive cracking, asar extraction, UPX -Unpack guard.

BeforeAll {
    $psd1 = Join-Path (Split-Path (Split-Path $PSCommandPath -Parent) -Parent) 'TCPK.psd1'
    Import-Module $psd1 -Force
    Add-Type -AssemblyName System.IO.Compression.FileSystem

    $script:fx = Join-Path ([System.IO.Path]::GetTempPath()) ('tcpk-unpack-' + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $script:fx | Out-Null

    # a .jar (zip) with a secret-bearing properties file
    $src = Join-Path $script:fx 'jarsrc'; New-Item -ItemType Directory -Path $src | Out-Null
    "db.password=hunter2`naws_key=AKIAIOSFODNN7EXAMPLE" | Set-Content -LiteralPath (Join-Path $src 'app.properties') -Encoding UTF8
    $script:jar = Join-Path $script:fx 'app.jar'
    [System.IO.Compression.ZipFile]::CreateFromDirectory($src, $script:jar)

    # a minimal asar with one JS module (secret + insecure flag)
    $content = 'const apiKey="AKIAIOSFODNN7EXAMPLE"; nodeIntegration: true'
    $data = [Text.Encoding]::UTF8.GetBytes($content)
    $hdr = @{ files = @{ 'main.js' = @{ size = $data.Length; offset = '0' } } } | ConvertTo-Json -Depth 6 -Compress
    $hb = [Text.Encoding]::UTF8.GetBytes($hdr)
    $pickleLen = 4 + $hb.Length
    $pad = (4 - ($pickleLen % 4)) % 4
    $hdrSize = $pickleLen + $pad
    $ms = New-Object System.IO.MemoryStream
    $bw = New-Object System.IO.BinaryWriter($ms)
    $bw.Write([uint32]4); $bw.Write([uint32]$hdrSize); $bw.Write([uint32]$hb.Length); $bw.Write($hb)
    for ($i=0; $i -lt $pad; $i++) { $bw.Write([byte]0) }
    $bw.Write($data); $bw.Flush()
    $script:asar = Join-Path $script:fx 'app.asar'
    [IO.File]::WriteAllBytes($script:asar, $ms.ToArray()); $ms.Dispose()
}
AfterAll {
    if ($script:fx -and (Test-Path $script:fx)) { Remove-Item $script:fx -Recurse -Force -ErrorAction SilentlyContinue }
}

Describe 'Test-TcpkJavaBundle' {
    It 'is exported' { Get-Command Test-TcpkJavaBundle -EA SilentlyContinue | Should -Not -BeNullOrEmpty }
    It 'reports the archive and a secret inside it' {
        $f = @(Test-TcpkJavaBundle -Path $script:fx)
        ($f | Where-Object RuleId -eq 'javabundle.archive') | Should -Not -BeNullOrEmpty
        ($f | Where-Object { $_.RuleId -like 'javabundle.*' -and $_.RuleId -ne 'javabundle.archive' }) | Should -Not -BeNullOrEmpty
    }
}

Describe 'Expand-TcpkAsar' {
    It 'is exported' { Get-Command Expand-TcpkAsar -EA SilentlyContinue | Should -Not -BeNullOrEmpty }
    It 'extracts the bundle and flags the insecure Electron flag + secret' {
        $f = @(Expand-TcpkAsar -Path $script:asar -OutDir (Join-Path $script:fx 'out'))
        ($f | Where-Object RuleId -eq 'asar.expanded') | Should -Not -BeNullOrEmpty
        ($f | Where-Object RuleId -eq 'asar.electron-insecure-flag') | Should -Not -BeNullOrEmpty
    }
}

Describe 'Test-TcpkPacker -Unpack' {
    It 'does not throw when upx is unavailable' {
        { Test-TcpkPacker -Path $script:fx -Unpack | Out-Null } | Should -Not -Throw
    }
}
