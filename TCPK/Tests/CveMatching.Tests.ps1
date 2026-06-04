#requires -Version 5.1
# Pester 5: Get-TcpkCveMatches native/embedded matching must not flag asset files.
# Regression for: Get-ChildItem -Include is ignored with -LiteralPath (so PNGs leaked
# into the DLL inventory) AND the bare 'nw' host token matched 'appicoNWideTile', so a
# PNG was wrongly treated as the zlib/libwebp embedding host.

BeforeAll {
    $psd1 = Join-Path (Split-Path (Split-Path $PSCommandPath -Parent) -Parent) 'TCPK.psd1'
    Import-Module $psd1 -Force
}

Describe 'Get-TcpkCveMatches - embedded-host attribution' {
    It 'does NOT flag a directory that only contains asset files (PNG)' {
        $dir = Join-Path $env:TEMP ('tcpk-cvet-a-' + [guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory -Path $dir | Out-Null
        Set-Content -LiteralPath (Join-Path $dir 'appiconWideTile.scale-100.png') -Value 'x' -Encoding ASCII
        try {
            $r = @(Get-TcpkCveMatches -Path $dir)
            @($r | Where-Object Status -eq 'PossiblyEmbedded') | Should -BeNullOrEmpty
            @($r | Where-Object { $_.File -like '*.png' })      | Should -BeNullOrEmpty
        } finally { Remove-Item $dir -Recurse -Force -ErrorAction SilentlyContinue }
    }
    It 'still attributes embedded CVEs to a real host library, not an asset' {
        $dir = Join-Path $env:TEMP ('tcpk-cvet-b-' + [guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory -Path $dir | Out-Null
        Set-Content -LiteralPath (Join-Path $dir 'WebView2Loader.dll') -Value 'x' -Encoding ASCII
        Set-Content -LiteralPath (Join-Path $dir 'appiconWideTile.scale-100.png') -Value 'x' -Encoding ASCII
        try {
            $emb = @(Get-TcpkCveMatches -Path $dir | Where-Object Status -eq 'PossiblyEmbedded')
            $emb.Count | Should -BeGreaterThan 0
            foreach ($e in $emb) { $e.File | Should -Not -BeLike '*.png' }
        } finally { Remove-Item $dir -Recurse -Force -ErrorAction SilentlyContinue }
    }
}
