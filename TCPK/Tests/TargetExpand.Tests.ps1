#requires -Version 5.1
# Target expansion: the audit accepts sealed containers and unwraps them to a folder.
# A directory / single exe is returned as-is; a ZIP is safely extracted (zip-slip guarded);
# MSI routes to msiexec /a (not unit-tested here -- needs a real MSI). Graceful on failure.

BeforeAll {
    $psd1 = Join-Path (Split-Path (Split-Path $PSCommandPath -Parent) -Parent) 'TCPK.psd1'
    Import-Module $psd1 -Force
    $script:work = Join-Path ([IO.Path]::GetTempPath()) ("tcpk-expand-" + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $script:work -Force | Out-Null

    # a plain dir and a single exe (both should pass through unchanged)
    $script:dir = Join-Path $script:work 'plaindir'
    New-Item -ItemType Directory -Path $script:dir -Force | Out-Null
    'x' | Set-Content -LiteralPath (Join-Path $script:dir 'a.txt')
    $script:exe = Join-Path $script:work 'app.exe'
    'MZ' | Set-Content -LiteralPath $script:exe

    # a zip with one safe entry and one zip-slip entry (escapes via ../)
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $script:slipMarker = 'tcpkslip_' + [guid]::NewGuid().ToString('N') + '.txt'
    $script:zip = Join-Path $script:work 'pkg.zip'
    $z = [System.IO.Compression.ZipFile]::Open($script:zip, 'Create')
    foreach ($pair in @(@{n='app/readme.txt'; t='hello'}, @{n=('../' + $script:slipMarker); t='evil'})) {
        $e = $z.CreateEntry($pair.n); $s = $e.Open()
        $b = [Text.Encoding]::ASCII.GetBytes($pair.t); $s.Write($b, 0, $b.Length); $s.Dispose()
    }
    $z.Dispose()
}

AfterAll {
    # remove the zip-slip marker if it somehow escaped, then the work dir
    $esc = Join-Path ([IO.Path]::GetTempPath()) $script:slipMarker
    if (Test-Path -LiteralPath $esc) { try { [IO.File]::Delete($esc) } catch {} }
    if ($script:work -and (Test-Path -LiteralPath $script:work)) { try { [System.IO.Directory]::Delete($script:work, $true) } catch {} }
}

Describe 'Expand-TcpkTarget' {
    It 'returns a directory unchanged' {
        (& (Get-Module TCPK) { param($p) Expand-TcpkTarget -Path $p } $script:dir) | Should -Be $script:dir
    }
    It 'returns a single exe path unchanged' {
        (& (Get-Module TCPK) { param($p) Expand-TcpkTarget -Path $p } $script:exe) | Should -Be $script:exe
    }
    It 'extracts a ZIP to a folder containing the safe entry' {
        $out = & (Get-Module TCPK) { param($p) Expand-TcpkTarget -Path $p } $script:zip
        $out | Should -Not -Be $script:zip
        (Test-Path -LiteralPath $out -PathType Container) | Should -BeTrue
        (Test-Path -LiteralPath (Join-Path $out 'app\readme.txt')) | Should -BeTrue
    }
    It 'guards zip-slip: the escaping entry is NOT written outside the extraction root' {
        $null = & (Get-Module TCPK) { param($p) Expand-TcpkTarget -Path $p } $script:zip 3>$null
        $escaped = Join-Path ([IO.Path]::GetTempPath()) $script:slipMarker
        (Test-Path -LiteralPath $escaped) | Should -BeFalse
    }
}
