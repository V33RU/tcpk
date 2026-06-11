#requires -Version 5.1
# G4: unsafe archive extraction (zip-slip) in the app's own code -- flagged unless a
#     path-containment guard is present (then INFO).
# G5: embedded local HTTP server -- bound to all interfaces (MEDIUM), loopback (INFO),
#     or unclear (LOW).

BeforeAll {
    $psd1 = Join-Path (Split-Path (Split-Path $PSCommandPath -Parent) -Parent) 'TCPK.psd1'
    Import-Module $psd1 -Force
    $script:work = Join-Path ([IO.Path]::GetTempPath()) ("tcpk-arcsrv-" + [guid]::NewGuid().ToString('N'))

    function New-ElectronDir([string]$name, [string]$mainjs) {
        $d = Join-Path $script:work $name
        New-Item -ItemType Directory -Path $d -Force | Out-Null
        New-Item -ItemType File -Path (Join-Path $d 'ffmpeg.dll') -Force | Out-Null
        $mainjs | Set-Content -LiteralPath (Join-Path $d 'main.js') -Encoding UTF8
        return $d
    }

    $script:zipUnsafe = New-ElectronDir 'zipunsafe' @'
const AdmZip = require('adm-zip');
const zip = new AdmZip(inputFile);
zip.extractAllTo(destDir, true);
'@
    $script:zipGuard = New-ElectronDir 'zipguard' @'
const AdmZip = require('adm-zip');
function check(entries, root) {
  entries.forEach(e => {
    const dest = path.resolve(root, e.entryName);
    if (!dest.startsWith(root)) throw new Error('zip slip blocked');
  });
}
zip.extractAllTo(destDir, true);
'@
    $script:srvExposed = New-ElectronDir 'srvexposed' @'
const http = require('http');
http.createServer(handler).listen(8080, '0.0.0.0');
'@
    $script:srvLoop = New-ElectronDir 'srvloop' @'
const http = require('http');
http.createServer(handler).listen(port, '127.0.0.1');
'@
    $script:srvUnclear = New-ElectronDir 'srvunclear' @'
const http = require('http');
http.createServer(handler).listen(8080);
'@
}

AfterAll {
    if ($script:work -and (Test-Path -LiteralPath $script:work)) {
        try { [System.IO.Directory]::Delete($script:work, $true) } catch {}
    }
}

Describe 'Test-TcpkElectron archive extraction (G4)' {
    It 'flags unguarded extraction as zip-slip MEDIUM' {
        $f = @(Test-TcpkElectron -Path $script:zipUnsafe | Where-Object RuleId -eq 'electron.archive-zip-slip')
        $f.Count | Should -BeGreaterThan 0
        $f[0].Severity | Should -Be 'MEDIUM'
    }
    It 'recognises a containment guard and demotes to INFO' {
        $r = @(Test-TcpkElectron -Path $script:zipGuard)
        @($r | Where-Object RuleId -eq 'electron.archive-zip-slip').Count | Should -Be 0
        @($r | Where-Object RuleId -eq 'electron.archive-extraction').Count | Should -BeGreaterThan 0
    }
}

Describe 'Test-TcpkElectron local HTTP server (G5)' {
    It 'flags an all-interfaces bind as MEDIUM' {
        $f = @(Test-TcpkElectron -Path $script:srvExposed | Where-Object RuleId -eq 'electron.local-server-exposed')
        $f.Count | Should -BeGreaterThan 0
        $f[0].Severity | Should -Be 'MEDIUM'
    }
    It 'treats a loopback bind as INFO' {
        $f = @(Test-TcpkElectron -Path $script:srvLoop | Where-Object RuleId -eq 'electron.local-server')
        $f.Count | Should -BeGreaterThan 0
        $f[0].Severity | Should -Be 'INFO'
    }
    It 'treats an unclear bind as LOW' {
        $f = @(Test-TcpkElectron -Path $script:srvUnclear | Where-Object RuleId -eq 'electron.local-server')
        $f.Count | Should -BeGreaterThan 0
        $f[0].Severity | Should -Be 'LOW'
    }
}
