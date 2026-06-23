#requires -Version 5.1
# Electron/JS TLS certificate-validation bypass detector (v1.7.x -- the "proof for Electron" slice).
# The custom cert-verify path is invisible to the .NET IL prover; this JS-aware check catches the
# accept-all shapes, including the trust-on-first-use-that-never-rejects shape that hid the
# real-world cert bypass we previously had to find by reading app.asar by hand.

BeforeAll {
    $psd1 = Join-Path (Split-Path (Split-Path $PSCommandPath -Parent) -Parent) 'TCPK.psd1'
    Import-Module $psd1 -Force
    $script:work = Join-Path ([IO.Path]::GetTempPath()) ("tcpk-certbypass-" + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $script:work -Force | Out-Null
    function New-AsarApp { param([string]$Dir, [string]$Js)
        New-Item -ItemType Directory -Path $Dir -Force | Out-Null
        [IO.File]::WriteAllText((Join-Path $Dir 'app.asar'), $Js)
    }
    # accept-all: a verify proc that can only ever succeed (callback(code), no callback(-2)) -- the TOFU shape
    $script:bypass = Join-Path $script:work 'bypass'
    New-AsarApp -Dir $script:bypass -Js @'
const { app, session } = require("electron");
const pins = {};
function verifyCertPin(host, fp){ if(!pins[host]){ pins[host]=[fp]; return {code:0}; } pins[host].push(fp); return {code:0}; }
session.defaultSession.setCertificateVerifyProc((request, callback) => {
  const { code } = verifyCertPin(request.hostname, request.certificate.fingerprint);
  callback(code);
});
'@
    # safe: a verifier that rejects a mismatch with callback(-2)
    $script:safe = Join-Path $script:work 'safe'
    New-AsarApp -Dir $script:safe -Js @'
session.defaultSession.setCertificateVerifyProc((request, callback) => {
  if (request.certificate.fingerprint === PINNED) { callback(0); } else { callback(-2); }
});
'@
    # explicit disable via rejectUnauthorized:false
    $script:disable = Join-Path $script:work 'disable'
    New-AsarApp -Dir $script:disable -Js 'const a = fetch(u, { agent: new https.Agent({ rejectUnauthorized: false }) });'
}
AfterAll { if ($script:work -and (Test-Path -LiteralPath $script:work)) { [IO.Directory]::Delete($script:work, $true) } }

Describe 'Electron cert-validation bypass detection' {
    It 'flags setCertificateVerifyProc with no callback(-2) reject path (the TOFU never-rejects shape)' {
        $f = @(Test-TcpkElectron -Path $script:bypass | Where-Object RuleId -eq 'electron.cert-validation-bypass')
        @($f).Count   | Should -BeGreaterThan 0
        $f[0].Severity | Should -Be 'HIGH'
    }
    It 'does NOT flag a verifier that rejects a mismatch with callback(-2)' {
        $f = @(Test-TcpkElectron -Path $script:safe | Where-Object RuleId -eq 'electron.cert-validation-bypass')
        @($f).Count | Should -Be 0
    }
    It 'flags rejectUnauthorized:false as Confirmed' {
        $f = @(Test-TcpkElectron -Path $script:disable | Where-Object RuleId -eq 'electron.cert-validation-bypass')
        @($f).Count    | Should -BeGreaterThan 0
        $f[0].Confidence | Should -Be 'Confirmed'
    }
}

Describe 'cert-validation-bypass standards mapping' {
    It 'maps to net-mitm CVSS, OWASP DA7, and ATT&CK T1557' {
        $r = & (Get-Module TCPK) {
            $a = New-TcpkFinding -Module static -RuleId 'electron.cert-validation-bypass' -Severity HIGH -Title 'x'
            [pscustomobject]@{
                Cvss = (Get-TcpkCvssVector $a).Source
                Da   = (Get-TcpkOwaspDa 'electron.cert-validation-bypass')
                Att  = ((Get-TcpkAttackTechnique 'electron.cert-validation-bypass') -join ',')
            }
        }
        $r.Cvss | Should -Match 'net-mitm'
        $r.Da   | Should -Match '^DA7'
        $r.Att  | Should -Match 'T1557'
    }
}
