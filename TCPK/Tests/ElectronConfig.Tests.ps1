#requires -Version 5.1
# G1: comment-aware Electron config detection. A renderer-security flag that only appears
# in a COMMENT must NOT fire (the webSecurity:false-in-a-comment false positive found on a
# real app). A real flag inside a webPreferences block is Confirmed; a bare flag elsewhere
# is Inferred (possible prose / dynamically-built options), not a hard finding.

BeforeAll {
    $psd1 = Join-Path (Split-Path (Split-Path $PSCommandPath -Parent) -Parent) 'TCPK.psd1'
    Import-Module $psd1 -Force

    $script:work = Join-Path ([IO.Path]::GetTempPath()) ("tcpk-elec-" + [guid]::NewGuid().ToString('N'))
    # dirA: comment-only webSecurity + a REAL webPreferences block (nodeIntegration/sandbox)
    $script:dirA = Join-Path $script:work 'a'
    New-Item -ItemType Directory -Path $script:dirA -Force | Out-Null
    New-Item -ItemType File -Path (Join-Path $script:dirA 'ffmpeg.dll') -Force | Out-Null   # trips isElectron
    @'
// We deliberately AVOID webSecurity:false here -- CORS is handled via header rewriting.
// see https://example.com/notes  (a URL with // must not break comment stripping)
const w = new BrowserWindow({
  webPreferences: { nodeIntegration: true, sandbox: false }
});
'@ | Set-Content -LiteralPath (Join-Path $script:dirA 'main.js') -Encoding UTF8

    # dirB: a bare webSecurity:false NOT inside any webPreferences/BrowserWindow context
    $script:dirB = Join-Path $script:work 'b'
    New-Item -ItemType Directory -Path $script:dirB -Force | Out-Null
    New-Item -ItemType File -Path (Join-Path $script:dirB 'ffmpeg.dll') -Force | Out-Null
    @'
const cfg = { webSecurity: false };
module.exports = cfg;
'@ | Set-Content -LiteralPath (Join-Path $script:dirB 'app.js') -Encoding UTF8
}

AfterAll {
    if ($script:work -and (Test-Path -LiteralPath $script:work)) {
        try { [System.IO.Directory]::Delete($script:work, $true) } catch {}
    }
}

Describe 'Test-TcpkElectron comment-awareness (G1)' {
    BeforeAll { $script:a = @(Test-TcpkElectron -Path $script:dirA) }

    It 'does NOT flag webSecurity when it only appears in a comment' {
        @($script:a | Where-Object RuleId -eq 'electron.webSecurity').Count | Should -Be 0
    }
    It 'still flags a real nodeIntegration:true as Confirmed CRITICAL' {
        $f = @($script:a | Where-Object RuleId -eq 'electron.nodeIntegration')
        $f.Count | Should -BeGreaterThan 0
        $f[0].Confidence | Should -Be 'Confirmed'
        $f[0].Severity   | Should -Be 'CRITICAL'
    }
    It 'flags sandbox:false inside the webPreferences block as Confirmed' {
        $f = @($script:a | Where-Object RuleId -eq 'electron.sandbox')
        $f.Count | Should -BeGreaterThan 0
        $f[0].Confidence | Should -Be 'Confirmed'
    }
    It 'downgrades an out-of-context flag to Inferred (not a hard finding)' {
        $f = @(Test-TcpkElectron -Path $script:dirB | Where-Object RuleId -eq 'electron.webSecurity')
        $f.Count | Should -BeGreaterThan 0
        $f[0].Confidence | Should -Be 'Inferred'
    }
}
