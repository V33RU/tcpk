#requires -Version 5.1
# G8: unsigned binaries DESPITE a code-signing pipeline reference in the bundle. If the
# shipped tree references signing/notarization but the binaries are unsigned, signing
# failed or was bypassed -- users get an unsigned, unverifiable binary.

BeforeAll {
    $psd1 = Join-Path (Split-Path (Split-Path $PSCommandPath -Parent) -Parent) 'TCPK.psd1'
    Import-Module $psd1 -Force
    $script:work = Join-Path ([IO.Path]::GetTempPath()) ("tcpk-unsignpipe-" + [guid]::NewGuid().ToString('N'))

    # dir with an unsigned DLL + a signing-pipeline reference -> should flag
    $script:disc = Join-Path $script:work 'disc'
    New-Item -ItemType Directory -Path $script:disc -Force | Out-Null
    Add-Type -TypeDefinition 'public class PipeA {}' -OutputAssembly (Join-Path $script:disc 'lib.dll') -OutputType Library
    @'
name: release
jobs:
  build:
    steps:
      - run: signtool sign /fd sha256 /tr http://ts dist/app.exe
      - run: notarytool submit
'@ | Set-Content -LiteralPath (Join-Path $script:disc 'release.yml') -Encoding UTF8

    # dir with an unsigned DLL but NO signing reference -> must NOT flag
    $script:clean = Join-Path $script:work 'clean'
    New-Item -ItemType Directory -Path $script:clean -Force | Out-Null
    Add-Type -TypeDefinition 'public class PipeB {}' -OutputAssembly (Join-Path $script:clean 'lib.dll') -OutputType Library
    "# Readme`nJust a normal user document." | Set-Content -LiteralPath (Join-Path $script:clean 'README.md') -Encoding UTF8
}

AfterAll {
    if ($script:work -and (Test-Path -LiteralPath $script:work)) {
        try { [System.IO.Directory]::Delete($script:work, $true) } catch {}
    }
}

Describe 'Test-TcpkSignature unsigned-despite-pipeline (G8)' {
    It 'flags unsigned binaries when a signing pipeline is referenced' -Skip:($IsWindows -eq $false) {
        $f = @(Test-TcpkSignature -Path $script:disc | Where-Object RuleId -eq 'authenticode.unsigned-despite-pipeline')
        $f.Count | Should -BeGreaterThan 0
        $f[0].Severity | Should -Be 'MEDIUM'
    }
    It 'does NOT flag when there is no signing reference' -Skip:($IsWindows -eq $false) {
        @(Test-TcpkSignature -Path $script:clean | Where-Object RuleId -eq 'authenticode.unsigned-despite-pipeline').Count | Should -Be 0
    }
}
