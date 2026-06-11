#requires -Version 5.1
# G6: internal dev/spec/threat docs leaked into the bundle. Gherkin acceptance criteria,
# user-story IDs, source-tree paths, CI/build refs and threat-model notes shipped to users
# are a recon map. User-facing README/EULA must NOT be flagged.

BeforeAll {
    $psd1 = Join-Path (Split-Path (Split-Path $PSCommandPath -Parent) -Parent) 'TCPK.psd1'
    Import-Module $psd1 -Force

    $script:work = Join-Path ([IO.Path]::GetTempPath()) ("tcpk-docleak-" + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $script:work -Force | Out-Null

    # internal spec/QE doc -- should flag (gherkin + scope + story-id + src-path)
    @'
# Feature: Single instance
Scenario: second launch forwards args
  Given the app is running
  When the user runs App.exe --project P2
  Then no second process appears
In Scope:
- single-instance lock
Reference: src/main/main.js
Related: US-APP-009, US-APP-012 (sign-in dialog)
'@ | Set-Content -LiteralPath (Join-Path $script:work 'feature-spec.md') -Encoding UTF8

    # ordinary user documentation -- must NOT flag
    @'
# MyApp User Guide
## Installation
Double-click the installer and follow the prompts.
## License
Accept the End-User License Agreement to continue.
'@ | Set-Content -LiteralPath (Join-Path $script:work 'README.md') -Encoding UTF8
}

AfterAll {
    if ($script:work -and (Test-Path -LiteralPath $script:work)) {
        try { [System.IO.Directory]::Delete($script:work, $true) } catch {}
    }
}

Describe 'Test-TcpkDevArtifacts internal-docs leak (G6)' {
    BeforeAll { $script:r = @(Test-TcpkDevArtifacts -Path $script:work | Where-Object RuleId -eq 'devartifact.internal-docs') }

    It 'flags an internal spec/QE document' {
        $hit = @($script:r | Where-Object { $_.File -like '*feature-spec.md' })
        $hit.Count | Should -BeGreaterThan 0
        $hit[0].Severity | Should -Be 'MEDIUM'   # src-paths present -> MEDIUM
    }
    It 'does NOT flag an ordinary user README' {
        @($script:r | Where-Object { $_.File -like '*README.md' }).Count | Should -Be 0
    }
}
