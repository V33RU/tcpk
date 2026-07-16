#requires -Version 5.1
# Pester 5: application-aware registry search.
#   - Get-TcpkIdentityTerms derives a SET of search terms from the app's identity
#     (MSIX manifest + exe), drops generic/short tokens, and dedupes.
#   - Test-TcpkTermMatch / Get-TcpkRegistrySearchRoots behave as the registry
#     checks expect.
#   - The registry checks accept a term ARRAY and find data under a key whose name
#     matches any term (functional test against a real, self-created HKCU key).

BeforeAll {
    $psd1 = Join-Path (Split-Path (Split-Path $PSCommandPath -Parent) -Parent) 'TCPK.psd1'
    Import-Module $psd1 -Force

    # --- fixture MSIX dir with a manifest carrying a known identity ---
    $script:fx = Join-Path ([System.IO.Path]::GetTempPath()) ('tcpk-reg-' + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $script:fx | Out-Null
    @'
<?xml version="1.0" encoding="utf-8"?>
<Package xmlns="http://schemas.microsoft.com/appx/manifest/foundation/windows10">
  <Identity Name="AcmeSoft.WidgetPro" Version="1.2.3.0" Publisher="CN=Acme Corp, O=Acme, C=US" />
  <Properties>
    <DisplayName>Widget Pro</DisplayName>
    <PublisherDisplayName>Acme Corporation</PublisherDisplayName>
  </Properties>
  <Applications>
    <Application Id="App" Executable="WidgetPro.exe" />
  </Applications>
</Package>
'@ | Set-Content -LiteralPath (Join-Path $script:fx 'AppxManifest.xml') -Encoding UTF8

    # helper to call a module-private function from the test
    $script:Inv = { param($sb, $a) & (Get-Module TCPK) $sb @a }

    # --- a real HKCU key we own, for the functional checks (Windows only; the HKCU: drive
    # does not exist off Windows, and the checks that read it are skipped there) ---
    $script:rkLeaf = 'TcpkRegTest_' + [guid]::NewGuid().ToString('N')
    $script:rkPath = $null
    if ($IsWindows -ne $false) {
        $script:rkPath = "HKCU:\SOFTWARE\$($script:rkLeaf)"
        New-Item -Path $script:rkPath -Force | Out-Null
        New-ItemProperty -Path $script:rkPath -Name 'ConnString' `
            -Value 'DefaultEndpointsProtocol=https;AccountName=foo;AccountKey=YWJjZGVmZ2hpamtsbW5vcA==' `
            -PropertyType String -Force | Out-Null
    }
}

AfterAll {
    if ($script:fx -and (Test-Path $script:fx)) { Remove-Item $script:fx -Recurse -Force -ErrorAction SilentlyContinue }
    if ($script:rkPath -and (Test-Path $script:rkPath)) { Remove-Item $script:rkPath -Recurse -Force -ErrorAction SilentlyContinue }
}

Describe 'Get-TcpkIdentityTerms - derives identity from the app' {
    It 'extracts manifest identity, display name, and publisher CN' {
        $terms = & (Get-Module TCPK) { param($p) Get-TcpkIdentityTerms -Path $p } $script:fx
        $terms | Should -Contain 'AcmeSoft.WidgetPro'
        $terms | Should -Contain 'Widget Pro'
        $terms | Should -Contain 'Acme Corp'
        $terms | Should -Contain 'Acme Corporation'
    }
    It 'drops generic stopwords and too-short tokens, and dedupes' {
        $terms = & (Get-Module TCPK) { param($p) Get-TcpkIdentityTerms -Path $p -Extra @('Microsoft','ab','Widget Pro') } $script:fx
        $terms | Should -Not -Contain 'Microsoft'   # pure stopword
        $terms | Should -Not -Contain 'ab'          # too short
        ($terms | Where-Object { $_ -eq 'Widget Pro' }).Count | Should -Be 1   # deduped vs manifest
    }
}

Describe 'Test-TcpkTermMatch - case-insensitive multi-term substring' {
    It 'matches any term, case-insensitively' {
        (& (Get-Module TCPK) { param($t,$x) Test-TcpkTermMatch -Text $t -Terms $x } 'Acme Widget Pro' @('zzz','widget')) | Should -BeTrue
    }
    It 'returns false when no term matches' {
        (& (Get-Module TCPK) { param($t,$x) Test-TcpkTermMatch -Text $t -Terms $x } 'nothing here' @('widget')) | Should -BeFalse
    }
    It 'returns false on empty text' {
        (& (Get-Module TCPK) { param($t,$x) Test-TcpkTermMatch -Text $t -Terms $x } '' @('x')) | Should -BeFalse
    }
}

Describe 'Get-TcpkRegistrySearchRoots - includes HKCR (Classes)' {
    It 'includes Software\Classes for both hives by default' {
        $roots = & (Get-Module TCPK) { Get-TcpkRegistrySearchRoots }
        $roots | Should -Contain 'HKLM:\SOFTWARE\Classes'
        $roots | Should -Contain 'HKCU:\SOFTWARE\Classes'
    }
    It 'MachineOnly excludes HKCU' {
        $roots = & (Get-Module TCPK) { Get-TcpkRegistrySearchRoots -MachineOnly }
        ($roots | Where-Object { $_ -like 'HKCU:*' }).Count | Should -Be 0
    }
}

Describe 'Registry checks accept a term array and find app data' -Skip:($IsWindows -eq $false) {
    It 'Test-TcpkRegistryValues finds a secret value via a matching term' {
        $f = @(Test-TcpkRegistryValues -NameLike @('zzz-no-match', $script:rkLeaf)) |
             Where-Object RuleId -eq 'registry.secret-value'
        $f | Should -Not -BeNullOrEmpty
    }
    It 'Test-TcpkRegistryFootprint surveys the key via a multi-term array' {
        $f = @(Test-TcpkRegistryFootprint -NameLike @('zzz-no-match', $script:rkLeaf)) |
             Where-Object RuleId -eq 'registry.footprint'
        $f | Should -Not -BeNullOrEmpty
    }
}

Describe 'Get-TcpkNameTerms / Test-TcpkNameInclude - shared predicate' {
    It 'Get-TcpkNameTerms drops blanks and the * sentinel' {
        $t = & (Get-Module TCPK) { Get-TcpkNameTerms -NameLike @('*','', 'Acme', $null) }
        @($t) | Should -Be @('Acme')
    }
    It 'Test-TcpkNameInclude includes everything when no terms (survey mode)' {
        (& (Get-Module TCPK) { param($x) Test-TcpkNameInclude -Text 'anything' -Terms $x } @()) | Should -BeTrue
        (& (Get-Module TCPK) { param($x) Test-TcpkNameInclude -Text 'anything' -Terms $x } @('*')) | Should -BeTrue
    }
    It 'Test-TcpkNameInclude filters when terms are present' {
        (& (Get-Module TCPK) { param($x) Test-TcpkNameInclude -Text 'AcmeWidget' -Terms $x } @('widget')) | Should -BeTrue
        (& (Get-Module TCPK) { param($x) Test-TcpkNameInclude -Text 'Unrelated' -Terms $x } @('widget')) | Should -BeFalse
    }
}

Describe 'Name-matched OS checks accept a term array (multi-term)' -Skip:($IsWindows -eq $false) {
    It 'Test-TcpkAutoStart surveys all entries when given no terms' {
        # A real machine always has at least one Run-key autostart entry.
        @(Test-TcpkAutoStart) | Where-Object RuleId -eq 'autostart.run-key' | Should -Not -BeNullOrEmpty
    }
    It 'Test-TcpkAutoStart returns no run-key hits for a non-matching term array' {
        @(Test-TcpkAutoStart -NameLike @('zzz-no-such-vendor-xyz','also-no-match')) |
            Where-Object RuleId -eq 'autostart.run-key' | Should -BeNullOrEmpty
    }
    It 'Test-TcpkServicePermissions accepts a string array and early-returns with no terms' {
        { Test-TcpkServicePermissions -NameLike @('zzz-no-such-svc-xyz') } | Should -Not -Throw
        @(Test-TcpkServicePermissions) | Should -BeNullOrEmpty   # no terms -> nothing surveyed
    }
}
