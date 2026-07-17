#requires -Version 5.1
# Pester 5: confidence-honesty relabels (substring detectors must be Inferred, not
# Confirmed) and the Confirm- bucket for deserialization / callsites.
#
# The relabel tests run a fixture DLL (a copied system PE with planted tokens drawn
# from the live rule data, so the test does not hard-code rule contents) - no
# Mono.Cecil needed. The Confirm- tests assert export + conservative behavior; the
# deep IL call-site promotion is verified on Windows against a real managed target.

BeforeAll {
    $psd1 = Join-Path (Split-Path (Split-Path $PSCommandPath -Parent) -Parent) 'TCPK.psd1'
    Import-Module $psd1 -Force

    # $env:TEMP is null off Windows -- use the cross-platform temp path.
    $script:fx = Join-Path ([System.IO.Path]::GetTempPath()) ('tcpk-honesty-' + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $script:fx | Out-Null
    $script:dll = Join-Path $script:fx 'Contoso.App.dll'
    # The three relabel detectors are pure substring/regex text scanners, so the
    # fixture only needs a .dll file whose bytes contain the planted tokens. On
    # Windows keep copying a real system PE (byte-identical to the prior behaviour);
    # off Windows there is no version.dll, so create an empty base file to append to.
    if ([System.Runtime.InteropServices.RuntimeInformation]::IsOSPlatform([System.Runtime.InteropServices.OSPlatform]::Windows)) {
        Copy-Item "$env:WINDIR\System32\version.dll" $script:dll -Force
    } else {
        New-Item -ItemType File -Path $script:dll | Out-Null
    }

    # Plant literal tokens the detectors look for, drawn from the live rule data.
    $script:deserToken = (& (Get-Module TCPK) { (Get-TcpkData).deser_tokens })[0].token
    $script:callPat    = (& (Get-Module TCPK) { (Get-TcpkData).callsite_patterns })[0].patterns[0]
    Add-Content -LiteralPath $script:dll -Encoding UTF8 -Value @(
        $script:deserToken
        $script:callPat
        'DtdProcessing = DtdProcessing.Parse'
    )
}

AfterAll {
    if ($script:fx -and (Test-Path $script:fx)) { Remove-Item $script:fx -Recurse -Force -ErrorAction SilentlyContinue }
}

Describe 'Confidence honesty - substring detectors are Inferred, not Confirmed' {
    It 'Deserialization labels a referenced formatter as Inferred' {
        $d = @(Test-TcpkDeserialization -Path $script:dll) | Where-Object RuleId -like 'deser.*' | Select-Object -First 1
        $d | Should -Not -BeNullOrEmpty
        $d.Confidence | Should -Be 'Inferred'
    }
    It 'Callsites labels a referenced API as Inferred' {
        $c = @(Test-TcpkCallsites -Path $script:dll) | Where-Object RuleId -like 'callsites.*' | Select-Object -First 1
        $c | Should -Not -BeNullOrEmpty
        $c.Confidence | Should -Be 'Inferred'
    }
    It 'Xxe code-setting match is Inferred' {
        $x = @(Test-TcpkXxe -Path $script:dll) | Where-Object RuleId -like 'xxe.*' | Select-Object -First 1
        $x | Should -Not -BeNullOrEmpty
        $x.Confidence | Should -Be 'Inferred'
    }
}

Describe 'Confirm- bucket (deser / callsites) is exported and conservative' {
    It '<_> is available' -ForEach @('Confirm-TcpkDeserialization','Confirm-TcpkCallsites') {
        Get-Command $_ -ErrorAction SilentlyContinue | Should -Not -BeNullOrEmpty
    }
    It 'passes a non-deser finding through Confirm-TcpkDeserialization unchanged' {
        $out = & (Get-Module TCPK) {
            $f = New-TcpkFinding -Module static -RuleId 'secrets.api-key' -Severity HIGH -Title 'k' -File 'x.dll' -Confidence 'Inferred'
            $f | Confirm-TcpkDeserialization
        }
        $out.RuleId     | Should -Be 'secrets.api-key'
        $out.Confidence | Should -Be 'Inferred'
    }
    It 'does NOT promote a deser finding without a real Deserialize() call site' {
        $out = & (Get-Module TCPK) { param($dll)
            $f = New-TcpkFinding -Module static -RuleId 'deser.binaryformatter' -Severity HIGH -Title 'bf' -File $dll -Confidence 'Inferred'
            $f | Confirm-TcpkDeserialization
        } $script:dll
        $out.Confidence | Should -Be 'Inferred'
    }
    It 'passes a non-callsites finding through Confirm-TcpkCallsites unchanged' {
        $out = & (Get-Module TCPK) {
            $f = New-TcpkFinding -Module static -RuleId 'deser.binaryformatter' -Severity HIGH -Title 'bf' -File 'x.dll' -Confidence 'Inferred'
            $f | Confirm-TcpkCallsites
        }
        $out.RuleId | Should -Be 'deser.binaryformatter'
    }
}
