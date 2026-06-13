#requires -Version 5.1
# Pester 5: v1.5.0 intelligence report (Export-TcpkReportIntel -> intel.html).
# A self-contained, offline, single-file "program intelligence" dashboard. Asserts it
# is created, embeds parseable data, renders the confidence/evidence ladder, carries the
# aggregated Affected list, survives a '</script>' injection in evidence (no early close
# of the embedded JSON), is portable (no external CDN refs), and is pure ASCII.

BeforeAll {
    $psd1 = Join-Path (Split-Path (Split-Path $PSCommandPath -Parent) -Parent) 'TCPK.psd1'
    Import-Module $psd1 -Force

    $script:out = Join-Path ([IO.Path]::GetTempPath()) ("tcpk-intel-" + [guid]::NewGuid().ToString('N') + '.html')

    & (Get-Module TCPK) {
        param($OutFile)
        $f1 = New-TcpkFinding -Module 'network' -RuleId 'tls-bypass.cert-callback-accepts-all' `
            -Severity 'CRITICAL' -Title 'TLS certificate validation disabled' -Confidence 'Confirmed (IL)' `
            -File 'C:\app\App.dll' -Cwe @('CWE-295') `
            -Evidence 'ServerCertificateValidationCallback = (s,c,ch,e) => true' `
            -Fix 'Remove the accept-all callback and validate the chain.'
        $f2 = New-TcpkFinding -Module 'static' -RuleId 'cleartext.http-url' -Severity 'MEDIUM' `
            -Title 'Cleartext HTTP endpoint' -Confidence 'Inferred' -File 'C:\app\config.js' `
            -Evidence 'http://updates.example.com/feed'
        $f2.Affected = @('http://a.example.com', 'http://b.example.com', 'http://c.example.com')
        $f3 = New-TcpkFinding -Module 'dynamic' -RuleId 'dynamic.argv-session-override' -Severity 'HIGH' `
            -Title 'Accepts attacker host/token via argv' -Confidence 'Confirmed (dynamic)' `
            -Evidence 'observed loopback CONNECT token=<sentinel>'
        # adversarial: a literal </script> in evidence must NOT close the embedded JSON early
        $f4 = New-TcpkFinding -Module 'webview2' -RuleId 'webview.injection' -Severity 'LOW' `
            -Title 'Reflected content' -Confidence 'Inferred' `
            -Evidence 'payload: </script><img src=x onerror=alert(1)>'

        Export-TcpkReportIntel -Findings @($f1, $f2, $f3, $f4) -OutFile $OutFile -Target 'Acme Desktop 2.1'
    } $script:out

    $script:html = Get-Content -LiteralPath $script:out -Raw
    $script:dataMatch = [regex]::Match($script:html, '(?s)id="tcpk-data"[^>]*>(.*?)</script>')
    $script:data = if ($script:dataMatch.Success) { $script:dataMatch.Groups[1].Value | ConvertFrom-Json } else { $null }
}

AfterAll { if ($script:out -and (Test-Path $script:out)) { Remove-Item -LiteralPath $script:out -Force } }

Describe 'Export-TcpkReportIntel' {
    It 'is an exported cmdlet' {
        Get-Command Export-TcpkReportIntel -ErrorAction SilentlyContinue | Should -Not -BeNullOrEmpty
    }
    It 'writes a single self-contained HTML file' {
        Test-Path $script:out | Should -BeTrue
        $script:html | Should -Match '<!doctype html'
        $script:html | Should -Match 'id="tcpk-data"'
    }
    It 'embeds parseable finding data with the right shape' {
        $script:dataMatch.Success | Should -BeTrue
        $script:data | Should -Not -BeNullOrEmpty
        @($script:data.findings).Count | Should -Be 4
        $script:data.meta.target | Should -Be 'Acme Desktop 2.1'
        $script:data.summary.severity.CRITICAL | Should -Be 1
    }
    It 'renders the evidence/confidence ladder tiers' {
        $script:html | Should -Match 'Confirmed \(IL\)'
        $script:html | Should -Match 'Confirmed \(dynamic\)'
        # the ladder explainer text is present so the report EXPLAINS, not just lists
        $script:html | Should -Match 'bytecode'
    }
    It 'carries the aggregated Affected list into the data' {
        $agg = $script:data.findings | Where-Object { $_.rule -eq 'cleartext.http-url' }
        @($agg.affected).Count | Should -Be 3
    }
    It 'enriches findings with CWE / CVSS / verify hints' {
        $tls = $script:data.findings | Where-Object { $_.rule -eq 'tls-bypass.cert-callback-accepts-all' }
        @($tls.cwe) | Should -Contain 'CWE-295'
        $tls.cvss | Should -Match '\d'          # computed CVSS v4.0 score present
        $tls.verify | Should -Not -BeNullOrEmpty # a how-to-verify playbook was attached
    }
    It 'neutralizes a closing-tag injection in evidence (no early close)' {
        # NB: use .Contains() (literal) not Should -Match -- piping a string that holds a
        # closing script tag into Pester's regex matcher mis-parses it.
        $needle = '</' + 'script>'
        # round-trips back to the literal tag after JSON unescape...
        $inj = $script:data.findings | Where-Object { $_.rule -eq 'webview.injection' }
        $inj.evidence.Contains($needle) | Should -BeTrue
        # ...but the RAW embedded data block contains no bare closing tag (it was escaped)
        $script:dataMatch.Groups[1].Value.Contains($needle) | Should -BeFalse
        $script:dataMatch.Groups[1].Value.Contains('u003c/script') | Should -BeTrue
    }
    It 'is portable - no external CDN script/style references' {
        $script:html | Should -Not -Match '<script[^>]+src='
        $script:html | Should -Not -Match '<link\b'
        $script:html | Should -Not -Match 'https?://[^"]*(cdn|googleapis|jsdelivr|unpkg)'
    }
    It 'is pure ASCII (no BOM, no smart punctuation)' {
        $bytes = [IO.File]::ReadAllBytes($script:out)
        @($bytes | Where-Object { $_ -gt 127 }).Count | Should -Be 0
    }
}
