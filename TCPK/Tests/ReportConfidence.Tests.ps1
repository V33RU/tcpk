#requires -Version 5.1
# Pester 5: the HTML report SEGREGATES findings by confidence (audit #2 fix). The flagship
# 'Confirmed (IL)' tier gets a distinct proof colour (it previously fell through to the grey
# default -- same as INFO/Skipped), proven findings sort FIRST within a severity, an
# evidence-tier summary is shown, and a "Confirmed only" toggle is rendered.

BeforeAll {
    $psd1 = Join-Path (Split-Path (Split-Path $PSCommandPath -Parent) -Parent) 'TCPK.psd1'
    Import-Module $psd1 -Force
    $script:out = Join-Path ([IO.Path]::GetTempPath()) ("tcpk-rptconf-" + [guid]::NewGuid().ToString('N') + '.html')
    & (Get-Module TCPK) {
        param($out)
        # Titles are chosen so an alphabetical / insertion-order sort would put the INFERRED one
        # first -- so if the proven one ends up first, it is the CONFIDENCE sort doing it.
        $inf = New-TcpkFinding -Module 'static' -RuleId 'auth.flag-name' -Severity 'HIGH' -Title 'AA inferred auth gate'
        $inf.Confidence = 'Inferred'
        $il  = New-TcpkFinding -Module 'static' -RuleId 'callsites.command-exec' -Severity 'HIGH' -Title 'ZZ proven RCE sink'
        $il.Confidence  = 'Confirmed (IL)'
        @($inf, $il) | Export-TcpkReportHtml -OutFile $out
    } $script:out
    $script:html = Get-Content -LiteralPath $script:out -Raw
}
AfterAll { if ($script:out -and (Test-Path $script:out)) { Remove-Item -LiteralPath $script:out -Force } }

Describe 'HTML report confidence segregation (audit #2)' {
    It 'gives Confirmed (IL) a distinct proof colour, not the grey default' {
        $script:html | Should -Match "background:#0b6e4f'>Confirmed \(IL\)"
    }
    It 'tags proven findings data-proven=1 and inferred data-proven=0' {
        $script:html | Should -Match "data-proven='1'"
        $script:html | Should -Match "data-proven='0'"
    }
    It 'shows an evidence-tier summary (proven + inferred counts)' {
        # rendered as metric cards: <span class='cmlabel'>Proven (IL/dynamic)</span><span class='cmval' ...>1</span>
        $script:html | Should -Match "Proven \(IL/dynamic\)</span><span class='cmval'[^>]*>1<"
        $script:html | Should -Match "Inferred -- verify</span><span class='cmval'[^>]*>1<"
    }
    It 'renders a Confirmed-only toggle' {
        $script:html | Should -Match "id='confOnly'"
    }
    It 'sorts the proven finding before the inferred one within the same severity' {
        $ilPos  = $script:html.IndexOf('ZZ proven RCE sink')
        $infPos = $script:html.IndexOf('AA inferred auth gate')
        $ilPos  | Should -BeGreaterThan 0
        $infPos | Should -BeGreaterThan $ilPos
    }
}
