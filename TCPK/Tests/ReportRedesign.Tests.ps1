#requires -Version 5.1
# Report redesign (v1.6.x): the finding card leads with proof, carries the standards
# mapping as tags, shows a real CVSS score+vector (no severity word), lists FULL affected
# paths, fixes the aggregated Verify path, splits [TCPK]/[LLM] process notes into a footer,
# and surfaces correlated chains as a prominent attack-path callout. Plus: Test-TcpkCallsites
# no longer scans bundled native runtimes (the libGLESv2 / Chromium false-positive).

BeforeAll {
    $psd1 = Join-Path (Split-Path (Split-Path $PSCommandPath -Parent) -Parent) 'TCPK.psd1'
    Import-Module $psd1 -Force

    $script:work = Join-Path ([IO.Path]::GetTempPath()) ("tcpk-redesign-" + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $script:work -Force | Out-Null

    # Build a report from synthetic findings: an aggregated file-based finding (distinct full
    # paths, [TCPK]/[LLM] notes in the description) + a correlated chain.
    $script:out = Join-Path $script:work 'report.html'
    & (Get-Module TCPK) {
        param($out)
        $p1 = 'C:\Program Files\WindowsApps\Vendor.App_1.0_x64\app\Main.exe'
        $p2 = 'C:\Program Files\WindowsApps\Vendor.App_1.0_x64\Uninstall Main.exe'
        $a = New-TcpkFinding -Module 'static' -RuleId 'callsites.insecure-temp' -Severity 'LOW' -Confidence 'Inferred' `
                -Title 'Insecure-temp-file pattern reference in Main.exe' -File $p1 -Evidence 'GetTempFileName' -Cwe @('CWE-377') `
                -Description 'A predictable temp-file pattern was referenced. [LLM: could not locate method IL for insecure-temp; left as-is.]'
        $b = New-TcpkFinding -Module 'static' -RuleId 'callsites.insecure-temp' -Severity 'LOW' -Confidence 'Inferred' `
                -Title 'Insecure-temp-file pattern reference in Uninstall Main.exe' -File $p2 -Evidence 'Path.GetTempPath' -Cwe @('CWE-377') `
                -Description 'A predictable temp-file pattern was referenced.'
        $c = New-TcpkFinding -Module 'chain' -RuleId 'chain.unsigned-update-writable' -Severity 'CRITICAL' -Confidence 'Inferred' `
                -Title 'Unsigned update + attacker-writable location -> code execution' -File 'C:\app\u.dll' -Evidence 'x' `
                -Cwe @('CWE-494') -Fix 'Verify a publisher signature before applying any update.'
        @($a, $b, $c) | Resolve-TcpkFindings | Export-TcpkReportHtml -OutFile $out
    } $script:out
    $script:html = [IO.File]::ReadAllText($script:out)
}
AfterAll {
    if ($script:work -and (Test-Path -LiteralPath $script:work)) {
        [IO.Directory]::Delete($script:work, $true)
    }
}

Describe 'CVSS: well-defined callsites subrule gets a real vector (not the placeholder)' {
    It 'scores callsites.insecure-temp as a local, in-band vector' {
        $v = & (Get-Module TCPK) {
            $f = New-TcpkFinding -Module 'static' -RuleId 'callsites.insecure-temp' -Severity 'LOW' -Title 't'
            Get-TcpkCvssVector $f
        }
        $v.Source | Should -Be 'anchored:local'
        $v.Vector | Should -Match '^CVSS:4\.0/AV:L/AC:H/AT:P'
        $v.Rating | Should -Be 'Low'
        $v.Score  | Should -BeGreaterThan 0
    }
    It 'no longer emits the "assign exact CVSS" placeholder text in the rendered card' {
        $script:html | Should -Not -Match 'assign exact CVSS'
    }
    It 'shows the CVSS score+vector WITHOUT the severity word' {
        # the card renders "<score> &middot; <code>CVSS:4.0/...</code>" -- never "(Low)"/"(Medium)"/...
        $script:html | Should -Match 'CVSS v4\.0</th><td>\d\.\d &middot; <code>CVSS:4\.0/'
        $script:html | Should -Not -Match 'CVSS v4\.0</th><td>[^<]*\((Low|Medium|High|Critical)\)'
    }
}

Describe 'Aggregated finding: full affected paths + fixed Verify path' {
    It 'lists the FULL path of every affected file (not just the leaf)' {
        $script:html | Should -Match 'WindowsApps\\Vendor\.App_1\.0_x64\\app\\Main\.exe'
        $script:html | Should -Match 'WindowsApps\\Vendor\.App_1\.0_x64\\Uninstall Main\.exe'
    }
    It 'builds the Verify command from a real path, never from the "N files" label' {
        $script:html | Should -Not -Match "Test-TcpkCallsites -Path &#39;\d+ files"
        $script:html | Should -Match 'Test-TcpkCallsites -Path &#39;C:\\Program Files'
    }
}

Describe 'Description hygiene: process notes split into an audit-notes footer' {
    It 'renders an audit-notes footer carrying the [LLM]/[TCPK] notes' {
        $script:html | Should -Match "class='auditnotes'"
        $script:html | Should -Match 'could not locate method IL'
    }
    It 'keeps the What row clean (no bracketed process notes)' {
        $m = [regex]::Match($script:html, '<th>What</th><td>(.*?)</td>')
        $m.Success | Should -BeTrue
        $m.Groups[1].Value | Should -Not -Match '\[(?:TCPK|LLM)'
        $m.Groups[1].Value | Should -Match 'predictable temp-file pattern'
    }
}

Describe 'Attack-path callout (correlated chains)' {
    It 'renders a Likely-attack-paths banner for chain.* findings' {
        $script:html | Should -Match 'Likely attack paths'
        $script:html | Should -Match "class='apath-title'>Unsigned update \+ attacker-writable"
    }
}

Describe 'Standards mapping kept (as tags)' {
    It 'renders CWE / ATT&CK / TASVS tags on the card' {
        $script:html | Should -Match "ftag-cwe'>CWE-377"
        $script:html | Should -Match "ftag-attack'"
        $script:html | Should -Match "ftag-tasvs'"
    }
}

Describe 'Test-TcpkCallsites skips bundled native runtimes' {
    It 'flags a first-party binary but NOT a Chromium/native-runtime lib with the same pattern' {
        $dir = Join-Path $script:work 'scan'
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
        # both contain an insecure-temp pattern; only the first-party one should be flagged
        [IO.File]::WriteAllText((Join-Path $dir 'MyApp.dll'),     'MZ first-party uses GetTempFileName here')
        [IO.File]::WriteAllText((Join-Path $dir 'libGLESv2.dll'), 'MZ chromium gpu lib uses GetTempFileName too')
        $hits = @(Test-TcpkCallsites -Path $dir | Where-Object { $_.RuleId -eq 'callsites.insecure-temp' })
        @($hits).Count | Should -Be 1
        (Split-Path $hits[0].File -Leaf) | Should -Be 'MyApp.dll'
    }
}

Describe 'Executive summary narrative (always-on)' {
    It 'leads with an executive-summary paragraph' {
        $script:html | Should -Match "class='card execsum'"
        $script:html | Should -Match 'Executive summary'
        $script:html | Should -Match 'This audit of'
    }
    It 'states the finding count and severity shape' {
        $script:html | Should -Match 'produced <b>2</b> findings'
        $script:html | Should -Match '1 critical'
    }
    It 'mentions the correlated attack path and the top finding' {
        $script:html | Should -Match 'correlated attack path'
        $script:html | Should -Match 'Most significant: Unsigned update'
    }
}

Describe 'Remediation plan + standards-coverage matrix (new sections)' {
    It 'renders a prioritized, de-duplicated remediation plan' {
        $script:html | Should -Match 'Remediation plan'
        $script:html | Should -Match "class='pri p1'"   # the CRITICAL chain fix is P1
    }
    It 'renders the OWASP Desktop Top 10 standards-coverage matrix' {
        $script:html | Should -Match 'Standards coverage'
        $script:html | Should -Match "class='da"
        $script:html | Should -Match '>DA1<'
        $script:html | Should -Match '>DA10<'
    }
}

Describe 'Risk gauge + severity donut + remediation colors' {
    It 'renders the risk-index gauge and the severity donut' {
        $script:html | Should -Match 'RISK INDEX'
        $script:html | Should -Match 'stroke-dasharray'
        $script:html | Should -Match "class='dleg'"
    }
    It 'defines the severity CSS variables the remediation/coverage sections use' {
        # regression guard for the v1.8.2 blocker: --crit/--high/--med/--low must exist in :root
        $script:html | Should -Match '--crit:#'
        $script:html | Should -Match '--low:#'
    }
}
