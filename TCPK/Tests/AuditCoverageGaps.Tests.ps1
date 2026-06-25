#requires -Version 5.1
# Pester 5: the five audit-coverage-gap features added to close the silent-skip gaps --
#   F1 auto-attach to the running process (Resolve-TcpkTargetProcess)
#   F2 coverage manifest (_RunCheck outcome recording + coverage.json)
#   F3 ALPC enumeration (compile-guarded P/Invoke, with fallback)
#   F4 self-elevation flag (-Elevate) + -NoAutoProcess
#   F5 OSV CVE cache (cache hit serves without the network; offline fallback)

BeforeAll {
    $psd1 = Join-Path (Split-Path (Split-Path $PSCommandPath -Parent) -Parent) 'TCPK.psd1'
    Import-Module $psd1 -Force
}

Describe 'F1: Resolve-TcpkTargetProcess' {
    It 'resolves a shipped exe that matches a running process' {
        InModuleScope TCPK {
            $rp = (Get-Process -Id $PID).ProcessName
            $dir = Join-Path ([IO.Path]::GetTempPath()) ("tcpk-proc-" + [guid]::NewGuid().ToString('N'))
            New-Item -ItemType Directory -Path $dir -Force | Out-Null
            Set-Content -LiteralPath (Join-Path $dir "$rp.exe") -Value 'x' -Encoding ASCII
            try {
                $r = Resolve-TcpkTargetProcess -Path $dir -IdTerms @($rp)
                $r | Should -Not -BeNullOrEmpty
                $r.Name | Should -Be $rp
                $r.ProcId | Should -Not -BeNullOrEmpty
            } finally { Remove-Item $dir -Recurse -Force -ErrorAction SilentlyContinue }
        }
    }
    It 'returns null when no shipped exe matches a running process' {
        InModuleScope TCPK {
            $dir = Join-Path ([IO.Path]::GetTempPath()) ("tcpk-proc-" + [guid]::NewGuid().ToString('N'))
            New-Item -ItemType Directory -Path $dir -Force | Out-Null
            Set-Content -LiteralPath (Join-Path $dir ("tcpk-nope-" + [guid]::NewGuid().ToString('N') + ".exe")) -Value 'x' -Encoding ASCII
            try {
                Resolve-TcpkTargetProcess -Path $dir | Should -BeNullOrEmpty
            } finally { Remove-Item $dir -Recurse -Force -ErrorAction SilentlyContinue }
        }
    }
}

Describe 'F2: coverage manifest' {
    It 'records statuses and tallies totals' {
        InModuleScope TCPK {
            Clear-TcpkCoverage
            Add-TcpkCoverage -Name 'A' -Status 'Ran' -Count 2
            Add-TcpkCoverage -Name 'B' -Status 'GatedNoProcess'
            Add-TcpkCoverage -Name 'C' -Status 'NeedsElevation'
            Add-TcpkCoverage -Name 'D' -Status 'Failed'
            $m = New-TcpkCoverageManifest
            $m.totals.ran            | Should -Be 1
            $m.totals.gated          | Should -Be 1
            $m.totals.needsElevation | Should -Be 1
            $m.totals.failed         | Should -Be 1
            $m.totals.total          | Should -Be 4
            @($m.checks).Count       | Should -Be 4
        }
    }
    It 'classifies a not-readable elevation stub as NeedsElevation' {
        InModuleScope TCPK {
            $f = New-TcpkFinding -Module runtime -RuleId 'avexclusion.not-readable' -Severity INFO -Confidence 'Skipped' -Title 't'
            (Get-TcpkCoverageStatusFromFindings -Findings $f) | Should -Be 'NeedsElevation'
        }
    }
    It 'classifies a not-enumerated stub as NotImplemented' {
        InModuleScope TCPK {
            $f = New-TcpkFinding -Module runtime -RuleId 'alpc.not-enumerated' -Severity INFO -Confidence 'Skipped' -Title 't'
            (Get-TcpkCoverageStatusFromFindings -Findings $f) | Should -Be 'NotImplemented'
        }
    }
    It 'treats normal findings as Ran' {
        InModuleScope TCPK {
            $f = New-TcpkFinding -Module static -RuleId 'x.y' -Severity LOW -Confidence 'Confirmed' -Title 't'
            (Get-TcpkCoverageStatusFromFindings -Findings $f) | Should -Be 'Ran'
        }
    }
    It 'writes coverage.json with gated live-process checks for a non-running target' {
        $fx = Join-Path ([IO.Path]::GetTempPath()) ("tcpk-covfx-" + [guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory -Path $fx -Force | Out-Null
        Set-Content -LiteralPath (Join-Path $fx 'app.js') -Value 'const u="http://x.insecure.test/a";' -Encoding ASCII
        $od = Join-Path ([IO.Path]::GetTempPath()) ("tcpk-covod-" + [guid]::NewGuid().ToString('N'))
        try {
            Invoke-TcpkAudit -Target $fx -OutDir $od -Acknowledge -NoAutoProcess 6>$null 5>$null 4>$null 3>$null | Out-Null
            $cov = Join-Path $od 'coverage.json'
            Test-Path $cov | Should -BeTrue
            $j = Get-Content $cov -Raw | ConvertFrom-Json
            $j.totals.gated | Should -BeGreaterThan 0
            @($j.checks | Where-Object { $_.status -eq 'GatedNoProcess' }).Count | Should -BeGreaterThan 0
        } finally {
            Remove-Item $fx -Recurse -Force -ErrorAction SilentlyContinue
            Remove-Item $od -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

Describe 'F3: ALPC enumeration' {
    It 'Add-TcpkAlpcType is idempotent (no throw on a second call)' {
        InModuleScope TCPK {
            { Add-TcpkAlpcType; Add-TcpkAlpcType } | Should -Not -Throw
            [bool]('TcpkAlpc' -as [type]) | Should -BeTrue
        }
    }
    It 'enumerates ALPC ports or falls back, always emitting an alpc.* finding' {
        InModuleScope TCPK {
            $r = Test-TcpkMailslotsAlpc -NameLike @('tcpk-nope-xyz')
            $rules = @($r | ForEach-Object { "$($_.RuleId)" })
            @($rules | Where-Object { $_ -match '^alpc\.(port|enumerated-clean|not-enumerated)$' }).Count | Should -BeGreaterThan 0
        }
    }
}

Describe 'F4: self-elevation and auto-process switches' {
    It 'exposes -Elevate as a switch parameter' {
        $p = (Get-Command Invoke-TcpkAudit).Parameters['Elevate']
        $p | Should -Not -BeNullOrEmpty
        $p.SwitchParameter | Should -BeTrue
    }
    It 'exposes -NoAutoProcess as a switch parameter' {
        $p = (Get-Command Invoke-TcpkAudit).Parameters['NoAutoProcess']
        $p | Should -Not -BeNullOrEmpty
        $p.SwitchParameter | Should -BeTrue
    }
}

Describe 'F5: OSV CVE cache' {
    It 'builds a stable lowercased cache key' {
        InModuleScope TCPK {
            (Get-TcpkOsvCacheKey -Ecosystem 'npm' -Name 'Electron' -Version '1.2.3') | Should -Be 'npm|electron|1.2.3'
        }
    }
    It 'round-trips the cache to disk' {
        InModuleScope TCPK {
            $old = $env:LOCALAPPDATA
            $tmp = Join-Path ([IO.Path]::GetTempPath()) ("tcpk-la-" + [guid]::NewGuid().ToString('N'))
            New-Item -ItemType Directory -Path $tmp -Force | Out-Null
            $env:LOCALAPPDATA = $tmp
            try {
                Save-TcpkOsvCache -Cache @{ 'npm|foo|1.0' = [pscustomobject]@{ fetchedUtc = 'x'; matches = @() } }
                $back = Get-TcpkOsvCache
                $back.ContainsKey('npm|foo|1.0') | Should -BeTrue
                Test-Path (Get-TcpkOsvCachePath) | Should -BeTrue
            } finally {
                $env:LOCALAPPDATA = $old
                Remove-Item $tmp -Recurse -Force -ErrorAction SilentlyContinue
            }
        }
    }
    It 'serves a fresh cache entry WITHOUT calling the network core' {
        InModuleScope TCPK {
            Mock Get-TcpkOsvCache { @{ 'npm|testpkg|9.9.9' = [pscustomobject]@{ fetchedUtc = ([DateTimeOffset]::UtcNow.ToString('o')); matches = @([pscustomobject]@{ Cve = 'CVE-TEST-1'; Package = 'testpkg'; ShippedVersion = '9.9.9' }) } } }
            Mock Save-TcpkOsvCache { }
            Mock Get-TcpkOsvQueryNet { throw 'NETWORK SHOULD NOT BE CALLED' }
            $r = Get-TcpkOsvMatches -Components @(@{ Name = 'testpkg'; Version = '9.9.9' }) -Ecosystem 'npm'
            @($r).Count | Should -BeGreaterThan 0
            "$(@($r)[0].Cve)" | Should -Be 'CVE-TEST-1'
            Assert-MockCalled Get-TcpkOsvQueryNet -Times 0 -Scope It
        }
    }
    It 'falls back to empty (no throw) when the network core returns nothing' {
        InModuleScope TCPK {
            Mock Get-TcpkOsvQueryNet { @() }
            $r = Get-TcpkOsvMatches -Components @(@{ Name = 'uncached-xyz'; Version = '0.0.1' }) -Ecosystem 'npm' -NoCache
            @($r).Count | Should -Be 0
        }
    }
}

Describe 'F5b: outdated-runtime CVE text reconciliation' {
    BeforeAll {
        $script:hintDesc = "The embedded Chromium is behind stable. Run with -OnlineCve to enumerate the specific advisories (OSV electron@41.2.0), or check electronjs.org/releases."
    }
    It 'offline (no -OnlineCve, no matches): keeps the Run with -OnlineCve hint' {
        InModuleScope TCPK -Parameters @{ d = $script:hintDesc } {
            param($d)
            $f = New-TcpkFinding -Module static -RuleId 'electron.outdated-runtime' -Severity MEDIUM -Confidence Inferred -Title 't' -Description $d
            $out = Update-TcpkRuntimeCveText -Finding $f -CveMatches @() -OnlineCve $false
            "$($out.Description)" | Should -Match 'Run with -OnlineCve'
        }
    }
    It 'OnlineCve ran but OSV empty: removes the hint and says it was queried' {
        InModuleScope TCPK -Parameters @{ d = $script:hintDesc } {
            param($d)
            $f = New-TcpkFinding -Module static -RuleId 'electron.outdated-runtime' -Severity MEDIUM -Confidence Inferred -Title 't' -Description $d
            $out = Update-TcpkRuntimeCveText -Finding $f -CveMatches @() -OnlineCve $true
            "$($out.Description)" | Should -Not -Match 'Run with -OnlineCve'
            "$($out.Description)" | Should -Match 'OSV was queried'
            # the version string must NOT be mangled by the replacement
            "$($out.Description)" | Should -Match 'electronjs\.org/releases'
        }
    }
    It 'OnlineCve ran with advisories: lists the CVE IDs and does not mangle the version' {
        InModuleScope TCPK -Parameters @{ d = $script:hintDesc } {
            param($d)
            $f = New-TcpkFinding -Module static -RuleId 'electron.outdated-runtime' -Severity MEDIUM -Confidence Inferred -Title 't' -Description $d
            $cm = @(
                [pscustomobject]@{ Package = 'electron'; Cve = 'CVE-2025-0001' },
                [pscustomobject]@{ Package = 'electron'; Cve = 'GHSA-aaaa-bbbb-cccc' }
            )
            $out = Update-TcpkRuntimeCveText -Finding $f -CveMatches $cm -OnlineCve $true
            "$($out.Description)" | Should -Not -Match 'Run with -OnlineCve'
            "$($out.Description)" | Should -Match 'CVE-2025-0001'
            "$($out.Description)" | Should -Match 'GHSA-aaaa-bbbb-cccc'
            "$($out.Evidence)"    | Should -Match 'CVE-2025-0001'
        }
    }
}
