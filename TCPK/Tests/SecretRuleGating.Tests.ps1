#requires -Version 5.1
#
# Every consumer of the secrets.json rules must apply the pre-filter gates.
#
# WHY THIS EXISTS. The gates were built inline inside Test-TcpkSecrets, so only that one
# check had them. Eight other cmdlets took the rules from Get-TcpkSecretRegexRules and ran
# all 49 regexes raw: the live-memory scan, the clipboard scan, the environment-block scan,
# the window-title scan, the Java bundle scan, and the asar / PyInstaller / single-file
# extractors. Four of those are on the GUI's Runtime tab.
#
# That is not a slower scan, it is a different and much worse one. 47 of the 49 rules carry
# a literal prefix or a prefilter needle set that is MANDATORY for the pattern to mean
# anything. particle-io-access-token is [0-9a-f]{40} at HIGH severity, gated on
# 'api.particle.io'. Run ungated against a process heap it matches every SHA-1, every
# certificate thumbprint and every hex blob in the address space, and reports each one HIGH.
# On a synthetic heap holding 400 SHA-1 hashes that single rule produced 401 of 486 total
# hits; the gates removed 83% of all output and cost nothing real.
#
# These are source-level assertions on purpose. The failure mode is a NEW consumer added
# later without the gate, which no behavioural test would catch unless someone remembered to
# write one for it.

BeforeAll {
    $script:Root       = Split-Path (Split-Path $PSCommandPath -Parent) -Parent
    $script:PublicDir  = Join-Path $script:Root 'Public'
    $script:PrivateDir = Join-Path $script:Root 'Private'

    # Files that ask for the compiled rule set.
    $script:Consumers = @(
        Get-ChildItem -LiteralPath $script:PublicDir -Recurse -File -Filter '*.ps1' |
            Where-Object {
                $t = [IO.File]::ReadAllText($_.FullName)
                $t -match 'Get-TcpkSecretRegexRules' -and $t -notmatch 'function Get-TcpkSecretRegexRules'
            }
    )
}

Describe 'secrets.json rule gating' {

    It 'finds at least one consumer (the scan itself is not silently empty)' {
        @($script:Consumers).Count | Should -BeGreaterThan 0
    }

    It 'has exactly one builder, so the rule set cannot be prepared two different ways' {
        # Two builders that disagreed about the match timeout, the Multiline flag and the
        # gates, both mutating the objects Get-TcpkData caches, meant whichever check ran
        # first in a session decided the behaviour of every check after it.
        $defs = @(Get-ChildItem -LiteralPath $script:Root -Recurse -File -Filter '*.ps1' |
            Where-Object { $_.FullName -notmatch '\\Tests\\' } |
            Where-Object { [IO.File]::ReadAllText($_.FullName) -match 'function\s+Get-TcpkSecretRegexRules' })
        @($defs).Count | Should -Be 1
    }

    It 'compiles every rule with a finite match timeout' {
        # Without one, RegexMatchTimeoutException can never be raised and the handler that
        # reports secrets.rule-timeout is dead code: a pathological rule stalls the audit
        # with no output instead of costing a few seconds and being reported.
        $src = [IO.File]::ReadAllText((Join-Path $script:PrivateDir '_MemRead.ps1'))
        $src | Should -Match '\[regex\]::new\('
        $src | Should -Match 'TcpkSecretsRuleTimeout'
    }

    It 'gates every consumer of the rule set' -ForEach @(
        @{ Name = 'Test-TcpkSecrets' }
        @{ Name = 'Test-TcpkMemorySecrets' }
        @{ Name = 'Test-TcpkClipboardSecrets' }
        @{ Name = 'Test-TcpkProcessEnvSecrets' }
        @{ Name = 'Test-TcpkUiDataExposure' }
        @{ Name = 'Test-TcpkJavaBundle' }
        @{ Name = 'Expand-TcpkAsar' }
        @{ Name = 'Expand-TcpkPyInstaller' }
        @{ Name = 'Expand-TcpkSingleFile' }
    ) {
        $file = Get-ChildItem -LiteralPath $script:PublicDir -Recurse -File -Filter "$Name.ps1" | Select-Object -First 1
        $file | Should -Not -BeNullOrEmpty -Because "$Name.ps1 should exist"
        $src = [IO.File]::ReadAllText($file.FullName)
        $src | Should -Match 'Test-TcpkSecretRuleApplies' -Because (
            "$Name runs the secret rules and must gate them; ungated, [0-9a-f]{40} at HIGH " +
            'matches every hash it sees')
    }

    It 'leaves no consumer ungated, including ones added after this test was written' {
        # The -ForEach list above names what existed. This catches the next one.
        $ungated = @($script:Consumers |
            Where-Object { [IO.File]::ReadAllText($_.FullName) -notmatch 'Test-TcpkSecretRuleApplies' } |
            ForEach-Object { $_.BaseName })
        $ungated -join ', ' | Should -BeNullOrEmpty -Because (
            'these cmdlets take the secret rules but never call Test-TcpkSecretRuleApplies')
    }
}

Describe 'Test-TcpkSecretRuleApplies behaviour' {

    BeforeAll { Import-Module (Join-Path $script:Root 'TCPK.psd1') -Force }

    It 'blocks a rule whose prefilter needle is absent from the text' {
        # A page of hashes with no Particle URL anywhere is the exact heap case.
        $r = & (Get-Module TCPK) {
            $rules = Get-TcpkSecretRegexRules
            $p = $rules | Where-Object { $_.id -eq 'particle-io-access-token' } | Select-Object -First 1
            Test-TcpkSecretRuleApplies -Rule $p -Text ('a1b2c3d4e5' * 40)
        }
        $r | Should -BeFalse
    }

    It 'passes the same rule once its needle is present' {
        $r = & (Get-Module TCPK) {
            $rules = Get-TcpkSecretRegexRules
            $p = $rules | Where-Object { $_.id -eq 'particle-io-access-token' } | Select-Object -First 1
            Test-TcpkSecretRuleApplies -Rule $p -Text 'GET https://api.particle.io/v1/devices'
        }
        $r | Should -BeTrue
    }

    It 'passes a rule that carries no gate at all' {
        # No literal prefix and no prefilter means the rule always runs: correctness first.
        $r = & (Get-Module TCPK) {
            $rules = Get-TcpkSecretRegexRules
            $p = $rules | Where-Object { -not $_._QuickLit -and -not @($_._Needles).Count } | Select-Object -First 1
            if (-not $p) { return $true }
            Test-TcpkSecretRuleApplies -Rule $p -Text 'anything at all'
        }
        $r | Should -BeTrue
    }

    It 'returns false for empty text rather than throwing' {
        $r = & (Get-Module TCPK) {
            $rules = Get-TcpkSecretRegexRules
            Test-TcpkSecretRuleApplies -Rule ($rules | Select-Object -First 1) -Text ''
        }
        $r | Should -BeFalse
    }

    It 'attaches both gates to every rule' {
        $bad = & (Get-Module TCPK) {
            @(Get-TcpkSecretRegexRules | Where-Object {
                -not $_.PSObject.Properties['_RX'] -or
                -not $_.PSObject.Properties['_QuickLit'] -or
                -not $_.PSObject.Properties['_Needles']
            } | ForEach-Object { $_.id })
        }
        $bad -join ', ' | Should -BeNullOrEmpty
    }
}
