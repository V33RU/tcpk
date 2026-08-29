#requires -Version 5.1
# Pester 5: the user-authored rule loader + runner.
#
# The whole loader is pure over JSON text and pure over parsed rules over a directory, so
# every case here runs cross-platform without touching Windows-specific APIs. The behaviour
# that matters most is the NEGATIVE: a broken rule is refused whole (not partially loaded
# with default values that read like a finding), and a rule with any field the parser does
# not recognise is refused. That is the property that keeps a community rule format from
# becoming a code-execution primitive.

BeforeAll {
    $psd1 = Join-Path (Split-Path (Split-Path $PSCommandPath -Parent) -Parent) 'TCPK.psd1'
    Import-Module $psd1 -Force

    $script:work = Join-Path ([IO.Path]::GetTempPath()) ('tcpk-ur-' + [guid]::NewGuid().ToString('N').Substring(0,10))
    New-Item -ItemType Directory -Force -Path $script:work | Out-Null
    $script:rules = Join-Path $script:work 'rules'
    $script:scan  = Join-Path $script:work 'scan'
    New-Item -ItemType Directory -Force -Path $script:rules,$script:scan | Out-Null
}
AfterAll {
    if ($script:work -and (Test-Path $script:work)) { Remove-Item -Recurse -Force -ErrorAction SilentlyContinue $script:work }
}

Describe 'Read-TcpkUserRule: schema validation refuses rather than partially loads' {
    It 'accepts a minimal well-formed rule' {
        InModuleScope TCPK {
            $r = Read-TcpkUserRule -Json '{"id":"x.hello","severity":"HIGH","description":"d","fix":"f","match":{"glob":"**/*.txt","regex":"secret"}}'
            $r.Errors.Count | Should -Be 0
            $r.Rule.Id | Should -Be 'x.hello'
            $r.Rule.Severity | Should -Be 'HIGH'
        }
    }

    It 'defaults type to file-regex when not supplied' {
        InModuleScope TCPK {
            (Read-TcpkUserRule -Json '{"id":"x.a","severity":"LOW","description":"d","fix":"f","match":{"glob":"*","regex":"."}}').Rule.Type | Should -Be 'file-regex'
        }
    }

    It 'refuses invalid JSON with a specific error, not an empty rule' {
        InModuleScope TCPK {
            $r = Read-TcpkUserRule -Json '{not json'
            $r.Rule | Should -BeNullOrEmpty
            ($r.Errors -join ' ') | Should -Match 'not valid JSON'
        }
    }

    It 'refuses an id that is uppercase or too short' {
        InModuleScope TCPK {
            (Read-TcpkUserRule -Json '{"id":"BAD","severity":"HIGH","description":"d","fix":"f","match":{"glob":"*","regex":"."}}').Rule | Should -BeNullOrEmpty
            (Read-TcpkUserRule -Json '{"id":"ab","severity":"HIGH","description":"d","fix":"f","match":{"glob":"*","regex":"."}}').Rule | Should -BeNullOrEmpty
        }
    }

    It 'refuses an unknown severity' {
        InModuleScope TCPK {
            $r = Read-TcpkUserRule -Json '{"id":"x.a","severity":"NUCLEAR","description":"d","fix":"f","match":{"glob":"*","regex":"."}}'
            ($r.Errors -join ' ') | Should -Match 'severity'
        }
    }

    It 'refuses an unknown top-level field so a future "script" or "run" cannot slip in' {
        InModuleScope TCPK {
            $r = Read-TcpkUserRule -Json '{"id":"x.a","severity":"HIGH","description":"d","fix":"f","match":{"glob":"*","regex":"."},"run":"powershell.exe"}'
            $r.Rule | Should -BeNullOrEmpty
            ($r.Errors -join ' ') | Should -Match "unknown field 'run'"
        }
    }

    It 'refuses an unknown check type instead of defaulting to something dangerous' {
        InModuleScope TCPK {
            $r = Read-TcpkUserRule -Json '{"id":"x.a","severity":"HIGH","type":"script","description":"d","fix":"f","match":{"glob":"*","regex":"."}}'
            ($r.Errors -join ' ') | Should -Match "'type' must be 'file-regex'"
        }
    }

    It 'refuses a malformed regex at load time, not scan time' {
        InModuleScope TCPK {
            $r = Read-TcpkUserRule -Json '{"id":"x.a","severity":"HIGH","description":"d","fix":"f","match":{"glob":"*","regex":"[unclosed"}}'
            ($r.Errors -join ' ') | Should -Match 'valid .NET regex'
        }
    }

    It 'requires description and fix, so a rule cannot produce an unactionable finding' {
        InModuleScope TCPK {
            $r = Read-TcpkUserRule -Json '{"id":"x.a","severity":"HIGH","match":{"glob":"*","regex":"."}}'
            ($r.Errors -join ' ') | Should -Match 'description'
            ($r.Errors -join ' ') | Should -Match 'fix'
        }
    }
}

Describe 'Convert-TcpkGlobToRegex' {
    It '** matches any depth including zero' {
        InModuleScope TCPK {
            $rx = [regex]::new((Convert-TcpkGlobToRegex '**/*.json'))
            $rx.IsMatch('a.json')       | Should -BeTrue
            $rx.IsMatch('sub/a.json')   | Should -BeTrue
            $rx.IsMatch('a/b/c/x.json') | Should -BeTrue
            $rx.IsMatch('a.txt')        | Should -BeFalse
        }
    }
    It '* matches within a single segment, not across /' {
        InModuleScope TCPK {
            $rx = [regex]::new((Convert-TcpkGlobToRegex 'src/*.cs'))
            $rx.IsMatch('src/a.cs')     | Should -BeTrue
            $rx.IsMatch('src/sub/a.cs') | Should -BeFalse
        }
    }
    It 'normalises backslashes to forward slashes' {
        InModuleScope TCPK {
            $rx = [regex]::new((Convert-TcpkGlobToRegex 'a\\b\\*.json'))
            $rx.IsMatch('a/b/x.json') | Should -BeTrue
        }
    }
}

Describe 'Test-TcpkUserRules: end-to-end with synthetic rules and files' {
    BeforeEach {
        Get-ChildItem -LiteralPath $script:rules -Recurse -File -ErrorAction SilentlyContinue | Remove-Item -Force
        Get-ChildItem -LiteralPath $script:scan  -Recurse -File -ErrorAction SilentlyContinue | Remove-Item -Force
    }

    It 'matches a rule and emits a finding under the rule id, with the rule severity' {
        $rule = @{
            id='u.hits'; severity='HIGH'; description='desc'; fix='fx'
            match=@{ glob='**/*.txt'; regex='SECRET' }
        } | ConvertTo-Json -Depth 6
        [IO.File]::WriteAllText((Join-Path $script:rules 'r.json'), $rule)
        [IO.File]::WriteAllText((Join-Path $script:scan 'a.txt'), 'no match here')
        [IO.File]::WriteAllText((Join-Path $script:scan 'b.txt'), 'the SECRET is out')

        $rows = @(Test-TcpkUserRules -Path $script:scan -ExtraPath $script:rules)
        $hit = $rows | Where-Object { $_.RuleId -eq 'u.hits' }
        $hit.Count | Should -Be 1
        $hit.Severity | Should -Be 'HIGH'
        $hit.File | Should -Match 'b\.txt$'
    }

    It 'never fires when the glob excludes the file' {
        $rule = @{
            id='u.miss'; severity='LOW'; description='d'; fix='f'
            match=@{ glob='**/*.json'; regex='.' }
        } | ConvertTo-Json -Depth 6
        [IO.File]::WriteAllText((Join-Path $script:rules 'r.json'), $rule)
        [IO.File]::WriteAllText((Join-Path $script:scan 'a.txt'), 'anything')

        @(Test-TcpkUserRules -Path $script:scan -ExtraPath $script:rules | Where-Object { $_.RuleId -eq 'u.miss' }).Count | Should -Be 0
    }

    It 'reports a malformed rule as a Skipped finding rather than throwing' {
        [IO.File]::WriteAllText((Join-Path $script:rules 'bad.json'), '{not json')
        $rows = @(Test-TcpkUserRules -Path $script:scan -ExtraPath $script:rules)
        ($rows | Where-Object { $_.RuleId -eq 'rules.malformed' }).Count | Should -BeGreaterThan 0
    }

    It 'refuses a rule with an id that duplicates one already loaded' {
        $r = @{ id='u.dup'; severity='LOW'; description='d'; fix='f'; match=@{ glob='*'; regex='.' } } | ConvertTo-Json -Depth 6
        [IO.File]::WriteAllText((Join-Path $script:rules 'a.json'), $r)
        [IO.File]::WriteAllText((Join-Path $script:rules 'b.json'), $r)
        [IO.File]::WriteAllText((Join-Path $script:scan 'x.txt'), 'x')
        $rows = @(Test-TcpkUserRules -Path $script:scan -ExtraPath $script:rules)
        ($rows | Where-Object { $_.RuleId -eq 'rules.malformed' -and $_.Title -match "already defined" }).Count |
            Should -BeGreaterThan 0
    }

    It 'caps hits per file so a bad regex cannot spam the report' {
        $r = @{ id='u.spam'; severity='INFO'; description='d'; fix='f'
                match=@{ glob='**/*.txt'; regex='X'; maxHits=3 } } | ConvertTo-Json -Depth 6
        [IO.File]::WriteAllText((Join-Path $script:rules 'r.json'), $r)
        [IO.File]::WriteAllText((Join-Path $script:scan 'lots.txt'), ('X' * 500))
        $hit = @(Test-TcpkUserRules -Path $script:scan -ExtraPath $script:rules | Where-Object { $_.RuleId -eq 'u.spam' })
        $hit.Count | Should -Be 1
        $hit.Evidence | Should -Match 'matches=500'
    }
}
