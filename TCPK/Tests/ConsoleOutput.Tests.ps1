#requires -Version 5.1
#
# The console lines Invoke-TcpkAudit writes are a CONTRACT, not cosmetics. The desktop GUI
# and the web / agentic workbench both drive their progress bars by regex over these exact
# lines, and nothing connects the two sides at compile time.
#
# The bug this file exists to prevent has already happened once. The failure line gained an
# elapsed time ("FAILED after 3s  (...)"), the GUI's matching pattern '\bFAILED\s+\(' was
# never updated, and from then on a failed check silently stopped advancing the progress
# bar. Nothing threw and nothing logged: a regex that stops matching just quietly does less.
#
# So both sides are asserted TOGETHER, and neither is copied into this file. The emitter
# format strings are read out of Invoke-TcpkAudit.ps1, the matching patterns are read out of
# Start-TCPKGui.ps1 and _WebUi.ps1, and the rendered lines are run through the real patterns.
# Change either side on its own and this fails.

Describe 'TCPK console output contract' {

    BeforeAll {
        $root = Split-Path (Split-Path $PSCommandPath -Parent) -Parent   # ...\TCPK
        $repo = Split-Path $root -Parent
        Import-Module (Join-Path $root 'TCPK.psd1') -Force -ErrorAction Stop

        $auditSrc      = Get-Content -LiteralPath (Join-Path $root 'Public\Invoke-TcpkAudit.ps1') -Raw
        $script:LogSrc = Get-Content -LiteralPath (Join-Path $root 'Private\_Log.ps1')            -Raw
        $guiSrc        = Get-Content -LiteralPath (Join-Path $repo 'Start-TCPKGui.ps1')           -Raw
        $webSrc        = Get-Content -LiteralPath (Join-Path $root 'Private\_WebUi.ps1')          -Raw

        # --- emitter: the three format strings, straight out of the audit source ----------
        $script:FmtFind = [regex]::Match($auditSrc, '"(\s*\{0,-\d+\} \{1,\d+\} findings[^"]*)"').Groups[1].Value
        $script:FmtFail = [regex]::Match($auditSrc, '"(\s*\{0,-\d+\}\s+FAILED after[^"]*)"').Groups[1].Value
        $script:FmtSkip = [regex]::Match($auditSrc, '"(\s*\{0,-\d+\}\s+skipped \(Quick profile\))"').Groups[1].Value

        # --- hosts: the matching patterns, keeping -match and -cmatch apart ---------------
        # -cmatch is case-SENSITIVE and that is load-bearing (see the negative cases), so the
        # emulation must preserve it rather than match everything case-insensitively.
        #
        # Each segment is cut off at the counter increment rather than at the end of the
        # enclosing function. Both hosts have further matching below that point for other
        # purposes, and sweeping those in would silently weaken the negative assertions.
        $script:GetPatterns = {
            param([string]$Segment)
            $out = @()
            foreach ($m in [regex]::Matches($Segment, "-(c?)match\s+'([^']+)'")) {
                $out += [pscustomobject]@{
                    CaseSensitive = ($m.Groups[1].Value -eq 'c')
                    Pattern       = $m.Groups[2].Value
                }
            }
            return $out
        }
        $script:Advances = {
            param([string]$Line, $Patterns)
            foreach ($p in $Patterns) {
                $opt = [System.Text.RegularExpressions.RegexOptions]::IgnoreCase
                if ($p.CaseSensitive) { $opt = [System.Text.RegularExpressions.RegexOptions]::None }
                if ([regex]::IsMatch($Line, $p.Pattern, $opt)) { return $true }
            }
            return $false
        }

        $script:GuiPatterns = & $script:GetPatterns ([regex]::Match($guiSrc, '(?s)function Step-ProgressFromLog.*?ChkDone\+\+').Value)
        $script:WebPatterns = & $script:GetPatterns ([regex]::Match($webSrc, '(?s)\$msg -match.{0,500}?ChecksDone\+\+').Value)

        # --- the lines, rendered from the REAL format strings -----------------------------
        # The awkward names are deliberate: a bundle suffix, an Invoke- verb and a name with
        # spaces are all real entries in the audit's check list, and the pattern the web host
        # used before this change ('^\s*Test-Tcpk\S+\s+\d+ findings') missed all 19 of them.
        $script:GoodLines = @(
            ($script:FmtFind -f 'Test-TcpkDevArtifacts', 47, 'C1 H3 M12 L20 I11', '189ms')
            ($script:FmtFind -f 'Test-TcpkDependencyConfusion', 0, '', '35ms')
            ($script:FmtFind -f 'Test-TcpkReflectionLoading (bundle)', 2, 'H1 M1', '1.4s')
            ($script:FmtFind -f 'Invoke-TcpkManagedCarve', 1, 'M1', '412ms')
            ($script:FmtFind -f 'Single-file bundle detected', 0, '', '3ms')
            ($script:FmtFail -f 'Test-TcpkKernelDrivers', '3.1s', 'Access is denied')
            ($script:FmtSkip -f 'Test-TcpkRegistryAcl')
        )
    }

    Context 'the emitter still produces the tokens the hosts key on' {
        It 'renders a per-check result line' { $script:FmtFind | Should -Not -BeNullOrEmpty }
        It 'renders a failure line'          { $script:FmtFail | Should -Not -BeNullOrEmpty }
        It 'renders a Quick-profile skip'    { $script:FmtSkip | Should -Not -BeNullOrEmpty }

        It 'writes FAILED in upper case' {
            # Lower case would collide with ordinary log text: _Cim.ps1 builds
            # "$label failed after ${sec}s: $msg" and _StringExtractor.ps1 builds
            # "extract failed after Ns on ...", both of which now reach the hosts as
            # [warn] / [error] console lines. The hosts use the case to tell them apart.
            $script:FmtFail | Should -MatchExactly 'FAILED after'
        }

        It 'indents every status line by exactly two spaces' {
            foreach ($f in @($script:FmtFind, $script:FmtFail, $script:FmtSkip)) {
                $f | Should -Match '^\s{2}\{'
            }
        }
    }

    Context 'both hosts advance on every line shape' {
        It 'found a pattern set in each host' {
            @($script:GuiPatterns).Count | Should -BeGreaterThan 0
            @($script:WebPatterns).Count | Should -BeGreaterThan 0
        }

        It 'counts every line the audit emits for a check' {
            foreach ($line in $script:GoodLines) {
                (& $script:Advances $line $script:GuiPatterns) | Should -BeTrue -Because "the desktop GUI must advance on: $line"
                (& $script:Advances $line $script:WebPatterns) | Should -BeTrue -Because "the workbench must advance on: $line"
            }
        }
    }

    Context 'neither host miscounts ordinary log output as a completed check' {
        # All of these reach the hosts on the same stream; counting any would overrun the
        # bar. The first two are the real strings built by _Cim.ps1 and _StringExtractor.ps1
        # and are the reason the FAILED test has to be case-sensitive.
        It 'ignores <_>' -ForEach @(
            '  [warn] cim: Win32_Service failed after 30s: timed out'
            '  [error] strings: extract failed after 12s on C:\app\big.dll -- aborted'
            '  Get-TcpkSigningMatrix                   stopped at the 30s budget (partial)'
            '  [heartbeat] pe-scan                      15s  412/638  current: xul.dll (130 MB)'
            "  [PAUSED] audit held before 'Test-TcpkSecrets' -- make your changes, then click Resume."
            '  [RESUMED] continuing audit.'
            '[TCPK] Target C:\app returned 812 files'
        ) {
            (& $script:Advances $_ $script:GuiPatterns) | Should -BeFalse -Because "the desktop GUI must not count: $_"
            (& $script:Advances $_ $script:WebPatterns) | Should -BeFalse -Because "the workbench must not count: $_"
        }
    }

    Context 'the console stays quiet unless something went wrong' {
        It 'does not force the LOGX mirror onto the console' {
            # Both hosts discard '^LOGX\t' on sight and the GUI Logs/Runtime tab is built
            # from run.jsonl on disk, so forcing this to Continue only ever duplicated every
            # check result and every heartbeat into the operator's terminal.
            $logx = [regex]::Match($script:LogSrc, '(?m)^.*MessageData \("LOGX.*$').Value
            $logx | Should -Not -BeNullOrEmpty
            $logx | Should -Not -Match '-InformationAction\s+Continue'
        }

        It 'keeps WARN and ERROR visible' {
            # For a long tail of swallowed failures Write-TcpkLog is the only terminal
            # surface there is. Silencing these would let a run finish with a report section
            # missing and nothing at all on screen.
            $script:LogSrc | Should -Match "Level -eq 'WARN'"
            $script:LogSrc | Should -Match "Level -eq 'ERROR'"
        }
    }

    Context 'Format-TcpkElapsed' {
        It 'renders <ms> ms as <expected>' -ForEach @(
            @{ ms = 0;       expected = '0ms'    }
            @{ ms = 189;     expected = '189ms'  }
            @{ ms = 999;     expected = '999ms'  }
            @{ ms = 1000;    expected = '1.0s'   }
            @{ ms = 1450;    expected = '1.4s'   }
            @{ ms = 60000;   expected = '1m00s'  }
            @{ ms = 521000;  expected = '8m41s'  }
            @{ ms = 3599000; expected = '59m59s' }
        ) {
            $span = [TimeSpan]::FromMilliseconds($ms)
            $got = & (Get-Module TCPK) { param($s) Format-TcpkElapsed $s } $span
            $got | Should -Be $expected
        }

        It 'floors the minutes instead of rounding them' {
            # [int] on a double is Convert.ToInt32, which rounds to nearest, so 521s would
            # come out as "9m41s": a minute in the future.
            $span = [TimeSpan]::FromMilliseconds(521000)
            (& (Get-Module TCPK) { param($s) Format-TcpkElapsed $s } $span) | Should -Be '8m41s'
        }
    }

    Context 'Get-TcpkSeverityTally' {
        It 'returns empty for no findings' {
            (& (Get-Module TCPK) { Get-TcpkSeverityTally -Findings @() }) | Should -BeNullOrEmpty
        }

        It 'orders buckets by severity and omits empty ones' {
            $f = @(
                [pscustomobject]@{ Severity = 'INFO' }
                [pscustomobject]@{ Severity = 'CRITICAL' }
                [pscustomobject]@{ Severity = 'HIGH' }
                [pscustomobject]@{ Severity = 'HIGH' }
            )
            (& (Get-Module TCPK) { param($x) Get-TcpkSeverityTally -Findings $x } $f) | Should -Be 'C1 H2 I1'
        }

        It 'counts INFO, so the tally always sums to the printed count' {
            # INFO is the most-emitted severity in the ruleset. Dropping it would make the
            # tally visibly disagree with the count printed beside it.
            $f = @()
            foreach ($i in 1..9) {
                foreach ($s in @('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO')) {
                    $f += [pscustomobject]@{ Severity = $s }
                }
            }
            $tally = & (Get-Module TCPK) { param($x) Get-TcpkSeverityTally -Findings $x } $f
            $sum = 0
            foreach ($tok in ($tally -split ' ')) { $sum = $sum + [int]$tok.Substring(1) }
            $sum | Should -Be @($f).Count
        }

        It 'ignores severities outside the ladder rather than throwing' {
            $f = @([pscustomobject]@{ Severity = 'Skipped' }, [pscustomobject]@{ Severity = '' })
            { & (Get-Module TCPK) { param($x) Get-TcpkSeverityTally -Findings $x } $f } | Should -Not -Throw
            (& (Get-Module TCPK) { param($x) Get-TcpkSeverityTally -Findings $x } $f) | Should -BeNullOrEmpty
        }
    }

    Context 'Reset-TcpkHeartbeat' {
        It 'does not re-arm an immediate heartbeat' {
            # Setting Last back to $null made the guard in Write-TcpkHeartbeat fall through,
            # so the first file of every check printed a heartbeat reading
            # "0s  1  current: <first file>". With ~69 checks iterating Get-TcpkPeFiles that
            # is ~69 lines per audit reporting no elapsed time and no progress.
            $last = & (Get-Module TCPK) { Reset-TcpkHeartbeat; $script:TcpkHeartbeatLast }
            $last | Should -Not -BeNullOrEmpty
            $last | Should -BeOfType [datetime]
        }

        It 'baselines both clocks together' {
            $r = & (Get-Module TCPK) {
                Reset-TcpkHeartbeat
                [pscustomobject]@{ Last = $script:TcpkHeartbeatLast; From = $script:TcpkHeartbeatFrom }
            }
            $r.From | Should -Be $r.Last
        }
    }
}
