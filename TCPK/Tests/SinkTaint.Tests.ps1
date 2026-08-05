Describe 'TCPK C10 - Sink Taint' {
    BeforeAll {
        $manifest = Join-Path $PSScriptRoot '..' 'TCPK.psd1'
        Import-Module (Resolve-Path $manifest) -Force -ErrorAction Stop
    }

    InModuleScope TCPK {

        # -----------------------------------------------------------------------
        # New-TcpkSinkAnalysis
        # -----------------------------------------------------------------------

        Describe 'New-TcpkSinkAnalysis' {

            It 'returns an object with all three elements' {
                $sa = New-TcpkSinkAnalysis -Source 'established' -SourceDetail 'HTTP query param' `
                    -Path 'established' -PathDetail 'direct concat' `
                    -Boundary 'established' -BoundaryDetail 'crosses user->kernel'
                $sa.Source   | Should -Be 'established'
                $sa.Path     | Should -Be 'established'
                $sa.Boundary | Should -Be 'established'
            }

            It 'defaults all three elements to untested' {
                $sa = New-TcpkSinkAnalysis
                $sa.Source   | Should -Be 'untested'
                $sa.Path     | Should -Be 'untested'
                $sa.Boundary | Should -Be 'untested'
            }

            It 'records neutralizer name' {
                $sa = New-TcpkSinkAnalysis -Path 'neutralized' -Neutralizer 'JsonSerializer.Serialize'
                $sa.Neutralizer | Should -Be 'JsonSerializer.Serialize'
            }
        }

        # -----------------------------------------------------------------------
        # Resolve-TcpkSinkSeverity - core severity mapping
        # -----------------------------------------------------------------------

        Describe 'Resolve-TcpkSinkSeverity - severity mapping' {

            It 'Source=absent -> INFO (API inventory, not a vulnerability)' {
                $sa = New-TcpkSinkAnalysis -Source 'absent' -SourceDetail 'argument is a shipped constant'
                $r  = Resolve-TcpkSinkSeverity -SinkAnalysis $sa -Candidate 'CRITICAL'
                $r.Severity | Should -Be 'INFO'
            }

            It 'Path=neutralized -> INFO' {
                $sa = New-TcpkSinkAnalysis -Source 'established' -Path 'neutralized' `
                    -Neutralizer 'HttpUtility.HtmlEncode'
                $r = Resolve-TcpkSinkSeverity -SinkAnalysis $sa -Candidate 'HIGH'
                $r.Severity | Should -Be 'INFO'
            }

            It 'Boundary=absent -> INFO (no privilege crossing)' {
                $sa = New-TcpkSinkAnalysis -Source 'established' -Path 'established' -Boundary 'absent'
                $r  = Resolve-TcpkSinkSeverity -SinkAnalysis $sa -Candidate 'CRITICAL'
                $r.Severity | Should -Be 'INFO'
            }

            It 'Source=established + Path=untested -> MEDIUM, Inferred' {
                $sa = New-TcpkSinkAnalysis -Source 'established' -Path 'untested' -Boundary 'established'
                $r  = Resolve-TcpkSinkSeverity -SinkAnalysis $sa -Candidate 'CRITICAL'
                $r.Severity   | Should -Be 'MEDIUM'
                $r.Confidence | Should -Be 'Inferred'
            }

            It 'Source=untested -> MEDIUM (caps CRITICAL)' {
                $sa = New-TcpkSinkAnalysis -Source 'untested' -Path 'established' -Boundary 'established'
                $r  = Resolve-TcpkSinkSeverity -SinkAnalysis $sa -Candidate 'CRITICAL'
                $r.Severity   | Should -Be 'MEDIUM'
                $r.Confidence | Should -Be 'Inferred'
            }

            It 'all untested -> MEDIUM (weakest cap from three untested)' {
                $sa = New-TcpkSinkAnalysis
                $r  = Resolve-TcpkSinkSeverity -SinkAnalysis $sa -Candidate 'HIGH'
                $r.Severity   | Should -Be 'MEDIUM'
                $r.Confidence | Should -Be 'Inferred'
            }

            It '(TP) all three established -> full candidate severity' {
                $sa = New-TcpkSinkAnalysis `
                    -Source 'established' -SourceDetail 'remote HTTP param passed to CreateProcess' `
                    -Path   'established' -PathDetail   'no encoding or allowlist observed in call chain' `
                    -Boundary 'established' -BoundaryDetail 'AppContainer -> medium IL process via COM'
                $r = Resolve-TcpkSinkSeverity -SinkAnalysis $sa -Candidate 'HIGH' -CandidateConf 'Confirmed'
                $r.Severity   | Should -Be 'HIGH'
                $r.Confidence | Should -Be 'Confirmed'
            }

            It '(TP) CRITICAL candidate with all established is not capped' {
                $sa = New-TcpkSinkAnalysis `
                    -Source 'established' -SourceDetail 'untrusted network data' `
                    -Path   'established' -PathDetail   'direct argument to DeserializeObject' `
                    -Boundary 'established' -BoundaryDetail 'crosses privilege boundary'
                $r = Resolve-TcpkSinkSeverity -SinkAnalysis $sa -Candidate 'CRITICAL' -CandidateConf 'Confirmed'
                $r.Severity   | Should -Be 'CRITICAL'
                $r.Confidence | Should -Be 'Confirmed'
            }
        }

        # -----------------------------------------------------------------------
        # AdjustmentEntries contain C10 annotation
        # -----------------------------------------------------------------------

        Describe 'Resolve-TcpkSinkSeverity - AdjustmentEntries annotation' {

            It 'AdjustmentEntries always contains a C10 SOURCE|PATH|BOUNDARY line' {
                $sa  = New-TcpkSinkAnalysis -Source 'established' -Path 'neutralized' -Neutralizer 'Encoding.HtmlEncode'
                $r   = Resolve-TcpkSinkSeverity -SinkAnalysis $sa -Candidate 'HIGH'
                $c10 = $r.AdjustmentEntries | Where-Object { $_ -match '^C10:' }
                $c10 | Should -Not -BeNullOrEmpty
                $c10 | Should -Match 'SOURCE='
                $c10 | Should -Match 'PATH='
                $c10 | Should -Match 'BOUNDARY='
            }

            It 'neutralizer name appears in AdjustmentEntries when Path=neutralized' {
                $sa  = New-TcpkSinkAnalysis -Path 'neutralized' -Neutralizer 'validateInput'
                $r   = Resolve-TcpkSinkSeverity -SinkAnalysis $sa -Candidate 'CRITICAL'
                $c10 = $r.AdjustmentEntries | Where-Object { $_ -match '^C10:' }
                $c10 | Should -Match 'validateInput'
            }

            It '-Log ref receives the annotation entries' {
                $log = [System.Collections.Generic.List[string]]::new()
                $sa  = New-TcpkSinkAnalysis -Source 'absent'
                $null = Resolve-TcpkSinkSeverity -SinkAnalysis $sa -Candidate 'HIGH' -Log ([ref]$log)
                $log.Count | Should -BeGreaterThan 0
                ($log | Where-Object { $_ -match '^C10:' }) | Should -Not -BeNullOrEmpty
            }
        }

        # -----------------------------------------------------------------------
        # Format-TcpkSinkSummary
        # -----------------------------------------------------------------------

        Describe 'Format-TcpkSinkSummary' {

            It 'all established -> only Established section' {
                $sa = New-TcpkSinkAnalysis -Source 'established' -Path 'established' -Boundary 'established'
                $s  = Format-TcpkSinkSummary -SinkAnalysis $sa
                $s | Should -Match 'Established: SOURCE, PATH, BOUNDARY'
                $s | Should -Not -Match 'Refuted'
                $s | Should -Not -Match 'Assumed'
            }

            It 'Source=absent -> Refuted/absent section mentions SOURCE' {
                $sa = New-TcpkSinkAnalysis -Source 'absent'
                $s  = Format-TcpkSinkSummary -SinkAnalysis $sa
                $s | Should -Match 'Refuted/absent:.*SOURCE'
                $s | Should -Match 'no external influence'
            }

            It 'Path=neutralized -> Refuted/absent section names the neutralizer' {
                $sa = New-TcpkSinkAnalysis -Source 'established' -Path 'neutralized' -Neutralizer 'HtmlEncode'
                $s  = Format-TcpkSinkSummary -SinkAnalysis $sa
                $s | Should -Match 'Refuted/absent:.*PATH.*HtmlEncode'
            }

            It 'Boundary=absent -> Refuted/absent mentions no privilege crossing' {
                $sa = New-TcpkSinkAnalysis -Source 'established' -Path 'established' -Boundary 'absent'
                $s  = Format-TcpkSinkSummary -SinkAnalysis $sa
                $s | Should -Match 'Refuted/absent:.*BOUNDARY'
                $s | Should -Match 'no privilege crossing'
            }

            It 'all untested -> only Assumed/untested section' {
                $sa = New-TcpkSinkAnalysis
                $s  = Format-TcpkSinkSummary -SinkAnalysis $sa
                $s | Should -Not -Match 'Established:'
                $s | Should -Match 'Assumed/untested:'
            }

            It 'mixed scenario renders all three sections' {
                $sa = New-TcpkSinkAnalysis -Source 'established' -Path 'neutralized' -Neutralizer 'enc' -Boundary 'untested'
                $s  = Format-TcpkSinkSummary -SinkAnalysis $sa
                $s | Should -Match 'Established:'
                $s | Should -Match 'Refuted/absent:'
                $s | Should -Match 'Assumed/untested:'
            }

            It '(TP) genuine sink with no neutralizer summary shows all Established' {
                $sa = New-TcpkSinkAnalysis `
                    -Source   'established' -SourceDetail 'HTTP body deserialized directly' `
                    -Path     'established' -PathDetail   'no neutralizer; BinaryFormatter.Deserialize called with stream from untrusted socket' `
                    -Boundary 'established' -BoundaryDetail 'process boundary (network -> local system)'
                $s = Format-TcpkSinkSummary -SinkAnalysis $sa
                $s | Should -Match 'Established: SOURCE, PATH, BOUNDARY'
                $s | Should -Not -Match 'Refuted'
            }
        }

        # -----------------------------------------------------------------------
        # Get-TcpkSinkPreconditions -> CAP5 integration
        # -----------------------------------------------------------------------

        Describe 'Get-TcpkSinkPreconditions - CAP5 integration' {

            It 'Source=absent produces a REFUTED precondition for sink-source-external' {
                $sa    = New-TcpkSinkAnalysis -Source 'absent'
                $precs = Get-TcpkSinkPreconditions -SinkAnalysis $sa
                $src   = $precs | Where-Object { $_.Name -eq 'sink-source-external' }
                $src.State | Should -Be 'REFUTED'
            }

            It 'Path=neutralized produces a REFUTED precondition for sink-path-unobstructed' {
                $sa    = New-TcpkSinkAnalysis -Path 'neutralized' -Neutralizer 'allowlist'
                $precs = Get-TcpkSinkPreconditions -SinkAnalysis $sa
                $path  = $precs | Where-Object { $_.Name -eq 'sink-path-unobstructed' }
                $path.State    | Should -Be 'REFUTED'
                $path.Evidence | Should -Match 'allowlist'
            }

            It 'Boundary=absent produces a REFUTED precondition for sink-boundary-crossed' {
                $sa    = New-TcpkSinkAnalysis -Boundary 'absent'
                $precs = Get-TcpkSinkPreconditions -SinkAnalysis $sa
                $bnd   = $precs | Where-Object { $_.Name -eq 'sink-boundary-crossed' }
                $bnd.State | Should -Be 'REFUTED'
            }

            It 'All established -> all three preconditions are CONFIRMED' {
                $sa    = New-TcpkSinkAnalysis -Source 'established' -Path 'established' -Boundary 'established'
                $precs = Get-TcpkSinkPreconditions -SinkAnalysis $sa
                $precs | ForEach-Object { $_.State | Should -Be 'CONFIRMED' }
            }

            It 'untested elements produce UNTESTED preconditions' {
                $sa    = New-TcpkSinkAnalysis -Source 'untested' -Path 'untested' -Boundary 'untested'
                $precs = Get-TcpkSinkPreconditions -SinkAnalysis $sa
                $precs | ForEach-Object { $_.State | Should -Be 'UNTESTED' }
            }
        }
    }
}
