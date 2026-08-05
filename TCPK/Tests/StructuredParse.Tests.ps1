Describe 'TCPK C9 - Structured Parse' {
    BeforeAll {
        $manifest = Join-Path $PSScriptRoot '..' 'TCPK.psd1'
        Import-Module (Resolve-Path $manifest) -Force -ErrorAction Stop
    }

    InModuleScope TCPK {

        # -----------------------------------------------------------------------
        # Get-TcpkArtifactParseLevel
        # -----------------------------------------------------------------------

        Describe 'Get-TcpkArtifactParseLevel' {

            It 'csp has a parser available' {
                $r = Get-TcpkArtifactParseLevel -ArtifactType 'csp'
                $r.ParseAvailable | Should -Be $true
                $r.MaxProvenance  | Should -Be 'structural-parse'
            }

            It 'sddl has no parser - string-match provenance only' {
                $r = Get-TcpkArtifactParseLevel -ArtifactType 'sddl'
                $r.ParseAvailable | Should -Be $false
                $r.MaxProvenance  | Should -Be 'string-match'
            }

            It 'unknown artifact type falls back to string-match' {
                $r = Get-TcpkArtifactParseLevel -ArtifactType 'binary-blob'
                $r.ParseAvailable | Should -Be $false
                $r.MaxProvenance  | Should -Be 'string-match'
            }
        }

        # -----------------------------------------------------------------------
        # Assert-TcpkStructuredClaim
        # -----------------------------------------------------------------------

        Describe 'Assert-TcpkStructuredClaim' {

            It 'csp claim with named element is valid' {
                $r = Assert-TcpkStructuredClaim -ArtifactType 'csp' -ClaimElement 'script-src'
                $r.Valid           | Should -Be $true
                $r.ProvenanceLevel | Should -Be 'structural-parse'
                $r.Warning         | Should -BeNullOrEmpty
            }

            It 'sddl claim is not valid - no parser' {
                $r = Assert-TcpkStructuredClaim -ArtifactType 'sddl' -ClaimElement 'D:(A;;FA;;;WD)'
                $r.Valid   | Should -Be $false
                $r.Warning | Should -Match 'string-match'
            }

            It 'csp claim without named element is not valid' {
                $r = Assert-TcpkStructuredClaim -ArtifactType 'csp' -ClaimElement ''
                $r.Valid   | Should -Be $false
                $r.Warning | Should -Match 'specific element'
            }
        }

        # -----------------------------------------------------------------------
        # ConvertTo-TcpkCspModel
        # -----------------------------------------------------------------------

        Describe 'ConvertTo-TcpkCspModel' {

            It 'parses each directive into a token array' {
                $m = ConvertTo-TcpkCspModel "default-src 'none'; script-src 'self'; style-src 'unsafe-inline'"
                $m['default-src'] | Should -Be @("'none'")
                $m['script-src']  | Should -Be @("'self'")
                $m['style-src']   | Should -Be @("'unsafe-inline'")
            }

            It 'directive names and values are lowercased' {
                $m = ConvertTo-TcpkCspModel "Script-Src 'SELF'"
                $m.ContainsKey('script-src') | Should -Be $true
                $m['script-src'] | Should -Contain "'self'"
            }

            It 'first directive wins on duplicate (RFC 7230 first-value rule)' {
                $m = ConvertTo-TcpkCspModel "script-src 'self'; script-src 'unsafe-inline'"
                $m['script-src'] | Should -Be @("'self'")
            }

            It 'directive with no values becomes an empty array' {
                $m = ConvertTo-TcpkCspModel "upgrade-insecure-requests"
                $m.ContainsKey('upgrade-insecure-requests') | Should -Be $true
                $m['upgrade-insecure-requests'].Count | Should -Be 0
            }
        }

        # -----------------------------------------------------------------------
        # Test-TcpkCspDirectivePermissive - isolation of directives (key spec scenario)
        # -----------------------------------------------------------------------

        Describe 'Test-TcpkCspDirectivePermissive - directive isolation' {

            BeforeAll {
                # The original observed FP scenario: unsafe-inline in style-src ONLY
                $script:CspStyleOnly = ConvertTo-TcpkCspModel `
                    "default-src 'none'; script-src 'self'; style-src 'unsafe-inline'"
            }

            It "(KEY SCENARIO) unsafe-inline in style-src does NOT make script-src permissive" {
                $r = Test-TcpkCspDirectivePermissive -CspModel $script:CspStyleOnly -Directive 'script-src'
                $r.Permissive       | Should -Be $false
                $r.PermissiveTokens | Should -BeNullOrEmpty
                $r.ResolvedFrom     | Should -Be 'script-src'
            }

            It "(TP control) style-src IS permissive when asked about style-src" {
                $r = Test-TcpkCspDirectivePermissive -CspModel $script:CspStyleOnly -Directive 'style-src'
                $r.Permissive       | Should -Be $true
                $r.PermissiveTokens | Should -Contain "'unsafe-inline'"
            }

            It "(TP) default-src unsafe-inline DOES make script-src permissive via fallback" {
                $m = ConvertTo-TcpkCspModel "default-src 'unsafe-inline'"
                $r = Test-TcpkCspDirectivePermissive -CspModel $m -Directive 'script-src'
                $r.Permissive    | Should -Be $true
                $r.ResolvedFrom  | Should -Be 'default-src'
            }

            It "missing script-src and missing default-src -> no restriction -> permissive" {
                $m = ConvertTo-TcpkCspModel "style-src 'self'"
                $r = Test-TcpkCspDirectivePermissive -CspModel $m -Directive 'script-src'
                $r.Permissive   | Should -Be $true
                $r.ResolvedFrom | Should -Be '(none)'
                $r.Reason       | Should -Match 'No restriction'
            }

            It "unsafe-eval in script-src is flagged permissive" {
                $m = ConvertTo-TcpkCspModel "script-src 'self' 'unsafe-eval'"
                $r = Test-TcpkCspDirectivePermissive -CspModel $m -Directive 'script-src'
                $r.Permissive       | Should -Be $true
                $r.PermissiveTokens | Should -Contain "'unsafe-eval'"
            }
        }

        # -----------------------------------------------------------------------
        # W3C fallback chain correctness
        # -----------------------------------------------------------------------

        Describe 'Test-TcpkCspDirectivePermissive - W3C fallback chain' {

            It 'script-src-elem falls back to script-src then default-src' {
                $m = ConvertTo-TcpkCspModel "default-src 'none'; script-src 'self'"
                # script-src-elem not present -> falls back to script-src 'self' -> restrictive
                $r = Test-TcpkCspDirectivePermissive -CspModel $m -Directive 'script-src-elem'
                $r.Permissive   | Should -Be $false
                $r.ResolvedFrom | Should -Be 'script-src'
            }

            It 'form-action does NOT fall back to default-src' {
                # default-src 'unsafe-inline' should NOT make form-action permissive
                $m = ConvertTo-TcpkCspModel "default-src 'unsafe-inline'"
                $r = Test-TcpkCspDirectivePermissive -CspModel $m -Directive 'form-action'
                # form-action has no fallback; missing form-action -> NoRestriction = true
                # (no form-action + no fallback = unrestricted)
                $r.ResolvedFrom | Should -Be '(none)'
                # The token is not propagated from default-src for form-action
                $r.PermissiveTokens | Should -BeNullOrEmpty
            }

            It 'worker-src falls back to child-src then default-src' {
                $m = ConvertTo-TcpkCspModel "default-src 'none'; child-src 'self' blob:"
                $r = Test-TcpkCspDirectivePermissive -CspModel $m -Directive 'worker-src'
                # worker-src missing -> falls back to child-src
                $r.ResolvedFrom | Should -Be 'child-src'
                # child-src 'self' blob: - 'self' is not permissive; blob: is not in the permissive list
                $r.Permissive | Should -Be $false
            }
        }

        # -----------------------------------------------------------------------
        # Test-TcpkCspScriptExecutionPermissive
        # -----------------------------------------------------------------------

        Describe 'Test-TcpkCspScriptExecutionPermissive' {

            It '(TP) default-src unsafe-eval -> script execution is permissive' {
                $m = ConvertTo-TcpkCspModel "default-src 'self' 'unsafe-eval'"
                $r = Test-TcpkCspScriptExecutionPermissive -CspModel $m
                $r.Permissive    | Should -Be $true
                $r.WeakDirective | Should -Be 'script-src'
                $r.ResolvedFrom  | Should -Be 'default-src'
            }

            It '(FP guard) unsafe-inline in style-src only -> script execution is NOT permissive' {
                $m = ConvertTo-TcpkCspModel "default-src 'none'; script-src 'self'; style-src 'unsafe-inline'"
                $r = Test-TcpkCspScriptExecutionPermissive -CspModel $m
                $r.Permissive | Should -Be $false
                # A correct verdict reached by wrong reasoning must fail.
                # The function must NOT report WeakDirective='style-src' or 'img-src' etc.
                $r.WeakDirective | Should -BeNullOrEmpty
            }

            It 'script-src with wildcard -> permissive' {
                $m = ConvertTo-TcpkCspModel "script-src * 'unsafe-inline'"
                $r = Test-TcpkCspScriptExecutionPermissive -CspModel $m
                $r.Permissive    | Should -Be $true
                $r.WeakDirective | Should -Be 'script-src'
            }

            It 'fully restrictive CSP -> not permissive' {
                $m = ConvertTo-TcpkCspModel "default-src 'none'; script-src 'self' 'nonce-abc123'; style-src 'self'"
                $r = Test-TcpkCspScriptExecutionPermissive -CspModel $m
                $r.Permissive | Should -Be $false
            }
        }
    }
}
