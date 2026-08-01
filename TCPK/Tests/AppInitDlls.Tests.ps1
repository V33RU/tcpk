#requires -Version 5.1
# Pester 5: Test-TcpkAppInitDlls (C25).
#
# What can and cannot be tested here, stated plainly:
#   * Populating AppInit_DLLs or AppCertDlls requires administrative rights and would
#     modify the machine under test. TCPK checks are read-only, so this suite NEVER
#     writes those keys. The end-to-end Windows tests therefore assert the invariants
#     that hold on any machine (read-only behaviour, bounded rule-id set, never silent).
#   * The false-positive boundaries that actually matter -- the AppInit_DLLs list
#     parser, the rooted-path resolver, and the vendor-attribution predicate -- live in
#     module-scope helpers and are exercised directly with hostile inputs.

BeforeDiscovery {
    $script:isWin = ($env:OS -eq 'Windows_NT')
}

BeforeAll {
    Import-Module "$PSScriptRoot\..\TCPK.psd1" -Force

    # Module-scope helpers are reached with "& (Get-Module TCPK) { ... }", the pattern
    # the rest of this suite directory uses. Resolving the module inline rather than
    # caching it in a $script: variable keeps the calls independent of Pester's
    # BeforeAll/It variable scoping.
    $script:appInitKey = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows'
}

Describe 'Test-TcpkAppInitDlls surface' {
    It 'is exported' {
        Get-Command Test-TcpkAppInitDlls -Module TCPK -ErrorAction SilentlyContinue | Should -Not -BeNullOrEmpty
    }

    It 'takes -Path and -NameLike' {
        $cmd = Get-Command Test-TcpkAppInitDlls -Module TCPK
        $cmd.Parameters.Keys | Should -Contain 'Path'
        $cmd.Parameters.Keys | Should -Contain 'NameLike'
    }

    It 'does not leak its internal helpers into the public surface' {
        foreach ($h in @('Split-TcpkAppInitValue', 'Resolve-TcpkAppInitEntry', 'Test-TcpkAppInitVendorOwned')) {
            Get-Command $h -ErrorAction SilentlyContinue | Should -BeNullOrEmpty -Because "$h is an internal helper"
        }
    }

    It 'documents that the finding is machine state rather than an application defect' {
        # The docstring must not let a reader file environment state against a vendor.
        $help = Get-Help Test-TcpkAppInitDlls -Full | Out-String
        $help | Should -Match 'ENVIRONMENT STATE'
        $help | Should -Match 'VENDOR-REPORTABLE'
    }
}

Describe 'AppInit_DLLs list parsing (false-positive boundaries)' {
    It 'returns nothing for an empty or whitespace value' {
        @(& (Get-Module TCPK) { Split-TcpkAppInitValue -Raw '' }).Count | Should -Be 0
        @(& (Get-Module TCPK) { Split-TcpkAppInitValue -Raw '   ' }).Count | Should -Be 0
    }

    It 'does NOT split a single path that contains spaces' {
        # The FP that matters: "C:\Program Files\Vendor\hook.dll" split on whitespace
        # would produce two invented paths, and the ACL pass would then report on a
        # directory that has nothing to do with the entry.
        $r = @(& (Get-Module TCPK) { Split-TcpkAppInitValue -Raw 'C:\Program Files\Vendor\hook.dll' })
        $r.Count | Should -Be 1
        $r[0] | Should -Be 'C:\Program Files\Vendor\hook.dll'
    }

    It 'splits a genuine space-delimited list where every token is a dll' {
        $r = @(& (Get-Module TCPK) { Split-TcpkAppInitValue -Raw 'hookA.dll hookB.dll' })
        $r.Count | Should -Be 2
        $r[1] | Should -Be 'hookB.dll'
    }

    It 'splits on commas and keeps spaces inside each comma-delimited path' {
        $r = @(& (Get-Module TCPK) { Split-TcpkAppInitValue -Raw 'C:\a\x.dll,C:\Program Files\v\y.dll' })
        $r.Count | Should -Be 2
        $r[1] | Should -Be 'C:\Program Files\v\y.dll'
    }

    It 'collapses repeated whitespace instead of emitting empty entries' {
        $r = @(& (Get-Module TCPK) { Split-TcpkAppInitValue -Raw "a.dll`t  b.dll " })
        $r.Count | Should -Be 2
        $r | Should -Not -Contain ''
    }

    It 'strips surrounding quotes' {
        $r = @(& (Get-Module TCPK) { Split-TcpkAppInitValue -Raw '"C:\a\x.dll"' })
        $r[0] | Should -Be 'C:\a\x.dll'
    }

    It 'treats a mixed value with a non-dll token as one opaque entry' {
        # "C:\Program Files\a.dll extra" is ambiguous. Falling back to a single entry
        # is the reading that cannot fabricate a path to ACL-check.
        $r = @(& (Get-Module TCPK) { Split-TcpkAppInitValue -Raw 'C:\Program Files\a.dll extra' })
        $r.Count | Should -Be 1
    }
}

Describe 'AppInit entry resolution' {
    It 'refuses to guess a directory for an unrooted entry' {
        # A bare name is resolved by the loader search order at runtime. Returning ''
        # keeps the check from ACL-checking, and reporting on, the wrong file.
        & (Get-Module TCPK) { Resolve-TcpkAppInitEntry -Entry 'evil.dll' } | Should -Be ''
        & (Get-Module TCPK) { Resolve-TcpkAppInitEntry -Entry '' } | Should -Be ''
    }

    It 'returns a rooted entry unchanged' {
        # '/' is rooted on both Windows and Unix, so this assertion is portable.
        & (Get-Module TCPK) { Resolve-TcpkAppInitEntry -Entry '/tmp/hook.dll' } | Should -Be '/tmp/hook.dll'
    }

    It 'expands environment variables in a rooted entry' -Skip:(-not $script:isWin) {
        $r = & (Get-Module TCPK) { Resolve-TcpkAppInitEntry -Entry '%SystemRoot%\hook.dll' }
        $r | Should -Not -Match '%'
        $r | Should -Match '(?i)hook\.dll$'
    }
}

Describe 'Vendor attribution predicate' {
    It 'is false with no install directory and no name terms' {
        # Default must be "environment state", never "the vendor did this".
        & (Get-Module TCPK) { Test-TcpkAppInitVendorOwned -Resolved 'C:\Windows\System32\hook.dll' -Entry 'hook.dll' -AppDir '' -Terms @() } |
            Should -BeFalse
    }

    It 'is true for a DLL under the audited install directory' {
        & (Get-Module TCPK) { Test-TcpkAppInitVendorOwned -Resolved 'C:\App\bin\hook.dll' -Entry 'hook.dll' -AppDir 'C:\App' -Terms @() } |
            Should -BeTrue
    }

    It 'does not claim a sibling directory with a shared prefix' {
        # "C:\App" must not swallow "C:\AppMalware": that would attribute an attacker's
        # DLL to the audited vendor.
        & (Get-Module TCPK) { Test-TcpkAppInitVendorOwned -Resolved 'C:\AppMalware\hook.dll' -Entry 'hook.dll' -AppDir 'C:\App' -Terms @() } |
            Should -BeFalse
    }

    It 'tolerates a trailing separator on the install directory' {
        & (Get-Module TCPK) { Test-TcpkAppInitVendorOwned -Resolved 'C:\App\hook.dll' -Entry 'hook.dll' -AppDir 'C:\App\' -Terms @() } |
            Should -BeTrue
    }

    It 'ignores the wildcard sentinel in the term list' {
        # '*' is the "no filter" sentinel elsewhere in TCPK; treating it as a substring
        # would attribute every AppInit entry on the machine to the vendor.
        & (Get-Module TCPK) { Test-TcpkAppInitVendorOwned -Resolved 'C:\Windows\System32\hook.dll' -Entry 'hook.dll' -AppDir '' -Terms @('*') } |
            Should -BeFalse
    }

    It 'matches a supplied vendor term case-insensitively' {
        & (Get-Module TCPK) { Test-TcpkAppInitVendorOwned -Resolved 'C:\Windows\VENDORhook.dll' -Entry 'x' -AppDir '' -Terms @('vendorhook') } |
            Should -BeTrue
    }

    It 'matches a vendor term in the file name of a deep path' {
        & (Get-Module TCPK) { Test-TcpkAppInitVendorOwned -Resolved 'C:\Program Files\Other\vendorhook.dll' -Entry 'x' -AppDir '' -Terms @('vendorhook') } |
            Should -BeTrue
    }

    It 'does NOT attribute on a term that only matches a directory component' {
        # The FP that matters for the term half: a machine-wide hook dropped in a user
        # profile whose folder name happens to contain the vendor term would otherwise
        # be escalated to a HIGH vendor-reportable finding against a vendor who never
        # registered it. Directory-level attribution is -Path's job, and it is anchored.
        & (Get-Module TCPK) { Test-TcpkAppInitVendorOwned -Resolved 'C:\Users\acme\AppData\Local\Temp\hook.dll' -Entry 'hook.dll' -AppDir '' -Terms @('acme') } |
            Should -BeFalse
        & (Get-Module TCPK) { Test-TcpkAppInitVendorOwned -Resolved 'C:\Program Files\AcmeOther\evil.dll' -Entry 'evil.dll' -AppDir '' -Terms @('acme') } |
            Should -BeFalse
    }

    It 'still attributes a directory-component match when -Path anchors it' {
        # The narrowed term match must not cost a genuine attribution: the anchored
        # install-directory half still fires for the same path.
        & (Get-Module TCPK) { Test-TcpkAppInitVendorOwned -Resolved 'C:\Program Files\Acme\bin\hook.dll' -Entry 'hook.dll' -AppDir 'C:\Program Files\Acme' -Terms @('acme') } |
            Should -BeTrue
    }

    It 'falls back to the raw entry when the path could not be resolved' {
        & (Get-Module TCPK) { Test-TcpkAppInitVendorOwned -Resolved '' -Entry 'vendorhook.dll' -AppDir '' -Terms @('vendorhook') } |
            Should -BeTrue
    }

    It 'does not throw on an entry with characters that are illegal in a path' {
        # GetFileName would throw on these under .NET Framework; the predicate must
        # degrade to "not attributable" rather than take the whole check down.
        { & (Get-Module TCPK) { Test-TcpkAppInitVendorOwned -Resolved '' -Entry 'C:\a|b<c>\x.dll' -AppDir '' -Terms @('zzz') } } |
            Should -Not -Throw
    }
}

Describe 'Test-TcpkAppInitDlls off Windows' -Skip:($script:isWin) {
    It 'emits nothing and does not throw' {
        $f = @(Test-TcpkAppInitDlls -WarningAction SilentlyContinue)
        $f.Count | Should -Be 0
    }
}

Describe 'Test-TcpkAppInitDlls on Windows' -Skip:(-not $script:isWin) {
    BeforeAll {
        $script:findings = @(Test-TcpkAppInitDlls)
    }

    It 'runs without throwing' {
        { Test-TcpkAppInitDlls } | Should -Not -Throw
    }

    It 'is never silent: a clean machine still records that the check ran' {
        # Silence must never be mistaken for a clean result, so the check emits either
        # a configured finding, a clean finding, or a Skipped finding.
        $script:findings.Count | Should -BeGreaterThan 0
    }

    It 'emits only rule ids belonging to this check' {
        $allowed = @(
            'appinit.configured'
            'appinit.dll-writable'
            'appinit.app-registers-dll'
            'appcert.configured'
            'appinit.clean'
            'appinit.not-readable'
        )
        foreach ($f in $script:findings) { $allowed | Should -Contain $f.RuleId }
    }

    It 'files non-skipped findings under the os module' {
        foreach ($f in ($script:findings | Where-Object { $_.Confidence -ne 'Skipped' })) {
            $f.Module | Should -Be 'os'
        }
    }

    It 'gives every reported finding a description and a fix' {
        foreach ($f in ($script:findings | Where-Object { $_.Confidence -ne 'Skipped' })) {
            $f.Description | Should -Not -BeNullOrEmpty
            $f.Fix | Should -Not -BeNullOrEmpty
        }
    }

    It 'labels a clean result INFO' {
        foreach ($f in ($script:findings | Where-Object { $_.RuleId -eq 'appinit.clean' })) {
            $f.Severity | Should -Be 'INFO'
        }
    }

    It 'names the registry views a clean result actually covers' {
        # A clean result must not imply coverage of a view it could not open, so the
        # evidence always names the views that were read.
        foreach ($f in ($script:findings | Where-Object { $_.RuleId -eq 'appinit.clean' })) {
            $f.Evidence | Should -Match 'AppInit_DLLs empty in: \S'
            $f.Evidence | Should -Match 'view'
        }
    }

    It 'says machine state in the environment-state findings' {
        # Guard against the docstring/finding drift that would let an auditor file a
        # populated AppInit_DLLs as an application defect.
        foreach ($f in ($script:findings | Where-Object { $_.RuleId -eq 'appinit.configured' })) {
            $f.Description | Should -Match 'MACHINE STATE'
        }
    }

    It 'says machine state in an unattributed AppCertDlls finding' {
        # Same drift guard for the AppCert half. The fixture runs with no -Path and no
        # -NameLike, so nothing here can be vendor-attributed and every
        # appcert.configured finding must carry the environment-state wording.
        foreach ($f in ($script:findings | Where-Object { $_.RuleId -eq 'appcert.configured' })) {
            $f.Description | Should -Match 'MACHINE STATE'
        }
    }

    It 'bounds the evidence of a populated key' {
        # A hostile or corrupt REG_SZ can hold ~1 MB. Neither half may copy it whole
        # into a finding.
        foreach ($f in ($script:findings | Where-Object { $_.RuleId -in @('appinit.configured', 'appcert.configured') })) {
            $f.Title.Length   | Should -BeLessThan 400
            $f.Evidence.Length | Should -BeLessThan 4096
        }
    }

    It 'is read-only: the AppInit_DLLs value is unchanged' {
        $before = $null
        $after  = $null
        try { $before = (Get-ItemProperty -LiteralPath $script:appInitKey -ErrorAction Stop).AppInit_DLLs } catch { }
        Test-TcpkAppInitDlls | Out-Null
        try { $after = (Get-ItemProperty -LiteralPath $script:appInitKey -ErrorAction Stop).AppInit_DLLs } catch { }
        "$after" | Should -Be "$before"
    }

    It 'tolerates a -Path that does not exist' {
        $bogus = Join-Path ([System.IO.Path]::GetTempPath()) ('tcpk-appinit-' + [guid]::NewGuid().ToString('N'))
        { Test-TcpkAppInitDlls -Path $bogus } | Should -Not -Throw
    }

    It 'does not attribute machine-wide entries to an unrelated target' {
        # With a temp directory as the audited target, nothing on a normal machine can
        # be vendor-attributable, so the vendor-reportable rule must stay silent.
        $tmp = Join-Path ([System.IO.Path]::GetTempPath()) ('tcpk-appinit-' + [guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory -Path $tmp -Force | Out-Null
        try {
            $f = @(Test-TcpkAppInitDlls -Path $tmp | Where-Object { $_.RuleId -eq 'appinit.app-registers-dll' })
            $f.Count | Should -Be 0
        } finally { Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue }
    }
}
