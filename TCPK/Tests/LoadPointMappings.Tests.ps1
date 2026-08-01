#requires -Version 5.1
# Pester 5: mapping-table guard for the C24/C25/C26/E23/A46 load-point detectors.
#
# WHY THIS EXISTS. A rule ID reaches four independent lookup tables -- ATT&CK
# (_Attack.ps1 TcpkAttackMap), OWASP Desktop Top 10 (_Attack.ps1 TcpkOwaspDaMap),
# TASVS (_Tasvs.ps1) and the CVSS archetype (_Finding.ps1). Every one of them is a
# list of narrow alternation regexes, and a miss is SILENT: the finding still renders,
# just with no technique, no control and a default vector. That is worse than a crash,
# because the report looks complete. These tests turn each silent miss into a failure.
#
# They are pure table lookups -- no process, no registry, no filesystem -- so they run
# anywhere, including on a non-Windows host where the detectors themselves cannot.

BeforeAll {
    $psd1 = Join-Path (Split-Path (Split-Path $PSCommandPath -Parent) -Parent) 'TCPK.psd1'
    Import-Module $psd1 -Force

    # Every rule ID emitted by the five detectors. Kept as a literal list rather than
    # scraped from the sources: if a detector adds a rule ID, this list must be updated
    # deliberately, which is the point.
    $script:RuleIds = @(
        'servicedll.writable', 'servicedll.key-writable', 'servicedll.enumerated', 'servicedll.unreadable'
        'appinit.configured', 'appinit.dll-writable', 'appinit.app-registers-dll', 'appinit.clean', 'appinit.not-readable'
        'appcert.configured'
        'loadpoint.writable', 'loadpoint.app-registered', 'loadpoint.census'
        'jni.library-path-writable', 'jni.manifest-classpath-writable', 'jni.native-libs', 'jni.load-path-unevaluated'
        'thread.unbacked-start', 'thread.start-unreadable'
    )

    # Sub-rules that describe a real weakness, as opposed to coverage/census/skip records.
    # Only these are required to carry a privesc-flavoured CVSS archetype.
    $script:WeaknessIds = @(
        'servicedll.writable', 'servicedll.key-writable'
        'appinit.dll-writable', 'appinit.app-registers-dll'
        'loadpoint.writable', 'loadpoint.app-registered'
        'jni.library-path-writable', 'jni.manifest-classpath-writable'
    )
}

Describe 'Load-point rule IDs are registered in every mapping table' {

    It 'maps <_> to at least one ATT&CK technique' -ForEach $script:RuleIds {
        $t = @(Get-TcpkAttackTechnique -RuleId $_)
        $t.Count | Should -BeGreaterThan 0 -Because "$_ has no entry in TcpkAttackMap (_Attack.ps1)"
    }

    It 'maps <_> to an OWASP Desktop Top 10 category' -ForEach $script:RuleIds {
        (Get-TcpkOwaspDa -RuleId $_) | Should -Not -BeNullOrEmpty -Because "$_ has no entry in TcpkOwaspDaMap (_Attack.ps1)"
    }

    It 'maps <_> to at least one TASVS control' -ForEach $script:RuleIds {
        $c = @(Get-TcpkTasvsControl -RuleId $_)
        $c.Count | Should -BeGreaterThan 0 -Because "$_ has no entry in TcpkTasvsMap (_Tasvs.ps1)"
    }

    It 'resolves <_> to a CVSS archetype rather than the per-finding fallback' -ForEach $script:RuleIds {
        $hit = $false
        foreach ($m in $script:TcpkCvssRuleArchetype) { if ($_ -match $m.Rx) { $hit = $true; break } }
        $hit | Should -BeTrue -Because "$_ has no entry in TcpkCvssRuleArchetype (_Finding.ps1)"
    }
}

Describe 'Technique choices are specific, not just present' {

    It 'maps servicedll.key-writable to the service-registry technique' {
        (Get-TcpkAttackTechnique -RuleId 'servicedll.key-writable') -join ' ' | Should -Match 'T1574\.011'
    }

    It 'maps appinit.* to AppInit DLLs and appcert.* to AppCert DLLs' {
        (Get-TcpkAttackTechnique -RuleId 'appinit.dll-writable') -join ' ' | Should -Match 'T1546\.010'
        (Get-TcpkAttackTechnique -RuleId 'appcert.configured')   -join ' ' | Should -Match 'T1546\.009'
    }

    It 'maps thread.unbacked-start to the injection techniques, not only the generic T1068' {
        # '^(thread|token)\.' also matches and contributes T1068; the two are unioned.
        # What matters is that the specific entry is present as well.
        $t = (Get-TcpkAttackTechnique -RuleId 'thread.unbacked-start') -join ' '
        $t | Should -Match 'T1055'
        $t | Should -Match 'T1620'
    }
}

Describe 'Severity-bearing rules score as escalation, coverage records do not' {

    $archetypeOf = {
        param($id)
        foreach ($m in $script:TcpkCvssRuleArchetype) { if ($id -match $m.Rx) { return $m.A } }
        return ''
    }

    It 'scores <_> as local-privesc' -ForEach $script:WeaknessIds {
        (& $archetypeOf $_) | Should -Be 'local-privesc'
    }

    It 'does not score census or skip records as escalation' {
        foreach ($id in 'servicedll.enumerated', 'servicedll.unreadable', 'loadpoint.census', 'appinit.clean', 'appinit.not-readable') {
            (& $archetypeOf $id) | Should -Not -Be 'local-privesc' -Because "$id is a coverage record, not a weakness"
        }
    }
}

Describe 'Detectors are exported and wired into the audit runner' {

    $cmdlets = @(
        'Test-TcpkServiceDll', 'Test-TcpkAppInitDlls', 'Test-TcpkRegistryLoadPoints',
        'Test-TcpkJavaNativeLoad', 'Test-TcpkThreadStart'
    )

    It 'exports <_>' -ForEach $cmdlets {
        Get-Command $_ -ErrorAction SilentlyContinue | Should -Not -BeNullOrEmpty
    }

    It 'calls <_> from Invoke-TcpkAudit' -ForEach $cmdlets {
        $runner = Join-Path (Split-Path (Split-Path $PSCommandPath -Parent) -Parent) 'Public\Invoke-TcpkAudit.ps1'
        (Get-Content -LiteralPath $runner -Raw) | Should -Match ([regex]::Escape("_RunCheck '$_'"))
    }

    It 'documents <_> in CHECKS.md' -ForEach $cmdlets {
        $docs = Join-Path (Split-Path (Split-Path (Split-Path $PSCommandPath -Parent) -Parent) -Parent) 'docs\CHECKS.md'
        (Get-Content -LiteralPath $docs -Raw) | Should -Match ([regex]::Escape("**$_**"))
    }
}
