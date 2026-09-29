#requires -Version 5.1
#
# Pester 5: Get-TcpkComSdLowPrivAces, the trustee test behind the AppID and machine-default
# COM permission rules.
#
# WHY THIS EXISTS. Test-TcpkComPrivilegeEscalation used to ask only "is LaunchPermission
# ABSENT". An AppID that set one and opened it to Everyone produced no finding, while the
# safer case of leaving it unset did. AccessPermission was read from the registry at line
# 140 and never looked at again. So the check was backwards on the deliberate case and
# blind on half the surface.
#
# The descriptors are BINARY self-relative security descriptors, not SDDL text, which is
# why they cannot go through Get-TcpkSddlLowPrivGrants and need their own converter. These
# tests build real RawSecurityDescriptors so the round trip through GetSddlForm is
# exercised rather than assumed.
#
# Trustees are matched by SDDL alias AND raw SID because GetSddlForm emits an alias for
# well-known accounts and a raw SID for everything else. A test for each form is the point.

BeforeAll {
    Import-Module (Join-Path (Split-Path (Split-Path $PSCommandPath -Parent) -Parent) 'TCPK.psd1') -Force

    # Build a binary COM security descriptor granting $Sid the given access mask.
    function New-ComSd([string]$Sid, [int]$Mask = 0x0B, [string]$AceType = 'A') {
        $sddl = "O:BAG:BAD:($AceType;;0x{0:x};;;{1})" -f $Mask, $Sid
        $sd = New-Object System.Security.AccessControl.RawSecurityDescriptor($sddl)
        $b = New-Object byte[] $sd.BinaryLength
        $sd.GetBinaryForm($b, 0)
        return $b
    }
    function Grade($Binary) {
        return & (Get-Module TCPK) { param($b) Get-TcpkComSdLowPrivAces -Binary $b } $Binary
    }
}

Describe 'Get-TcpkComSdLowPrivAces' {

    It 'flags Everyone (alias WD)' {
        $r = Grade (New-ComSd 'WD')
        $r.Ok | Should -BeTrue
        @($r.BadAces).Count | Should -BeGreaterThan 0
    }

    It 'flags Authenticated Users (alias AU)' {
        @((Grade (New-ComSd 'AU')).BadAces).Count | Should -BeGreaterThan 0
    }

    It 'flags Users (alias BU)' {
        @((Grade (New-ComSd 'BU')).BadAces).Count | Should -BeGreaterThan 0
    }

    It 'flags a raw SID that GetSddlForm does not alias' {
        # S-1-5-7 is ANONYMOUS. Whether it renders as AN or as the raw SID depends on the
        # platform, so the rule has to accept both spellings; this is the case a
        # alias-only matcher silently misses.
        @((Grade (New-ComSd 'S-1-5-7')).BadAces).Count | Should -BeGreaterThan 0
    }

    It 'does NOT flag an admin-only descriptor' {
        # BA = BUILTIN\Administrators. The correct configuration must stay silent or the
        # rule is worthless.
        @((Grade (New-ComSd 'BA')).BadAces).Count | Should -Be 0
    }

    It 'does NOT flag SYSTEM' {
        @((Grade (New-ComSd 'SY')).BadAces).Count | Should -Be 0
    }

    It 'ignores DENY aces for a broad principal' {
        # A deny for Everyone is the opposite of the bug. Counting it would invert the rule.
        $r = Grade (New-ComSd 'WD' 0x0B 'D')
        $r.Ok | Should -BeTrue
        @($r.BadAces).Count | Should -Be 0
    }

    It 'reports Ok=false for a descriptor it cannot parse, never a clean pass' {
        # An unreadable descriptor must be surfaced as unknown. Returning "no bad ACEs"
        # would report a permissive AppID as safe.
        $r = Grade ([byte[]]@(1,2,3))
        $r.Ok | Should -BeFalse
        @($r.BadAces).Count | Should -Be 0
    }

    It 'reports Ok=false for a null descriptor' {
        (Grade $null).Ok | Should -BeFalse
    }

    It 'returns the SDDL so the finding can quote what it saw' {
        (Grade (New-ComSd 'WD')).Sddl | Should -Match 'D:'
    }
}

Describe 'AppID permission rules are wired' {

    It 'maps the weak-permission rules to a local-privesc CVSS archetype' {
        # Falling through to the generic hardening archetype would score a privilege
        # escalation with the wrong vector.
        $src = [IO.File]::ReadAllText((Join-Path (Split-Path (Split-Path $PSCommandPath -Parent) -Parent) 'Private\_Finding.ps1'))
        $src | Should -Match "com\\\.appid\\\.\(launch-perm-weak\|access-perm-weak\|auto-elevation\)"
    }

    It 'grades both descriptors, not only LaunchPermission' {
        $src = [IO.File]::ReadAllText((Join-Path (Split-Path (Split-Path $PSCommandPath -Parent) -Parent) 'Public\OsIntegration\Test-TcpkComPrivilegeEscalation.ps1'))
        $src | Should -Match 'com\.appid\.launch-perm-weak'
        $src | Should -Match 'com\.appid\.access-perm-weak'
        $src | Should -Match 'com\.appid\.no-access-perm'
    }

    It 'uses the shared helper in both COM permission checks, not two copies' {
        $root = Split-Path (Split-Path $PSCommandPath -Parent) -Parent
        foreach ($f in @('Public\OsIntegration\Test-TcpkComPrivilegeEscalation.ps1',
                         'Public\OsIntegration\Test-TcpkComMachineDefaults.ps1')) {
            [IO.File]::ReadAllText((Join-Path $root $f)) |
                Should -Match 'Get-TcpkComSdLowPrivAces' -Because "$f should share the trustee test"
        }
    }
}

Describe 'Low-privilege principal set covers AppContainers' {

    # TCPK audits MSIX targets. For a packaged application the principal on the other side
    # of the boundary IS the AppContainer, so a directory any sandboxed package can write
    # has to grade as low-privilege writable. Before this, every ACL check in the tool
    # returned clean on exactly that case.

    It 'includes the two catch-all package SIDs' {
        $sids = & (Get-Module TCPK) { $script:TcpkLowPrivSids }
        $sids | Should -Contain 'S-1-15-2-1'   # ALL APPLICATION PACKAGES
        $sids | Should -Contain 'S-1-15-2-2'   # ALL RESTRICTED APPLICATION PACKAGES
    }

    It 'still includes the classic low-priv SIDs' {
        $sids = & (Get-Module TCPK) { $script:TcpkLowPrivSids }
        foreach ($s in 'S-1-1-0','S-1-5-11','S-1-5-32-545','S-1-5-4','S-1-5-7','S-1-5-32-546') {
            $sids | Should -Contain $s
        }
    }

    It 'grades a write grant to ALL APPLICATION PACKAGES as low-priv' {
        $grants = & (Get-Module TCPK) {
            Get-TcpkSddlLowPrivGrants -Sddl 'O:BAG:BAD:(A;;0x2;;;S-1-15-2-1)' `
                -RightsMap ([ordered]@{ 'WriteData/AddFile' = 0x2 })
        }
        @($grants).Count | Should -BeGreaterThan 0
    }

    It 'does NOT grade a per-package SID, which identifies one package not a boundary' {
        $perPkg = 'S-1-15-2-1861897761-1695161497-2927542615-642690995-327840285-2659745135-2630312742'
        $grants = & (Get-Module TCPK) { param($s)
            Get-TcpkSddlLowPrivGrants -Sddl "O:BAG:BAD:(A;;0x2;;;$s)" `
                -RightsMap ([ordered]@{ 'WriteData/AddFile' = 0x2 })
        } $perPkg
        @($grants).Count | Should -Be 0
    }

    It 'has exactly one low-priv SID literal in the codebase' {
        # Test-TcpkProcessDacl carried a byte-identical copy, so extending the shared list
        # left process.dacl-injectable grading by the old set.
        $root = Split-Path (Split-Path $PSCommandPath -Parent) -Parent
        $dupes = @(Get-ChildItem -LiteralPath $root -Recurse -File -Filter '*.ps1' |
            Where-Object { $_.FullName -notmatch '\\Tests\\' } |
            Where-Object { [IO.File]::ReadAllText($_.FullName) -match "'S-1-5-32-545'\s*,\s*'S-1-5-4'" } |
            ForEach-Object { $_.Name })
        $dupes -join ', ' | Should -Be '_ObjSecurity.ps1'
    }
}
