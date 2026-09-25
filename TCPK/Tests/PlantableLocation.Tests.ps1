#requires -Version 5.1
# Pester 5: Get-TcpkPlantGrants / Resolve-TcpkComServerImage (Private\_ObjSecurity.ps1).
#
# These two back the dangling-COM-registration rule in Test-TcpkComHijack
# (comhijack.server-missing-plantable). That rule reads HKLM, which a test cannot write
# without elevation, so the cmdlet end to end is not fixturable here. The security
# reasoning is, and it all lives in these two helpers, so that is what is pinned.
#
# WHAT MATTERS AND WHY EACH CASE IS HERE.
#
# Get-TcpkPlantGrants answers "can a low-privilege principal put a file at this path",
# for a path that may not exist yet. Which right is the primitive depends on that:
#
#   leaf directory EXISTS   -> FILE_ADD_FILE (WriteData, 0x2)
#   leaf directory MISSING  -> FILE_ADD_SUBDIRECTORY (AppendData, 0x4) on the nearest
#                              existing ancestor; creating it makes the attacker owner
#
# The split is load-bearing, not cosmetic. Test-TcpkRegistryLoadPoints excludes
# AppendData on purpose, because every drive root grants it to BUILTIN\Users and there
# the DLL already exists and has to be REPLACED. Counting it on the leaf-exists branch
# would reproduce exactly that false positive, so there is a test for it.
#
# ACLs are made deterministic rather than trusted: every fixture directory gets a
# PROTECTED DACL, so results do not depend on how %TEMP% happens to be secured.
#
# Windows-only. Get-Acl, SIDs and backslash path semantics do not exist on Linux, and
# the file-level BeforeAll must stay safe there.

BeforeDiscovery {
    $script:isWin = ($env:OS -eq 'Windows_NT')
}

BeforeAll {
    Import-Module (Join-Path (Split-Path $PSScriptRoot -Parent) 'TCPK.psd1') -Force
    $script:win = ($env:OS -eq 'Windows_NT')

    $script:tmpRoot = Join-Path ([IO.Path]::GetTempPath()) ("tcpk-plant-" + [guid]::NewGuid().ToString('N').Substring(0, 8))
    if ($script:win) { New-Item -ItemType Directory -Path $script:tmpRoot -Force | Out-Null }

    function New-FixtureDir {
        $d = Join-Path $script:tmpRoot ([guid]::NewGuid().ToString('N').Substring(0, 8))
        New-Item -ItemType Directory -Path $d -Force | Out-Null
        return $d
    }

    # Protected DACL: current user FullControl, plus BUILTIN\Users with exactly $Rights.
    # $Propagation 'InheritOnly' produces the ACE that must NOT count as an effective
    # grant on the directory itself.
    function Set-UsersRight([string]$DirPath, [string]$Rights, [string]$Propagation = 'None') {
        $acl = Get-Acl -LiteralPath $DirPath
        $acl.SetAccessRuleProtection($true, $false)
        foreach ($r in @($acl.Access)) { $acl.RemoveAccessRuleSpecific($r) }
        $me = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
        $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
            $me, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')))
        $sid = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-545')
        $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
            $sid, $Rights, 'ContainerInherit,ObjectInherit', $Propagation, 'Allow')))
        Set-Acl -LiteralPath $DirPath -AclObject $acl
    }

    function Set-OwnerOnly([string]$DirPath) {
        $acl = Get-Acl -LiteralPath $DirPath
        $acl.SetAccessRuleProtection($true, $false)
        foreach ($r in @($acl.Access)) { $acl.RemoveAccessRuleSpecific($r) }
        $me = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
        $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
            $me, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')))
        Set-Acl -LiteralPath $DirPath -AclObject $acl
    }

    function Add-UsersDeny([string]$DirPath, [string]$Rights) {
        $acl = Get-Acl -LiteralPath $DirPath
        $sid = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-545')
        $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
            $sid, $Rights, 'ContainerInherit,ObjectInherit', 'None', 'Deny')))
        Set-Acl -LiteralPath $DirPath -AclObject $acl
    }

    function Invoke-PlantGrants([string]$P) {
        return & (Get-Module TCPK) { param($x) Get-TcpkPlantGrants -Path $x } $P
    }
    function Invoke-ResolveImage([string]$V) {
        return & (Get-Module TCPK) { param($x) Resolve-TcpkComServerImage -Value $x } $V
    }
}

AfterAll {
    if ($script:tmpRoot -and (Test-Path -LiteralPath $script:tmpRoot)) {
        Remove-Item -LiteralPath $script:tmpRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
}

Describe 'Get-TcpkPlantGrants -- which right is the planting primitive' -Skip:(-not $script:isWin) {

    It 'reports AddFile when the leaf directory exists and Users can create files there' {
        $d = New-FixtureDir
        Set-UsersRight $d 'CreateFiles'
        $r = Invoke-PlantGrants (Join-Path $d 'absent.dll')
        $r.Ok     | Should -BeTrue
        $r.Needed | Should -Be 'WriteData/AddFile'
        $r.Anchor | Should -Be $d
        @($r.Grants).Count | Should -BeGreaterThan 0
    }

    It 'reports nothing when the leaf directory exists but only the owner can write it' {
        $d = New-FixtureDir
        Set-OwnerOnly $d
        $r = Invoke-PlantGrants (Join-Path $d 'absent.dll')
        $r.Ok | Should -BeTrue
        @($r.Grants).Count | Should -Be 0
    }

    It 'walks up to the nearest existing ancestor and needs AddSubdirectory there' {
        # The shape of the bug this rule exists for: the vendor directory named by the
        # registration was never created, and the ancestor lets a standard user create it.
        $d = New-FixtureDir
        Set-UsersRight $d 'CreateDirectories'
        $r = Invoke-PlantGrants (Join-Path $d 'NeverCreated\nested\server.dll')
        $r.Ok     | Should -BeTrue
        $r.Needed | Should -Be 'AppendData/AddSubdirectory'
        $r.Anchor | Should -Be $d
        @($r.Grants).Count | Should -BeGreaterThan 0
    }

    It 'does NOT accept AddSubdirectory when the leaf directory already exists' {
        # This is the Test-TcpkRegistryLoadPoints false positive, and the reason the two
        # rules disagree about AppendData without contradicting each other: creating a
        # subdirectory cannot put a file into a directory that is already there.
        $d = New-FixtureDir
        Set-UsersRight $d 'CreateDirectories'
        $r = Invoke-PlantGrants (Join-Path $d 'absent.dll')
        $r.Needed | Should -Be 'WriteData/AddFile'
        @($r.Grants).Count | Should -Be 0
    }

    It 'ignores an INHERIT-ONLY grant, which does not apply to the directory itself' {
        # C:\ProgramData ships both an InheritOnly ACE for Users and a separate effective
        # one. Counting the InheritOnly ACE would report a primitive the OS will refuse.
        $d = New-FixtureDir
        Set-UsersRight $d 'CreateFiles' 'InheritOnly'
        $r = Invoke-PlantGrants (Join-Path $d 'absent.dll')
        $r.Ok | Should -BeTrue
        @($r.Grants).Count | Should -Be 0
    }

    It 'lets an explicit DENY override the allow for the same principal' {
        $d = New-FixtureDir
        Set-UsersRight $d 'CreateFiles'
        Add-UsersDeny  $d 'CreateFiles'
        $r = Invoke-PlantGrants (Join-Path $d 'absent.dll')
        @($r.Grants).Count | Should -Be 0
    }

    It 'ignores a DENY that does not cover the right doing the planting' {
        # The mirror of the case above. A deny of something irrelevant must not suppress
        # a real grant, or the check silently stops finding the bug it exists for.
        $d = New-FixtureDir
        Set-UsersRight $d 'CreateFiles'
        Add-UsersDeny  $d 'WriteAttributes'
        $r = Invoke-PlantGrants (Join-Path $d 'absent.dll')
        @($r.Grants).Count | Should -BeGreaterThan 0
    }

    It 'returns no grants for a value with no directory part' {
        $r = Invoke-PlantGrants 'server.dll'
        @($r.Grants).Count | Should -Be 0
    }

    It 'does not throw on a path whose whole chain is absent' {
        { Invoke-PlantGrants 'Q:\no\such\place\x.dll' } | Should -Not -Throw
    }
}

Describe 'Resolve-TcpkComServerImage -- parsing a registry server value' -Skip:(-not $script:isWin) {

    It 'prefers the quoted span over an argument-stripped reading' {
        $d = New-FixtureDir
        $exe = Join-Path $d 'my srv.exe'
        Set-Content -LiteralPath $exe -Value 'x' -Encoding ASCII
        $r = Invoke-ResolveImage ('"' + $exe + '" -Embedding')
        $r.Exists | Should -BeTrue
        $r.Path   | Should -Be $exe
    }

    It 'does not mangle an unquoted path that contains a space and a hyphen' {
        # The old single-regex strip cut at the first " -" and turned a real path into a
        # missing one, which this rule would have reported as a dangling registration.
        $d = New-FixtureDir
        $sub = Join-Path $d 'My App -X'
        New-Item -ItemType Directory -Path $sub -Force | Out-Null
        $dll = Join-Path $sub 'srv.dll'
        Set-Content -LiteralPath $dll -Value 'x' -Encoding ASCII
        $r = Invoke-ResolveImage $dll
        $r.Exists | Should -BeTrue
        $r.Path   | Should -Be $dll
    }

    It 'expands environment variables in the value' {
        $r = Invoke-ResolveImage '%SystemRoot%\System32\ole32.dll'
        $r.Exists | Should -BeTrue
        $r.Path   | Should -Match 'System32'
    }

    It 'reports a genuinely absent path as not existing, keeping the expanded form' {
        $r = Invoke-ResolveImage '%ProgramData%\TcpkNoSuchVendor\TcpkNoSuchServer.dll'
        $r.Exists | Should -BeFalse
        $r.Path   | Should -Not -Match '%'
    }

    It 'drops a value containing an invalid path character instead of throwing' {
        { Invoke-ResolveImage "C:\bad`0path\x.dll" } | Should -Not -Throw
    }

    It 'returns null for an empty value' {
        Invoke-ResolveImage '' | Should -BeNullOrEmpty
    }
}
