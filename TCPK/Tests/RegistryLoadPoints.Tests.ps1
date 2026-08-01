#requires -Version 5.1
# Pester 5: Test-TcpkRegistryLoadPoints (C26).
#
# The value of this detector is its ATTRIBUTION FILTER, so that is what these tests
# exercise. The fixture registers six real shell-extension load points under HKCU
# (keys the test creates and removes itself, no HKLM and no elevation): three whose
# DLL lives inside the audited tree, one whose DLL lives outside it, one whose
# registered value contains an invalid path character, and one that is a bare COM
# server name. The suite then asserts the in-tree ones become findings, the
# out-of-tree one becomes census only, neither unresolvable value produces a finding
# or kills the run, and the ACL layer does not manufacture a writable finding from an
# owner-only directory or from an INHERIT-ONLY ACE.
#
# ACLs are made deterministic rather than trusted: each fixture directory gets a
# PROTECTED DACL (inheritance from %TEMP% removed), so the result does not depend on
# how the machine's temp directory happens to be secured.
#
# Windows-only work is gated on $script:isWin; the file-level BeforeAll must stay safe
# on Linux, where the registry drives and Get-Acl semantics do not exist.

BeforeDiscovery {
    $script:isWin = ($env:OS -eq 'Windows_NT')
}

BeforeAll {
    Import-Module (Join-Path (Split-Path $PSScriptRoot -Parent) 'TCPK.psd1') -Force

    $script:win = ($env:OS -eq 'Windows_NT')

    $tmp = [System.IO.Path]::GetTempPath()
    $tag = [guid]::NewGuid().ToString('N').Substring(0, 8)
    $script:root     = Join-Path $tmp "tcpk-lp-$tag"
    $script:outside  = Join-Path $tmp "tcpk-lp-out-$tag"
    $script:cleanDir = Join-Path $script:root 'clean'
    $script:plantDir = Join-Path $script:root 'plant'
    $script:ioDir    = Join-Path $script:root 'inherit'
    foreach ($d in @($script:root, $script:outside, $script:cleanDir, $script:plantDir, $script:ioDir)) {
        New-Item -ItemType Directory -Path $d -Force | Out-Null
    }

    $script:cleanDll = Join-Path $script:cleanDir 'clean.dll'
    $script:plantDll = Join-Path $script:plantDir 'plant.dll'
    $script:ioDll    = Join-Path $script:ioDir   'inherit.dll'
    $script:outDll   = Join-Path $script:outside 'other.dll'
    foreach ($f in @($script:cleanDll, $script:plantDll, $script:ioDll, $script:outDll)) {
        Set-Content -LiteralPath $f -Encoding ASCII -Value 'MZ placeholder, never parsed by this check'
    }

    $script:regLeaves   = @()
    $script:regClsids   = @()
    $script:createdKeys = @()
    $script:res         = @()

    # Two registry values that must NOT resolve to a path. 'C:\bad|name.dll' contains a
    # character in [System.IO.Path]::GetInvalidPathChars(): on .NET Framework (PS 5.1)
    # Path::IsPathRooted THROWS on it, which used to abort the whole scan from inside the
    # resolver. 'evil.dll' is a bare name under a COM family, where the check must leave
    # it unresolved instead of guessing System32.
    $script:badCharValue = 'C:\bad|name.dll'
    $script:bareComValue = 'evil.dll'

    if ($script:win) {
        # Protected DACL: current user always FullControl, optionally BUILTIN\Users
        # (S-1-5-32-545) either effectively or INHERIT-ONLY. Inheritance is switched off
        # so nothing leaks in from %TEMP%.
        function _SetFixtureAcl {
            param(
                [Parameter(Mandatory)][string]$TargetPath,
                [switch]$UsersModify,
                [switch]$UsersInheritOnly
            )
            $isDir = Test-Path -LiteralPath $TargetPath -PathType Container
            $acl = Get-Acl -LiteralPath $TargetPath
            $acl.SetAccessRuleProtection($true, $false)
            $me = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
            if ($isDir) {
                $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
                    $me, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')))
            } else {
                $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
                    $me, 'FullControl', 'Allow')))
            }
            $users = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-545')
            if ($UsersModify) {
                $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
                    $users, 'Modify', 'ContainerInherit,ObjectInherit', 'None', 'Allow')))
            }
            if ($UsersInheritOnly) {
                $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
                    $users, 'Modify', 'ContainerInherit,ObjectInherit', 'InheritOnly', 'Allow')))
            }
            Set-Acl -LiteralPath $TargetPath -AclObject $acl
        }

        # Record which shellex ancestor keys did NOT exist before the suite ran, so
        # AfterAll can remove exactly what it created and nothing else. Leaving an empty
        # HKCU\...\Directory\shellex\ContextMenuHandlers behind on a developer machine is
        # test pollution, and blind-deleting it would destroy a real registration.
        $script:shellexChain = @(
            'HKCU:\SOFTWARE\Classes\Directory\shellex\ContextMenuHandlers'
            'HKCU:\SOFTWARE\Classes\Directory\shellex'
            'HKCU:\SOFTWARE\Classes\Directory'
        )
        foreach ($ck in $script:shellexChain) {
            if (-not (Test-Path -LiteralPath $ck)) { $script:createdKeys += $ck }
        }

        # Register one shell context-menu handler for a raw InprocServer32 value. The
        # handler key's default value is the CLSID; the CLSID's InprocServer32 default
        # value is the DLL reference -- exactly the two-hop resolution the detector
        # performs. -Dll takes the raw string, not necessarily a real path, so the
        # unresolvable cases can be fixtured too.
        function _RegisterHandler {
            param([Parameter(Mandatory)][string]$Dll)
            $clsid = '{' + [guid]::NewGuid().ToString() + '}'
            $leaf  = 'TcpkLoadPointTest_' + [guid]::NewGuid().ToString('N').Substring(0, 8)
            $ip = "HKCU:\SOFTWARE\Classes\CLSID\$clsid\InprocServer32"
            New-Item -Path $ip -Force | Out-Null
            Set-ItemProperty -Path $ip -Name '(Default)' -Value $Dll
            $hk = "HKCU:\SOFTWARE\Classes\Directory\shellex\ContextMenuHandlers\$leaf"
            New-Item -Path $hk -Force | Out-Null
            Set-ItemProperty -Path $hk -Name '(Default)' -Value $clsid
            $script:regClsids += $clsid
            $script:regLeaves += $hk
        }

        # Directory ACLs first, then the file ACLs: setting a directory DACL propagates
        # inheritable ACEs to existing children, so the files are protected afterwards to
        # keep each case isolated to the property under test.
        _SetFixtureAcl -TargetPath $script:cleanDir
        _SetFixtureAcl -TargetPath $script:plantDir -UsersModify
        _SetFixtureAcl -TargetPath $script:ioDir -UsersInheritOnly
        foreach ($f in @($script:cleanDll, $script:plantDll, $script:ioDll)) {
            _SetFixtureAcl -TargetPath $f
        }

        _RegisterHandler -Dll $script:cleanDll
        _RegisterHandler -Dll $script:plantDll
        _RegisterHandler -Dll $script:ioDll
        _RegisterHandler -Dll $script:outDll
        _RegisterHandler -Dll $script:badCharValue
        _RegisterHandler -Dll $script:bareComValue

        $script:res = @(Test-TcpkRegistryLoadPoints -Path $script:root -WarningAction SilentlyContinue)
    }
}

AfterAll {
    if ($script:regLeaves) {
        foreach ($hk in $script:regLeaves) {
            Remove-Item -LiteralPath $hk -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
    if ($script:regClsids) {
        foreach ($c in $script:regClsids) {
            Remove-Item -LiteralPath "HKCU:\SOFTWARE\Classes\CLSID\$c" -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
    # Only the ancestor keys this suite had to create, deepest first, and only while they
    # are still empty. A key that existed beforehand, or that something else populated, is
    # left alone.
    if ($script:createdKeys) {
        foreach ($ck in $script:createdKeys) {
            if (-not (Test-Path -LiteralPath $ck)) { continue }
            $k = Get-Item -LiteralPath $ck -ErrorAction SilentlyContinue
            if (-not $k) { continue }
            if ($k.SubKeyCount -eq 0 -and $k.ValueCount -eq 0) {
                Remove-Item -LiteralPath $ck -Force -ErrorAction SilentlyContinue
            }
        }
    }
    foreach ($d in @($script:root, $script:outside)) {
        if ($d -and (Test-Path -LiteralPath $d)) {
            Remove-Item -LiteralPath $d -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

Describe 'Test-TcpkRegistryLoadPoints - attribution filter' -Skip:(-not $script:isWin) {

    It 'reports exactly the load points whose DLL is inside the audited tree' {
        $app = @($script:res | Where-Object { $_.RuleId -eq 'loadpoint.app-registered' -and $_.Confidence -eq 'Confirmed' })
        $app.Count | Should -Be 3
        foreach ($f in $app) {
            "$($f.File)".ToLowerInvariant().StartsWith($script:root.ToLowerInvariant()) | Should -BeTrue
        }
    }

    It 'does not raise a finding for a load point registered outside the tree' {
        # The whole point of the filter: this registration exists and is enumerated, but
        # it is not the audited vendor's to fix, so it must not become a finding.
        @($script:res | Where-Object { "$($_.File)" -eq $script:outDll }).Count | Should -Be 0
    }

    It 'counts every enumerated load point in a single census line instead' {
        $c = @($script:res | Where-Object { $_.RuleId -eq 'loadpoint.census' -and $_.Confidence -eq 'Confirmed' })
        $c.Count | Should -Be 1
        $c[0].Severity | Should -Be 'INFO'
        $c[0].Evidence | Should -Match 'shell-context-menu entries='
        $c[0].Evidence | Should -Match 'out-of-tree=[1-9]'
        $c[0].Evidence | Should -Match 'attribution-enabled=True'
        # entries- vs processed-: the exact enumeration count must be reported separately
        # from the count that -MaxKeys truncates, and a cap must be named, never implied
        # by a smaller number.
        $c[0].Evidence | Should -Match 'entries-total=\d+'
        $c[0].Evidence | Should -Match 'processed-total=\d+'
        $c[0].Evidence | Should -Match 'capped-families=none'
    }

    It 'does not truncate findings at the default -MaxKeys and says so by staying silent' {
        # The truncation notice is the honest half of the cap. With 3 in-tree load points
        # and a cap of 300 it must not fire; if it ever does, the cap accounting is wrong.
        @($script:res | Where-Object {
            $_.RuleId -eq 'loadpoint.app-registered' -and $_.Confidence -eq 'Skipped'
        }).Count | Should -Be 0
    }

    It 'survives a registered value containing an invalid path character' {
        # 'C:\bad|name.dll' makes Path::IsPathRooted throw on .NET Framework. That throw
        # came from inside the resolver and killed the whole cmdlet, so the real assertion
        # is that the run above produced results at all and still found exactly the three
        # in-tree load points.
        $script:res.Count | Should -BeGreaterThan 0
        @($script:res | Where-Object { "$($_.File)" -match '\|' }).Count | Should -Be 0
    }

    It 'leaves a bare COM server name unresolved instead of guessing System32' {
        # System32 resolution is the documented convention for print and netsh families
        # only. Guessing it for a COM server would put a path in the evidence that the
        # registry never contained.
        $guessed = Join-Path (Join-Path $env:SystemRoot 'System32') $script:bareComValue
        @($script:res | Where-Object { "$($_.File)" -eq $guessed }).Count | Should -Be 0
    }

    It 'names the resolved DLL and the host process in the evidence' {
        $f = @($script:res | Where-Object { $_.RuleId -eq 'loadpoint.app-registered' -and "$($_.File)" -eq $script:cleanDll })
        $f.Count | Should -Be 1
        $f[0].Evidence | Should -Match 'ContextMenuHandlers'
        $f[0].Evidence | Should -Match 'explorer\.exe'
        # A shell extension loads into explorer as the logged-on user, not SYSTEM.
        $f[0].Severity | Should -Be 'LOW'
    }
}

Describe 'Test-TcpkRegistryLoadPoints - ACL false-positive boundaries' -Skip:(-not $script:isWin) {

    It 'flags an app-registered load point whose directory grants BUILTIN\Users write' {
        $w = @($script:res | Where-Object { $_.RuleId -eq 'loadpoint.writable' -and "$($_.File)" -eq $script:plantDll })
        $w.Count | Should -Be 1
        $w[0].Severity | Should -Be 'HIGH'
        $w[0].Evidence | Should -Match 'S-1-5-32-545'
        # The grant is on the DIRECTORY, not on the file: the file got a protected
        # owner-only DACL. Evidence that blurred the two would misdescribe the fix.
        $w[0].Evidence | Should -Match 'file-grants=\[\]'
        $w[0].Evidence | Should -Not -Match 'dir-grants=\[\]'
    }

    It 'raises exactly one writable finding for the whole fixture tree' {
        # Locks the ACL layer down in both directions at once: it fires for the one
        # deliberately weak directory and for nothing else, so a future loosening of the
        # rights map or of the inherit-only filter shows up here.
        @($script:res | Where-Object { $_.RuleId -eq 'loadpoint.writable' }).Count | Should -Be 1
    }

    It 'does not flag a load point whose DLL and directory are owner-only' {
        @($script:res | Where-Object { $_.RuleId -eq 'loadpoint.writable' -and "$($_.File)" -eq $script:cleanDll }).Count | Should -Be 0
    }

    It 'does not treat an INHERIT-ONLY ACE on the directory as a writable directory' {
        # An inherit-only ACE applies to children created later, not to the object it sits
        # on. Reporting it would be a false positive, and the SDDL alone cannot tell the
        # difference -- the detector cross-checks the propagation flags.
        @($script:res | Where-Object { $_.RuleId -eq 'loadpoint.writable' -and "$($_.File)" -eq $script:ioDll }).Count | Should -Be 0
    }

    It 'still reports the inherit-only case as an app-registered load point' {
        # The registration itself is real; only the writable verdict is withheld.
        @($script:res | Where-Object { $_.RuleId -eq 'loadpoint.app-registered' -and "$($_.File)" -eq $script:ioDll }).Count | Should -Be 1
    }
}

Describe 'Test-TcpkRegistryLoadPoints - scope guards' -Skip:(-not $script:isWin) {

    It 'refuses attribution for a system-wide -Path and says so instead of going silent' {
        $r = @(Test-TcpkRegistryLoadPoints -Path $env:SystemRoot -MaxKeys 25 -WarningAction SilentlyContinue)
        @($r | Where-Object { $_.RuleId -eq 'loadpoint.app-registered' -and $_.Confidence -eq 'Skipped' }).Count | Should -Be 1
        @($r | Where-Object { $_.RuleId -eq 'loadpoint.app-registered' -and $_.Confidence -eq 'Confirmed' }).Count | Should -Be 0
        $c = @($r | Where-Object { $_.RuleId -eq 'loadpoint.census' -and $_.Confidence -eq 'Confirmed' })
        $c.Count | Should -Be 1
        $c[0].Evidence | Should -Match 'attribution-enabled=False'
    }

    It 'honours -MaxKeys and keeps enumeration counts exact when the cap bites' {
        # entries= is an enumeration count and must never shrink because the cap stopped
        # the per-entry work; processed= is the number the cap governs. Conflating them
        # is what turns a truncated census into something that reads as complete.
        $r = @(Test-TcpkRegistryLoadPoints -Path $script:root -MaxKeys 20 -WarningAction SilentlyContinue)
        $c = @($r | Where-Object { $_.RuleId -eq 'loadpoint.census' -and $_.Confidence -eq 'Confirmed' })
        $c.Count | Should -Be 1
        $m = [regex]::Match("$($c[0].Evidence)", 'shell-context-menu entries=(\d+) processed=(\d+)')
        $m.Success | Should -BeTrue
        $entries   = [int]$m.Groups[1].Value
        $processed = [int]$m.Groups[2].Value
        ($processed -le 20) | Should -BeTrue
        ($entries -ge $processed) | Should -BeTrue
    }

    It 'rejects a MaxKeys below the allowed range' {
        { Test-TcpkRegistryLoadPoints -Path $script:root -MaxKeys 1 -WarningAction SilentlyContinue } | Should -Throw
    }

    It 'returns nothing for a path that does not exist' {
        # Deliberate, and documented in .PARAMETER Path. A missing -Path is a caller
        # error, not a check that could not run, and every OsIntegration cmdlet returns
        # silently for it. The silence-is-not-clean rule is carried instead by the
        # loadpoint.census Skipped finding for unreadable registry locations and by the
        # loadpoint.app-registered Skipped findings for a system-wide -Path and for
        # -MaxKeys truncation.
        $missing = Join-Path $script:root 'no-such-subdir'
        @(Test-TcpkRegistryLoadPoints -Path $missing -WarningAction SilentlyContinue).Count | Should -Be 0
    }
}

Describe 'Test-TcpkRegistryLoadPoints - surface' {

    It 'is exported with the documented parameters' {
        $cmd = Get-Command Test-TcpkRegistryLoadPoints -ErrorAction SilentlyContinue
        $cmd | Should -Not -BeNullOrEmpty
        $cmd.Parameters.Keys | Should -Contain 'Path'
        $cmd.Parameters.Keys | Should -Contain 'MaxKeys'
    }

    It 'emits nothing off Windows rather than throwing' -Skip:($script:isWin) {
        @(Test-TcpkRegistryLoadPoints -Path $script:root -WarningAction SilentlyContinue).Count | Should -Be 0
    }
}
