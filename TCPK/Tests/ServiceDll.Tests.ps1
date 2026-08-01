#requires -Version 5.1
# Pester 5: Test-TcpkServiceDll (C24). svchost ServiceDll hijack surface.
#
# The behavioural suite is Windows-only (the check reads HKLM and Windows ACLs and refuses
# to run elsewhere). The rights-map suite is gated on whether SDDL parsing actually works in
# this runtime rather than on the platform, because those maps are where the false positives
# live and they are worth exercising anywhere they can be exercised.

BeforeDiscovery {
    $script:isWin = ($env:OS -eq 'Windows_NT')

    # Capability probe, not a platform probe: RawSecurityDescriptor is what
    # Get-TcpkSddlLowPrivGrants parses with, so if it cannot be constructed the map
    # assertions below are meaningless.
    $script:canSddl = $false
    try {
        $null = New-Object System.Security.AccessControl.RawSecurityDescriptor('D:(A;;GA;;;BA)')
        $script:canSddl = $true
    } catch { }
}

BeforeAll {
    $psd1 = Join-Path (Split-Path -Parent $PSScriptRoot) 'TCPK.psd1'
    Import-Module $psd1 -Force

    $script:root = Join-Path ([System.IO.Path]::GetTempPath()) ("tcpk-svcdll-" + [guid]::NewGuid().ToString('N').Substring(0, 8))
    New-Item -ItemType Directory -Path $script:root -Force | Out-Null
    # The cmdlet reports the scope root as Get-Item(...).FullName, which is not always
    # character-identical to what GetTempPath returned (8.3 short names, casing). Assert
    # against the canonical form or the scope-label test flakes on some hosts.
    $script:rootCanon = (Get-Item -LiteralPath $script:root).FullName.TrimEnd('\', '/')

    # Call the module-private SDDL parser with one of the cmdlet's own rights maps.
    function Invoke-MapGrants {
        param([string]$Sddl, [string]$MapName)
        & (Get-Module TCPK) {
            param($s, $n)
            $m = Get-Variable -Name $n -ValueOnly
            Get-TcpkSddlLowPrivGrants -Sddl $s -RightsMap $m
        } $Sddl $MapName
    }

    function Get-MapValues {
        param([string]$MapName)
        & (Get-Module TCPK) {
            param($n)
            @((Get-Variable -Name $n -ValueOnly).Values | ForEach-Object { [int]$_ })
        } $MapName
    }
}
AfterAll {
    if ($script:root) { Remove-Item -LiteralPath $script:root -Recurse -Force -ErrorAction SilentlyContinue }
}

Describe 'Test-TcpkServiceDll command surface' {
    It 'is exported with the attribution and bound parameters' {
        $cmd = Get-Command Test-TcpkServiceDll -ErrorAction Stop
        $cmd.Parameters.Keys | Should -Contain 'Path'
        $cmd.Parameters.Keys | Should -Contain 'MaxServices'
    }

    It 'does not throw when invoked' {
        { Test-TcpkServiceDll -Path $script:root -WarningAction SilentlyContinue } | Should -Not -Throw
    }

    It 'documents the limitations the code actually has' {
        # Docstring drift is the defect class that bites this check hardest: the help is what
        # an analyst reads before deciding whether a clean result means anything. Each string
        # below corresponds to a real behaviour of the code, so if one is deleted from the
        # help while the behaviour stays, this fails.
        $src = Get-Content -LiteralPath (Get-Command Test-TcpkServiceDll).ScriptBlock.File -Raw
        $help = [regex]::Match($src, '(?s)<#.*?#>').Value
        $help | Should -Not -BeNullOrEmpty
        foreach ($claim in @(
            'UNDER-REPORTING',      # only well-known low-priv SIDs are matched
            'OVER-REPORTING',       # deny ACEs and INHERIT_ONLY are not evaluated
            'not a rooted path',    # unrooted ServiceDll counted, not reported
            'does not exist on disk', # phantom-DLL case counted, not reported
            'CurrentControlSet',    # other control sets and offline hives are not read
            'WALK TRUNCATED',       # -MaxServices cut the walk short
            '32-bit'                # WOW64 refusal
        )) {
            $help | Should -BeLike "*$claim*" -Because "the help must still state: $claim"
        }
    }

    It 'uses only ASCII in source and help' {
        $src = Get-Content -LiteralPath (Get-Command Test-TcpkServiceDll).ScriptBlock.File -Raw
        @([regex]::Matches($src, '[^\x00-\x7F]')).Count | Should -Be 0
    }
}

Describe 'Test-TcpkServiceDll enumeration' -Skip:(-not $script:isWin) {
    # One machine-wide run, reused. Each call reads every service key and Get-Acls every
    # resolved DLL, directory and key; running it once per It made the suite do that work
    # three times over for assertions on the same object.
    BeforeAll {
        $script:wide     = @(Test-TcpkServiceDll -WarningAction SilentlyContinue)
        $script:wideEnum = @($script:wide | Where-Object { $_.RuleId -eq 'servicedll.enumerated' })
    }

    It 'always emits a coverage record so silence is never a clean result' {
        $script:wideEnum.Count | Should -Be 1
        $script:wideEnum[0].Severity | Should -Be 'INFO'
        $script:wideEnum[0].Module   | Should -Be 'os'
        $script:wideEnum[0].Evidence | Should -Match 'service keys present=\d+'
        $script:wideEnum[0].Evidence | Should -Match 'service keys read=\d+'
        $script:wideEnum[0].Evidence | Should -Match 'with a ServiceDll value=\d+'
        $script:wideEnum[0].Evidence | Should -Match 'ACL checks attempted=\d+, denied=\d+'
    }

    It 'finds ServiceDll values on a normal Windows install' {
        # Every supported Windows build ships svchost-hosted services (Dhcp, Dnscache,
        # Schedule, ...). A zero here means the reader never worked, not that the machine
        # is clean, so this asserts the check is actually looking at something.
        $m = [regex]::Match($script:wideEnum[0].Evidence, 'with a ServiceDll value=(\d+)')
        $m.Success | Should -BeTrue
        [int]$m.Groups[1].Value | Should -BeGreaterThan 0
    }

    It 'labels an unscoped run as machine-wide' {
        $script:wideEnum[0].Evidence | Should -Match 'scope=machine-wide'
    }

    It 'does not falsely skip the whole hive when some service subkeys are unreadable' {
        # A single access-denied subkey is a NON-terminating error. If the enumerator ever
        # goes back to -ErrorAction Stop, the readable keys are discarded and the check
        # emits 'Service registry hive could not be enumerated' instead of any coverage.
        @($script:wide | Where-Object { $_.Title -eq 'Service registry hive could not be enumerated' }).Count |
            Should -Be 0
        $m = [regex]::Match($script:wideEnum[0].Evidence, 'service keys present=(\d+)')
        [int]$m.Groups[1].Value | Should -BeGreaterThan 0
    }

    It 'reports the sample as a sample and never as a count' {
        # The capped list must not be readable as a total: the exact figure lives in
        # 'in scope and resolving to a file=N' and the ellipsis names the cap explicitly.
        $ev = $script:wideEnum[0].Evidence
        $ev | Should -Match 'in scope and resolving to a file=\d+'
        $m  = [regex]::Match($ev, 'in scope and resolving to a file=(\d+)')
        if ([int]$m.Groups[1].Value -gt 15) {
            $ev | Should -Match 'sample capped at 15 of \d+'
        }
    }
}

Describe 'Test-TcpkServiceDll attribution scoping' -Skip:(-not $script:isWin) {
    BeforeAll {
        $script:scoped     = @(Test-TcpkServiceDll -Path $script:root -WarningAction SilentlyContinue)
        $script:scopedEnum = @($script:scoped | Where-Object { $_.RuleId -eq 'servicedll.enumerated' })[0]
    }

    It 'reports nothing writable when -Path is a tree that holds no service DLL' {
        @($script:scoped | Where-Object { $_.RuleId -eq 'servicedll.writable' }).Count | Should -Be 0
        @($script:scoped | Where-Object { $_.RuleId -eq 'servicedll.key-writable' }).Count | Should -Be 0
    }

    It 'records the scope root and an in-scope count of zero for an unrelated tree' {
        $script:scopedEnum.Evidence | Should -Match ([regex]::Escape("scope=restricted to $script:rootCanon"))
        $script:scopedEnum.Evidence | Should -Match 'in scope and resolving to a file=0'
    }

    It 'still counts the machine-wide surface while scoped, so scoping is visible not silent' {
        $m = [regex]::Match($script:scopedEnum.Evidence, 'with a ServiceDll value=(\d+)')
        [int]$m.Groups[1].Value | Should -BeGreaterThan 0
    }

    It 'emits a Skipped finding rather than silence when -Path does not exist' {
        $missing = Join-Path $script:root ('nope-' + [guid]::NewGuid().ToString('N').Substring(0, 6))
        $r = @(Test-TcpkServiceDll -Path $missing -WarningAction SilentlyContinue)
        $s = @($r | Where-Object { $_.Confidence -eq 'Skipped' })
        $s.Count | Should -Be 1
        $s[0].RuleId | Should -Be 'servicedll.unreadable'
        # Must land in the OsIntegration bucket. New-TcpkSkippedFinding hardcodes
        # -Module 'runtime', so using it here would file the non-run record under the wrong
        # module and leave 'os' with no record that the check refused to run.
        $s[0].Module | Should -Be 'os'
        @($r | Where-Object { $_.RuleId -eq 'servicedll.enumerated' }).Count | Should -Be 0
    }

    It 'honours MaxServices as a hard cap on the walk' {
        $f = @(Test-TcpkServiceDll -MaxServices 5 -WarningAction SilentlyContinue |
            Where-Object { $_.RuleId -eq 'servicedll.enumerated' })[0]
        $m = [regex]::Match($f.Evidence, 'service keys read=(\d+)')
        [int]$m.Groups[1].Value | Should -BeLessOrEqual 5
    }

    It 'says WALK TRUNCATED when the cap cut the walk short, so a partial run is not read as clean' {
        # Every Windows install has far more than 5 service keys, so this always truncates.
        $f = @(Test-TcpkServiceDll -MaxServices 5 -WarningAction SilentlyContinue |
            Where-Object { $_.RuleId -eq 'servicedll.enumerated' })[0]
        $f.Evidence | Should -Match 'WALK TRUNCATED'
        $f.Title    | Should -Match 'WALK TRUNCATED'
        $f.Fix      | Should -Match 'Re-run with -MaxServices'
        # present > read is the whole point: read alone cannot be told from a full walk.
        $present = [int][regex]::Match($f.Evidence, 'service keys present=(\d+)').Groups[1].Value
        $read    = [int][regex]::Match($f.Evidence, 'service keys read=(\d+)').Groups[1].Value
        $present | Should -BeGreaterThan $read
    }
}

# The maps are the false-positive boundary of this check. Get-TcpkSddlLowPrivGrants ORs every
# map value into one danger mask, so a single composite constant (FILE_ALL_ACCESS,
# KEY_ALL_ACCESS) would drag the READ bits in with it and flag every read-only ACE on the
# machine. These tests pin that behaviour.
Describe 'ServiceDll rights maps reject benign ACEs' -Skip:(-not $script:canSddl) {
    It 'defines all three maps with content' {
        # A map that silently went missing or empty would make Get-TcpkSddlLowPrivGrants OR
        # up a danger mask of 0, which matches nothing: the check would report clean on a
        # world-writable machine. Assert the maps exist before asserting what is in them.
        foreach ($n in @('TcpkServiceDllFileRights', 'TcpkServiceDllDirRights', 'TcpkServiceDllKeyRights')) {
            @(Get-MapValues $n).Count | Should -BeGreaterThan 0 -Because "$n must not be empty"
        }
    }

    It 'never lists a composite ALL_ACCESS constant that would carry read bits' {
        Get-MapValues 'TcpkServiceDllFileRights' | Should -Not -Contain 0x1F01FF
        Get-MapValues 'TcpkServiceDllDirRights'  | Should -Not -Contain 0x1F01FF
        Get-MapValues 'TcpkServiceDllKeyRights'  | Should -Not -Contain 0xF003F
    }

    It 'carries GENERIC_ALL and GENERIC_WRITE in every map' {
        # SDDL writes full control as GA and write as GW. Both bits sit outside the
        # FILE_ALL_ACCESS / KEY_ALL_ACCESS numeric ranges, so dropping them from a map would
        # silently miss the most common way a full-control ACE is actually written.
        foreach ($n in @('TcpkServiceDllFileRights', 'TcpkServiceDllDirRights', 'TcpkServiceDllKeyRights')) {
            Get-MapValues $n | Should -Contain 0x10000000 -Because "$n needs GENERIC_ALL (SDDL GA)"
            Get-MapValues $n | Should -Contain 0x40000000 -Because "$n needs GENERIC_WRITE (SDDL GW)"
        }
    }

    It 'excludes the write bits that cannot change DLL content' {
        # FILE_WRITE_EA (0x10) and FILE_WRITE_ATTRIBUTES (0x100) are write-class but change
        # no byte of the DLL. They are on the default ACL of ordinary directories, so listing
        # them would flag benign trees.
        foreach ($n in @('TcpkServiceDllFileRights', 'TcpkServiceDllDirRights')) {
            Get-MapValues $n | Should -Not -Contain 0x10  -Because "$n must not list FILE_WRITE_EA"
            Get-MapValues $n | Should -Not -Contain 0x100 -Because "$n must not list FILE_WRITE_ATTRIBUTES"
        }
        # 0x116 = WRITE_DATA | APPEND | WRITE_EA | WRITE_ATTRIBUTES on a file: only the
        # WRITE_DATA bit may be reported.
        $g = @(Invoke-MapGrants 'D:(A;;0x000116;;;BU)' 'TcpkServiceDllFileRights')
        $g.Count | Should -Be 1
        @($g[0].Granted).Count | Should -Be 1
        $g[0].Granted | Should -Contain 'WRITE_DATA'
    }

    It 'ignores the read-and-execute grant Users holds on every system DLL' {
        # 0x1200A9 = FILE_GENERIC_READ | FILE_GENERIC_EXECUTE for BUILTIN\Users.
        @(Invoke-MapGrants 'D:(A;;FA;;;BA)(A;;0x1200a9;;;BU)' 'TcpkServiceDllFileRights').Count | Should -Be 0
    }

    It 'ignores an append-only grant on the DLL file' {
        # FILE_APPEND_DATA cannot redirect execution in a mapped PE, so it must not read as
        # "the DLL is replaceable".
        @(Invoke-MapGrants 'D:(A;;0x000004;;;BU)' 'TcpkServiceDllFileRights').Count | Should -Be 0
    }

    It 'flags a real write grant on the DLL file' {
        $g = @(Invoke-MapGrants 'D:(A;;0x120116;;;BU)' 'TcpkServiceDllFileRights')
        $g.Count | Should -Be 1
        $g[0].Sid | Should -Be 'S-1-5-32-545'
        $g[0].Granted | Should -Contain 'WRITE_DATA'
        $g[0].Granted | Should -Not -Contain 'DELETE'
    }

    It 'ignores FILE_ADD_SUBDIRECTORY on the DLL directory' {
        # The default ACL on C:\ grants Users "create folders / append data". Treating that
        # as a plant would flag the parent of anything installed at the root of a volume.
        @(Invoke-MapGrants 'D:(A;;0x000004;;;BU)' 'TcpkServiceDllDirRights').Count | Should -Be 0
    }

    It 'flags FILE_ADD_FILE and FILE_DELETE_CHILD on the DLL directory' {
        $add = @(Invoke-MapGrants 'D:(A;;0x000002;;;BU)' 'TcpkServiceDllDirRights')
        $add.Count | Should -Be 1
        $add[0].Granted | Should -Contain 'ADD_FILE'
        $add[0].Granted | Should -Not -Contain 'DELETE_CHILD'

        $del = @(Invoke-MapGrants 'D:(A;;0x000040;;;BU)' 'TcpkServiceDllDirRights')
        $del.Count | Should -Be 1
        $del[0].Granted | Should -Contain 'DELETE_CHILD'
        $del[0].Granted | Should -Not -Contain 'ADD_FILE'
    }

    It 'ignores KEY_READ on the service key' {
        @(Invoke-MapGrants 'D:(A;;KR;;;BU)' 'TcpkServiceDllKeyRights').Count | Should -Be 0
    }

    It 'flags KEY_WRITE on the service key' {
        $g = @(Invoke-MapGrants 'D:(A;;KW;;;BU)' 'TcpkServiceDllKeyRights')
        $g.Count | Should -Be 1
        $g[0].Granted | Should -Contain 'KEY_SET_VALUE'
        $g[0].Granted | Should -Contain 'KEY_CREATE_SUB_KEY'
    }

    It 'flags a generic-form GA ace, which KEY_ALL_ACCESS alone would miss' {
        # SDDL writes full control as "GA" (0x10000000). That bit is not inside 0xF003F, so
        # the map carries GENERIC_ALL explicitly.
        $g = @(Invoke-MapGrants 'D:(A;;GA;;;BU)' 'TcpkServiceDllKeyRights')
        $g.Count | Should -Be 1
        $g[0].Granted | Should -Contain 'GENERIC_ALL'
    }

    It 'separates the rights that reach the existing DLL from the ones that only plant next to it' {
        # This is the MEDIUM/HIGH split in the directory branch of the check. ADD_FILE and
        # GENERIC_WRITE cannot overwrite an existing file (planting primitive, MEDIUM);
        # DELETE_CHILD, WRITE_DAC, WRITE_OWNER and GENERIC_ALL do reach it (HIGH). If a right
        # moves between these sets the severity of a real finding moves with it.
        $strong = @('DELETE_CHILD', 'WRITE_DAC', 'WRITE_OWNER', 'GENERIC_ALL')

        $weak = @(Invoke-MapGrants 'D:(A;;GW;;;BU)' 'TcpkServiceDllDirRights')
        $weak.Count | Should -Be 1
        @(@($weak[0].Granted) | Where-Object { $strong -contains $_ }).Count |
            Should -Be 0 -Because 'GENERIC_WRITE alone must stay a planting primitive (MEDIUM)'

        $full = @(Invoke-MapGrants 'D:(A;;GA;;;BU)' 'TcpkServiceDllDirRights')
        $full.Count | Should -Be 1
        @(@($full[0].Granted) | Where-Object { $strong -contains $_ }).Count |
            Should -BeGreaterThan 0 -Because 'GENERIC_ALL reaches the existing DLL (HIGH)'
    }

    It 'ignores full control held only by Administrators and SYSTEM' {
        foreach ($map in @('TcpkServiceDllFileRights', 'TcpkServiceDllDirRights', 'TcpkServiceDllKeyRights')) {
            @(Invoke-MapGrants 'D:(A;;GA;;;BA)(A;;GA;;;SY)(A;;GA;;;S-1-5-80-0)' $map).Count |
                Should -Be 0 -Because "$map must only report low-privilege principals"
        }
    }
}
