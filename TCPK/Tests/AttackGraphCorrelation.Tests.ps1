#requires -Version 5.1
# Pester 5: the attack graph must JOIN the two halves of a load-order hijack.
#
# WHY. A DLL hijack needs both a name the loader looks for and fails to find, AND a
# writable location on its search path. TCPK reported those separately -- pe-imports.phantom
# on one line, path.writable on another -- and the graph knew about the second but not the
# first. So a finding set could contain a complete local privilege escalation and nothing in
# the report ever said so.
#
# That is the exact shape of the publicly disclosed reports in this class: a phantom DLL
# resolved through a user-writable PATH entry, most often
# %LOCALAPPDATA%\Microsoft\WindowsApps. Several separate reports, one join.
#
# These tests also pin the HONESTY boundary: the pair alone is code execution, but it is only
# an ESCALATION when the loading process is privileged. Planting a DLL that loads into a
# process running as the same user crosses no boundary.

BeforeAll {
    $psd1 = Join-Path (Split-Path (Split-Path $PSCommandPath -Parent) -Parent) 'TCPK.psd1'
    Import-Module $psd1 -Force
}

# Build a finding without depending on the private constructor signature.
function New-Fx {
    param([string]$RuleId, [string]$Severity = 'MEDIUM', [string]$File = 'C:\app\app.exe')
    InModuleScope TCPK -Parameters @{ r = $RuleId; s = $Severity; f = $File } {
        param($r, $s, $f)
        New-TcpkFinding -Module 'static' -RuleId $r -Severity $s -Confidence 'Confirmed' `
            -Title "synthetic $r" -File $f
    }
}

function Get-Goals {
    param([object[]]$Findings)
    $g = InModuleScope TCPK -Parameters @{ fs = $Findings } {
        param($fs) @($fs | Get-TcpkAttackGraph)
    }
    return @($g | Where-Object { $_.RuleId -eq 'attackgraph.reachable-goal' })
}

Describe 'Phantom DLL + writable search path correlate' {

    It 'raises a goal when BOTH halves are present' {
        $f = @((New-Fx 'pe-imports.phantom' 'MEDIUM'), (New-Fx 'path.writable' 'MEDIUM'))
        $goals = Get-Goals -Findings $f
        $goals.Count | Should -BeGreaterThan 0 -Because 'this pair IS a complete DLL-hijack chain'
    }

    It 'raises NOTHING from the phantom name alone' {
        $goals = Get-Goals -Findings @((New-Fx 'pe-imports.phantom' 'MEDIUM'))
        $goals.Count | Should -Be 0 -Because 'an unresolved import with nowhere writable to plant is not a bug'
    }

    It 'raises NOTHING from the writable directory alone' {
        $goals = Get-Goals -Findings @((New-Fx 'path.writable' 'MEDIUM'))
        $goals.Count | Should -Be 0 -Because 'a writable PATH entry with nothing looking for a missing DLL is not a bug'
    }

    It 'accepts the runtime half (dll-search.name-not-found) as the phantom' {
        $f = @((New-Fx 'dll-search.name-not-found' 'MEDIUM'), (New-Fx 'install-dir.user-writable' 'MEDIUM'))
        (Get-Goals -Findings $f).Count | Should -BeGreaterThan 0
    }

    It 'accepts the static side-load candidate as the phantom' {
        $f = @((New-Fx 'dllsearch.sideload-candidate' 'MEDIUM'), (New-Fx 'acl.programdata-user-writable' 'MEDIUM'))
        (Get-Goals -Findings $f).Count | Should -BeGreaterThan 0
    }
}

Describe 'The SYSTEM claim requires a privileged loader' {

    It 'does not claim SYSTEM from phantom + writable path alone' {
        $f = @((New-Fx 'pe-imports.phantom' 'MEDIUM'), (New-Fx 'path.writable' 'MEDIUM'))
        $goals = Get-Goals -Findings $f
        @($goals | Where-Object { $_.Title -match 'SYSTEM' }).Count | Should -Be 0 `
            -Because 'planting into a same-user process crosses no privilege boundary'
    }

    It 'DOES claim SYSTEM once the loader is observed running privileged' {
        $f = @(
            (New-Fx 'pe-imports.phantom' 'MEDIUM'),
            (New-Fx 'path.writable' 'MEDIUM'),
            (New-Fx 'process.running-as-system' 'HIGH')
        )
        $goals = Get-Goals -Findings $f
        @($goals | Where-Object { $_.Title -match 'SYSTEM' }).Count | Should -BeGreaterThan 0
    }
}

Describe 'Privileged load points escalate on their own' {

    # svchost runs ServiceDll as SYSTEM; AppInit_DLLs loads into every user32 process;
    # LSA / print monitors / Winlogon notify all run privileged. A writable one of these
    # needs no second condition.
    It 'raises SYSTEM for <_> with no other finding' -ForEach @(
        'servicedll.writable', 'servicedll.key-writable',
        'appinit.dll-writable', 'appinit.app-registers-dll',
        'loadpoint.writable', 'loadpoint.app-registered'
    ) {
        $goals = Get-Goals -Findings @((New-Fx $_ 'HIGH'))
        @($goals | Where-Object { $_.Title -match 'SYSTEM' }).Count | Should -BeGreaterThan 0 `
            -Because "$_ is a privileged load point, writable = direct escalation"
    }
}

Describe 'Coverage/skip records never reach the graph' {
    It '<_> raises no goal' -ForEach @(
        'servicedll.enumerated', 'servicedll.unreadable',
        'appinit.clean', 'appinit.not-readable', 'loadpoint.census',
        'jni.native-libs', 'dll-search.skipped-no-admin'
    ) {
        (Get-Goals -Findings @((New-Fx $_ 'INFO'))).Count | Should -Be 0 `
            -Because 'a census or skip record is not an attack primitive'
    }
}

Describe 'Every graph category still matches a real rule ID' {
    # A category whose regex matches nothing can never fire, so the graph would silently
    # lose that whole class. Cheap to assert, and it catches a rule-ID rename.
    It 'has no dead category' {
        InModuleScope TCPK {
            $src = Get-Content -LiteralPath (Join-Path $script:TcpkRoot 'Public\Recon\Get-TcpkAttackGraph.ps1') -Raw
            $rxs = [regex]::Matches($src, "Id = '([\w.]+)';\s*Role = '\w+';\s*Label = '[^']+';\s*Rx = '([^']+)'")
            $ids = New-Object 'System.Collections.Generic.HashSet[string]'
            foreach ($f in (Get-ChildItem -LiteralPath $script:TcpkRoot -Recurse -File -Filter '*.ps1')) {
                if ($f.FullName -match '\\Tests\\') { continue }
                foreach ($m in [regex]::Matches((Get-Content -LiteralPath $f.FullName -Raw), "-RuleId\s+'([a-z0-9._-]+)'")) {
                    [void]$ids.Add($m.Groups[1].Value)
                }
            }
            $dead = @()
            foreach ($m in $rxs) {
                $rx = $m.Groups[2].Value
                $hit = @($ids | Where-Object { $_ -match $rx })
                if (-not $hit.Count) { $dead += $m.Groups[1].Value }
            }
            $dead | Should -BeNullOrEmpty
        }
    }
}
