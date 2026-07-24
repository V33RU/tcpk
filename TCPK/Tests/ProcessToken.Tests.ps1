#requires -Version 5.1
# E13 process-token uplift: integrity-level readout + impactful-privilege
# detection. The classification is a pure function (unit-tested with synthetic
# token strings); the cmdlet path is exercised through mockable wrappers so the
# enabled-privilege finding is proven without a live elevated token on CI.

BeforeAll {
    $psd1 = Join-Path (Split-Path (Split-Path $PSCommandPath -Parent) -Parent) 'TCPK.psd1'
    Import-Module $psd1 -Force
}

Describe 'Get-TcpkIntegrityLabel' {
    It 'maps <Label> to <Expected>' -ForEach @(
        @{ Label = 'RID 0x0000'; Rid = 0x0000; Expected = 'Untrusted' }
        @{ Label = 'RID 0x1000'; Rid = 0x1000; Expected = 'Low' }
        @{ Label = 'RID 0x2000'; Rid = 0x2000; Expected = 'Medium' }
        @{ Label = 'RID 0x3000'; Rid = 0x3000; Expected = 'High' }
        @{ Label = 'RID 0x4000'; Rid = 0x4000; Expected = 'System' }
    ) {
        InModuleScope TCPK -Parameters @{ Rid = $Rid; Expected = $Expected } {
            param($Rid, $Expected)
            Get-TcpkIntegrityLabel $Rid | Should -Be $Expected
        }
    }
}

Describe 'Split-TcpkImpactfulPrivileges' {
    It 'flags an enabled system-grade privilege and marks SawSystemGrade' {
        InModuleScope TCPK {
            $r = Split-TcpkImpactfulPrivileges -PrivRaw 'SeImpersonatePrivilege:enabled;SeBackupPrivilege:present;SeChangeNotifyPrivilege:enabled'
            $r.Enabled | Should -Contain 'SeImpersonatePrivilege'
            $r.Present | Should -Contain 'SeBackupPrivilege'
            $r.SawSystemGrade | Should -BeTrue
            # a non-impactful privilege must never appear
            $r.Enabled | Should -Not -Contain 'SeChangeNotifyPrivilege'
        }
    }
    It 'treats a resource-grade privilege as impactful but not system-grade' {
        InModuleScope TCPK {
            $r = Split-TcpkImpactfulPrivileges -PrivRaw 'SeBackupPrivilege:enabled;SeRestorePrivilege:present'
            $r.Enabled | Should -Contain 'SeBackupPrivilege'
            $r.Present | Should -Contain 'SeRestorePrivilege'
            $r.SawSystemGrade | Should -BeFalse
        }
    }
    It 'ignores a token with only ordinary privileges' {
        InModuleScope TCPK {
            $r = Split-TcpkImpactfulPrivileges -PrivRaw 'SeChangeNotifyPrivilege:enabled;SeShutdownPrivilege:present;SeTimeZonePrivilege:present'
            $r.Enabled.Count | Should -Be 0
            $r.Present.Count | Should -Be 0
        }
    }
    It 'returns an empty result for a blank string' {
        InModuleScope TCPK {
            (Split-TcpkImpactfulPrivileges -PrivRaw '').Enabled.Count | Should -Be 0
        }
    }
}

Describe 'Test-TcpkProcessToken end-to-end (mocked token)' {
    It 'reports High integrity + MEDIUM impactful-privileges for an enabled system-grade privilege' {
        InModuleScope TCPK {
            Mock Assert-TcpkWindows { $true }
            Mock Get-TcpkProcess { [pscustomobject]@{ Id = 4321; Name = 'vuln'; StartTime = $null } }
            Mock Get-TcpkProcessIntegrityRid { 0x3000 }
            Mock Get-TcpkProcessPrivilegeString { 'SeImpersonatePrivilege:enabled;SeBackupPrivilege:present' }

            $f = Test-TcpkProcessToken -ProcessId 4321
            ($f | Where-Object { $_.RuleId -eq 'process.integrity-level' }).Title | Should -Match 'High integrity'
            $imp = $f | Where-Object { $_.RuleId -eq 'process.impactful-privileges' }
            $imp | Should -Not -BeNullOrEmpty
            $imp.Severity   | Should -Be 'MEDIUM'
            $imp.Confidence | Should -Be 'Confirmed'
            $imp.Evidence   | Should -Match 'SeImpersonatePrivilege'
            $imp.Evidence   | Should -Match 'SeBackupPrivilege'   # present-but-disabled listed for context
        }
    }
    It 'downgrades to LOW when only a resource-grade privilege is enabled' {
        InModuleScope TCPK {
            Mock Assert-TcpkWindows { $true }
            Mock Get-TcpkProcess { [pscustomobject]@{ Id = 22; Name = 'app'; StartTime = $null } }
            Mock Get-TcpkProcessIntegrityRid { 0x2000 }
            Mock Get-TcpkProcessPrivilegeString { 'SeBackupPrivilege:enabled;SeRestorePrivilege:present' }

            $imp = Test-TcpkProcessToken -ProcessId 22 | Where-Object { $_.RuleId -eq 'process.impactful-privileges' }
            $imp.Severity | Should -Be 'LOW'
        }
    }
    It 'emits no impactful-privileges finding for an ordinary user token' {
        InModuleScope TCPK {
            Mock Assert-TcpkWindows { $true }
            Mock Get-TcpkProcess { [pscustomobject]@{ Id = 33; Name = 'app'; StartTime = $null } }
            Mock Get-TcpkProcessIntegrityRid { 0x2000 }
            Mock Get-TcpkProcessPrivilegeString { 'SeChangeNotifyPrivilege:enabled;SeShutdownPrivilege:present' }

            $f = Test-TcpkProcessToken -ProcessId 33
            ($f | Where-Object { $_.RuleId -eq 'process.impactful-privileges' }) | Should -BeNullOrEmpty
        }
    }
}

Describe 'Test-TcpkProcessToken live token read' {
    It 'reads this process integrity level via the P/Invoke path' -Skip:($IsWindows -eq $false) {
        $f = Test-TcpkProcessToken -ProcessId $PID
        $lvl = $f | Where-Object { $_.RuleId -eq 'process.integrity-level' }
        $lvl | Should -Not -BeNullOrEmpty
        $lvl.Title | Should -Match '(Low|Medium|High|System) integrity'
    }
}
