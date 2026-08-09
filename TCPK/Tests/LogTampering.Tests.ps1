#requires -Version 5.1
# Pester 5: the log-TAMPERING half of Test-TcpkLogFiles.
#
# Distinct from what a log LEAKS. The question here is whether a non-admin principal can
# rewrite or delete the record, because a log the investigated account can edit is not
# evidence, and one they can delete removes the trail of everything else.
#
# The ACL assertions are Windows-only: Get-Acl on a non-Windows host does not return
# FileSystemAccessRule objects with FileSystemRights, so they self-skip rather than
# failing for the wrong reason. The inventory assertions run everywhere.

BeforeDiscovery {
    $script:isWin = $IsWindows -or ($PSVersionTable.PSEdition -eq 'Desktop')
}

BeforeAll {
    $psd1 = Join-Path (Split-Path (Split-Path $PSCommandPath -Parent) -Parent) 'TCPK.psd1'
    Import-Module $psd1 -Force

    $script:work = Join-Path ([IO.Path]::GetTempPath()) ("tcpk-logtamper-" + [guid]::NewGuid().ToString('N'))
    $script:logDir = Join-Path $script:work 'logs'
    New-Item -ItemType Directory -Force -Path $script:logDir | Out-Null
    $script:logFile = Join-Path $script:logDir 'app.log'
    @(
        '2026-08-09 10:00:00 INFO  service started'
        '2026-08-09 10:00:01 INFO  user signed in'
    ) | Set-Content -LiteralPath $script:logFile -Encoding UTF8

    # Grant Users Modify on the log file and its directory, which is the condition under
    # test. Done with the real ACL API so the check sees a genuine grant, not a mock.
    function script:Grant-UsersModify([string]$Target) {
        try {
            $acl = Get-Acl -LiteralPath $Target
            $sid = New-Object System.Security.Principal.SecurityIdentifier(
                       [System.Security.Principal.WellKnownSidType]::BuiltinUsersSid, $null)
            $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
                        $sid, 'Modify', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
            $acl.AddAccessRule($rule)
            Set-Acl -LiteralPath $Target -AclObject $acl
            return $true
        } catch { return $false }
    }
}

AfterAll {
    if ($script:work -and (Test-Path $script:work)) {
        Remove-Item $script:work -Recurse -Force -ErrorAction SilentlyContinue
    }
}

Describe 'Test-TcpkLogFiles: inventory still works' {
    It 'finds the log file and emits an inventory finding' {
        $f = @(Test-TcpkLogFiles -Path $script:work)
        @($f | Where-Object { $_.RuleId -eq 'log.file-present' }).Count | Should -BeGreaterThan 0
    }
}

Describe 'Test-TcpkLogFiles: tamperable log file' -Skip:(-not $script:isWin) {
    BeforeAll {
        $script:granted = script:Grant-UsersModify $script:logFile
        $script:tf = @(Test-TcpkLogFiles -Path $script:work)
    }

    It 'flags a log file a non-admin principal can rewrite' -Skip:(-not $script:granted) {
        $t = @($script:tf | Where-Object { $_.RuleId -eq 'log.tamperable-file' })
        $t.Count | Should -BeGreaterThan 0
        $t[0].Severity | Should -Be 'MEDIUM'
        $t[0].Confidence | Should -Be 'Confirmed'
    }

    It 'names the principal and the right in the evidence' -Skip:(-not $script:granted) {
        $t = @($script:tf | Where-Object { $_.RuleId -eq 'log.tamperable-file' })
        "$($t[0].Evidence)" | Should -Match '(?i)users'
        "$($t[0].Evidence)" | Should -Match '(?i)modify|fullcontrol|writedata'
    }

    It 'states the repudiation consequence, not just the ACL fact' -Skip:(-not $script:granted) {
        $t = @($script:tf | Where-Object { $_.RuleId -eq 'log.tamperable-file' })
        "$($t[0].Description)" | Should -Match '(?i)repudiable|cannot be relied on'
    }

    It 'does not claim tampering occurred, only that it is possible' -Skip:(-not $script:granted) {
        $t = @($script:tf | Where-Object { $_.RuleId -eq 'log.tamperable-file' })
        "$($t[0].Description)" | Should -Match '(?i)not about whether'
    }
}

Describe 'Test-TcpkLogFiles: tamperable log directory' -Skip:(-not $script:isWin) {
    BeforeAll {
        $script:dgranted = script:Grant-UsersModify $script:logDir
        $script:df = @(Test-TcpkLogFiles -Path $script:work)
    }

    It 'flags the directory separately from the file' -Skip:(-not $script:dgranted) {
        $d = @($script:df | Where-Object { $_.RuleId -eq 'log.tamperable-directory' })
        $d.Count | Should -BeGreaterThan 0
    }

    It 'reports the directory once, not once per log file in it' -Skip:(-not $script:dgranted) {
        $second = Join-Path $script:logDir 'app2.log'
        'x' | Set-Content -LiteralPath $second -Encoding UTF8
        $f2 = @(Test-TcpkLogFiles -Path $script:work)
        @($f2 | Where-Object { $_.RuleId -eq 'log.tamperable-directory' }).Count | Should -Be 1
        Remove-Item $second -Force -ErrorAction SilentlyContinue
    }

    It 'explains that parent Delete defeats a hardened file ACL' -Skip:(-not $script:dgranted) {
        $d = @($script:df | Where-Object { $_.RuleId -eq 'log.tamperable-directory' })
        "$($d[0].Description)" | Should -Match '(?i)regardless of its own permissions|defeats a hardened'
    }
}

Describe 'Test-TcpkLogFiles: a locked-down log stays silent' -Skip:(-not $script:isWin) {
    It 'emits no tamper finding when no non-admin principal has write access' {
        $clean = Join-Path $script:work 'clean'
        New-Item -ItemType Directory -Force -Path $clean | Out-Null
        $cd = Join-Path $clean 'logs'
        New-Item -ItemType Directory -Force -Path $cd | Out-Null
        $cf = Join-Path $cd 'locked.log'
        'nothing interesting' | Set-Content -LiteralPath $cf -Encoding UTF8
        try {
            # Break inheritance and strip everything but the current owner, so no
            # Users / Everyone / INTERACTIVE grant remains.
            $acl = Get-Acl -LiteralPath $cf
            $acl.SetAccessRuleProtection($true, $false)
            foreach ($r in @($acl.Access)) { [void]$acl.RemoveAccessRule($r) }
            $me = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
            $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
                $me, 'FullControl', 'None', 'None', 'Allow')))
            Set-Acl -LiteralPath $cf -AclObject $acl
        } catch {
            Set-ItResult -Skipped -Because 'could not rewrite the ACL in this environment'
            return
        }
        $f = @(Test-TcpkLogFiles -Path $clean)
        @($f | Where-Object { $_.RuleId -eq 'log.tamperable-file' }).Count | Should -Be 0
    }
}
