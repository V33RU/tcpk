#requires -Version 5.1
# Pester 5: readability guard in Invoke-TcpkAudit.
#
# WHY. On a real Crestron ConfigurePro run against C:\Program Files\WindowsApps\... the audit
# printed "audit complete -- 0 findings" and produced no findings.json, because the WindowsApps
# ACL blocks the recursive walk even for admin. The tool has to refuse loudly rather than
# quietly emit a clean-looking report.

BeforeAll {
    $psd1 = Join-Path (Split-Path (Split-Path $PSCommandPath -Parent) -Parent) 'TCPK.psd1'
    Import-Module $psd1 -Force
    $script:empty = Join-Path ([IO.Path]::GetTempPath()) ('tcpk-empty-' + [guid]::NewGuid().ToString('N').Substring(0,10))
    New-Item -ItemType Directory -Force -Path $script:empty | Out-Null
}
AfterAll {
    if ($script:empty -and (Test-Path $script:empty)) { Remove-Item -Recurse -Force -ErrorAction SilentlyContinue $script:empty }
}

Describe 'Invoke-TcpkAudit refuses an unreadable target loudly' {
    It 'emits scan.target-unreadable HIGH when the walk sees zero files' {
        # Empty directory is functionally identical to an ACL-blocked one: Get-ChildItem returns
        # nothing. We do not need to fabricate a WindowsApps ACL to prove the guard fires.
        $out = Join-Path ([IO.Path]::GetTempPath()) ('tcpk-out-' + [guid]::NewGuid().ToString('N').Substring(0,8))
        try {
            $rows = @(Invoke-TcpkAudit -Target $script:empty -Acknowledge -OutDir $out -Quick 3>$null 2>$null | Where-Object { $_.RuleId -eq 'scan.target-unreadable' })
            $rows.Count | Should -BeGreaterThan 0
            $rows[0].Severity | Should -Be 'HIGH'
            $rows[0].Confidence | Should -Be 'Confirmed'
        } finally {
            if (Test-Path $out) { Remove-Item -Recurse -Force -ErrorAction SilentlyContinue $out }
        }
    }
}

Describe 'Pre-flight guard does not abort on any path shape' {
    # Regression: an earlier revision used -match against a path containing "\Program", which
    # .NET regex parses as \P (invalid escape). The regex threw during compile and the audit
    # died before any check ran. Anything runnable on a WindowsApps-shaped path must not throw.
    It 'runs cleanly against a synthetic WindowsApps-shaped path with real content' {
        $winShape = Join-Path ([IO.Path]::GetTempPath()) ('tcpk-win-' + [guid]::NewGuid().ToString('N').Substring(0,8) + '\Program Files\WindowsApps\TestApp')
        New-Item -ItemType Directory -Force -Path $winShape | Out-Null
        # a real file so the guard is happy
        'hello' | Set-Content -LiteralPath (Join-Path $winShape 'app.txt') -Encoding UTF8
        $out = Join-Path ([IO.Path]::GetTempPath()) ('tcpk-out-' + [guid]::NewGuid().ToString('N').Substring(0,8))
        try {
            # If the pre-flight regex threw, this call would throw before returning any findings
            $rows = @(Invoke-TcpkAudit -Target $winShape -Acknowledge -OutDir $out -Quick 3>$null 2>$null)
            # Anything returned means the audit completed the pre-flight and reached the check loop
            $rows | Should -Not -BeNullOrEmpty
        } finally {
            if (Test-Path $out) { Remove-Item -Recurse -Force -ErrorAction SilentlyContinue $out }
            if (Test-Path (Split-Path $winShape -Parent -Resolve -ErrorAction SilentlyContinue)) {
                Remove-Item -Recurse -Force -ErrorAction SilentlyContinue (Split-Path $winShape -Parent | Split-Path -Parent | Split-Path -Parent)
            }
        }
    }
}
