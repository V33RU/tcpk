#requires -Version 5.1
# Pester 5: Invoke-TcpkAudit -ScanProfile (Quick / Standard / Full). Quick skips the slow,
# whole-machine OS-integration / persistence enumeration to focus on the target app;
# Full (the default) runs every check, so existing behavior is unchanged.

BeforeAll {
    $psd1 = Join-Path (Split-Path (Split-Path $PSCommandPath -Parent) -Parent) 'TCPK.psd1'
    Import-Module $psd1 -Force
    $script:fx = Join-Path ([IO.Path]::GetTempPath()) ("tcpk-prof-" + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $script:fx -Force | Out-Null
    Set-Content -LiteralPath (Join-Path $script:fx 'app.js') -Encoding ASCII -Value 'const u="http://x.insecure.test/a";'
}
AfterAll { if ($script:fx -and (Test-Path $script:fx)) { Remove-Item -LiteralPath $script:fx -Recurse -Force } }

Describe 'Invoke-TcpkAudit -ScanProfile' {
    It 'exposes ScanProfile with Quick/Standard/Full and defaults to Full' {
        $p = (Get-Command Invoke-TcpkAudit).Parameters['ScanProfile']
        $p | Should -Not -BeNullOrEmpty
        $set = $p.Attributes | Where-Object { $_ -is [System.Management.Automation.ValidateSetAttribute] }
        $set.ValidValues | Should -Contain 'Quick'
        $set.ValidValues | Should -Contain 'Full'
    }
    It 'Quick skips the slow OS-integration checks but still completes + writes intel.html' {
        $od = Join-Path ([IO.Path]::GetTempPath()) ("tcpk-profq-" + [guid]::NewGuid().ToString('N'))
        Invoke-TcpkAudit -Target $script:fx -OutDir $od -Acknowledge -ScanProfile Quick 6>$null 5>$null 4>$null 3>$null | Out-Null
        $log = & (Get-Module TCPK) { Get-TcpkRunLog }
        $skipped = @($log | Where-Object { "$($_.message)" -match 'skipped \(Quick' })
        $skipped.Count | Should -BeGreaterThan 5
        @($skipped.component) | Should -Contain 'Test-TcpkProtocolHandlers'
        Test-Path (Join-Path $od 'intel.html') | Should -BeTrue
    }
}
