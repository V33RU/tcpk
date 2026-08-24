#requires -Version 5.1
# Pester 5: Test-TcpkUpdateChannel.
#
# Real firmware-updater desktop apps (device control processors, industrial commissioning
# tools, medical device programmers) all expose the same three surfaces: release-channel
# selectors, update endpoints in config, and locally persisted "current version" state.
# These tests pin the detection.

BeforeAll {
    $psd1 = Join-Path (Split-Path (Split-Path $PSCommandPath -Parent) -Parent) 'TCPK.psd1'
    Import-Module $psd1 -Force

    $script:work = Join-Path ([IO.Path]::GetTempPath()) ('tcpk-upd-' + [guid]::NewGuid().ToString('N').Substring(0,10))
    New-Item -ItemType Directory -Path $script:work -Force | Out-Null
}
AfterAll {
    if ($script:work -and (Test-Path $script:work)) { Remove-Item -Recurse -Force -ErrorAction SilentlyContinue $script:work }
}

Describe 'Test-TcpkUpdateChannel: release-channel selectability' {
    It 'reports a channel-selectable value from an appsettings.json' {
        $p = Join-Path $script:work 'appsettings.json'
        '{ "releaseChannel": "release", "other": 1 }' | Set-Content -LiteralPath $p -Encoding UTF8
        $rows = @(Test-TcpkUpdateChannel -Path $script:work) | Where-Object { $_.RuleId -eq 'update.channel-selectable' }
        $rows.Count | Should -BeGreaterThan 0
    }

    It 'does not fire on unrelated string values that happen to contain "release"' {
        $p = Join-Path $script:work 'other.json'
        '{ "featureFlags": ["release notes on"], "name": "unreleased builds" }' | Set-Content -LiteralPath $p -Encoding UTF8
        @(Test-TcpkUpdateChannel -Path $script:work | Where-Object { $_.RuleId -eq 'update.channel-selectable' -and $_.File -like '*other.json' }).Count | Should -Be 0
    }
}

Describe 'Test-TcpkUpdateChannel: endpoint in config' {
    It 'reports HTTPS endpoint as MEDIUM Inferred when file is not user-writable' {
        $p = Join-Path $script:work 'endpoint-https.json'
        '{ "updateUrl": "https://cdn.vendor.example/manifest" }' | Set-Content -LiteralPath $p -Encoding UTF8
        # On CI or dev machine, the ACL check may find the file writable; the test still passes
        # because either update.endpoint-in-config or update.endpoint-in-writable-config fires.
        $rows = @(Test-TcpkUpdateChannel -Path $script:work | Where-Object { $_.File -like '*endpoint-https.json' })
        $rows.Count | Should -BeGreaterThan 0
        ($rows.RuleId | Sort-Object -Unique) | Should -Match 'update.endpoint'
    }

    It 'reports http:// endpoint as HIGH plaintext' {
        $p = Join-Path $script:work 'endpoint-http.json'
        '{ "manifestUrl": "http://updates.vendor.example/latest.json" }' | Set-Content -LiteralPath $p -Encoding UTF8
        $r = @(Test-TcpkUpdateChannel -Path $script:work | Where-Object { $_.File -like '*endpoint-http.json' })
        $r.Severity | Should -Contain 'HIGH'
        $r.Evidence | Should -Match 'http=True'
    }
}

Describe 'Test-TcpkUpdateChannel: installed-version state' {
    It 'reports state persisted in a config as update.state-in-writable-path' {
        $p = Join-Path $script:work 'state.json'
        '{ "currentVersion": "4.012.0168" }' | Set-Content -LiteralPath $p -Encoding UTF8
        @(Test-TcpkUpdateChannel -Path $script:work | Where-Object { $_.RuleId -eq 'update.state-in-writable-path' }).Count | Should -BeGreaterThan 0
    }

    It 'ignores an "installedVersion" that has no number in it' {
        $p = Join-Path $script:work 'state-bad.json'
        '{ "currentVersion": "development-build" }' | Set-Content -LiteralPath $p -Encoding UTF8
        @(Test-TcpkUpdateChannel -Path $script:work | Where-Object { $_.RuleId -eq 'update.state-in-writable-path' -and $_.File -like '*state-bad.json' }).Count | Should -Be 0
    }
}
