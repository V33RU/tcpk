#requires -Version 5.1
# Pester 5: Test-TcpkCefSharp.
#
# Detection is a text scan of PE strings, so synthetic ASCII blobs that mimic what would sit
# in the .rdata / string heap of a real assembly cover it without a real DLL.

BeforeAll {
    $psd1 = Join-Path (Split-Path (Split-Path $PSCommandPath -Parent) -Parent) 'TCPK.psd1'
    Import-Module $psd1 -Force

    $script:work = Join-Path ([IO.Path]::GetTempPath()) ('tcpk-cef-' + [guid]::NewGuid().ToString('N').Substring(0, 12))
    New-Item -ItemType Directory -Path $script:work -Force | Out-Null

    function script:Make([string]$name, [string]$body) {
        $p = Join-Path $script:work $name
        [IO.File]::WriteAllBytes($p, [Text.Encoding]::ASCII.GetBytes($body))
        return $p
    }

    # A vendor assembly that registers a bridge object
    $script:bridge = script:Make 'Vendor.App.dll' 'ChromiumWebBrowser browser.RegisterJsObject nativeApi bridge exposed'
    # Turned on: remote debugging
    $script:dbg    = script:Make 'Vendor.App.RemoteDbg.dll' 'CefSettings RemoteDebuggingPort 9222 something'
    # Combined config disaster
    $script:combo  = script:Make 'Vendor.App.Combo.dll' 'ChromiumWebBrowser CefSharp RegisterAsyncJsObject WebSecurityDisabled true'
    # Just uses CefSharp with none of the flags
    $script:plain  = script:Make 'Vendor.App.Plain.dll' 'ChromiumWebBrowser sample host CefSharp v100'
    # Doesn't use CEF at all
    $script:none   = script:Make 'Vendor.App.None.dll'  'System.Windows.Forms.Button ordinary WinForms application'
    # CefSharp itself: first-party, should never be reported
    $script:self   = script:Make 'CefSharp.Core.dll' 'RegisterJsObject WebSecurityDisabled RemoteDebuggingPort all here'
}

AfterAll {
    if ($script:work -and (Test-Path $script:work)) { Remove-Item -Recurse -Force -ErrorAction SilentlyContinue $script:work }
}

Describe 'Test-TcpkCefSharp' {
    It 'reports a bridge registration as HIGH Confirmed' {
        InModuleScope TCPK -Parameters @{ p = $script:bridge } {
            param($p)
            $rows = @(Test-TcpkCefSharp -Path $p)
            $r = $rows | Where-Object { $_.RuleId -eq 'cef.js-bridge-registered' }
            $r | Should -Not -BeNullOrEmpty
            $r.Severity | Should -Be 'HIGH'
            $r.Confidence | Should -Be 'Confirmed'
        }
    }

    It 'reports remote debugging as HIGH Inferred' {
        InModuleScope TCPK -Parameters @{ p = $script:dbg } {
            param($p)
            $r = @(Test-TcpkCefSharp -Path $p) | Where-Object { $_.RuleId -eq 'cef.remote-debugging-enabled' }
            $r.Severity | Should -Be 'HIGH'
        }
    }

    It 'reports both bridge and web-security disabled from one binary' {
        InModuleScope TCPK -Parameters @{ p = $script:combo } {
            param($p)
            $ids = @(Test-TcpkCefSharp -Path $p | ForEach-Object RuleId)
            $ids | Should -Contain 'cef.js-bridge-registered'
            $ids | Should -Contain 'cef.web-security-disabled'
            # And NOT the scope-only INFO, since higher findings fired
            $ids | Should -Not -Contain 'cef.uses-cefsharp'
        }
    }

    It 'emits the scope-only INFO exactly when nothing higher fired' {
        InModuleScope TCPK -Parameters @{ p = $script:plain } {
            param($p)
            $rows = @(Test-TcpkCefSharp -Path $p)
            $rows.Count | Should -Be 1
            $rows[0].RuleId | Should -Be 'cef.uses-cefsharp'
            $rows[0].Severity | Should -Be 'INFO'
        }
    }

    It 'never reports a binary that does not reference CEF' {
        InModuleScope TCPK -Parameters @{ p = $script:none } {
            param($p)
            @(Test-TcpkCefSharp -Path $p).Count | Should -Be 0
        }
    }

    It 'skips first-party CefSharp assemblies even when they contain every marker' {
        # The strings sit inside CefSharp.dll itself; reporting them there is noise.
        InModuleScope TCPK -Parameters @{ p = $script:self } {
            param($p)
            @(Test-TcpkCefSharp -Path $p).Count | Should -Be 0
        }
    }

    It 'deduplicates a repeated API string from the same file' {
        InModuleScope TCPK -Parameters @{ w = $script:work } {
            param($w)
            $spam = Join-Path $w 'Vendor.App.Spam.dll'
            [IO.File]::WriteAllBytes($spam, [Text.Encoding]::ASCII.GetBytes(('ChromiumWebBrowser RegisterJsObject ' * 20)))
            $rows = @(Test-TcpkCefSharp -Path $spam | Where-Object { $_.RuleId -eq 'cef.js-bridge-registered' })
            $rows.Count | Should -Be 1
        }
    }
}
