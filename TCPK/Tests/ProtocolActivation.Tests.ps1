#requires -Version 5.1
# HKCR URI-activation surface: enumerate custom URI-scheme handlers and, crucially,
# attribute them to the AUDITED app -- only a handler whose command executable lives
# under the target path is the target's own registration (a machine-wide mailto: /
# ms-* handler must not be blamed on the target). Registry access is mocked so the
# test runs cross-platform without touching HKCR.

BeforeAll {
    $psd1 = Join-Path (Split-Path (Split-Path $PSCommandPath -Parent) -Parent) 'TCPK.psd1'
    Import-Module $psd1 -Force
}

Describe 'Test-TcpkProtocolHandlers -TargetPath attribution' {
    It 'reports only the handler whose command is under the target path' {
        $r = InModuleScope TCPK {
            Mock Assert-TcpkWindows { $true }
            Mock Get-ChildItem {
                @(
                    [pscustomobject]@{ PSChildName = 'myapp'; PSPath = 'Registry::HKEY_CLASSES_ROOT\myapp' }
                    [pscustomobject]@{ PSChildName = 'other'; PSPath = 'Registry::HKEY_CLASSES_ROOT\other' }
                )
            }
            Mock Get-ItemProperty { [pscustomobject]@{ 'URL Protocol' = '' } } -ParameterFilter { $Name -eq 'URL Protocol' }
            Mock Get-ItemProperty {
                if ("$LiteralPath" -match 'myapp') { [pscustomobject]@{ '(default)' = '"C:\Target\app.exe" %1' } }
                else                               { [pscustomobject]@{ '(default)' = '"C:\Other\x.exe" %1' } }
            } -ParameterFilter { "$LiteralPath" -like '*shell\open\command*' }

            @(Test-TcpkProtocolHandlers -TargetPath 'C:\Target')
        }
        $ph = @($r | Where-Object { $_.RuleId -eq 'protocol-handler' })
        $ph.Count | Should -Be 1
        $ph[0].Title | Should -Match 'myapp://'
        $ph[0].Severity | Should -Be 'HIGH'   # unquoted %1 -> argv injection
    }

    It 'frames the handler as a remote-trigger URI-activation entry point' {
        $r = InModuleScope TCPK {
            Mock Assert-TcpkWindows { $true }
            Mock Get-ChildItem { @([pscustomobject]@{ PSChildName = 'myapp'; PSPath = 'Registry::HKEY_CLASSES_ROOT\myapp' }) }
            Mock Get-ItemProperty { [pscustomobject]@{ 'URL Protocol' = '' } } -ParameterFilter { $Name -eq 'URL Protocol' }
            Mock Get-ItemProperty { [pscustomobject]@{ '(default)' = '"C:\Target\app.exe" "%1"' } } -ParameterFilter { "$LiteralPath" -like '*shell\open\command*' }
            @(Test-TcpkProtocolHandlers -TargetPath 'C:\Target')
        }
        $ph = @($r | Where-Object { $_.RuleId -eq 'protocol-handler' })
        $ph.Count | Should -Be 1
        $ph[0].Severity    | Should -Be 'MEDIUM'   # quoted %1 -> no argv injection, still an activation surface
        $ph[0].Description | Should -Match 'REMOTE-TRIGGER'
    }
}
