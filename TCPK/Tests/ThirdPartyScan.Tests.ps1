#requires -Version 5.1
# Opt-in scan of bundled third-party package code (Invoke-TcpkAudit -IncludeThirdParty).
# By default package code (Newtonsoft.*, log4net.*, libcrypto*, site-packages, node_modules) is
# skipped by the pattern checks; with the switch only the platform (System.*, Microsoft.*, C and
# browser runtimes) stays out, and every finding in package code names its package.

BeforeAll {
    $psd1 = Join-Path (Split-Path (Split-Path $PSCommandPath -Parent) -Parent) 'TCPK.psd1'
    Import-Module $psd1 -Force
    $script:work = Join-Path ([IO.Path]::GetTempPath()) ('tcpk-3p-' + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $script:work -Force | Out-Null

    function script:Set-ThirdParty([bool]$On) { & (Get-Module TCPK) { param($v) $script:TcpkIncludeThirdParty = $v } $On }
    function script:Invoke-InModule([scriptblock]$Block, [object[]]$ArgList = @()) { & (Get-Module TCPK) $Block @ArgList }

    # A PE-named file whose bytes carry a full PEM private key block (Test-TcpkKeyMaterial's rule).
    $b64 = [Convert]::ToBase64String((1..400 | ForEach-Object { [byte]($_ % 251) }))
    $pem = "-----BEGIN RSA PRIVATE KEY-----`n" + (($b64 -split '(.{64})' | Where-Object { $_ }) -join "`n") + "`n-----END RSA PRIVATE KEY-----"
    $script:keyDir = Join-Path $script:work 'keys'
    New-Item -ItemType Directory -Path $script:keyDir -Force | Out-Null
    [IO.File]::WriteAllText((Join-Path $script:keyDir 'Newtonsoft.Fake.dll'), "MZ padding $pem trailer")
    [IO.File]::WriteAllText((Join-Path $script:keyDir 'System.Fake.dll'), "MZ padding $pem trailer")

    # A Python package in site-packages that shells out with a request value.
    $script:pyDir = Join-Path $script:work 'py'
    $pkg = Join-Path $script:pyDir 'Lib/site-packages/badpkg'
    New-Item -ItemType Directory -Path $pkg -Force | Out-Null
    [IO.File]::WriteAllText((Join-Path $pkg 'runner.py'), "import os`nimport subprocess`ndef run(cmd):`n    subprocess.call(cmd, shell=True)`n    os.system(cmd)`n")
}

AfterAll {
    Set-ThirdParty $false
    if ($script:work -and (Test-Path -LiteralPath $script:work)) { try { [IO.Directory]::Delete($script:work, $true) } catch { } }
}

Describe 'Third-party package scanning (-IncludeThirdParty)' {
    AfterEach { Set-ThirdParty $false }

    Context 'classifiers' {
        It 'by default a package and the platform are both framework files' {
            Invoke-InModule { Test-TcpkIsFrameworkFile 'Newtonsoft.Json.dll' } | Should -BeTrue
            Invoke-InModule { Test-TcpkIsFrameworkFile 'System.Text.Json.dll' } | Should -BeTrue
        }
        It 'with the switch only the platform stays a framework file' {
            Set-ThirdParty $true
            Invoke-InModule { Test-TcpkIsFrameworkFile 'Newtonsoft.Json.dll' } | Should -BeFalse
            Invoke-InModule { Test-TcpkIsFrameworkFile 'log4net.dll' } | Should -BeFalse
            Invoke-InModule { Test-TcpkIsFrameworkFile 'System.Text.Json.dll' } | Should -BeTrue
            Invoke-InModule { Test-TcpkIsFrameworkFile 'Microsoft.Identity.Client.dll' } | Should -BeTrue
        }
        It 'a vendor config named after a package is never a framework file' {
            Invoke-InModule { Test-TcpkIsFrameworkFile 'NLog.config' } | Should -BeFalse
            Set-ThirdParty $true
            Invoke-InModule { Test-TcpkIsFrameworkFile 'NLog.config' } | Should -BeFalse
        }
        It 'native packages are lifted with the switch, C and browser runtimes are not' {
            Invoke-InModule { Test-TcpkIsNativeNoise 'libcrypto-3-x64.dll' } | Should -BeTrue
            Set-ThirdParty $true
            Invoke-InModule { Test-TcpkIsNativeNoise 'libcrypto-3-x64.dll' } | Should -BeFalse
            Invoke-InModule { Test-TcpkIsNativeNoise 'libsodium.dll' } | Should -BeFalse
            Invoke-InModule { Test-TcpkIsNativeNoise 'vcruntime140.dll' } | Should -BeTrue
            Invoke-InModule { Test-TcpkIsNativeNoise 'libcef.dll' } | Should -BeTrue
        }
    }

    Context 'origin label' {
        It '<File> belongs to <Want>' -ForEach @(
            @{ File = 'C:\app\Newtonsoft.Json.dll';                                   Want = 'Newtonsoft.Json' }
            @{ File = 'C:\app\libsodium.dll';                                         Want = 'libsodium' }
            @{ File = 'C:\app\resources\app\node_modules\left-pad\index.js';          Want = 'left-pad' }
            @{ File = 'C:\app\resources\app\node_modules\@scope\pkg\lib\x.js';        Want = '@scope/pkg' }
            @{ File = 'C:\app\node_modules\a\node_modules\b\index.js';                Want = 'b' }
            @{ File = 'C:\app\python\Lib\site-packages\requests\api.py';              Want = 'requests' }
            @{ File = 'C:\app\python\Lib\site-packages\six.py';                       Want = 'six' }
            @{ File = 'C:\app\Vendor.Core.dll';                                       Want = '' }
            @{ File = 'C:\app\System.Text.Json.dll';                                  Want = '' }
            @{ File = 'C:\app\NLog.config';                                           Want = '' }
            @{ File = '';                                                             Want = '' }
        ) {
            Invoke-InModule { param($f) Get-TcpkCodeOrigin $f } @($File) | Should -Be $Want
        }

        It 'a finding records its origin in every run, but only an -IncludeThirdParty run tags the title' {
            $off = Invoke-InModule { New-TcpkFinding -Module static -RuleId 'x.y' -Severity LOW -Title 't' -File 'C:\app\Newtonsoft.Json.dll' }
            $off.Origin | Should -Be 'Newtonsoft.Json'
            $off.Title  | Should -Be 't'
            Set-ThirdParty $true
            $on = Invoke-InModule { New-TcpkFinding -Module static -RuleId 'x.y' -Severity LOW -Title 't' -File 'C:\app\Newtonsoft.Json.dll' }
            $on.Title       | Should -Be 't (third-party package Newtonsoft.Json)'
            $on.Title       | Should -Not -Match ': '
            $on.Description | Should -Match 'did not check whether the application''s own code reaches'
        }

        It 'cloning a tagged finding does not tag it twice' {
            Set-ThirdParty $true
            $once = Invoke-InModule { New-TcpkFinding -Module static -RuleId 'x.y' -Severity LOW -Title 't' -File 'C:\app\Newtonsoft.Json.dll' }
            $twice = Invoke-InModule { param($t, $d) New-TcpkFinding -Module static -RuleId 'x.y' -Severity LOW -Title $t -Description $d -File '2 files' -Origin 'Newtonsoft.Json' } @($once.Title, $once.Description)
            $twice.Title | Should -Be $once.Title
            ([regex]::Matches($twice.Description, 'scanned because -IncludeThirdParty')).Count | Should -Be 1
        }

        It 'a vendor file gets no origin and no tag' {
            Set-ThirdParty $true
            $f = Invoke-InModule { New-TcpkFinding -Module static -RuleId 'x.y' -Severity LOW -Title 't' -File 'C:\app\Vendor.Core.dll' }
            $f.Origin | Should -Be ''
            $f.Title  | Should -Be 't'
        }
    }

    Context 'checks' {
        It 'key material in a package DLL is skipped by default and reported, labelled, with the switch' {
            @(Test-TcpkKeyMaterial -Path $script:keyDir | Where-Object { $_.File -match 'Newtonsoft' }).Count | Should -Be 0
            Set-ThirdParty $true
            $f = @(Test-TcpkKeyMaterial -Path $script:keyDir | Where-Object { $_.File -match 'Newtonsoft' })
            $f.Count | Should -BeGreaterThan 0
            $f[0].Origin | Should -Be 'Newtonsoft.Fake'
            $f[0].Title  | Should -Match 'third-party package Newtonsoft\.Fake'
            # the platform stays excluded
            @(Test-TcpkKeyMaterial -Path $script:keyDir | Where-Object { $_.File -match 'System\.Fake' }).Count | Should -Be 0
        }

        It 'a Python package in site-packages is skipped by default and scanned with the switch' {
            @(Test-TcpkPythonCallsites -Path $script:pyDir).Count | Should -Be 0
            Set-ThirdParty $true
            $f = @(Test-TcpkPythonCallsites -Path $script:pyDir)
            $f.Count | Should -BeGreaterThan 0
            @($f | Where-Object { $_.Origin -ne 'badpkg' }).Count | Should -Be 0
        }
    }

    Context 'aggregation and the audit switch' {
        It 'a package occurrence does not merge with the vendor''s own occurrence of the same rule' {
            $list = Invoke-InModule {
                @(
                    New-TcpkFinding -Module static -RuleId 'x.y' -Severity MEDIUM -Confidence Inferred -Title 't' -File 'C:\app\Vendor.Core.dll'
                    New-TcpkFinding -Module static -RuleId 'x.y' -Severity MEDIUM -Confidence Inferred -Title 't' -File 'C:\app\Vendor.Ui.dll'
                    New-TcpkFinding -Module static -RuleId 'x.y' -Severity MEDIUM -Confidence Inferred -Title 't' -File 'C:\app\Newtonsoft.Json.dll'
                )
            }
            $agg = @($list | Resolve-TcpkFindings -AggregateOnly)
            $agg.Count | Should -Be 2
            @($agg | Where-Object { $_.Origin -eq 'Newtonsoft.Json' }).Count | Should -Be 1
            @($agg | Where-Object { $_.Origin -eq '' }).Count | Should -Be 1
        }

        It 'Invoke-TcpkAudit has -IncludeThirdParty and the module flag is off by default' {
            (Get-Command Invoke-TcpkAudit).Parameters.ContainsKey('IncludeThirdParty') | Should -BeTrue
            Invoke-InModule { [bool]$script:TcpkIncludeThirdParty } | Should -BeFalse
        }
    }
}
