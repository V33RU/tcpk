#requires -Version 5.1
# Pester 5: Test-TcpkQtSurface. All fixtures are synthetic and built in the temp dir --
# no real-world blobs, no vendor names, no real hosts. Everything here is offline and
# cross-platform (nothing depends on a Windows ACL or on a real PE header, because the
# QProcess scan reads mangled symbol STRINGS, not the import table).

BeforeAll {
    $psd1 = Join-Path (Split-Path (Split-Path $PSCommandPath -Parent) -Parent) 'TCPK.psd1'
    Import-Module $psd1 -Force

    # The one value the redaction assertions hunt for. Deliberately high-entropy so it
    # cannot collide with anything the module emits on its own.
    $script:secret = 'Zx9Qw4Rt7Lm2Ns5Kd8Pv'

    $script:root = Join-Path ([System.IO.Path]::GetTempPath()) ("tcpk-qt-" + [guid]::NewGuid().ToString('N').Substring(0, 8))
    New-Item -ItemType Directory -Path $script:root -Force | Out-Null
    New-Item -ItemType Directory -Path (Join-Path $script:root 'settings')  -Force | Out-Null
    New-Item -ItemType Directory -Path (Join-Path $script:root 'qml')       -Force | Out-Null
    New-Item -ItemType Directory -Path (Join-Path $script:root 'resources') -Force | Out-Null

    # --- Qt runtime marker (makes the target "a Qt app") -----------------------------
    Set-Content -LiteralPath (Join-Path $script:root 'Qt6Core.dll') -Encoding ASCII -Value 'MZ stub Qt6Core'

    # --- bundled Chromium, with a recoverable version --------------------------------
    Set-Content -LiteralPath (Join-Path $script:root 'Qt6WebEngineCore.dll') -Encoding ASCII -Value @'
MZ stub
AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.5615.213 Safari/537.36
QtWebEngine/6.5.0
'@

    # --- first-party binary using the single-string QProcess command API --------------
    # MSVC-mangled QProcess::startCommand(const QString&, QIODevice::OpenMode).
    Set-Content -LiteralPath (Join-Path $script:root 'app.exe') -Encoding ASCII -Value @'
MZ stub
?startCommand@QProcess@@QEAAX_NAEBVQString@@W4OpenModeFlag@QIODevice@@@Z
'@

    # --- first-party binary using only the program + argument-list overload -----------
    Set-Content -LiteralPath (Join-Path $script:root 'helper.exe') -Encoding ASCII -Value @'
MZ stub
?start@QProcess@@QEAAXAEBVQString@@AEBV?$QList@VQString@@@@W4OpenModeFlag@QIODevice@@@Z
'@

    # --- QSettings INI backing store --------------------------------------------------
    $sec = $script:secret
    Set-Content -LiteralPath (Join-Path (Join-Path $script:root 'settings') 'app.ini') -Encoding ASCII -Value @"
[General]
language=en
SavePassword=true
password=$sec

[Server]
apiKey=CHANGEME
token=
"@

    # --- QML: one non-literal dynamic build, one literal, one remote source ------------
    Set-Content -LiteralPath (Join-Path (Join-Path $script:root 'qml') 'Main.qml') -Encoding ASCII -Value @'
import QtQuick 2.15
Item {
    function build(spec) {
        var o = Qt.createQmlObject(spec, parent, "dyn");
        return o;
    }
    Component.onCompleted: {
        var lit = Qt.createQmlObject("import QtQuick 2.15; Rectangle { width: 10 }", parent, "lit");
    }
    Loader { source: "http://qml.example.invalid/remote.qml" }
}
'@

    # --- compiled Qt resource bundle ---------------------------------------------------
    Set-Content -LiteralPath (Join-Path (Join-Path $script:root 'resources') 'app.rcc') -Encoding ASCII -Value 'qres binary resource stub'

    $script:res = @(Test-TcpkQtSurface -Path $script:root)
}

AfterAll {
    if ($script:root) { Remove-Item -LiteralPath $script:root -Recurse -Force -ErrorAction SilentlyContinue }
}

Describe 'Test-TcpkQtSurface' {

    Context 'gating' {
        It 'stays silent on a target with no Qt signal at all' {
            $empty = Join-Path ([System.IO.Path]::GetTempPath()) ("tcpk-qt-none-" + [guid]::NewGuid().ToString('N').Substring(0, 6))
            New-Item -ItemType Directory -Path $empty -Force | Out-Null
            try {
                Set-Content -LiteralPath (Join-Path $empty 'readme.txt') -Value 'not a Qt app'
                Set-Content -LiteralPath (Join-Path $empty 'app.ini')    -Value "[General]`npassword=whatever"
                @(Test-TcpkQtSurface -Path $empty).Count | Should -Be 0
            } finally { Remove-Item -LiteralPath $empty -Recurse -Force -ErrorAction SilentlyContinue }
        }

        It 'reports a Skipped finding instead of silence when the path is unreadable' {
            $missing = Join-Path ([System.IO.Path]::GetTempPath()) ("tcpk-qt-missing-" + [guid]::NewGuid().ToString('N').Substring(0, 6))
            $f = @(Test-TcpkQtSurface -Path $missing)
            $f.Count | Should -BeGreaterThan 0
            $f[0].RuleId     | Should -Be 'qt.path-unreadable'
            $f[0].Confidence | Should -Be 'Skipped'
        }

        It 'emits an inventory finding when Qt is detected and nothing fires' {
            $clean = Join-Path ([System.IO.Path]::GetTempPath()) ("tcpk-qt-clean-" + [guid]::NewGuid().ToString('N').Substring(0, 6))
            New-Item -ItemType Directory -Path $clean -Force | Out-Null
            try {
                Set-Content -LiteralPath (Join-Path $clean 'Qt6Core.dll') -Value 'MZ stub Qt6Core'
                Set-Content -LiteralPath (Join-Path $clean 'app.ini')     -Value "[General]`nlanguage=en"
                $f = @(Test-TcpkQtSurface -Path $clean)
                $f.Count | Should -Be 1
                $f[0].RuleId   | Should -Be 'qt.surface-inventory'
                $f[0].Severity | Should -Be 'INFO'
            } finally { Remove-Item -LiteralPath $clean -Recurse -Force -ErrorAction SilentlyContinue }
        }
    }

    Context 'QSettings credential storage' {
        It 'flags the stored credential value as HIGH' {
            $f = @($script:res | Where-Object RuleId -eq 'qt.qsettings-credential')
            $f.Count       | Should -Be 1
            $f[0].Severity | Should -Be 'HIGH'
            $f[0].Cwe      | Should -Contain 'CWE-256'
            $f[0].Cwe      | Should -Contain 'CWE-522'
            $f[0].Title    | Should -Match "key 'password'"
            $f[0].Evidence | Should -Match '\[General\]'
        }

        It 'never prints the raw secret in ANY field of ANY finding' {
            foreach ($x in $script:res) {
                $blob = @($x.Title, $x.Evidence, $x.Description, $x.Impact, $x.Fix, $x.File) -join "`n"
                $blob | Should -Not -Match ([regex]::Escape($script:secret))
            }
        }

        It 'masks the value but keeps enough shape to correlate' {
            $f = @($script:res | Where-Object RuleId -eq 'qt.qsettings-credential')[0]
            $f.Evidence | Should -Match '\*{4,}'
            $f.Evidence | Should -Match "len=$($script:secret.Length)"
        }

        It 'reports empty / placeholder credential keys at MEDIUM' {
            $f = @($script:res | Where-Object RuleId -eq 'qt.qsettings-credential-key')
            $f.Count | Should -Be 2
            ($f | ForEach-Object { $_.Severity } | Select-Object -Unique) | Should -Be 'MEDIUM'
            ($f | Where-Object { $_.Title -match "key 'apiKey'" }).Count | Should -Be 1
            ($f | Where-Object { $_.Title -match "key 'token'"  }).Count | Should -Be 1
        }

        It 'does not treat a boolean preference flag as a credential' {
            @($script:res | Where-Object { $_.Title -match 'SavePassword' }).Count | Should -Be 0
        }
    }

    Context 'QProcess surface' {
        It 'flags the single-string command overload at MEDIUM without claiming injection' {
            $f = @($script:res | Where-Object RuleId -eq 'qt.qprocess-string-command')
            $f.Count       | Should -Be 1
            $f[0].Severity | Should -Be 'MEDIUM'
            $f[0].Cwe      | Should -Contain 'CWE-78'
            $f[0].File     | Should -Match 'app\.exe$'
            $f[0].Evidence | Should -Match 'startCommand@QProcess'
            $f[0].Title    | Should -Match 'NOT proven'
        }

        It 'records the program + argument-list overload as INFO only' {
            $f = @($script:res | Where-Object { $_.RuleId -eq 'qt.qprocess-surface' -and $_.File -match 'helper\.exe$' })
            $f.Count       | Should -Be 1
            $f[0].Severity | Should -Be 'INFO'
        }

        It 'does not attribute the Qt runtime DLL''s own QProcess symbols to the app' {
            @($script:res | Where-Object { $_.RuleId -like 'qt.qprocess*' -and $_.File -match 'Qt6' }).Count | Should -Be 0
        }
    }

    Context 'Qt WebEngine' {
        It 'recovers the bundled Chromium version and states it as observed' {
            $f = @($script:res | Where-Object RuleId -eq 'qt.webengine-chromium')
            $f.Count       | Should -Be 1
            $f[0].Severity | Should -Be 'MEDIUM'
            $f[0].Cwe      | Should -Contain 'CWE-1395'
            $f[0].Title    | Should -Match 'Chrome/112\.0\.5615\.213'
            $f[0].Evidence | Should -Match 'QtWebEngine/6\.5\.0'
        }

        It 'falls back to a presence-only INFO when no version string is recoverable' {
            $nv = Join-Path ([System.IO.Path]::GetTempPath()) ("tcpk-qt-nover-" + [guid]::NewGuid().ToString('N').Substring(0, 6))
            New-Item -ItemType Directory -Path $nv -Force | Out-Null
            try {
                Set-Content -LiteralPath (Join-Path $nv 'Qt5WebEngineCore.dll') -Value 'MZ stub no version here'
                $f = @(Test-TcpkQtSurface -Path $nv | Where-Object RuleId -eq 'qt.webengine-present')
                $f.Count       | Should -Be 1
                $f[0].Severity | Should -Be 'INFO'
            } finally { Remove-Item -LiteralPath $nv -Recurse -Force -ErrorAction SilentlyContinue }
        }
    }

    Context 'QML dynamic loading' {
        It 'flags Qt.createQmlObject with a non-literal argument at MEDIUM' {
            $f = @($script:res | Where-Object RuleId -eq 'qt.qml-dynamic-eval')
            $f.Count       | Should -Be 1
            $f[0].Severity | Should -Be 'MEDIUM'
            $f[0].Cwe      | Should -Contain 'CWE-95'
            $f[0].Evidence | Should -Match 'Qt\.createQmlObject\(spec'
        }

        It 'separates the literal-argument call into its own LOW rule' {
            $f = @($script:res | Where-Object RuleId -eq 'qt.qml-dynamic-eval-literal')
            $f.Count       | Should -Be 1
            $f[0].Severity | Should -Be 'LOW'
        }

        It 'flags QML loaded from a cleartext network URL at HIGH' {
            $f = @($script:res | Where-Object RuleId -eq 'qt.qml-remote-source')
            $f.Count       | Should -Be 1
            $f[0].Severity | Should -Be 'HIGH'
            $f[0].Evidence | Should -Match 'remote\.qml'
        }
    }

    Context '.rcc inventory' {
        It 'inventories the compiled resource bundle without parsing it' {
            $f = @($script:res | Where-Object RuleId -eq 'qt.rcc-bundle')
            $f.Count       | Should -Be 1
            $f[0].Severity | Should -Be 'INFO'
            $f[0].File     | Should -Match 'app\.rcc$'
            $f[0].Fix      | Should -Match 'Unpack'
        }
    }

    Context 'finding hygiene' {
        It 'every finding carries a RuleId under the qt. prefix and an attribution basis' {
            foreach ($x in $script:res) {
                $x.RuleId           | Should -Match '^qt\.'
                $x.Module           | Should -Be 'static'
                $x.AttributionBasis | Should -Not -BeNullOrEmpty
            }
        }

        It 'uses no em dash anywhere in the emitted text' {
            foreach ($x in $script:res) {
                $blob = @($x.Title, $x.Evidence, $x.Description, $x.Impact, $x.Fix) -join "`n"
                $blob | Should -Not -Match ([char]0x2014)
            }
        }
    }
}
