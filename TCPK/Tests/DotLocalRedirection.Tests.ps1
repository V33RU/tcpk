#requires -Version 5.1
# A52 DotLocal (.local) DLL redirection. This detector is pure filesystem (no IL, no live
# process), so the fixture and the test run everywhere - no Cecil/Desktop gate needed.
# Guards: a '<module>.exe/.dll' + '.local' FILE or DIRECTORY next to a binary is flagged
# dllredirect.dotlocal (MEDIUM, Confirmed); a '.local' whose base is not a module is ignored.
# Added 2026-10-15: this detector (commit aecc3c9) shipped without a fixture.

BeforeAll {
    $psd1 = Join-Path (Split-Path (Split-Path $PSCommandPath -Parent) -Parent) 'TCPK.psd1'
    Import-Module $psd1 -Force

    $script:work = Join-Path ([IO.Path]::GetTempPath()) ("tcpk-dotlocal-" + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $script:work -Force | Out-Null
    # a .local FILE redirecting an exe, a .local DIRECTORY redirecting a dll, and a non-module .local
    New-Item -ItemType File      -Path (Join-Path $script:work 'app.exe.local')    -Force | Out-Null
    New-Item -ItemType Directory -Path (Join-Path $script:work 'plugin.dll.local') -Force | Out-Null
    New-Item -ItemType File      -Path (Join-Path $script:work 'notes.local')      -Force | Out-Null

    $script:f = @(Test-TcpkDotLocalRedirection -Path $script:work)
}

AfterAll {
    if ($script:work -and (Test-Path -LiteralPath $script:work)) {
        try { [System.IO.Directory]::Delete($script:work, $true) } catch {}
    }
}

Describe 'Test-TcpkDotLocalRedirection (A52)' {

    It 'flags a .local FILE redirecting an .exe (MEDIUM, Confirmed)' {
        $m = @($script:f | Where-Object { $_.RuleId -eq 'dllredirect.dotlocal' -and $_.File -like '*app.exe.local' })
        $m | Should -Not -BeNullOrEmpty
        $m[0].Severity   | Should -Be 'MEDIUM'
        $m[0].Confidence | Should -Be 'Confirmed'
        $m[0].Title      | Should -BeLike '*app.exe*'
    }

    It 'flags a .local DIRECTORY redirecting a .dll' {
        ($script:f | Where-Object { $_.RuleId -eq 'dllredirect.dotlocal' -and $_.File -like '*plugin.dll.local' }) |
            Should -Not -BeNullOrEmpty
    }

    It 'ignores a .local whose base is not a module (notes.local)' {
        ($script:f | Where-Object { $_.File -like '*notes.local' }) | Should -BeNullOrEmpty
    }

    It 'emits exactly the two module redirections' {
        @($script:f | Where-Object { $_.RuleId -eq 'dllredirect.dotlocal' }).Count | Should -Be 2
    }

    It 'carries established-footprint attribution (shipped in the target tree)' {
        $m = @($script:f | Where-Object { $_.RuleId -eq 'dllredirect.dotlocal' })[0]
        $m.AttributionBasis | Should -Be 'established-footprint'
    }
}
