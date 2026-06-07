#requires -Version 5.1
# Native coverage: /GS stack-cookie detection in the hardening matrix, and the
# expanded SDL-banned CRT function set (catches the A/W-decorated Win32 unbounded
# helpers + the no-null-terminate printf family the old \bword\b pattern missed).

BeforeAll {
    $psd1 = Join-Path (Split-Path (Split-Path $PSCommandPath -Parent) -Parent) 'TCPK.psd1'
    Import-Module $psd1 -Force

    $script:work = Join-Path ([IO.Path]::GetTempPath()) ("tcpk-nat-" + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $script:work -Force | Out-Null

    $script:sys = 'C:\Windows\System32'
    # a freshly-compiled managed DLL has no native security cookie
    Add-Type -TypeDefinition 'public class Mgd { public int X(){ return 1; } }' -OutputAssembly (Join-Path $script:work 'Mgd.dll') -OutputType Library
}

AfterAll {
    if ($script:work -and (Test-Path -LiteralPath $script:work)) {
        try { [System.IO.Directory]::Delete($script:work, $true) } catch {}
    }
}

Describe '/GS stack-cookie detection (Read-TcpkPe + Get-TcpkPeHardening)' {
    It 'reports StackCookie=Yes for a /GS-built system DLL (kernel32)' {
        $k = Join-Path $script:sys 'kernel32.dll'
        if (-not (Test-Path $k)) { Set-ItResult -Skipped -Because 'kernel32.dll not present'; return }
        $pe = & (Get-Module TCPK) { param($p) Read-TcpkPe -Path $p } $k
        $pe.StackCookie | Should -Be 'Yes'
    }

    It 'reports StackCookie=No for a managed assembly (no native cookie)' {
        $pe = & (Get-Module TCPK) { param($p) Read-TcpkPe -Path $p } (Join-Path $script:work 'Mgd.dll')
        $pe.StackCookie | Should -Be 'No'
    }

    It 'surfaces a GS column in the hardening matrix' {
        $k = Join-Path $script:sys 'kernel32.dll'
        if (-not (Test-Path $k)) { Set-ItResult -Skipped -Because 'kernel32.dll not present'; return }
        $dst = Join-Path $script:work 'k.dll'; Copy-Item $k $dst -Force
        $h = & (Get-Module TCPK) { param($p) Get-TcpkPeHardening -Path $p } $dst
        $h.PSObject.Properties.Name | Should -Contain 'GS'
        $h.GS | Should -Be 'YES'
    }
}

Describe 'Expanded unsafe-CRT detection (Test-TcpkUnsafeNativeApis)' {
    It 'flags A/W-decorated Win32 unbounded string helpers the old pattern missed' {
        # shlwapi.dll references StrCpyW / StrCatW / wvsprintfW. Copy under a neutral
        # name so the framework/native-noise name filters do not skip it.
        $src = Join-Path $script:sys 'shlwapi.dll'
        if (-not (Test-Path $src)) { Set-ItResult -Skipped -Because 'shlwapi.dll not present'; return }
        $d = Join-Path $script:work 'crt'; New-Item -ItemType Directory -Path $d -Force | Out-Null
        Copy-Item $src (Join-Path $d 'vendorlib.dll') -Force
        $f = @(Test-TcpkUnsafeNativeApis -Path $d)
        $f.Count | Should -BeGreaterThan 0
        $f[0].RuleId | Should -Be 'native.unsafe-crt'
        # at least one of the newly-added decorated names must appear in the evidence
        $f[0].Evidence | Should -Match 'StrCpyW|StrCatW|wvsprintfW|_vsnprintf|_vsnwprintf'
    }
}
