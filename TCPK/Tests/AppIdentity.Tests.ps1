#requires -Version 5.1
# Pester 5: Get-TcpkAppIdentity -- the fast pre-audit "what kind of app is this" fingerprint
# surfaced in the GUI / web panel / agentic workbench before an audit runs. Offline (no network).

BeforeAll {
    $psd1 = Join-Path (Split-Path (Split-Path $PSCommandPath -Parent) -Parent) 'TCPK.psd1'
    Import-Module $psd1 -Force
    $script:fx = Join-Path $env:TEMP ('tcpk-ident-' + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $script:fx | Out-Null
    # a lone .exe with no managed markers -> should classify as a native Win32 app
    Set-Content -LiteralPath (Join-Path $script:fx 'DemoApp.exe') -Value 'MZ stub' -Encoding ASCII
}
AfterAll {
    if ($script:fx -and (Test-Path $script:fx)) { Remove-Item $script:fx -Recurse -Force -ErrorAction SilentlyContinue }
}

Describe 'Get-TcpkAppIdentity - pre-audit fingerprint' {
    It 'returns a concise identity object with a one-line Summary' {
        $id = Get-TcpkAppIdentity -Path $script:fx
        $id                             | Should -Not -BeNullOrEmpty
        $id.AppType                     | Should -Not -BeNullOrEmpty
        $id.Runtime                     | Should -Not -BeNullOrEmpty
        "$($id.Summary)"                | Should -Match '\|'   # "Type | Runtime ..." shape
        $id.PSObject.Properties.Name    | Should -Contain 'Managed'
        $id.PSObject.Properties.Name    | Should -Contain 'SignatureStatus'
    }
    It 'classifies a lone unmanaged .exe as a native Win32 app' {
        $id = Get-TcpkAppIdentity -Path $script:fx
        $id.AppType  | Should -Be 'Win32 application'
        $id.Runtime  | Should -Be 'Native (C/C++)'
        $id.Managed  | Should -BeFalse
    }
    It 'is exported as a public cmdlet' {
        Get-Command Get-TcpkAppIdentity -ErrorAction SilentlyContinue | Should -Not -BeNullOrEmpty
    }
}
