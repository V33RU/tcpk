#requires -Version 5.1
#
# Pester 5: Test-TcpkMsixVfs (B14) -- VFS redirections a Desktop Bridge package declares.
#
# WHY THIS CHECK EXISTS. TCPK shipped eleven MSIX cmdlets and twenty-four msix.* rules and
# never looked at the VFS directory, which is the package's own declaration of which system
# locations it overlays. It is the most target-shaped artifact in the packaging format: a
# static folder, chosen by the vendor, fixable by the vendor.
#
# WHAT IT IS NOT. A VFS folder is a supported, documented packaging feature and plenty of
# converted Win32 applications need one. The check reports what is mapped and how much
# executable content sits under each mapping; it does not claim the package is broken. The
# severity split exists for that reason: overlaying ProgramFiles is ordinary, overlaying
# System32 is not.

BeforeAll {
    Import-Module (Join-Path (Split-Path (Split-Path $PSCommandPath -Parent) -Parent) 'TCPK.psd1') -Force
    $script:root = Join-Path ([IO.Path]::GetTempPath()) ('tcpk-vfs-' + [guid]::NewGuid().ToString('N'))

    function New-Pkg([hashtable]$Vfs) {
        $p = Join-Path $script:root ([guid]::NewGuid().ToString('N').Substring(0,8))
        New-Item -ItemType Directory -Path $p -Force | Out-Null
        # A minimal manifest so the package looks real to anything that reads one.
        Set-Content -LiteralPath (Join-Path $p 'AppxManifest.xml') -Encoding UTF8 -Value `
            '<?xml version="1.0"?><Package><Identity Name="t" Publisher="CN=t" Version="1.0.0.0"/></Package>'
        foreach ($folder in $Vfs.Keys) {
            $d = Join-Path (Join-Path $p 'VFS') $folder
            New-Item -ItemType Directory -Path $d -Force | Out-Null
            foreach ($file in $Vfs[$folder]) {
                Set-Content -LiteralPath (Join-Path $d $file) -Value 'x' -Encoding ASCII
            }
        }
        return $p
    }
    function Rules($p) { return @(Test-TcpkMsixVfs -Path $p | Select-Object -ExpandProperty RuleId) }
}
AfterAll {
    if ($script:root -and (Test-Path $script:root)) { Remove-Item $script:root -Recurse -Force -ErrorAction SilentlyContinue }
}

Describe 'Test-TcpkMsixVfs' {

    It 'stays silent on a package with no VFS folder' {
        # The common case. Most packages have none and must produce nothing at all.
        $p = New-Pkg @{}
        @(Test-TcpkMsixVfs -Path $p) | Should -BeNullOrEmpty
    }

    It 'reports a data-tier mapping at LOW' {
        # Overlaying AppData is the ordinary shape for a converted application.
        $p = New-Pkg @{ 'Common AppData' = @('settings.ini') }
        $f = @(Test-TcpkMsixVfs -Path $p | Where-Object { $_.RuleId -eq 'msix.vfs-redirection' })
        $f | Should -Not -BeNullOrEmpty
        $f[0].Severity | Should -Be 'LOW'
    }

    It 'raises a system-tier mapping above a data-tier one' {
        $p = New-Pkg @{ 'SystemX64' = @('helper.txt') }
        $f = @(Test-TcpkMsixVfs -Path $p | Where-Object { $_.RuleId -eq 'msix.vfs-redirection' })
        $f[0].Severity | Should -Be 'MEDIUM'
    }

    It 'calls out executable content over a system location separately' {
        # A .txt under SystemX64 is worth knowing; a .dll is what the loader consumes.
        $p = New-Pkg @{ 'SystemX64' = @('shim.dll', 'notes.txt') }
        $r = Rules $p
        $r | Should -Contain 'msix.vfs-system-code'
        $f = @(Test-TcpkMsixVfs -Path $p | Where-Object { $_.RuleId -eq 'msix.vfs-system-code' })
        $f[0].Evidence | Should -Match '1 executable file'
    }

    It 'does NOT raise the code rule for a data-tier mapping holding a DLL' {
        # A DLL under AppData is not being served at a system path, so it is not this finding.
        $p = New-Pkg @{ 'LocalAppData' = @('plugin.dll') }
        Rules $p | Should -Not -Contain 'msix.vfs-system-code'
    }

    It 'treats an undocumented VFS folder name as system-tier, not as ignorable' {
        # The documented set has grown over time. A name outside it is more interesting,
        # not less, so it must not fall through as benign.
        $p = New-Pkg @{ 'SomeFutureFolder' = @('a.txt') }
        $f = @(Test-TcpkMsixVfs -Path $p | Where-Object { $_.RuleId -eq 'msix.vfs-redirection' })
        $f[0].Severity  | Should -Be 'MEDIUM'
        $f[0].Evidence  | Should -Match 'not a documented VFS folder name'
    }

    It 'names every mapping and its real target in the evidence' {
        $p = New-Pkg @{ 'SystemX64' = @('a.dll'); 'ProgramFilesX64' = @('b.txt') }
        $f = @(Test-TcpkMsixVfs -Path $p | Where-Object { $_.RuleId -eq 'msix.vfs-redirection' })
        $f[0].Evidence | Should -Match 'SystemX64 -> C:\\Windows\\System32'
        $f[0].Evidence | Should -Match 'ProgramFilesX64 -> C:\\Program Files'
    }

    It 'is exported and runs in the audit' {
        Get-Command Test-TcpkMsixVfs -ErrorAction SilentlyContinue | Should -Not -BeNullOrEmpty
        $audit = [IO.File]::ReadAllText((Join-Path (Split-Path (Split-Path $PSCommandPath -Parent) -Parent) 'Public\Invoke-TcpkAudit.ps1'))
        $audit | Should -Match "_RunCheck 'Test-TcpkMsixVfs'"
    }
}
