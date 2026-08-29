#requires -Version 5.1
# Pester 5: safety gates of Invoke-TcpkFirmwarePlantProbe.
#
# The observation half (ETW file trace, updater launch) needs Windows and admin, so it is
# out of scope for cross-platform CI. What CAN be pinned cross-platform is the ordering of
# refusals: the cmdlet must NEVER touch the firmware file until every gate is passed, since
# the failure mode of a mistake here is a modified firmware image with no restore.

BeforeAll {
    $psd1 = Join-Path (Split-Path (Split-Path $PSCommandPath -Parent) -Parent) 'TCPK.psd1'
    Import-Module $psd1 -Force

    $script:work = Join-Path ([IO.Path]::GetTempPath()) ('tcpk-fwp-' + [guid]::NewGuid().ToString('N').Substring(0,10))
    New-Item -ItemType Directory -Force -Path $script:work | Out-Null
    $script:fw = Join-Path $script:work 'test.bin'
    [IO.File]::WriteAllBytes($script:fw, [byte[]]@(0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08))
    $script:updater = Join-Path $script:work 'updater.exe'
    New-Item -ItemType File -Path $script:updater -Force | Out-Null
    $script:origHash = (Get-FileHash -LiteralPath $script:fw -Algorithm SHA256).Hash
}
AfterAll {
    if ($script:work -and (Test-Path $script:work)) { Remove-Item -Recurse -Force -ErrorAction SilentlyContinue $script:work }
}

Describe 'Invoke-TcpkFirmwarePlantProbe: gates' {
    It 'refuses to run without Enable-TcpkExploit -Acknowledge' {
        InModuleScope TCPK { $script:TcpkExploitEnabled = $false }
        { Invoke-TcpkFirmwarePlantProbe -FirmwarePath $script:fw -UpdaterPath $script:updater } |
            Should -Throw
    }

    It 'refuses to run without -ConfirmActive' {
        Enable-TcpkExploit -Acknowledge | Out-Null
        { Invoke-TcpkFirmwarePlantProbe -FirmwarePath $script:fw -UpdaterPath $script:updater } |
            Should -Throw -ExpectedMessage '*ConfirmActive*'
    }

    It 'refuses AppendMarker without -AllowDevicePresent' {
        Enable-TcpkExploit -Acknowledge | Out-Null
        { Invoke-TcpkFirmwarePlantProbe -FirmwarePath $script:fw -UpdaterPath $script:updater `
            -Mode AppendMarker -ConfirmActive } |
            Should -Throw -ExpectedMessage '*AllowDevicePresent*'
    }

    It 'leaves the firmware file byte-identical when a required gate rejects the call' {
        Enable-TcpkExploit -Acknowledge | Out-Null
        try { Invoke-TcpkFirmwarePlantProbe -FirmwarePath $script:fw -UpdaterPath $script:updater `
            -Mode AppendMarker -ConfirmActive } catch { }
        (Get-FileHash -LiteralPath $script:fw -Algorithm SHA256).Hash | Should -Be $script:origHash
    }
}

Describe 'Invoke-TcpkFirmwarePlantProbe: pre-flight refusals do not touch the file' {
    It 'reports firmware.plant.no-image when the firmware path does not exist' {
        Enable-TcpkExploit -Acknowledge | Out-Null
        $missing = Join-Path $script:work 'nope.bin'
        $rows = @(Invoke-TcpkFirmwarePlantProbe -FirmwarePath $missing -UpdaterPath $script:updater -ConfirmActive)
        ($rows | Where-Object { $_.RuleId -eq 'firmware.plant.no-image' }) | Should -Not -BeNullOrEmpty
    }

    It 'reports firmware.plant.no-updater when the updater path does not exist' {
        Enable-TcpkExploit -Acknowledge | Out-Null
        $missing = Join-Path $script:work 'no-updater.exe'
        $rows = @(Invoke-TcpkFirmwarePlantProbe -FirmwarePath $script:fw -UpdaterPath $missing -ConfirmActive)
        ($rows | Where-Object { $_.RuleId -eq 'firmware.plant.no-updater' }) | Should -Not -BeNullOrEmpty
    }
}
