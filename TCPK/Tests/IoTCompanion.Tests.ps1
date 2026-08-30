#requires -Version 5.1
# Pester 5: the four IoT-companion detectors.
#
# All four read files off disk and pattern-match, so synthetic inputs cover them without needing
# a real Windows binary. The behaviour that matters most is the NEGATIVE one: a firmware
# extension without the header magic must not match, and a match against an unrelated file must
# not fire. That is the class of defect these detectors will introduce first.

BeforeAll {
    $psd1 = Join-Path (Split-Path (Split-Path $PSCommandPath -Parent) -Parent) 'TCPK.psd1'
    Import-Module $psd1 -Force

    $script:work = Join-Path ([IO.Path]::GetTempPath()) ('tcpk-iot-' + [guid]::NewGuid().ToString('N').Substring(0, 12))
    New-Item -ItemType Directory -Path $script:work -Force | Out-Null

    # Synthetic firmware images with real header magic
    $uf2 = New-Object 'byte[]' 512
    [Array]::Copy([byte[]]@(0x55,0x46,0x32,0x0A), $uf2, 4)
    [IO.File]::WriteAllBytes((Join-Path $script:work 'boot.uf2'), $uf2)

    $elf = New-Object 'byte[]' 2048
    [Array]::Copy([byte[]]@(0x7F,0x45,0x4C,0x46), $elf, 4)
    [IO.File]::WriteAllBytes((Join-Path $script:work 'firmware.elf'), $elf)

    $srec = ':10010000214601360121470136007EFE09D2190140' + [Environment]::NewLine
    [IO.File]::WriteAllText((Join-Path $script:work 'image.hex'), $srec)

    # Not firmware: a text file with a .bin extension SHOULD still be reported as raw-bin
    [IO.File]::WriteAllText((Join-Path $script:work 'not-firmware.bin'), 'hello world hello world hello world')

    # An unrelated text file with no relevant extension: must never appear
    [IO.File]::WriteAllText((Join-Path $script:work 'README.txt'), 'nothing to see')

    # A vendor CLI, but empty; the check is name-based
    New-Item -ItemType File -Path (Join-Path $script:work 'esptool.exe') -Force | Out-Null
    New-Item -ItemType File -Path (Join-Path $script:work 'espefuse.exe') -Force | Out-Null

    # A regular exe that should not match the tool table
    New-Item -ItemType File -Path (Join-Path $script:work 'MyApp.exe') -Force | Out-Null
}

AfterAll {
    if ($script:work -and (Test-Path $script:work)) { Remove-Item -Recurse -Force $script:work -ErrorAction SilentlyContinue }
}

Describe 'Test-TcpkFirmwareImages' {
    It 'reports the UF2 by its magic, not by its extension alone' {
        $f = @(Test-TcpkFirmwareImages -Path $script:work | Where-Object { $_.File -like '*boot.uf2' })
        $f.Count | Should -Be 1
        $f[0].RuleId | Should -Be 'firmware.image-shipped'
        $f[0].Evidence | Should -Match 'kind=UF2'
    }

    It 'grades firmware.image-shipped as Inferred (file existence Confirmed, attack primitive is inference)' {
        # Attribution ladder: this rule proves the file exists. It does not prove the vendor
        # updater reads it or flashes it unsigned. Confidence is Inferred; Invoke-TcpkFirmwarePlantProbe (K25)
        # promotes to Confirmed (dynamic) when the read is observed.
        $f = @(Test-TcpkFirmwareImages -Path $script:work | Where-Object { $_.RuleId -eq 'firmware.image-shipped' })
        $f.Count | Should -BeGreaterThan 0
        foreach ($row in $f) { $row.Confidence | Should -Be 'Inferred' }
    }

    It 'reports the ELF and the Intel HEX text file' {
        $rows = @(Test-TcpkFirmwareImages -Path $script:work)
        ($rows | Where-Object { $_.File -like '*firmware.elf' }).Evidence | Should -Match 'kind=ELF'
        ($rows | Where-Object { $_.File -like '*image.hex' }).Evidence  | Should -Match 'kind=IntelHEX'
    }

    It 'reports a plain .bin as raw-bin (no magic exists for it)' {
        (Test-TcpkFirmwareImages -Path $script:work | Where-Object { $_.File -like '*not-firmware.bin' }).Evidence |
            Should -Match 'kind=raw-bin'
    }

    It 'never reports an unrelated file' {
        @(Test-TcpkFirmwareImages -Path $script:work | Where-Object { $_.File -like '*README.txt' }).Count | Should -Be 0
    }
}

Describe 'Test-TcpkShippedTooling' {
    It 'reports esptool as MEDIUM (flasher) and espefuse as HIGH (fuse writer)' {
        $rows = @(Test-TcpkShippedTooling -Path $script:work)
        ($rows | Where-Object { $_.File -like '*esptool.exe' }).Severity | Should -Be 'MEDIUM'
        ($rows | Where-Object { $_.File -like '*espefuse.exe' }).Severity | Should -Be 'HIGH'
    }

    It 'ignores a name that is not on the known-tool list' {
        @(Test-TcpkShippedTooling -Path $script:work | Where-Object { $_.File -like '*MyApp.exe' }).Count | Should -Be 0
    }

    It 'names the vendor in the evidence, so a report is attributable' {
        (Test-TcpkShippedTooling -Path $script:work | Where-Object { $_.File -like '*esptool.exe' }).Evidence |
            Should -Match 'vendor=Espressif'
    }
}

Describe 'Test-TcpkDeviceComm: synthetic PE-like blob' {
    BeforeAll {
        # A file with ASCII import names, which is how a real PE stores them. The regex in the
        # cmdlet is text-based, so this is enough to exercise the detection.
        $blob = "any prefix bytes here `0 WinUsb_Initialize `0 WinUsb_ControlTransfer `0 tail"
        $script:winusbFile = Join-Path $script:work 'usb-fake.dll'
        [IO.File]::WriteAllBytes($script:winusbFile, [Text.Encoding]::ASCII.GetBytes($blob))
    }

    It 'reports the usb-winusb channel and no others when only WinUsb symbols are present' {
        InModuleScope TCPK -Parameters @{ p = $script:winusbFile } {
            param($p)
            $rows = @(Test-TcpkDeviceComm -Path $p)
            $kinds = @($rows | ForEach-Object { $_.RuleId })
            $kinds | Should -Contain 'devcomm.usb-winusb'
            @($kinds | Where-Object { $_ -eq 'devcomm.ble' }).Count | Should -Be 0
        }
    }
}
