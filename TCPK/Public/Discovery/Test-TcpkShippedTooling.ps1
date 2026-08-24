function Test-TcpkShippedTooling {
<#
.SYNOPSIS
    D09. Vendor / third-party device-programming CLIs shipped inside the install tree.

.DESCRIPTION
    Many companion apps ship a signed third-party CLI alongside their GUI: esptool for ESP32,
    STLINK-CLI or STM32CubeProgrammer for STM32, JLink for Segger targets, dfu-util for USB
    DFU, OpenOCD, nRF Util for Nordic, avrdude for AVR, and the various USB serial driver
    installers.

    That is a real primitive. A local attacker who reads the install tree does not need to
    build their own flashing chain: the vendor already ships one, code-signed, that talks to
    the physical device with the vendor's own protocol. If the app also ships firmware images
    (see firmware.image-shipped from Test-TcpkFirmwareImages) it is a two-line reproduction.

    Matches by executable name, not by hash. A recompile or a fork with the same filename
    still qualifies, which is the correct semantic here.

.PARAMETER Path
    Install directory to scan.

.OUTPUTS
    [TcpkFinding]
#>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path)) { return }

    # Filename plus a one-liner on what it does. Match is case-insensitive, exact stem plus .exe.
    $tools = @(
        @{ Name='esptool.exe';               Vendor='Espressif'; Function='ESP32 / ESP8266 flasher and secure-boot / eFuse writer' }
        @{ Name='espefuse.exe';              Vendor='Espressif'; Function='ESP32 eFuse programmer (writes secure-boot keys and permanent bits)' }
        @{ Name='espsecure.exe';             Vendor='Espressif'; Function='ESP32 image signer / secure-boot key handling' }
        @{ Name='ST-LINK_CLI.exe';           Vendor='STMicroelectronics'; Function='STM32 flasher and option-byte writer' }
        @{ Name='STM32_Programmer_CLI.exe';  Vendor='STMicroelectronics'; Function='STM32 unified programmer' }
        @{ Name='STVP_CmdLine.exe';          Vendor='STMicroelectronics'; Function='STM8 programmer' }
        @{ Name='JLink.exe';                 Vendor='SEGGER'; Function='J-Link CLI (any Cortex-M target with SWD/JTAG)' }
        @{ Name='JLinkExe.exe';              Vendor='SEGGER'; Function='J-Link CLI (any Cortex-M target with SWD/JTAG)' }
        @{ Name='JLinkGDBServer.exe';        Vendor='SEGGER'; Function='J-Link GDB server (arbitrary target debugging)' }
        @{ Name='openocd.exe';               Vendor='OpenOCD'; Function='On-chip debugger and flasher for many MCU families' }
        @{ Name='dfu-util.exe';              Vendor='dfu-util'; Function='USB DFU class-driver flasher' }
        @{ Name='avrdude.exe';               Vendor='avrdude'; Function='AVR / ATmega programmer' }
        @{ Name='nrfutil.exe';               Vendor='Nordic Semiconductor'; Function='nRF firmware packaging and DFU driver' }
        @{ Name='nrfjprog.exe';              Vendor='Nordic Semiconductor'; Function='nRF direct SWD flasher / eraser' }
        @{ Name='MSPFlasher.exe';            Vendor='Texas Instruments'; Function='MSP430 flasher' }
        @{ Name='UniFlash.exe';              Vendor='Texas Instruments'; Function='TI unified programmer (Sitara, MSP, Simplelink)' }
        @{ Name='cc2538-bsl.exe';            Vendor='Texas Instruments'; Function='CC2538 serial bootloader' }
        @{ Name='iomelt.exe';                Vendor='Realtek'; Function='Realtek 8710 flasher' }
        @{ Name='MOTIONNC.exe';              Vendor='Renesas'; Function='Renesas flash programmer' }
        @{ Name='RFP-CLI.exe';               Vendor='Renesas'; Function='Renesas RFP programmer CLI' }
        @{ Name='CH341A.exe';                Vendor='WCH'; Function='CH341A programmer (SPI flash)' }
        @{ Name='flashrom.exe';              Vendor='flashrom'; Function='SPI/LPC/FWH flash programmer' }
        @{ Name='mspdebug.exe';              Vendor='MSP430'; Function='MSP430 debugger and flasher' }
        @{ Name='pyocd.exe';                 Vendor='Arm'; Function='Cortex-M debug / flash over CMSIS-DAP' }
        @{ Name='pyocd-tool.exe';            Vendor='Arm'; Function='Cortex-M debug / flash over CMSIS-DAP' }
        @{ Name='ozone.exe';                 Vendor='SEGGER'; Function='J-Link debugger IDE' }
        @{ Name='usb-serial-installer.exe';  Vendor='various';  Function='USB serial driver installer, often SYSTEM-privileged' }
    )

    $byName = @{}
    foreach ($t in $tools) { $byName[$t.Name.ToLowerInvariant()] = $t }

    $files = @()
    try { $files = Get-ChildItem -LiteralPath $Path -Recurse -File -Filter *.exe -ErrorAction SilentlyContinue } catch { return }

    foreach ($f in $files) {
        $key = $f.Name.ToLowerInvariant()
        if (-not $byName.ContainsKey($key)) { continue }
        $t = $byName[$key]

        # Grade by function: fuse / secure-boot writers are HIGH, flashers MEDIUM, debuggers MEDIUM.
        # An eFuse writer that is invocable by a local user is not the same class as a serial driver installer.
        $sev = 'MEDIUM'
        if ($t.Function -match '(?i)fuse|secure-boot|option-byte|signer') { $sev = 'HIGH' }

        New-TcpkFinding -Module 'discovery' -RuleId 'devtool.shipped-cli' `
            -Severity $sev -Confidence 'Confirmed' `
            -Title "Vendor programming CLI shipped inside install tree: $($f.Name)" `
            -File $f.FullName -Evidence "vendor=$($t.Vendor)" `
            -Cwe @('CWE-506') `
            -Description ("The install tree ships the $($t.Vendor) $($f.Name), which is: " + $t.Function + ". " +
                "A local user (or any process able to read the install directory) has the vendor's own signed " +
                "tool available to talk to the physical device, using the vendor's own protocol. Combined with a " +
                "firmware image in the same tree (see firmware.image-shipped) this is a two-step reproduction of " +
                "a device compromise from any local account. This is not a defect in the tool; it is a threat-model " +
                "condition the vendor has probably not documented.") `
            -Fix ('Where the CLI is only used by the installer / updater, ship it outside the running install ' +
                'directory or remove it after install. Where the desktop GUI shells to it at runtime, ' +
                'restrict the containing directory ACL to the service account rather than allowing local users to run it.')
    }
}
