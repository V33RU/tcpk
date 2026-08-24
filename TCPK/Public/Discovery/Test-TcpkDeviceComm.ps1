function Test-TcpkDeviceComm {
<#
.SYNOPSIS
    A50. Device-communication surface: serial (RS-232/CDC-ACM), USB HID/WinUSB, and BLE.

.DESCRIPTION
    A Windows companion application for a connected device talks to that device over one of a
    small number of physical channels. This cmdlet enumerates which channels a shipped binary
    is set up to use, from IL API references in .NET assemblies and imported symbol names in
    native PEs.

    The point is scoping. A tester who knows the app opens a serial port has a completely
    different threat model to one who knows it drives a BLE peripheral or flashes a signed
    firmware image over WinUSB. The tool currently sees zero of that.

    This is INFERENCE, deliberately. A reference in a binary is not proof the channel is used
    at runtime. Confidence is Inferred; a live intercept or an API trace closes it.

    Reported channels:
      serial    System.IO.Ports.SerialPort, native SetupComm/GetCommState/CreateFile of COMx
      usb-hid   HidDevice / HidD_GetHidGuid / SetupDiEnumDeviceInterfaces
      usb-winusb  WinUsb_ initialize / read / write
      usb-libusb  libusb / libusbK / libusb_open / libusb_control_transfer
      ble       BluetoothLEAdvertisementWatcher / GattDeviceService / BluetoothLEDevice
      bluetooth-classic  BluetoothClient / BluetoothRadio / SPP
      driver-io  DeviceIoControl with IOCTL codes (kernel driver contact)

.PARAMETER Path
    Install directory or single binary.

.OUTPUTS
    [TcpkFinding]
#>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    # Channel definitions: display kind, .NET / IL text markers, native PE import names, and
    # the threat-model paragraph. Extending the list is one entry.
    $channels = @(
        @{ Kind = 'serial';    Sev = 'MEDIUM'
           Needles = @('System.IO.Ports.SerialPort','SerialPort.Open','SerialPort.Write','SerialDevice.FromIdAsync')
           Imports = @('SetupComm','GetCommState','SetCommState','SetCommTimeouts','BuildCommDCB','CreateFileW','ClearCommError')
           Why = 'Framing and length handling on a serial link are the classic buffer-overflow / parser-confusion surface for embedded devices, and the desktop side owns the frames.' }
        @{ Kind = 'usb-hid';   Sev = 'MEDIUM'
           Needles = @('HidDevice.FromIdAsync','Windows.Devices.HumanInterfaceDevice','HidD_GetHidGuid')
           Imports = @('HidD_GetHidGuid','HidD_GetAttributes','HidP_GetCaps','HidD_SetOutputReport','HidD_GetFeature')
           Why = 'HID vendor collections carry arbitrary payloads. A companion tool writing feature reports is often the only side that validates length, and the device does not.' }
        @{ Kind = 'usb-winusb'; Sev = 'HIGH'
           Needles = @()
           Imports = @('WinUsb_Initialize','WinUsb_ReadPipe','WinUsb_WritePipe','WinUsb_ControlTransfer','WinUsb_SetPipePolicy')
           Why = 'WinUSB is the raw bulk/control channel used by vendor flashing utilities. The commands it issues are the firmware-update primitive.' }
        @{ Kind = 'usb-libusb'; Sev = 'HIGH'
           Needles = @()
           Imports = @('libusb_open','libusb_control_transfer','libusb_bulk_transfer','libusb_get_device_list')
           Why = 'libusb / libusbK is the cross-platform equivalent of WinUSB. Same threat model, same firmware-update primitive.' }
        @{ Kind = 'ble';       Sev = 'HIGH'
           Needles = @('BluetoothLEAdvertisementWatcher','BluetoothLEDevice','GattDeviceService','GattCharacteristic','BluetoothLEScanningMode')
           Imports = @('BluetoothGATTGetServices','BluetoothGATTSetCharacteristicValue','BluetoothFindFirstRadio')
           Why = 'BLE central-role apps commission and provision the device. Pairing bypass, characteristic write with no authorization, and MITM during pairing are the standard failures. The desktop client holds the pairing state.' }
        @{ Kind = 'bluetooth-classic'; Sev = 'MEDIUM'
           Needles = @('BluetoothClient','BluetoothRadio','BluetoothSecurity','BluetoothDeviceInfo')
           Imports = @('BluetoothAuthenticateDevice','BluetoothSetServiceState','BluetoothSdpGetContainerElementData')
           Why = 'Classic SPP profiles carry vendor protocols with authentication that is often optional. Pairing may be Just-Works.' }
        @{ Kind = 'driver-io'; Sev = 'MEDIUM'
           Needles = @('DeviceIoControl')
           Imports = @('DeviceIoControl','NtDeviceIoControlFile')
           Why = 'DeviceIoControl calls a kernel driver directly. Vendor drivers are the standard bring-your-own-vulnerable-driver primitive; the IOCTL codes issued here are worth reviewing.' }
    )

    # File set: the install directory recursively, or one file.
    $items = @()
    if (-not (Test-Path -LiteralPath $Path)) { return }
    if ((Get-Item -LiteralPath $Path).PSIsContainer) {
        try { $items = @(Get-TcpkPeFiles -Path $Path) } catch { return }
    } else {
        try { $items = @([IO.FileInfo]::new((Resolve-Path -LiteralPath $Path).Path)) } catch { return }
    }

    foreach ($pe in $items) {
        if (Test-TcpkIsFrameworkFile $pe.Name) { continue }

        $text = Read-TcpkAllText -Path $pe.FullName
        if (-not $text) { continue }

        foreach ($c in $channels) {
            $hitTerms = New-Object 'System.Collections.Generic.List[string]'
            foreach ($n in $c.Needles) {
                $count = ([regex]::Matches($text, [regex]::Escape($n))).Count
                if ($count -gt 0) { $hitTerms.Add("$n(x$count)") }
            }
            foreach ($imp in $c.Imports) {
                # Import names are ASCII in a PE import table and appear literally in the file.
                # Word-boundary keeps 'CreateFileW' from matching inside 'MyCreateFileWrapper'.
                if ([regex]::IsMatch($text, '(?<![A-Za-z0-9_])' + [regex]::Escape($imp) + '(?![A-Za-z0-9_])')) {
                    $hitTerms.Add("$imp(imp)")
                }
            }
            if ($hitTerms.Count -eq 0) { continue }

            $rule = "devcomm.$($c.Kind)"
            New-TcpkFinding -Module 'discovery' -RuleId $rule `
                -Severity $c.Sev -Confidence 'Inferred' `
                -Title "$($pe.Name) references the $($c.Kind) device-communication surface" `
                -File $pe.FullName -Evidence (($hitTerms | Select-Object -First 6) -join ', ') `
                -Description ("The binary contains references consistent with talking to a device over the " +
                    "$($c.Kind) channel. " + $c.Why + " A runtime trace (Invoke-TcpkApiTrace or a pcap) " +
                    "promotes this to Confirmed and reveals the actual command set.") `
                -Fix 'No fix required. This is scope information for the operator: run channel-appropriate follow-up checks (SerialPort framing review, BLE pairing model, DeviceIoControl IOCTL enumeration).'
        }
    }
}
