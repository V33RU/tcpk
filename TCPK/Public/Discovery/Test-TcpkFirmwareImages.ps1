function Test-TcpkFirmwareImages {
<#
.SYNOPSIS
    A49. Firmware images shipped inside a desktop companion app's install tree.

.DESCRIPTION
    A companion application that programs, updates or diagnoses a physical device usually
    carries the device's firmware next to itself: as a .bin, .hex, Motorola srec, DFU package,
    Nordic ZIP OTA image, or one of the newer container formats (uf2, esp32 flasher bundles).

    Presence is the signal. Firmware shipped in the install tree means an attacker with local
    write can plant a modified image and the desktop tool will happily flash it to the device.
    That is the seam the Evil PLC, TRITON and Havex work all traced.

    Signature verification is not decidable from the file alone, so this cmdlet reports the
    IMAGE and its resting DACL; the update-manifest / signature-verification check that
    consumes the finding is a separate concern.

    Header magic is read for the four formats where a single value settles it. Extension alone
    is unreliable (any .bin is a .bin) so a mismatch is called out rather than assumed to
    invalidate the finding.

.PARAMETER Path
    Install directory to scan.

.OUTPUTS
    [TcpkFinding]
#>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path)) { return }

    # Extensions worth surfacing. .img is deliberately out: too broadly used for disk images
    # unrelated to device firmware, and false positives on it swamp the real hits.
    $extRx = '\.(bin|hex|s(rec|19|28|37)|dfu|uf2|zip|fw|firmware|rom|elf|axf|out|iso9660)$'

    # Magic bytes for the formats where one value settles it. Intel HEX and Motorola SREC are
    # text formats and are identified by the first character rather than by binary magic.
    $magic = @(
        @{ Kind = 'UF2';        Off = 0;  Bytes = [byte[]]@(0x55, 0x46, 0x32, 0x0A) }        # "UF2\n"
        @{ Kind = 'DFU-suffix'; Off = -8; Bytes = [byte[]]@(0x55, 0x46, 0x44, 0x00) }        # 'UFD\0' at end of DFU
        @{ Kind = 'ELF';        Off = 0;  Bytes = [byte[]]@(0x7F, 0x45, 0x4C, 0x46) }        # 7F 'ELF'
        @{ Kind = 'ZIP';        Off = 0;  Bytes = [byte[]]@(0x50, 0x4B, 0x03, 0x04) }        # 'PK\x03\x04' (Nordic OTA, ESP flashbundle)
    )

    $files = @()
    try {
        $files = Get-ChildItem -LiteralPath $Path -Recurse -File -ErrorAction SilentlyContinue |
                 Where-Object { $_.Extension -and ($_.Name -imatch $extRx) }
    } catch { return }

    foreach ($f in $files) {
        $ext = $f.Extension.ToLowerInvariant().TrimStart('.')
        $len = $f.Length
        if ($len -lt 16) { continue }

        $kind = $null; $mismatch = $false
        try {
            $fs = [IO.File]::OpenRead($f.FullName)
            try {
                $head = New-Object 'byte[]' 16
                [void]$fs.Read($head, 0, [Math]::Min(16, $len))
                # SREC and Intel HEX are ASCII, first char is 'S' or ':' respectively
                if ($ext -in 'srec','s19','s28','s37' -and $head[0] -eq 0x53) { $kind = 'SREC' }
                elseif ($ext -eq 'hex' -and $head[0] -eq 0x3A) { $kind = 'IntelHEX' }
                else {
                    foreach ($m in $magic) {
                        $off = if ($m.Off -lt 0) { $len + $m.Off } else { $m.Off }
                        if ($off -lt 0 -or ($off + $m.Bytes.Length) -gt $len) { continue }
                        $buf = New-Object 'byte[]' $m.Bytes.Length
                        $fs.Position = $off
                        [void]$fs.Read($buf, 0, $m.Bytes.Length)
                        $ok = $true
                        for ($i = 0; $i -lt $m.Bytes.Length; $i++) { if ($buf[$i] -ne $m.Bytes[$i]) { $ok = $false; break } }
                        if ($ok) { $kind = $m.Kind; break }
                    }
                }
            } finally { $fs.Dispose() }
        } catch { continue }

        # A raw .bin has no magic by design, so extension is the only signal.
        if (-not $kind -and $ext -eq 'bin') { $kind = 'raw-bin' }
        # A .zip with no PK header is either not really a zip or corrupt: report but tag.
        if (-not $kind -and $ext -eq 'zip') { $mismatch = $true; $kind = 'zip-extension-only' }
        if (-not $kind) { continue }

        # World-writable resting DACL escalates. A vendor tool that flashes an image from a
        # directory every local user can write to is the plant-and-wait primitive stated.
        $writable = $false
        try {
            $acl = Get-Acl -LiteralPath $f.FullName -ErrorAction SilentlyContinue
            if ($acl) {
                foreach ($a in $acl.Access) {
                    if ("$($a.IdentityReference)" -match '(?i)Users|Everyone|Authenticated Users' -and
                        "$($a.FileSystemRights)" -match '(?i)Write|Modify|FullControl' -and
                        $a.AccessControlType -eq 'Allow') { $writable = $true; break }
                }
            }
        } catch { }

        $sev = if ($writable) { 'HIGH' } else { 'MEDIUM' }
        $rule = if ($writable) { 'firmware.image-writable' } else { 'firmware.image-shipped' }
        $evParts = @("kind=$kind", "ext=$ext", "size=$len")
        if ($mismatch) { $evParts += 'header=missing' }
        if ($writable) { $evParts += 'writable-by-users=true' }

        New-TcpkFinding -Module 'discovery' -RuleId $rule `
            -Severity $sev -Confidence 'Confirmed' `
            -Title "$($f.Name) is a device firmware image ($kind)" `
            -File $f.FullName -Evidence ($evParts -join ' ') `
            -Cwe @('CWE-494') `
            -Description ('A firmware image sits inside the install tree. If the desktop tool that flashes ' +
                'or updates a device reads its payload from this path without verifying a vendor signature, ' +
                'local write on this file becomes remote code on the device. This is the exact seam Evil PLC ' +
                'and TRITON traced from an engineering workstation into controller code.' +
                $(if ($writable) { ' The resting DACL grants write to a non-admin group, so no elevation is needed to plant a modified image.' } else { '' })) `
            -Fix ('Verify a vendor signature on every image before it is transmitted to the device, and ' +
                'restrict the image directory ACL to the installer identity (SYSTEM or the vendor service account). ' +
                'A code-signed image the desktop tool refuses to flash on signature failure closes the whole class.')
    }
}
