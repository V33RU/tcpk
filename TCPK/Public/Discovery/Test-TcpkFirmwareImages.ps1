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

        $sev  = if ($writable) { 'HIGH' } else { 'MEDIUM' }
        $rule = if ($writable) { 'firmware.image-writable' } else { 'firmware.image-shipped' }
        # Attribution ladder: 'firmware.image-writable' is Confirmed because both facts it
        # rests on (the file exists at this path, the DACL grants non-admin write) are
        # directly observed by this rule. 'firmware.image-shipped' has only the file-exists
        # fact directly observed; the claim that the vendor's updater LOADS it and flashes it
        # without a signature check is inference. K25 Invoke-TcpkFirmwarePlantProbe promotes
        # the shipped case to Confirmed (dynamic) when the read is observed.
        $conf = if ($writable) { 'Confirmed' } else { 'Inferred' }
        $evParts = @("kind=$kind", "ext=$ext", "size=$len")
        if ($mismatch) { $evParts += 'header=missing' }
        if ($writable) { $evParts += 'writable-by-users=true' }

        $desc = if ($writable) {
            ('A firmware image is present in the install tree AND the resting DACL grants write ' +
             'to a non-admin group. Both facts are directly observed here. The exploit outcome ' +
             '(a modified image is flashed to the physical device on the next update) requires ' +
             'the vendor updater to READ this file and to flash it without a signature check. ' +
             'That second half is not proven by this rule; run Invoke-TcpkFirmwarePlantProbe ' +
             '(K25) to confirm dynamically. Local write on a firmware image that the updater ' +
             'does read and flash unsigned is the primitive Evil PLC and TRITON traced from an ' +
             'engineering workstation into controller code.')
        } else {
            ('A firmware image is present in the install tree. Only this fact is directly ' +
             'observed here (file exists, header magic matches). Whether the vendor updater ' +
             'actually reads it at flash time, and whether it verifies a vendor signature over ' +
             'the payload, is INFERENCE. Confidence is Inferred until Invoke-TcpkFirmwarePlantProbe ' +
             '(K25) runs and reports a read by the updater PID, or Test-TcpkUpdateFlow (F02) ' +
             'reports missing signature primitives near the update code path.')
        }

        New-TcpkFinding -Module 'discovery' -RuleId $rule `
            -Severity $sev -Confidence $conf `
            -Title "$($f.Name) is a device firmware image ($kind)" `
            -File $f.FullName -Evidence ($evParts -join ' ') `
            -Cwe @('CWE-494') `
            -Description $desc `
            -Fix ('Verify a vendor signature on every image before it is transmitted to the device, and ' +
                'restrict the image directory ACL to the installer identity (SYSTEM or the vendor service account). ' +
                'A code-signed image the desktop tool refuses to flash on signature failure closes the whole class.')
    }
}
