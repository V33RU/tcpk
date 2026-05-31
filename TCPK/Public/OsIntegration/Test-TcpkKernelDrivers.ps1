function Test-TcpkKernelDrivers {
<#
.SYNOPSIS
    C14. Kernel-mode drivers (.sys) shipped or installed by the app.

.DESCRIPTION
    A thick client that ships or installs a kernel driver opens the entire
    kernel attack surface (IOCTL handlers, ring-0 memory bugs, BYOVD). This is
    high-value and frequently overlooked in application pentests.

    Reports every .sys under the install path, its Authenticode status, and --
    when -NameLike is supplied -- any matching kernel-driver service registered
    on the host (Type 1/2 in HKLM\System\CurrentControlSet\Services).

.PARAMETER Path
    Install file or directory (scanned for shipped .sys files).

.PARAMETER NameLike
    Optional. Vendor/product substring to match installed driver services.

.OUTPUTS
    [TcpkFinding]
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [string]$NameLike
    )

    if (-not (Assert-TcpkWindows 'Test-TcpkKernelDrivers')) { return }

    # 1) shipped .sys files
    $sysFiles = @()
    try {
        $item = Get-Item -LiteralPath $Path -ErrorAction Stop
        if ($item.PSIsContainer) {
            $sysFiles = Get-ChildItem -LiteralPath $Path -Recurse -File -Filter '*.sys' -ErrorAction SilentlyContinue
        } elseif ($item.Extension -ieq '.sys') {
            $sysFiles = @($item)
        }
    } catch { }

    foreach ($s in $sysFiles) {
        $sig = $null
        try { $sig = Get-AuthenticodeSignature -FilePath $s.FullName -ErrorAction Stop } catch { }
        $sigTxt = if ($sig) { "$($sig.Status)" } else { 'unknown' }
        $sev = if ($sigTxt -ne 'Valid') { 'HIGH' } else { 'MEDIUM' }
        New-TcpkFinding -Module 'os' -RuleId 'driver.shipped-sys' `
            -Severity $sev -Confidence 'Confirmed' `
            -Title "Kernel driver shipped: $($s.Name) (sig=$sigTxt)" `
            -File $s.FullName -Evidence "Authenticode=$sigTxt" -Cwe @('CWE-1188','CWE-269') `
            -Description 'A kernel-mode driver expands the attack surface into ring 0. Audit every IOCTL handler for missing access checks, unchecked buffer lengths, and arbitrary read/write primitives. An unsigned or weakly-signed driver also enables BYOVD.' `
            -Fix 'Minimize/justify the kernel driver; enforce strict IOCTL access (FILE_DEVICE_SECURE_OPEN + explicit SDDL), validate all input lengths, and WHQL-sign.'
    }

    # 2) installed kernel driver services matching the vendor
    if ($NameLike) {
        $svcRoot = 'HKLM:\SYSTEM\CurrentControlSet\Services'
        $svcKeys = Get-ChildItem -Path $svcRoot -ErrorAction SilentlyContinue |
            Where-Object { $_.PSChildName -like "*$NameLike*" }
        foreach ($k in $svcKeys) {
            $props = $null
            try { $props = Get-ItemProperty -LiteralPath $k.PSPath -ErrorAction Stop } catch { continue }
            # Type 1 = kernel driver, Type 2 = file-system driver
            if ($props.Type -in 1,2) {
                New-TcpkFinding -Module 'os' -RuleId 'driver.installed-service' `
                    -Severity 'HIGH' -Confidence 'Confirmed' `
                    -Title "Kernel driver service installed: $($k.PSChildName)" `
                    -File ($k.PSPath -replace 'Microsoft\.PowerShell\.Core\\Registry::','') `
                    -Evidence "ImagePath=$($props.ImagePath); Start=$($props.Start)" -Cwe @('CWE-1188') `
                    -Description 'A kernel driver is registered as a service on this host by the product. Confirm its IOCTL surface and load permissions.'
            }
        }
    }
}
