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
        [string[]]$NameLike,
        # Optional path to a full LOLDrivers export (drivers.json from
        # github.com/magicsword-io/LOLDrivers). The cmdlet consumes the shipped
        # curated subset (TCPK/Data/loldrivers-curated.json) regardless.
        [string]$LolDriversPath
    )

    if (-not (Assert-TcpkWindows 'Test-TcpkKernelDrivers')) { return }

    # ---- Load LOLDrivers datasets ------------------------------------------------
    # 1) always-on: TCPK/Data/loldrivers-curated.json (basenames only, no hashes).
    # 2) optional : a full LOLDrivers export at either $LolDriversPath or
    #    TCPK/Data/loldrivers-full.json (SHA-256-indexed).
    $lolBasenames = @{}   # basename lowercased -> reason
    $lolHashes    = @{}   # sha256 lowercased -> reason
    try {
        $curated = Join-Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) 'Data\loldrivers-curated.json'
        if (Test-Path -LiteralPath $curated) {
            $doc = Get-Content -LiteralPath $curated -Raw | ConvertFrom-Json
            foreach ($e in @($doc.entries)) {
                if ($e.name) { $lolBasenames[$e.name.ToLowerInvariant()] = "$($e.vendor) - $($e.why)" }
            }
        }
    } catch { }
    $fullPath = $LolDriversPath
    if (-not $fullPath) {
        $candidate = Join-Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) 'Data\loldrivers-full.json'
        if (Test-Path -LiteralPath $candidate) { $fullPath = $candidate }
    }
    if ($fullPath -and (Test-Path -LiteralPath $fullPath)) {
        try {
            $full = Get-Content -LiteralPath $fullPath -Raw | ConvertFrom-Json
            # LOLDrivers upstream schema: a top-level array of driver objects, each with
            # KnownVulnerableSamples[] containing SHA256 / OriginalFilename. Be tolerant
            # of both the upstream shape and a flat array of {sha256,name} objects.
            $entries = if ($full -is [array]) { $full } else { @($full.entries) }
            foreach ($drv in $entries) {
                $samples = @()
                if ($drv.KnownVulnerableSamples) { $samples += $drv.KnownVulnerableSamples }
                elseif ($drv.sha256 -or $drv.SHA256) { $samples += $drv }
                foreach ($s in $samples) {
                    $h = "$($s.SHA256)"; if (-not $h) { $h = "$($s.sha256)" }
                    if ($h -match '^[0-9a-fA-F]{64}$') {
                        $reason = if ($drv.Description) { $drv.Description } elseif ($drv.description) { $drv.description } else { 'LOLDrivers full-set entry' }
                        $lolHashes[$h.ToLowerInvariant()] = "$reason"
                    }
                    $sn = "$($s.OriginalFilename)"; if (-not $sn) { $sn = "$($s.Filename)" }
                    if ($sn) { $lolBasenames[$sn.ToLowerInvariant()] = "LOLDrivers full-set (name match)" }
                }
            }
        } catch { }
    }

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

    # Same CRL/OCSP stall risk as the other Authenticode loops: bound it and say so.
    $drvIdx = 0
    $sysFiles = @($sysFiles)
    foreach ($s in $sysFiles) {
        if (Test-TcpkCheckBudgetExpired) {
            New-TcpkSkippedFinding -RuleId 'driver.budget-exhausted' `
                -Title "Driver signature check stopped early: $($sysFiles.Count - $drvIdx) of $($sysFiles.Count) .sys files not verified" `
                -Reason ("This check hit its wall-clock budget after $drvIdx drivers. Authenticode " +
                    "verification can block on a CRL/OCSP fetch when the network is filtered. The " +
                    "remaining drivers are UNVERIFIED, not unsigned.")
            break
        }
        $drvIdx++
        Write-TcpkHeartbeat -Component 'Test-TcpkKernelDrivers' -Index $drvIdx -Total $sysFiles.Count -Current $s.Name -CurrentBytes $s.Length
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

        # ---- driver.byovd-loldrivers-match --------------------------------------
        # Basename match: always available (curated + optional full-set names).
        # Hash match:     only when the operator supplied a full LOLDrivers export.
        $nameLc = $s.Name.ToLowerInvariant()
        $nameHit = if ($lolBasenames.ContainsKey($nameLc)) { $lolBasenames[$nameLc] } else { '' }
        $hashHit = ''; $sha = ''
        if ($lolHashes.Count -gt 0) {
            try {
                $sha = (Get-FileHash -LiteralPath $s.FullName -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()
                if ($lolHashes.ContainsKey($sha)) { $hashHit = $lolHashes[$sha] }
            } catch { }
        }
        if ($nameHit -or $hashHit) {
            $why = if ($hashHit) { "SHA-256 match: $sha - $hashHit" } else { "basename match: $($s.Name) - $nameHit (SHA-256 not evaluated: no full LOLDrivers export shipped or supplied)" }
            $conf = if ($hashHit) { 'Confirmed' } else { 'Inferred' }
            New-TcpkFinding -Module 'os' -RuleId 'driver.byovd-loldrivers-match' `
                -Severity 'HIGH' -Confidence $conf `
                -Title "Shipped kernel driver matches LOLDrivers BYOVD set: $($s.Name)" `
                -File $s.FullName -Evidence $why `
                -Cwe @('CWE-1188','CWE-269') `
                -Description ('The shipped .sys is present in the TCPK-curated LOLDrivers subset (or in the ' +
                    'operator-supplied full export). Basename matches are Inferred - two vendors can ship ' +
                    'unrelated drivers under the same filename; SHA-256 matches against a full LOLDrivers ' +
                    'export are Confirmed. LOLDrivers-listed drivers expose kernel primitives (arbitrary ' +
                    'physmem / MSR / port IO / process-handle escalation) that turn a low-priv install ' +
                    'into SYSTEM. The signature check on driver.shipped-sys is not sufficient: many entries ' +
                    'in the list ARE validly signed - that is why they are useful for BYOVD.') `
                -Fix 'Remove the driver from the release. If the app needs the hardware access it provides, replace it with a purpose-built driver whose IOCTL surface is narrowed to what the app actually calls, and WHQL-sign that. If you cannot remove it, block-list the SHA-256 in the Microsoft driver block-list policy so Windows refuses to load it.'
        }
    }

    # 2) installed kernel driver services matching the vendor
    $terms = Get-TcpkNameTerms -NameLike $NameLike
    if ($terms.Count) {
        $svcRoot = 'HKLM:\SYSTEM\CurrentControlSet\Services'
        $svcKeys = Get-ChildItem -Path $svcRoot -ErrorAction SilentlyContinue |
            Where-Object { Test-TcpkTermMatch -Text $_.PSChildName -Terms $terms }
        foreach ($k in $svcKeys) {
            $props = $null
            try { $props = Get-ItemProperty -LiteralPath $k.PSPath -ErrorAction Stop } catch { continue }
            # Type 1 = kernel driver, Type 2 = file-system driver
            if ($props.Type -in 1,2) {
                New-TcpkFinding -Module 'os' -RuleId 'driver.installed-service' `
                    -Severity 'MEDIUM' -Confidence 'Confirmed' `
                    -Title "Kernel driver service installed: $($k.PSChildName)" `
                    -File ($k.PSPath -replace 'Microsoft\.PowerShell\.Core\\Registry::','') `
                    -Evidence "ImagePath=$($props.ImagePath); Start=$($props.Start)" -Cwe @('CWE-1188') `
                    -Description 'A kernel driver is registered as a service on this host by the product. Confirm its IOCTL surface and load permissions.'
            }
        }
    }
}
