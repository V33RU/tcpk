function Test-TcpkLoadedModuleSignatures {
<#
.SYNOPSIS
    E02. Authenticode status of every module loaded into the live process.

.OUTPUTS
    [TcpkFinding]
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ParameterSetName='ByName')][string]$ProcessName,
        [Parameter(Mandatory, ParameterSetName='ById')][int]$ProcessId
    )

    if (-not (Assert-TcpkWindows 'Test-TcpkLoadedModuleSignatures')) { return }

    # Get-AuthenticodeSignature (Microsoft.PowerShell.Security) does not always auto-load in
    # background-job runspaces. The module psm1 imports it eagerly; if it STILL is not present
    # (a genuinely locked-down host), skip honestly with one finding rather than throwing.
    if (-not (Get-Command Get-AuthenticodeSignature -ErrorAction SilentlyContinue)) {
        try { Import-Module Microsoft.PowerShell.Security -ErrorAction Stop } catch { }
    }
    if (-not (Get-Command Get-AuthenticodeSignature -ErrorAction SilentlyContinue)) {
        New-TcpkFinding -Module 'runtime' -RuleId 'loaded.unsigned' -Severity 'INFO' -Confidence 'Skipped' `
            -Title 'Loaded-module signature check skipped (Microsoft.PowerShell.Security unavailable)' `
            -Evidence 'Get-AuthenticodeSignature could not be loaded in this runspace' `
            -Description 'The Authenticode cmdlet did not load in this session, so live loaded-module signatures were not verified. Re-run from a normal PowerShell host; the on-disk DLL signing matrix (Get-TcpkSigningMatrix) is unaffected.'
        return
    }

    $procs = if ($PSCmdlet.ParameterSetName -eq 'ByName') {
        Get-TcpkProcess -ProcessName $ProcessName
    } else {
        Get-TcpkProcess -ProcessId $ProcessId
    }
    # Cache: for each install-dir parent, does it have AppxMetadata\CodeIntegrity.cat?
    # MSIX-internal PEs are catalog-signed; per-PE Authenticode validation will return
    # UnknownError as a false positive. Skip those modules.
    $catCache = @{}
    function _IsMsixCatalogCovered($modulePath) {
        $dir = Split-Path -Parent $modulePath
        while ($dir -and (Test-Path $dir)) {
            if ($catCache.ContainsKey($dir)) { return $catCache[$dir] }
            if (Test-Path (Join-Path $dir 'AppxMetadata\CodeIntegrity.cat')) {
                $catCache[$dir] = $true; return $true
            }
            if (Test-Path (Join-Path $dir 'AppxManifest.xml')) {
                # MSIX root reached without finding catalog. Stop walking up.
                $catCache[$dir] = $false; return $false
            }
            $parent = Split-Path -Parent $dir
            if ($parent -eq $dir) { break }
            $dir = $parent
        }
        return $false
    }

    # This is the heaviest signature loop in the tool: EVERY loaded module of EVERY matched
    # process, and a modern browser or Electron app loads 150-400 of them per process. Each
    # Get-AuthenticodeSignature can trigger a CRL/OCSP fetch, and on a box with no route out
    # (or a black-holing proxy) each of those sits on the WinVerifyTrust network timeout. A
    # few hundred modules times that timeout is a stall measured in hours, from a check whose
    # name never even reached the screen. Budget + heartbeat, same as Test-TcpkSignature.
    $modIdx = 0
    $modSkipped = 0
    $modTotal = 0
    foreach ($p in $procs) { try { $modTotal += @($p.Modules).Count } catch { } }

    :proc foreach ($p in $procs) {
        try { $mods = $p.Modules } catch { continue }
        # The main module (.exe) is already covered by the on-disk authenticode.pe-not-signed
        # finding; re-flagging it here as a "loaded unsigned module" is redundant noise -- exclude it.
        # Dependency DLLs (the genuine hijack/tamper candidates) remain in scope.
        $mainPath = $null; try { $mainPath = $p.MainModule.FileName } catch { }
        foreach ($m in $mods) {
            if (Test-TcpkCheckBudgetExpired) { $modSkipped = $modTotal - $modIdx; break proc }
            $modIdx++
            Write-TcpkHeartbeat -Component 'Test-TcpkLoadedModuleSignatures' -Index $modIdx -Total $modTotal -Current (Split-Path $m.FileName -Leaf)

            if ($mainPath -and $m.FileName -eq $mainPath) { continue }
            # Skip catalog-covered MSIX-internal modules: per-PE Authenticode is N/A for them.
            if (_IsMsixCatalogCovered $m.FileName) { continue }

            $sig = $null
            try { $sig = Get-AuthenticodeSignature -FilePath $m.FileName -ErrorAction Stop } catch { continue }
            if (-not $sig) { continue }
            if ($sig.Status -eq 'Valid') { continue }
            # UnknownError on a non-MSIX path is still suspicious enough to surface as INFO.
            if ($sig.Status -eq 'UnknownError') {
                $sev = 'INFO'
            } elseif ($m.FileName -match '\\System32\\|\\SysWOW64\\|\\WinSxS\\') {
                $sev = 'INFO'
            } else {
                $sev = 'MEDIUM'
            }
            New-TcpkFinding -Module 'runtime' -RuleId 'loaded.unsigned' `
                -Severity $sev -Confidence 'Confirmed' `
                -Title "Loaded module $(Split-Path $m.FileName -Leaf) signature=$($sig.Status)" `
                -File $m.FileName -Evidence "PID=$($p.Id) status=$($sig.Status)" `
                -Cwe @('CWE-347')
        }
    }

    if ($modSkipped -gt 0) {
        New-TcpkSkippedFinding -RuleId 'loaded.budget-exhausted' `
            -Title "Loaded-module signature check stopped early: $modSkipped of $modTotal modules not verified" `
            -Reason ("This check hit its wall-clock budget after $modIdx modules. Authenticode " +
                "verification can block on a CRL/OCSP fetch when the network is filtered, and a " +
                "browser or Electron target loads hundreds of modules, so the usual cause is " +
                "revocation lookups timing out rather than the modules themselves. The remaining " +
                "$modSkipped are UNVERIFIED, not unsigned. Re-run with network access to the CA's " +
                "CRL endpoints, or raise -CheckBudgetSec.")
    }
}
