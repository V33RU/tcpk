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

    foreach ($p in $procs) {
        try { $mods = $p.Modules } catch { continue }
        # The main module (.exe) is already covered by the on-disk authenticode.pe-not-signed
        # finding; re-flagging it here as a "loaded unsigned module" is redundant noise -- exclude it.
        # Dependency DLLs (the genuine hijack/tamper candidates) remain in scope.
        $mainPath = $null; try { $mainPath = $p.MainModule.FileName } catch { }
        foreach ($m in $mods) {
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
}
