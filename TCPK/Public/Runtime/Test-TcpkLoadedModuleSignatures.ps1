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
        foreach ($m in $mods) {
            # Skip catalog-covered MSIX-internal modules: per-PE Authenticode is N/A for them.
            if (_IsMsixCatalogCovered $m.FileName) { continue }

            $sig = Get-AuthenticodeSignature -FilePath $m.FileName
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
