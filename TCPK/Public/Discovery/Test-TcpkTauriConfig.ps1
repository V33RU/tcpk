function Test-TcpkTauriConfig {
<#
.SYNOPSIS
    A38. Audit a Tauri app configuration (tauri.conf.json) for insecure settings.

.DESCRIPTION
    Tauri (Rust core + system WebView) is configured by tauri.conf.json. The same
    misconfigurations that turn a front-end XSS into native RCE are visible in that
    file. This audits both Tauri v1 (allowlist model) and v2 (security + capabilities):

      * Missing / empty CSP            -> an XSS can reach the IPC bridge (RCE).
      * dangerousRemoteDomainIpcAccess -> remote origins may invoke the Rust API.
      * dangerousDisableAssetCspModification.
      * allowlist.all / shell.* / fs.all / broad fs scope -> command + file access
        exposed to the front-end.
      * updater without a pubkey, or over http:// -> unsigned / MITM-able updates.

    Note: release builds compile the config in and usually do NOT ship
    tauri.conf.json; this is most useful for source / dev-build review (where the
    file is present). It scans -Path recursively for the config.

.PARAMETER Path
    File (tauri.conf.json) or a directory to search recursively.

.OUTPUTS
    [TcpkFinding]
#>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    $item = Get-Item -LiteralPath $Path -ErrorAction SilentlyContinue
    if (-not $item) { return }
    $confNames = @('tauri.conf.json', 'tauri.windows.conf.json', 'tauri.linux.conf.json', 'tauri.macos.conf.json')
    $confs = if ($item.PSIsContainer) {
        Get-ChildItem -LiteralPath $Path -Recurse -File -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -in $confNames }
    } elseif ($item.Name -in $confNames) { @($item) } else { @() }

    $broadFsRx = '(?i)(^|[\\/])(\*\*|\$HOME|\$APPDATA|\$RESOURCE|\$DOCUMENT|\$DOWNLOAD|\$DESKTOP|\$LOCALDATA)([\\/]\*\*)?'

    foreach ($cf in $confs) {
        $cfg = $null
        try { $cfg = Get-Content -LiteralPath $cf.FullName -Raw | ConvertFrom-Json } catch {
            New-TcpkFinding -Module 'static' -RuleId 'tauri.parse-failed' -Severity 'INFO' -Confidence 'Skipped' `
                -Title "Could not parse $($cf.Name)" -File $cf.FullName -Evidence $_.Exception.Message
            continue
        }
        if (-not $cfg) { continue }

        # v1 nests under .tauri; v2 uses top-level .app / .plugins
        $isV2     = [bool]($cfg.PSObject.Properties['app'] -or $cfg.PSObject.Properties['identifier'])
        $security = if ($cfg.tauri) { $cfg.tauri.security } elseif ($cfg.app) { $cfg.app.security } else { $null }
        $allow    = if ($cfg.tauri) { $cfg.tauri.allowlist } else { $null }
        $updater  = if ($cfg.tauri -and $cfg.tauri.updater) { $cfg.tauri.updater }
                    elseif ($cfg.plugins -and $cfg.plugins.updater) { $cfg.plugins.updater } else { $null }
        $verTag = if ($isV2) { 'v2' } else { 'v1' }

        # ---- CSP ----
        $csp = if ($security) { $security.csp } else { $null }
        if (-not $csp -or ("$csp").Trim() -eq '') {
            New-TcpkFinding -Module 'static' -RuleId 'tauri.no-csp' `
                -Severity 'HIGH' -Confidence 'Confirmed' `
                -Title "Tauri ($verTag): no Content-Security-Policy set" `
                -File $cf.FullName -Evidence 'security.csp is null / empty' `
                -Cwe @('CWE-1021', 'CWE-79') `
                -Description 'With no CSP, a cross-site-scripting bug in the front-end can load arbitrary script and reach the Tauri IPC bridge, turning XSS into native code execution.' `
                -Fix "Set a strict security.csp (script-src 'self', no unsafe-inline / remote origins)."
        }

        # ---- dangerous IPC / CSP flags (v1) ----
        if ($security -and $security.PSObject.Properties['dangerousRemoteDomainIpcAccess'] -and $security.dangerousRemoteDomainIpcAccess) {
            $domains = @($security.dangerousRemoteDomainIpcAccess | ForEach-Object { $_.domain }) -join ', '
            New-TcpkFinding -Module 'static' -RuleId 'tauri.remote-ipc-access' `
                -Severity 'HIGH' -Confidence 'Confirmed' `
                -Title "Tauri ($verTag): remote domains granted IPC access" `
                -File $cf.FullName -Evidence ("dangerousRemoteDomainIpcAccess: $domains") `
                -Cwe @('CWE-749', 'CWE-829') `
                -Description 'Remote web origins are allowed to invoke the Rust IPC commands. A compromised or malicious remote page can drive native functionality.' `
                -Fix 'Remove dangerousRemoteDomainIpcAccess; only the bundled local front-end should reach the IPC bridge.'
        }
        if ($security -and $security.PSObject.Properties['dangerousDisableAssetCspModification'] -and $security.dangerousDisableAssetCspModification) {
            New-TcpkFinding -Module 'static' -RuleId 'tauri.csp-modification-disabled' `
                -Severity 'MEDIUM' -Confidence 'Confirmed' `
                -Title "Tauri ($verTag): asset CSP modification disabled" `
                -File $cf.FullName -Evidence 'dangerousDisableAssetCspModification = true' `
                -Cwe @('CWE-1021') `
                -Description 'Tauri will not inject per-asset CSP nonces/hashes, weakening the CSP it does ship.' `
                -Fix 'Leave dangerousDisableAssetCspModification unset (false).'
        }

        # ---- allowlist (v1) ----
        if ($allow) {
            if ($allow.all) {
                New-TcpkFinding -Module 'static' -RuleId 'tauri.allowlist-all' `
                    -Severity 'HIGH' -Confidence 'Confirmed' `
                    -Title 'Tauri (v1): allowlist.all = true (entire API exposed)' `
                    -File $cf.FullName -Evidence 'allowlist.all = true' `
                    -Cwe @('CWE-749') `
                    -Description 'The complete Tauri API surface (fs, shell, process, http, ...) is exposed to the front-end. Any front-end compromise gains the full native API.' `
                    -Fix 'Disable allowlist.all and opt in only to the specific commands the app needs.'
            }
            $shell = $allow.shell
            if ($shell -and ($shell.all -or $shell.open -or $shell.execute -or $shell.sidecar)) {
                $en = @(); foreach ($k in 'all','open','execute','sidecar') { if ($shell.$k) { $en += $k } }
                New-TcpkFinding -Module 'static' -RuleId 'tauri.shell-access' `
                    -Severity 'HIGH' -Confidence 'Confirmed' `
                    -Title "Tauri (v1): shell access enabled ($([string]::Join('/', $en)))" `
                    -File $cf.FullName -Evidence ("allowlist.shell: " + ([string]::Join(', ', $en))) `
                    -Cwe @('CWE-78') `
                    -Description 'The front-end can spawn processes / open shells via the Tauri shell API. Combined with any injection this is command execution.' `
                    -Fix 'Disable allowlist.shell, or restrict shell.scope to an explicit, argument-validated command list.'
            }
            $fs = $allow.fs
            if ($fs -and $fs.all) {
                New-TcpkFinding -Module 'static' -RuleId 'tauri.fs-all' `
                    -Severity 'HIGH' -Confidence 'Confirmed' `
                    -Title 'Tauri (v1): filesystem API fully enabled (fs.all)' `
                    -File $cf.FullName -Evidence 'allowlist.fs.all = true' `
                    -Cwe @('CWE-22') `
                    -Description 'The front-end can read/write the filesystem through the Tauri fs API with no scope restriction.' `
                    -Fix 'Disable fs.all; set a narrow allowlist.fs.scope.'
            }
            elseif ($fs -and $fs.scope) {
                $broad = @($fs.scope | Where-Object { $_ -match $broadFsRx })
                if ($broad.Count) {
                    New-TcpkFinding -Module 'static' -RuleId 'tauri.fs-broad-scope' `
                        -Severity 'MEDIUM' -Confidence 'Confirmed' `
                        -Title 'Tauri (v1): broad filesystem scope' `
                        -File $cf.FullName -Evidence ("fs.scope: " + (($broad | Select-Object -First 5) -join ', ')) `
                        -Cwe @('CWE-22') `
                        -Description 'The fs scope grants the front-end access to broad locations (home / appdata / recursive globs). A front-end bug can read or overwrite user files.' `
                        -Fix 'Narrow allowlist.fs.scope to the specific subdirectories the app needs.'
                }
            }
        }

        # ---- updater ----
        if ($updater) {
            $active = if ($updater.PSObject.Properties['active']) { [bool]$updater.active } else { $true }
            $pubkey = $updater.pubkey
            $eps    = @($updater.endpoints)
            if ($active -and (-not $pubkey -or "$pubkey".Trim() -eq '')) {
                New-TcpkFinding -Module 'static' -RuleId 'tauri.updater-no-pubkey' `
                    -Severity 'HIGH' -Confidence 'Confirmed' `
                    -Title "Tauri ($verTag): updater enabled without a signature pubkey" `
                    -File $cf.FullName -Evidence 'updater.active with empty updater.pubkey' `
                    -Cwe @('CWE-347') `
                    -Description 'The auto-updater accepts update artifacts without verifying a signature, so a MITM or compromised endpoint can push arbitrary code.' `
                    -Fix 'Set updater.pubkey and sign artifacts with the matching private key.'
            }
            $httpEp = @($eps | Where-Object { $_ -match '(?i)^http://' })
            if ($httpEp.Count) {
                New-TcpkFinding -Module 'static' -RuleId 'tauri.updater-insecure-endpoint' `
                    -Severity 'HIGH' -Confidence 'Confirmed' `
                    -Title "Tauri ($verTag): updater endpoint over cleartext http" `
                    -File $cf.FullName -Evidence (($httpEp | Select-Object -First 3) -join ', ') `
                    -Cwe @('CWE-319') `
                    -Description 'An auto-update endpoint is plain http, so the update check / download can be intercepted and tampered with.' `
                    -Fix 'Use https endpoints (and keep updater.pubkey signing on).'
            }
        }
    }
}
