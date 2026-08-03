function Test-TcpkMsixPsf {
<#
.SYNOPSIS
    Detect Package Support Framework (PSF) script injection in MSIX packages.

.DESCRIPTION
    The MSIX Package Support Framework uses config.json to define fixups and can
    execute PowerShell scripts before/after the packaged app via
    StartingScriptWrapper.ps1 / EndingScriptWrapper.ps1. An attacker who can
    modify config.json or the referenced scripts gets code execution in the MSIX
    container (and potentially outside it with runFullTrust).

    Checks:
      1. PSF config.json with script references (startScript / endScript)
      2. Dangerous patterns in referenced scripts
      3. PsfLauncher / PsfRunDll fixup DLLs
      4. runFullTrust capability combined with PSF scripts

.PARAMETER Path
    File or directory to scan (expanded MSIX directory or installed package path).

.OUTPUTS
    [TcpkFinding]
#>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    $dir = $Path
    try { if (-not (Get-Item -LiteralPath $Path).PSIsContainer) { $dir = Split-Path -Parent $Path } } catch { return }

    # --- Find PSF config.json ---
    $configFiles = @(Get-ChildItem -LiteralPath $dir -Recurse -File -Filter 'config.json' -ErrorAction SilentlyContinue |
        Where-Object { $true })   # no size filter: a large PSF config is still a PSF config

    $psfDetected = $false

    foreach ($cf in $configFiles) {
        try {
            $raw = Get-Content -LiteralPath $cf.FullName -Raw -ErrorAction Stop
            $cfg = $raw | ConvertFrom-Json
        } catch { continue }

        if (-not $cfg.applications) { continue }

        foreach ($app in $cfg.applications) {
            if ($app.executable -match '(?i)PsfLauncher') { $psfDetected = $true }

            foreach ($scriptKey in @('startScript','endScript')) {
                $scriptObj = $app.$scriptKey
                if (-not $scriptObj) { continue }
                $psfDetected = $true

                $scriptPath = $scriptObj.scriptPath
                if (-not $scriptPath) { continue }

                $cfDir = Split-Path -Parent $cf.FullName
                $resolvedScript = Join-Path $cfDir $scriptPath
                $scriptExists = Test-Path -LiteralPath $resolvedScript

                $evidence = "$scriptKey.scriptPath=$scriptPath"
                if ($scriptObj.runInVirtualEnvironment -eq $true) { $evidence += '; runsInVirtualEnv' }
                if ($scriptObj.runOnce -eq $true) { $evidence += '; runOnce' }
                if ($scriptObj.waitForScriptToFinish -eq $false) { $evidence += '; async' }

                New-TcpkFinding -Module 'static' -RuleId "msix.psf-$scriptKey" `
                    -Severity 'MEDIUM' -Confidence 'Confirmed' `
                    -Title "MSIX PSF executes a $scriptKey script: $scriptPath" `
                    -File $cf.FullName `
                    -Evidence $evidence `
                    -Cwe @('CWE-94','CWE-427') `
                    -Description ("The Package Support Framework config.json defines a $scriptKey " +
                        "that executes a script ($scriptPath) before or after the packaged application. " +
                        'If the script or config.json can be modified, an attacker gets code execution ' +
                        'in the MSIX container context.') `
                    -Fix 'Verify the PSF script contents are benign. Restrict write access to config.json and all referenced scripts. Remove PSF scripts that are not strictly necessary.'

                # Analyze the script content if it exists
                if (-not $scriptExists) { continue }
                try { $scriptContent = Get-Content -LiteralPath $resolvedScript -Raw -ErrorAction Stop } catch { continue }
                if (-not $scriptContent) { continue }

                $dangers = @()
                if ($scriptContent -match 'Invoke-Expression|iex\s') { $dangers += 'Invoke-Expression' }
                if ($scriptContent -match 'Invoke-WebRequest|Invoke-RestMethod|Net\.WebClient|DownloadString|DownloadFile') { $dangers += 'network-download' }
                if ($scriptContent -match 'Start-Process|cmd\.exe|powershell\.exe|pwsh') { $dangers += 'process-spawn' }
                if ($scriptContent -match 'Set-ItemProperty|New-ItemProperty|reg\.exe|Remove-ItemProperty') { $dangers += 'registry-modify' }
                if ($scriptContent -match 'Add-Type.*-TypeDefinition|Add-Type.*-MemberDefinition') { $dangers += 'inline-compile' }

                if ($dangers.Count -gt 0) {
                    New-TcpkFinding -Module 'static' -RuleId 'msix.psf-script-dangerous' `
                        -Severity 'HIGH' -Confidence 'Inferred' `
                        -Title "PSF script contains dangerous operations: $scriptPath" `
                        -File $resolvedScript `
                        -Evidence "patterns: $($dangers -join ', ')" `
                        -Cwe @('CWE-94') `
                        -Description ('The PSF startup/shutdown script uses operations that can download ' +
                            'and execute code, modify the registry, or spawn processes. In a PSF context ' +
                            'these run every time the MSIX app launches -- persistence and code execution ' +
                            'if the script is compromised.') `
                        -Fix 'Review and minimize the PSF script. Remove network, process-spawn, or registry operations unless strictly required for compatibility.'
                }
            }

            # Fixup DLLs
            if ($app.fixups) {
                $fixupDlls = @($app.fixups | Where-Object { $_.dll } | ForEach-Object { $_.dll })
                if ($fixupDlls.Count -gt 0) {
                    $psfDetected = $true
                    New-TcpkFinding -Module 'static' -RuleId 'msix.psf-fixup-dlls' `
                        -Severity 'LOW' -Confidence 'Confirmed' `
                        -Title "PSF fixup DLLs loaded: $($fixupDlls -join ', ')" `
                        -File $cf.FullName `
                        -Evidence "fixup DLLs: $($fixupDlls -join ', ')" `
                        -Cwe @('CWE-427') `
                        -Description ('The PSF config loads fixup DLLs that intercept and redirect API calls ' +
                            'for the packaged application. While these are typically compatibility shims ' +
                            '(FileRedirectionFixup, RegLegacyFixups), a modified fixup DLL gets arbitrary ' +
                            'code execution in the app''s context.') `
                        -Fix 'Verify fixup DLLs are the official PSF binaries (hash-check). Document why each fixup is needed.'
                }
            }
        }
    }

    # --- PsfLauncher presence without config ---
    $psfExes = @(Get-ChildItem -LiteralPath $dir -Recurse -File -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -match '^Psf(Launcher|RunDll)(32|64)?\.exe$' })
    if ($psfExes.Count -gt 0) {
        $psfDetected = $true
        if ($configFiles.Count -eq 0) {
            New-TcpkFinding -Module 'static' -RuleId 'msix.psf-launcher-no-config' `
                -Severity 'LOW' -Confidence 'Confirmed' `
                -Title 'PsfLauncher present but no config.json found' `
                -File $psfExes[0].FullName `
                -Evidence "PSF executables: $(@($psfExes | ForEach-Object { $_.Name }) -join ', ')" `
                -Cwe @('CWE-427') `
                -Description ('PsfLauncher / PsfRunDll executables are present but no config.json was found. ' +
                    'The PSF may be misconfigured or the config may be loaded from an alternative location.') `
                -Fix 'Verify the PSF configuration. If PSF is not needed, remove the launcher executables.'
        }
    }

    if (-not $psfDetected) { return }

    # --- AppxManifest: runFullTrust + PSF = container escape ---
    $manifests = @(Get-ChildItem -LiteralPath $dir -Recurse -File -Filter 'AppxManifest.xml' -ErrorAction SilentlyContinue |
        Select-Object -First 1)
    foreach ($mf in $manifests) {
        try { $mxml = Get-Content -LiteralPath $mf.FullName -Raw -ErrorAction Stop } catch { continue }
        if ($mxml -match 'runFullTrust') {
            New-TcpkFinding -Module 'static' -RuleId 'msix.psf-full-trust' `
                -Severity 'HIGH' -Confidence 'Confirmed' `
                -Title 'MSIX has runFullTrust + PSF scripts: container escape risk' `
                -File $mf.FullName `
                -Evidence 'runFullTrust capability + PSF detected' `
                -Cwe @('CWE-250','CWE-94') `
                -Description ('This MSIX package declares the runFullTrust capability AND uses the Package ' +
                    'Support Framework. PSF scripts execute PowerShell before/after the app, and runFullTrust ' +
                    'means the app (and its PSF scripts) run outside the MSIX container sandbox -- they have ' +
                    'full access to the user''s machine. If an attacker can modify the PSF config or scripts, ' +
                    'they get unrestricted code execution.') `
                -Fix 'Remove the runFullTrust capability if not strictly needed. If required, ensure PSF config and scripts are integrity-protected and minimal.'
        }
    }
}
