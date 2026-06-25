function Invoke-TcpkAudit {
<#
.SYNOPSIS
    Run every TCPK check against a target and write reports.

.DESCRIPTION
    The top-level audit driver. Dispatches every Discovery cmdlet against
    the supplied path, collects findings, prints a per-check progress line,
    and writes HTML + JSON + Markdown reports to the output directory.

    Checks that throw produce a single 'meta.cmdlet-failed' finding rather
    than aborting the audit.

.PARAMETER Target
    What to audit. Accepts: an install / extracted directory; a single EXE/DLL; or a
    sealed container that TCPK unwraps automatically -- MSIX/AppX (Expand-TcpkMsix),
    MSI (msiexec /a administrative install), or ZIP (safe, zip-slip-guarded extraction).
    NSIS / Inno / other installers are not auto-unwrapped: extract them first, then point
    -Target at the folder.

.PARAMETER ProcessName
    Optional. If supplied, runtime checks (Phase 5+) will target the
    running process. Currently no-op until Phase 5 cmdlets land.

.PARAMETER PackageName
    Optional. Used by Test-TcpkInstalledPackage (Phase 3) when present.

.PARAMETER OutDir
    Directory to write reports into. Created if missing.

.PARAMETER Acknowledge
    Skip the interactive authorization prompt. Equivalent to typing 'yes'.

.PARAMETER FailOn
    INFO/LOW/MEDIUM/HIGH/CRITICAL -- throws at the end if any finding meets
    or exceeds the threshold (useful in CI).

.PARAMETER EnableLlm
    Run the optional LLM Stage-2 (Invoke-TcpkLlmCodeJudgment) inline after triage.
    It annotates the Confidence of code-construct findings (callsites / tls-bypass /
    deser / xxe / webview2) with an '(LLM)' verdict; it never changes Severity.
    Local-only by default: if the configured provider is a CLOUD backend it is
    skipped (the decompiled IL would leave the machine) unless -AllowCloudLlm is
    also supplied. No-op with a warning if no backend is reachable.

.PARAMETER AllowCloudLlm
    Permit -EnableLlm to use a CLOUD LLM provider, sending decompiled IL off-box.
    Only use this when the engagement allows the target's code to leave the machine.

.EXAMPLE
    Invoke-TcpkAudit -Target 'C:\Path\To\App.msix' -OutDir .\out\App -Acknowledge

.EXAMPLE
    # audit + local AI triage in one run (Ollama):
    Invoke-TcpkAudit -Target 'C:\App' -Acknowledge -EnableLlm

.OUTPUTS
    [TcpkFinding[]] -- the full collected pipeline, after writing reports.
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Target,
        [string]$ProcessName,
        [string]$PackageName,
        [string]$PackageFamilyName,
        [string]$OutDir,
        [switch]$Acknowledge,
        [switch]$EnableDeepRuntime,
        [switch]$EnableLlm,
        [switch]$AllowCloudLlm,
        [string]$PauseSignalPath,
        [ValidateSet('INFO','LOW','MEDIUM','HIGH','CRITICAL')][string]$FailOn,
        # Scan profile. Full/Standard run every check; Quick skips the slow, whole-machine
        # OS-integration / persistence enumeration to focus on the target app (named
        # -ScanProfile, not -Profile, to avoid shadowing the automatic $Profile variable).
        [ValidateSet('Quick','Standard','Full')][string]$ScanProfile = 'Full',
        # OPT-IN online CVE enrichment. Default OFF keeps the audit fully offline. When set, the
        # shipped NuGet components (name+version) are sent to the OSV API (api.osv.dev) for live
        # vulnerability matching on top of the offline catalog. No findings/secrets/target name
        # leave the box -- only public package identifiers.
        [switch]$OnlineCve,
        # Auto-attach: when -ProcessName is NOT supplied, TCPK tries to find the target's own
        # running process (install-dir exe intersected with the running process list) so the
        # live-process (Bucket E) checks fire automatically. -NoAutoProcess disables that; an
        # explicit -ProcessName always wins.
        [switch]$NoAutoProcess,
        # Self-elevation: if set AND the current session is not elevated, relaunch the same
        # audit as admin via UAC (Start-Process -Verb RunAs) so the elevation-gated checks
        # (Defender exclusions, deeper ACLs) actually run. Never auto-elevates without this.
        [switch]$Elevate
    )

    # --- preflight ---
    if (-not (Test-Path -LiteralPath $Target)) {
        throw "Target not found: $Target"
    }

    # Authorization gate
    if (-not $Acknowledge) {
        Write-TcpkBanner -Target $Target
        $resp = Read-Host "Are you authorized to test this target? [y/N]"
        if ($resp -notmatch '^(y|yes)$') {
            Write-TcpkInfo "Aborted by operator."
            return
        }
    } else {
        Write-TcpkBanner -Target $Target
        Write-TcpkInfo "Authorization acknowledged via -Acknowledge."
    }

    # Default OutDir under .\out\<target-leaf>_<date>
    if (-not $OutDir) {
        $leaf = Split-Path -Leaf $Target
        $stamp = (Get-Date).ToString('yyyy-MM-dd')
        $OutDir = Join-Path (Get-Location) ("out\${leaf}_${stamp}")
    }
    if (-not (Test-Path $OutDir)) { New-Item -ItemType Directory -Path $OutDir -Force | Out-Null }

    # --- self-elevation (opt-in via -Elevate): relaunch as admin so elevation-gated checks
    # (Defender exclusions, deeper ACLs) actually run. Never auto-elevates without the flag.
    # On a successful relaunch the parent waits, then returns the elevated child's findings.
    # On UAC decline / failure it falls through and continues NON-elevated (coverage.json will
    # show the NeedsElevation rows). ---
    $isElevated = $false
    try {
        $isElevated = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
    } catch { }
    if ($Elevate -and -not $isElevated) {
        Write-TcpkInfo "Self-elevation requested (-Elevate); session is not elevated. Relaunching as admin via UAC..."
        $fwd = @{}
        foreach ($k in $PSBoundParameters.Keys) { if ($k -ne 'Elevate') { $fwd[$k] = $PSBoundParameters[$k] } }
        $fwd['OutDir'] = $OutDir
        $fwd['Acknowledge'] = $true
        $manifest = Join-Path $script:TcpkRoot 'TCPK.psd1'
        # Build a self-contained launcher (.ps1) -- avoids all -Command quoting pitfalls.
        $sb = New-Object System.Text.StringBuilder
        [void]$sb.AppendLine('$p = @{')
        foreach ($k in $fwd.Keys) {
            $v = $fwd[$k]
            if ($v -is [switch]) { if ($v.IsPresent) { [void]$sb.AppendLine("  $k = `$true") } }
            elseif ($v -is [bool]) { [void]$sb.AppendLine("  $k = `$" + $v.ToString().ToLowerInvariant()) }
            else { [void]$sb.AppendLine("  $k = '" + ("$v" -replace "'", "''") + "'") }
        }
        [void]$sb.AppendLine('}')
        [void]$sb.AppendLine("Import-Module '$manifest' -Force")
        [void]$sb.AppendLine('Invoke-TcpkAudit @p')
        $launcher = Join-Path $OutDir '_tcpk-elevated-launch.ps1'
        Set-Content -LiteralPath $launcher -Value $sb.ToString() -Encoding UTF8
        $relaunched = $false
        try {
            $proc = Start-Process powershell.exe -Verb RunAs -PassThru -Wait `
                -ArgumentList '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $launcher -ErrorAction Stop
            $relaunched = $true
            Write-TcpkInfo "Elevated audit finished (exit $($proc.ExitCode)). Reading its reports from $OutDir."
        } catch {
            Write-TcpkInfo "Elevation declined or failed ($($_.Exception.Message)); continuing NON-elevated. Elevation-gated checks will be flagged in coverage.json."
        }
        if ($relaunched) {
            $jf = Join-Path $OutDir 'findings.json'
            if (Test-Path -LiteralPath $jf) {
                try { return , (@(Get-Content -LiteralPath $jf -Raw | ConvertFrom-Json)) } catch { return }
            }
            return
        }
    }

    # Unwrap a sealed container target (MSIX / MSI / ZIP) to a folder to scan; a directory,
    # a single exe, or anything else is scanned as-is. Degrades to $Target on any failure.
    $expanded = try { Expand-TcpkTarget -Path $Target } catch { $Target }

    # --- application-identity search terms (drives the OS / registry bucket) ---
    # Apps store data under product codes, CLSIDs, ProgIDs and brand names that
    # differ from the package name, so we search for a SET of terms derived from
    # the app's own identity (manifest + main exe), not just a hand-typed -PackageName.
    $idTerms = @(Get-TcpkIdentityTerms -Path $expanded -Extra $PackageName)

    # --- collected findings ---
    $all = New-Object 'System.Collections.Generic.List[TcpkFinding]'

    # Quick profile: skip the slow, whole-machine OS-integration / persistence enumeration
    # (these scan the SYSTEM, not the target) so a fast pass focuses on the app itself.
    # Full/Standard leave this empty -> every check runs (unchanged default behavior).
    $quickSkip = @(
        'Test-TcpkRegistryFootprint','Test-TcpkRegistryAcl','Test-TcpkRegistryValues',
        'Test-TcpkFirewallRules','Test-TcpkAvExclusions','Test-TcpkServiceBinaryAcl',
        'Test-TcpkServicePermissions','Test-TcpkUnquotedServicePath','Test-TcpkAutoStart',
        'Test-TcpkProgramDataAcls','Test-TcpkScheduledTaskAcl','Test-TcpkWmiPersistence',
        'Test-TcpkProtocolHandlers','Test-TcpkShimCache','Test-TcpkAppPaths',
        'Test-TcpkIfeoHijack','Test-TcpkComObjects','Test-TcpkKernelDrivers',
        'Test-TcpkTrustStore','Test-TcpkNamedPipes','Test-TcpkNamedPipeDacl'
    )

    # --- per-check runner ---
    function _RunCheck([string]$Name, [scriptblock]$Block) {
        # Quick profile: skip the slow whole-machine OS-integration checks above.
        if ($ScanProfile -eq 'Quick' -and ($quickSkip -contains $Name)) {
            Write-Information -MessageData ("  {0,-32}  skipped (Quick profile)" -f $Name) -InformationAction Continue
            Write-TcpkLog -Level INFO -Component $Name -Message 'skipped (Quick profile)' | Out-Null
            Add-TcpkCoverage -Name $Name -Status 'SkippedQuickProfile'
            return
        }
        # Cooperative pause: while the GUI's pause-signal file exists, hold here at the
        # check boundary (capped at 30 min so a stale flag can't hang the audit forever).
        # No PauseSignalPath (CLI default) -> never pauses.
        if ($PauseSignalPath -and (Test-Path -LiteralPath $PauseSignalPath)) {
            Write-Information -MessageData "  [PAUSED] audit held before '$Name' -- make your changes, then click Resume." -InformationAction Continue
            $psw = [System.Diagnostics.Stopwatch]::StartNew()
            while ((Test-Path -LiteralPath $PauseSignalPath) -and $psw.Elapsed.TotalMinutes -lt 30) { Start-Sleep -Milliseconds 400 }
            Write-Information -MessageData "  [RESUMED] continuing audit." -InformationAction Continue
        }
        Write-TcpkLog -Level DEBUG -Component $Name -Message 'start' | Out-Null
        try {
            $sw = [System.Diagnostics.Stopwatch]::StartNew()
            $r = & $Block
            $sw.Stop()
            $count = if ($r) { @($r).Count } else { 0 }
            if ($r) { foreach ($f in @($r)) { $all.Add($f) } }
            $msg = "  {0,-32} {1,5} findings  ({2,4}s)" -f $Name, $count, [int]$sw.Elapsed.TotalSeconds
            Write-Information -MessageData $msg -InformationAction Continue
            $lvl = if ($count -gt 0) { 'SUCCESS' } else { 'INFO' }
            Write-TcpkLog -Level $lvl -Component $Name -Message "$count findings" -DurationMs ([int]$sw.Elapsed.TotalMilliseconds) | Out-Null
            # Coverage: Ran, unless the check emitted only a self-skip stub (needs-elevation /
            # not-implemented) -- classify so coverage.json reflects what truly executed.
            $covStatus = Get-TcpkCoverageStatusFromFindings -Findings $r
            Add-TcpkCoverage -Name $Name -Status $covStatus -Count $count -DurationMs ([int]$sw.Elapsed.TotalMilliseconds)
        } catch {
            $sw.Stop()
            $msg = "  {0,-32}  FAILED  ({1})" -f $Name, $_.Exception.Message
            Write-Information -MessageData $msg -InformationAction Continue
            Write-TcpkLog -Level ERROR -Component $Name -Message $_.Exception.Message -DurationMs ([int]$sw.Elapsed.TotalMilliseconds) | Out-Null
            Add-TcpkCoverage -Name $Name -Status 'Failed' -DurationMs ([int]$sw.Elapsed.TotalMilliseconds)
            $all.Add( (New-TcpkFinding -Module 'meta' -RuleId 'meta.cmdlet-failed' `
                -Severity 'INFO' -Confidence 'Skipped' `
                -Title "Check '$Name' did not complete" `
                -File $Target -Evidence $_.Exception.Message `
                -Description "The audit continued; this check produced no findings.") )
        }
    }

    Write-Information -MessageData "" -InformationAction Continue
    Write-Information -MessageData "Running checks..." -InformationAction Continue

    # Reset structured run-log + per-audit file-text cache + IL assembly cache + coverage manifest
    Clear-TcpkRunLog
    Clear-TcpkTextCache
    Clear-TcpkCecilCache
    Clear-TcpkCoverage
    $script:TcpkAutoProcess = $null
    Write-TcpkLog -Level INFO -Component 'audit' -Message "Audit start: $Target" | Out-Null
    if ($idTerms.Count) {
        Write-Information -MessageData ("Identity search terms ({0}): {1}" -f $idTerms.Count, ($idTerms -join ', ')) -InformationAction Continue
        Write-TcpkLog -Level INFO -Component 'audit.identity' -Message ("terms: " + ($idTerms -join ', ')) | Out-Null
    }

    # Stopwatch for scan timing (recorded into the report scope footer)
    $auditSw = [System.Diagnostics.Stopwatch]::StartNew()

    # ----- Bucket A (static binary analysis, 21 cmdlets) -----
    _RunCheck 'Test-TcpkSignature'           { Test-TcpkSignature           -Path $Target   }
    # Missing binary-hardening (ASLR/DEP/CFG/HighEntropyVA) is reported as POSTURE in
    # the DLL Mitigation Matrix (Get-TcpkPeHardening -> hardening.json, below), NOT as
    # findings: a missing mitigation is defense-in-depth, not an exploitable bug on its
    # own, and a per-DLL HIGH/MEDIUM finding per module would drown the real issues.
    # Run Test-TcpkPeMitigations manually if an engagement specifically needs them as
    # findings (e.g. an SDL / CIS compliance line item).
    _RunCheck 'Test-TcpkPeImports'           { Test-TcpkPeImports           -Path $expanded }
    _RunCheck 'Test-TcpkPeExports'           { Test-TcpkPeExports           -Path $expanded }
    _RunCheck 'Test-TcpkStrongName'          { Test-TcpkStrongName          -Path $expanded }
    _RunCheck 'Test-TcpkStrings'             { Test-TcpkStrings             -Path $expanded -FirstParty }
    _RunCheck 'Test-TcpkResources'           { Test-TcpkResources           -Path $expanded }
    _RunCheck 'Test-TcpkSecrets'             { Test-TcpkSecrets             -Path $expanded }
    _RunCheck 'Test-TcpkEndpoints'           { Test-TcpkEndpoints           -Path $expanded }
    _RunCheck 'Test-TcpkDeserialization'     { Test-TcpkDeserialization     -Path $expanded }
    _RunCheck 'Test-TcpkCallsites'           { Test-TcpkCallsites           -Path $expanded }
    _RunCheck 'Test-TcpkTlsBypass'           { Test-TcpkTlsBypass           -Path $expanded }
    _RunCheck 'Test-TcpkXxe'                 { Test-TcpkXxe                 -Path $expanded }
    _RunCheck 'Test-TcpkWcfConfig'           { Test-TcpkWcfConfig           -Path $expanded }
    _RunCheck 'Test-TcpkCodeIntegrity'       { Test-TcpkCodeIntegrity       -Path $Target   }
    _RunCheck 'Test-TcpkReflectionLoading'   { Test-TcpkReflectionLoading   -Path $expanded }
    _RunCheck 'Test-TcpkPInvokeSurface'      { Test-TcpkPInvokeSurface      -Path $expanded }
    _RunCheck 'Test-TcpkNativeInterop'       { Test-TcpkNativeInterop       -Path $expanded }
    _RunCheck 'Test-TcpkDependencyCves'      { Test-TcpkDependencyCves      -Path $expanded }
    _RunCheck 'Test-TcpkPackageManifests'    { Test-TcpkPackageManifests    -Path $expanded }
    _RunCheck 'Test-TcpkJavaBundle'          { Test-TcpkJavaBundle          -Path $expanded }
    _RunCheck 'Test-TcpkDevArtifacts'        { Test-TcpkDevArtifacts        -Path $expanded }
    _RunCheck 'Test-TcpkEmbeddedScripts'     { Test-TcpkEmbeddedScripts     -Path $expanded }
    _RunCheck 'Test-TcpkWebViewNavTargets'   { Test-TcpkWebViewNavTargets   -Path $expanded }
    _RunCheck 'Test-TcpkNamedObjects'        { Test-TcpkNamedObjects        -Path $expanded }
    _RunCheck 'Test-TcpkPacker'              { Test-TcpkPacker              -Path $expanded }
    _RunCheck 'Test-TcpkAuthFlags'           { Test-TcpkAuthFlags           -Path $expanded }
    _RunCheck 'Test-TcpkElectron'            { Test-TcpkElectron            -Path $expanded }
    _RunCheck 'Test-TcpkElectronJs'          { Test-TcpkElectronJs          -Path $expanded }
    _RunCheck 'Test-TcpkElectronFuses'       { Test-TcpkElectronFuses       -Path $expanded }
    _RunCheck 'Test-TcpkUnsafeNativeApis'    { Test-TcpkUnsafeNativeApis    -Path $expanded }
    _RunCheck 'Test-TcpkRpcSurface'          { Test-TcpkRpcSurface          -Path $expanded }
    _RunCheck 'Test-TcpkEntropySecrets'      { Test-TcpkEntropySecrets      -Path $expanded }
    _RunCheck 'Test-TcpkCryptoMisuse'        { Test-TcpkCryptoMisuse        -Path $expanded }
    _RunCheck 'Test-TcpkJwt'                 { Test-TcpkJwt                 -Path $expanded }
    _RunCheck 'Test-TcpkSessionHandling'     { Test-TcpkSessionHandling     -Path $expanded }
    _RunCheck 'Test-TcpkZipSlip'             { Test-TcpkZipSlip             -Path $expanded }
    _RunCheck 'Test-TcpkDebugFlags'          { Test-TcpkDebugFlags          -Path $expanded }
    _RunCheck 'Test-TcpkUiLeakSurface'       { Test-TcpkUiLeakSurface       -Path $expanded }
    _RunCheck 'Test-TcpkTauriConfig'         { Test-TcpkTauriConfig         -Path $expanded }
    _RunCheck 'Test-TcpkCsvInjection'        { Test-TcpkCsvInjection        -Path $expanded }
    _RunCheck 'Test-TcpkAppStack'            { Test-TcpkAppStack            -Path $expanded }

    # ----- Single-file (.NET PublishSingleFile): extract bundled assemblies + re-scan -----
    # A single-file apphost embeds all managed assemblies inside the .exe, so the
    # checks above see nothing on disk. Extract them and re-run the managed static
    # checks against the recovered assemblies (temp folder, so ACL/dev-artifact
    # checks are not re-run against them).
    $sfRoot = $null
    try { $sfRoot = Expand-TcpkSingleFileForScan -Path $expanded } catch { $sfRoot = $null }
    if ($sfRoot) {
        _RunCheck 'Single-file bundle detected' { New-TcpkFinding -Module 'static' -RuleId 'singlefile.bundle-detected' -Severity 'LOW' -Confidence 'Confirmed' -Title 'Single-file (.NET PublishSingleFile) bundle detected' -File $expanded -Evidence "managed assemblies extracted to $sfRoot" -Description 'Managed assemblies are bundled inside the apphost .exe; on-disk static checks would otherwise miss them. TCPK extracted the bundle and re-ran the managed checks against the recovered assemblies. Single-file packaging is not a security boundary.' -Fix 'Treat all bundled code and strings as recoverable.' }
        _RunCheck 'Test-TcpkSecrets (bundle)'          { Test-TcpkSecrets          -Path $sfRoot }
        _RunCheck 'Test-TcpkEndpoints (bundle)'        { Test-TcpkEndpoints        -Path $sfRoot }
        _RunCheck 'Test-TcpkDeserialization (bundle)'  { Test-TcpkDeserialization  -Path $sfRoot }
        _RunCheck 'Test-TcpkCallsites (bundle)'        { Test-TcpkCallsites        -Path $sfRoot }
        _RunCheck 'Test-TcpkTlsBypass (bundle)'        { Test-TcpkTlsBypass        -Path $sfRoot }
        _RunCheck 'Test-TcpkCryptoMisuse (bundle)'     { Test-TcpkCryptoMisuse     -Path $sfRoot }
        _RunCheck 'Test-TcpkJwt (bundle)'              { Test-TcpkJwt              -Path $sfRoot }
        _RunCheck 'Test-TcpkDependencyCves (bundle)'   { Test-TcpkDependencyCves   -Path $sfRoot }
        _RunCheck 'Test-TcpkReflectionLoading (bundle)' { Test-TcpkReflectionLoading -Path $sfRoot }
        _RunCheck 'Test-TcpkEntropySecrets (bundle)'   { Test-TcpkEntropySecrets   -Path $sfRoot }
        _RunCheck 'Test-TcpkAuthFlags (bundle)'        { Test-TcpkAuthFlags        -Path $sfRoot }
        _RunCheck 'Test-TcpkSessionHandling (bundle)'  { Test-TcpkSessionHandling  -Path $sfRoot }
    }

    # ----- Bucket B (MSIX manifest, 8 cmdlets) -----
    _RunCheck 'Test-TcpkMsixCapabilities'    { Test-TcpkMsixCapabilities    -Path $Target   }
    _RunCheck 'Test-TcpkMsixFrameworkDeps'   { Test-TcpkMsixFrameworkDeps   -Path $Target   }
    _RunCheck 'Test-TcpkMsixProtocols'       { Test-TcpkMsixProtocols       -Path $Target   }
    _RunCheck 'Test-TcpkMsixFileAssocs'      { Test-TcpkMsixFileAssocs      -Path $Target   }
    _RunCheck 'Test-TcpkMsixAppInstaller'    { Test-TcpkMsixAppInstaller    -Path $Target   }
    _RunCheck 'Test-TcpkMsixComServers'      { Test-TcpkMsixComServers      -Path $Target   }
    _RunCheck 'Test-TcpkMsixExtensions'      { Test-TcpkMsixExtensions      -Path $Target   }
    _RunCheck 'Test-TcpkMsixDeclaredVsUsed'  { Test-TcpkMsixDeclaredVsUsed  -Path $Target   }
    _RunCheck 'Test-TcpkUacManifest'         { Test-TcpkUacManifest         -Path $expanded }

    # ----- Bucket C (OS integration, 11 cmdlets) -----
    # Path-targeted
    _RunCheck 'Test-TcpkInstallDirAcl'       { Test-TcpkInstallDirAcl       -Path $expanded }
    _RunCheck 'Test-TcpkFolderAcls'          { Test-TcpkFolderAcls          -Path $expanded }
    _RunCheck 'Test-TcpkSxsManifests'        { Test-TcpkSxsManifests        -Path $expanded }
    _RunCheck 'Test-TcpkKernelDrivers'       { Test-TcpkKernelDrivers       -Path $expanded -NameLike $idTerms }
    _RunCheck 'Test-TcpkTrustStore'          { Test-TcpkTrustStore          -NameLike $idTerms -Path $expanded }
    # All name-targeted checks are app-aware: they take the FULL derived term set so
    # they find data keyed by product code / CLSID / brand name / vendor, not just one
    # hand-typed package name. They run whenever any term was derived (or supplied).
    if ($idTerms.Count) {
        _RunCheck 'Test-TcpkRegistryFootprint'   { Test-TcpkRegistryFootprint   -NameLike $idTerms }
        _RunCheck 'Test-TcpkRegistryAcl'         { Test-TcpkRegistryAcl         -NameLike $idTerms }
        _RunCheck 'Test-TcpkRegistryValues'      { Test-TcpkRegistryValues      -NameLike $idTerms }
        _RunCheck 'Test-TcpkFirewallRules'       { Test-TcpkFirewallRules       -NameLike $idTerms -Path $expanded }
        _RunCheck 'Test-TcpkAvExclusions'        { Test-TcpkAvExclusions        -NameLike $idTerms -Path $expanded }
        _RunCheck 'Test-TcpkServiceBinaryAcl'    { Test-TcpkServiceBinaryAcl    -NameLike $idTerms }
        _RunCheck 'Test-TcpkServicePermissions'  { Test-TcpkServicePermissions  -NameLike $idTerms }
        _RunCheck 'Test-TcpkUnquotedServicePath' { Test-TcpkUnquotedServicePath -NameLike $idTerms }
        _RunCheck 'Test-TcpkAutoStart'           { Test-TcpkAutoStart           -NameLike $idTerms }
        _RunCheck 'Test-TcpkProgramDataAcls'     { Test-TcpkProgramDataAcls     -NameLike $idTerms }
        _RunCheck 'Test-TcpkScheduledTaskAcl'    { Test-TcpkScheduledTaskAcl    -NameLike $idTerms }
        _RunCheck 'Test-TcpkWmiPersistence'      { Test-TcpkWmiPersistence      -NameLike $idTerms }
        _RunCheck 'Test-TcpkProtocolHandlers'    { Test-TcpkProtocolHandlers    -NameLike $idTerms }
        _RunCheck 'Test-TcpkShimCache'           { Test-TcpkShimCache           -NameLike $idTerms }
        _RunCheck 'Test-TcpkAppPaths'            { Test-TcpkAppPaths            -NameLike $idTerms }
        _RunCheck 'Test-TcpkIfeoHijack'          { Test-TcpkIfeoHijack          -NameLike $idTerms }
    }

    # ----- Bucket D (credential storage, 6 cmdlets) -----
    _RunCheck 'Test-TcpkDpapiBlobs'          { Test-TcpkDpapiBlobs          -Path $expanded }
    _RunCheck 'Test-TcpkPlaintextConfigs'    { Test-TcpkPlaintextConfigs    -Path $expanded }
    _RunCheck 'Test-TcpkAppConfigSecrets'    { Test-TcpkAppConfigSecrets    -Path $expanded }
    _RunCheck 'Test-TcpkTokenCaches'         { Test-TcpkTokenCaches         -Path $expanded }
    _RunCheck 'Test-TcpkKeyMaterial'         { Test-TcpkKeyMaterial         -Path $expanded }
    _RunCheck 'Test-TcpkLocalDb'             { Test-TcpkLocalDb             -Path $expanded -NameLike $idTerms }
    if ($idTerms.Count) {
        _RunCheck 'Test-TcpkCredentialManager'  { Test-TcpkCredentialManager  -NameLike $idTerms }
        # WebView2 creds need PackageFamilyName not Name; defer to user passing it
        if ($PSBoundParameters.ContainsKey('PackageFamilyName')) {
            _RunCheck 'Test-TcpkWebViewCreds'   { Test-TcpkWebViewCreds       -PackageFamilyName $PackageFamilyName }
        }
        _RunCheck 'Test-TcpkBrowserTokenStore'  { Test-TcpkBrowserTokenStore  -NameLike $idTerms }
    }

    # ----- Bucket E (runtime / live process, 14 cmdlets) -----
    # Auto-attach: if the caller did not name a process (and did not opt out), find the
    # target's own running process so these checks fire without -ProcessName. Read-only.
    if (-not $ProcessName -and -not $NoAutoProcess) {
        $auto = $null
        try { $auto = Resolve-TcpkTargetProcess -Path $expanded -IdTerms $idTerms } catch { }
        if ($auto -and $auto.Name) {
            $ProcessName = $auto.Name
            $script:TcpkAutoProcess = $auto
            Write-Information -MessageData ("  [auto-process] attached to '{0}' (PID {1}); live-process checks enabled. -NoAutoProcess to disable." -f $auto.Name, $auto.ProcId) -InformationAction Continue
            Write-TcpkLog -Level INFO -Component 'audit.autoprocess' -Message "attached to $($auto.Name) (PID $($auto.ProcId))" | Out-Null
        }
    }
    $liveProcChecks = @(
        'Test-TcpkProcessMitigations','Test-TcpkLoadedModuleSignatures','Test-TcpkListeningPorts',
        'Test-TcpkLoadedModulePaths','Test-TcpkHandleEnumeration','Test-TcpkWindowEnumeration',
        'Test-TcpkGuiInspector','Test-TcpkProcessToken','Test-TcpkChildProcesses',
        'Test-TcpkProcessDacl','Test-TcpkProcessEnvSecrets'
    )
    $liveProcOn = [bool]($ProcessName -and (Get-Process -Name $ProcessName -ErrorAction SilentlyContinue))
    if ($liveProcOn) {
        _RunCheck 'Test-TcpkProcessMitigations'      { Test-TcpkProcessMitigations      -ProcessName $ProcessName }
        _RunCheck 'Test-TcpkLoadedModuleSignatures'  { Test-TcpkLoadedModuleSignatures  -ProcessName $ProcessName }
        _RunCheck 'Test-TcpkListeningPorts'          { Test-TcpkListeningPorts          -ProcessName $ProcessName }
        _RunCheck 'Test-TcpkLoadedModulePaths'       { Test-TcpkLoadedModulePaths       -ProcessName $ProcessName }
        _RunCheck 'Test-TcpkHandleEnumeration'       { Test-TcpkHandleEnumeration       -ProcessName $ProcessName }
        _RunCheck 'Test-TcpkWindowEnumeration'       { Test-TcpkWindowEnumeration       -ProcessName $ProcessName }
        _RunCheck 'Test-TcpkGuiInspector'            { Test-TcpkGuiInspector            -ProcessName $ProcessName }
        _RunCheck 'Test-TcpkProcessToken'            { Test-TcpkProcessToken            -ProcessName $ProcessName }
        _RunCheck 'Test-TcpkChildProcesses'          { Test-TcpkChildProcesses          -ProcessName $ProcessName }
        _RunCheck 'Test-TcpkProcessDacl'             { Test-TcpkProcessDacl             -ProcessName $ProcessName }
        _RunCheck 'Test-TcpkProcessEnvSecrets'       { Test-TcpkProcessEnvSecrets       -ProcessName $ProcessName }
    } else {
        # No live process resolved -> record the gated live-process checks so coverage.json
        # shows them as GatedNoProcess instead of silently omitting them.
        foreach ($n in $liveProcChecks) { Add-TcpkCoverage -Name $n -Status 'GatedNoProcess' }
    }
    if ($idTerms.Count) {
        _RunCheck 'Test-TcpkNamedPipes'              { Test-TcpkNamedPipes              -NameLike $idTerms }
        _RunCheck 'Test-TcpkNamedPipeDacl'           { Test-TcpkNamedPipeDacl           -NameLike $idTerms }
        _RunCheck 'Test-TcpkComObjects'              { Test-TcpkComObjects              -NameLike $idTerms -Path $expanded }
        _RunCheck 'Test-TcpkMailslotsAlpc'           { Test-TcpkMailslotsAlpc           -NameLike $idTerms }
    }
    # ETW and memory dump only when explicitly requested via -EnableDeepRuntime
    if ($EnableDeepRuntime -and $ProcessName) {
        _RunCheck 'Test-TcpkDllSearchTrace'          { Test-TcpkDllSearchTrace          -ProcessName $ProcessName -Seconds 30 }
        _RunCheck 'Test-TcpkMemoryDump'              { Test-TcpkMemoryDump              -ProcessName $ProcessName }
        _RunCheck 'Test-TcpkMemorySecrets'           { Test-TcpkMemorySecrets           -ProcessName $ProcessName }
    }

    # ----- Bucket F (network, 6 cmdlets) -----
    _RunCheck 'Test-TcpkTlsPinning'        { Test-TcpkTlsPinning        -Path $expanded }
    _RunCheck 'Test-TcpkUpdateFlow'        { Test-TcpkUpdateFlow        -Path $expanded }
    _RunCheck 'Test-TcpkBackendEndpoints'  { Test-TcpkBackendEndpoints  -Path $expanded }
    _RunCheck 'Test-TcpkTlsProtocols'      { Test-TcpkTlsProtocols      -Path $expanded }
    _RunCheck 'Test-TcpkDnsLeakage'        { Test-TcpkDnsLeakage        -Path $expanded }
    _RunCheck 'Test-TcpkCrlOcsp'           { Test-TcpkCrlOcsp           -Path $expanded }
    _RunCheck 'Test-TcpkInsecureSchemes'   { Test-TcpkInsecureSchemes   -Path $expanded }
    _RunCheck 'Test-TcpkSelfHostedServer'  { Test-TcpkSelfHostedServer  -Path $expanded }
    _RunCheck 'Test-TcpkRpcChannels'       { Test-TcpkRpcChannels       -Path $expanded }

    # ----- Bucket G (WebView2, 6 new cmdlets; G03 already in Discovery as WebViewNavTargets) -----
    _RunCheck 'Test-TcpkWv2HostObjects'    { Test-TcpkWv2HostObjects    -Path $expanded }
    _RunCheck 'Test-TcpkWv2WebMessage'     { Test-TcpkWv2WebMessage     -Path $expanded }
    _RunCheck 'Test-TcpkWv2VirtualHost'    { Test-TcpkWv2VirtualHost    -Path $expanded }
    _RunCheck 'Test-TcpkWv2DevTools'       { Test-TcpkWv2DevTools       -Path $expanded }
    _RunCheck 'Test-TcpkWv2ScriptInjection'{ Test-TcpkWv2ScriptInjection -Path $expanded }
    _RunCheck 'Test-TcpkWv2ResourcePolicy' { Test-TcpkWv2ResourcePolicy -Path $expanded }

    # ----- Bucket H (logging / telemetry, 3 cmdlets) -----
    _RunCheck 'Test-TcpkLogFiles'          { Test-TcpkLogFiles          -Path $expanded }
    _RunCheck 'Test-TcpkTelemetrySdks'     { Test-TcpkTelemetrySdks     -Path $expanded }
    _RunCheck 'Test-TcpkPiiInLogs'         { Test-TcpkPiiInLogs         -Path $expanded }
    _RunCheck 'Test-TcpkEtwProviders'      { Test-TcpkEtwProviders      -Path $expanded }

    # ----- Bucket I (memory hygiene, 3 cmdlets) -----
    $exeName = if ($ProcessName) { "$ProcessName.exe" } else { '' }
    _RunCheck 'Test-TcpkWerPolicy'         { Test-TcpkWerPolicy         -ExeName $exeName }
    _RunCheck 'Test-TcpkPageFile'          { Test-TcpkPageFile }
    _RunCheck 'Test-TcpkSecureStringUsage' { Test-TcpkSecureStringUsage -Path $expanded }

    # ----- Bucket J (anti-debug, 4 cmdlets) -----
    _RunCheck 'Test-TcpkAntiDebugRefs'       { Test-TcpkAntiDebugRefs       -Path $expanded }
    _RunCheck 'Test-TcpkSelfIntegrityCheck'  { Test-TcpkSelfIntegrityCheck  -Path $expanded }
    _RunCheck 'Test-TcpkAntiInjection'       { Test-TcpkAntiInjection       -Path $expanded }
    _RunCheck 'Test-TcpkTimingAntiDebug'     { Test-TcpkTimingAntiDebug     -Path $expanded }

    # --- Verify layer: dedupe + false-positive killers + correlation ---
    Write-Information -MessageData "" -InformationAction Continue
    Write-Information -MessageData "Triaging via Resolve-TcpkFindings..." -InformationAction Continue
    $before = $all.Count
    # Triage only (dedupe + false-positive killers + correlation). Aggregation is
    # deferred until AFTER the optional LLM pass, so the LLM can read each occurrence's
    # method IL on its own file before identical findings are collapsed.
    $resolved = $all | Resolve-TcpkFindings -NoAggregate
    $all = New-Object 'System.Collections.Generic.List[TcpkFinding]'
    foreach ($f in $resolved) { $all.Add($f) }
    Write-Information -MessageData "  $before -> $($all.Count) findings after dedupe + triage" -InformationAction Continue
    Write-TcpkLog -Level INFO -Component 'triage' -Message "$before -> $($all.Count) findings after dedupe + triage" | Out-Null

    # --- deterministic IL verification (real-vs-FP) for callsites.* findings ---
    # Reads the IL with Cecil: is the flagged API actually invoked, reachable, and fed
    # by external input? Refines Confidence to 'Confirmed (IL)' / 'Likely-FP (IL)'.
    # Runs BEFORE the LLM so the model + reports inherit the proven verdicts. No model.
    try {
        $ilRefined = $all | Confirm-TcpkCallsiteUsage
        $all = New-Object 'System.Collections.Generic.List[TcpkFinding]'
        foreach ($f in $ilRefined) { $all.Add($f) }
        $ilOk = @($all | Where-Object { "$($_.Confidence)" -eq 'Confirmed (IL)' }).Count
        $ilFp = @($all | Where-Object { "$($_.Confidence)" -eq 'Likely-FP (IL)' }).Count
        if ($ilOk -or $ilFp) {
            Write-Information -MessageData "  IL verify: $ilOk confirmed, $ilFp likely-FP (callsite reachability + argument analysis)" -InformationAction Continue
            Write-TcpkLog -Level INFO -Component 'il-verify' -Message "$ilOk confirmed, $ilFp likely-FP" | Out-Null
        }
    } catch {
        Write-TcpkLog -Level WARN -Component 'il-verify' -Message $_.Exception.Message | Out-Null
    }

    # --- optional LLM Stage-2 (opt-in): annotate code-construct findings ---
    # Advisory only: updates Confidence to a '(LLM)' verdict + appends reasoning,
    # never changes Severity. Local-only unless -AllowCloudLlm (cloud would send the
    # decompiled IL off-box). Degrades to a no-op + warning if no backend / Cecil.
    $llmRan = $false
    if ($EnableLlm) {
        $llmCloud = $false
        try { $llmCloud = Test-TcpkLlmIsCloud } catch { }
        if ($llmCloud -and -not $AllowCloudLlm) {
            $pn = (Get-TcpkLlmConfig).provider
            Write-Information -MessageData "  LLM: provider '$pn' is a CLOUD backend; SKIPPED to protect target confidentiality (decompiled IL would leave this machine). Re-run with -AllowCloudLlm to send it, or switch to a local provider (ollama)." -InformationAction Continue
            Write-TcpkLog -Level WARN -Component 'llm' -Message "cloud provider '$pn' skipped (no -AllowCloudLlm)" | Out-Null
        } else {
            # -AllowCloudLlm confirmed (or a local provider): open the cloud gate for
            # this run so Resolve-TcpkLlmBackend permits a cloud backend. Without this,
            # a cloud provider throws "Run Enable-TcpkLlmCloud" inside the judgment call.
            if ($llmCloud) { $script:TcpkLlmCloudEnabled = $true }
            Write-Information -MessageData "" -InformationAction Continue
            Write-Information -MessageData "LLM Stage-2 (code-construct judgment)..." -InformationAction Continue
            try {
                $judged = $all.ToArray() | Invoke-TcpkLlmCodeJudgment
                $all = New-Object 'System.Collections.Generic.List[TcpkFinding]'
                foreach ($f in $judged) { $all.Add($f) }
                $llmCount = @($all | Where-Object { "$($_.Confidence)" -match '\(LLM\)' }).Count
                Write-Information -MessageData "  LLM annotated $llmCount code-construct finding(s)" -InformationAction Continue
                Write-TcpkLog -Level SUCCESS -Component 'llm' -Message "$llmCount finding(s) annotated" | Out-Null
                $llmRan = $true
            } catch {
                Write-Information -MessageData "  LLM Stage-2 failed: $($_.Exception.Message)" -InformationAction Continue
                Write-TcpkLog -Level ERROR -Component 'llm' -Message $_.Exception.Message | Out-Null
            }
        }
    }

    # Snapshot the FULL (un-aggregated) findings BEFORE collapsing. The recon profile,
    # attack-surface map and exploit plan are per-occurrence inventories -- they must
    # see every endpoint/port/host individually, not the aggregated "(N affected)" view.
    $findingsFull = $all.ToArray()

    # --- aggregate identical findings (now that the LLM has judged per-file) ---
    # Collapse same RuleId + Severity + Confidence into one finding with an Affected
    # list. Done after the LLM pass so files sharing a verdict merge, while files with
    # different verdicts (e.g. Confirmed (LLM) vs Likely-FP (LLM)) stay separate.
    $beforeAgg = $all.Count
    $aggregated = $all | Resolve-TcpkFindings -AggregateOnly
    $all = New-Object 'System.Collections.Generic.List[TcpkFinding]'
    foreach ($f in $aggregated) { $all.Add($f) }
    if ($all.Count -ne $beforeAgg) {
        Write-Information -MessageData "  $beforeAgg -> $($all.Count) findings after aggregating identical rules" -InformationAction Continue
        Write-TcpkLog -Level INFO -Component 'aggregate' -Message "$beforeAgg -> $($all.Count) after aggregation" | Out-Null
    }

    # --- CVE exposure: match shipped components vs the offline CVE catalog ---
    $cveMatches = @()
    try {
        $cveMatches = @(Get-TcpkCveMatches -Path $expanded -OnlineCve:$OnlineCve)
        $vulnCount = 0
        foreach ($m in $cveMatches) {
            if ($m.Status -ne 'Vulnerable') { continue }   # only emit confirmed vulnerable as findings
            $vulnCount++
            $all.Add( (New-TcpkFinding -Module 'static' -RuleId "cve.$($m.Cve)" `
                -Severity $m.Severity -Confidence $m.Confidence `
                -Title "$($m.Package) $($m.ShippedVersion) -- $($m.Cve): $($m.Title)" `
                -File $m.File -Evidence "shipped $($m.ShippedVersion); fixed in $($m.FixedVersion)" `
                -Cwe ([string[]]@($m.Cwe)) -Description $m.Summary `
                -Fix "Upgrade $($m.Package) to >= $($m.FixedVersion). Ref: $(@($m.References)[0])") )
        }
        Write-Information -MessageData "  CVE catalog: $(@($cveMatches).Count) component matches ($vulnCount confirmed-vulnerable -> findings)" -InformationAction Continue
        Write-TcpkLog -Level SUCCESS -Component 'cve.match' -Message "$(@($cveMatches).Count) matches, $vulnCount confirmed-vulnerable" | Out-Null
    } catch {
        Write-Information -MessageData "  CVE matching failed: $($_.Exception.Message)" -InformationAction Continue
        Write-TcpkLog -Level ERROR -Component 'cve.match' -Message $_.Exception.Message | Out-Null
    }

    # Make the electron.outdated-runtime finding REPORT WHAT THE OSV CHECK ACTUALLY DID (advisories
    # found / queried-but-empty / offline) instead of always showing the static "Run with -OnlineCve"
    # hint -- see Update-TcpkRuntimeCveText. Best-effort; never breaks the audit.
    try {
        $ort = $all | Where-Object { "$($_.RuleId)" -eq 'electron.outdated-runtime' } | Select-Object -First 1
        if ($ort) {
            Update-TcpkRuntimeCveText -Finding $ort -CveMatches $cveMatches -OnlineCve ([bool]$OnlineCve) | Out-Null
            Write-TcpkLog -Level INFO -Component 'cve.electron-wire' -Message "outdated-runtime text reconciled with OSV result (online=$([bool]$OnlineCve))" | Out-Null
        }
    } catch { }

    # --- correlate findings into exploit chains (raises co-occurring conditions
    #     to their true, combined severity; appended so reports + summary see them) ---
    try {
        $chains = @($all.ToArray() | Get-TcpkExploitChains)
        foreach ($c in $chains) { $all.Add($c) }
        if ($chains.Count) {
            Write-Information -MessageData "  exploit chains: $($chains.Count) correlated (see CRITICAL/HIGH 'chain.*' findings)" -InformationAction Continue
            Write-TcpkLog -Level SUCCESS -Component 'chains' -Message "$($chains.Count) correlated chain(s)" | Out-Null
        }
    } catch {
        Write-Information -MessageData "  chain correlation failed: $($_.Exception.Message)" -InformationAction Continue
        Write-TcpkLog -Level ERROR -Component 'chains' -Message $_.Exception.Message | Out-Null
    }

    # --- summary ---
    Write-Information -MessageData "" -InformationAction Continue
    Write-Information -MessageData "Severity breakdown:" -InformationAction Continue
    foreach ($sev in 'CRITICAL','HIGH','MEDIUM','LOW','INFO') {
        $count = ($all | Where-Object Severity -eq $sev).Count
        if ($count -gt 0) {
            Write-Information -MessageData ("  {0,-9} {1,4}" -f $sev, $count) -InformationAction Continue
        }
    }
    Write-Information -MessageData "" -InformationAction Continue

    $auditSw.Stop()

    # --- recon / target profile (drives the report header card) ---
    Write-Information -MessageData "Building target profile (recon)..." -InformationAction Continue
    $targetProfile = $null
    try {
        $psw = [System.Diagnostics.Stopwatch]::StartNew()
        $targetProfile = Get-TcpkTargetProfile -Path $expanded -Findings $findingsFull
        $psw.Stop()
        Write-TcpkLog -Level SUCCESS -Component 'recon.profile' -Message "built ($($targetProfile.Name) $($targetProfile.Version))" -DurationMs ([int]$psw.Elapsed.TotalMilliseconds) | Out-Null
    } catch {
        Write-Information -MessageData "  profile failed: $($_.Exception.Message)" -InformationAction Continue
        Write-TcpkLog -Level ERROR -Component 'recon.profile' -Message $_.Exception.Message | Out-Null
    }

    # Interesting-strings extraction (recon-tab only; written as a sidecar, NOT in reports)
    try {
        $reconStrings = Get-TcpkReconStrings -Path $expanded
        $reconStrings | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Join-Path $OutDir 'strings.json') -Encoding UTF8
        Write-Information -MessageData ("  strings.json: {0} URLs, {1} paths, {2} reg keys, {3} IPs, {4} emails, {5} cmd refs" -f `
            @($reconStrings.Urls).Count, @($reconStrings.FilePaths).Count, @($reconStrings.RegistryKeys).Count, `
            @($reconStrings.IpAddresses).Count, @($reconStrings.Emails).Count, @($reconStrings.Commands).Count) -InformationAction Continue
        Write-TcpkLog -Level SUCCESS -Component 'recon.strings' -Message "$(@($reconStrings.Urls).Count) URLs, $(@($reconStrings.IpAddresses).Count) IPs, $(@($reconStrings.Interesting).Count) secret-ish" | Out-Null
    } catch {
        Write-Information -MessageData "  strings extraction failed: $($_.Exception.Message)" -InformationAction Continue
        Write-TcpkLog -Level ERROR -Component 'recon.strings' -Message $_.Exception.Message | Out-Null
    }

    # --- attack-surface map (synthesized entry-point view; Batch C deliverable) ---
    try {
        $surface = $findingsFull | Get-TcpkAttackSurface
        $surface | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Join-Path $OutDir 'attack-surface.json') -Encoding UTF8
        $catSummary = (@($surface.Categories) | ForEach-Object { "$($_.Label)=$($_.Count)" }) -join '; '
        $all.Add( (New-TcpkFinding -Module 'recon' -RuleId 'attacksurface.summary' `
            -Severity 'INFO' -Confidence 'Confirmed' `
            -Title "Attack surface: $($surface.TotalEntryPoints) entry point(s) across $($surface.CategoryCount) categories" `
            -File $Target -Evidence $catSummary `
            -Description 'Synthesized map of how the app can be reached (protocols, IPC, listeners, exports, web bridges). See attack-surface.json.') )
        Write-Information -MessageData "  attack-surface.json: $($surface.TotalEntryPoints) entry points, $($surface.CategoryCount) categories" -InformationAction Continue
        Write-TcpkLog -Level SUCCESS -Component 'recon.attacksurface' -Message "$($surface.TotalEntryPoints) entry points, $($surface.CategoryCount) categories" | Out-Null
    } catch {
        Write-Information -MessageData "  attack-surface build failed: $($_.Exception.Message)" -InformationAction Continue
        Write-TcpkLog -Level ERROR -Component 'recon.attacksurface' -Message $_.Exception.Message | Out-Null
    }

    # --- SBOM (CycloneDX; Batch C deliverable) ---
    # Inventory once (SHA-256 hashing is the expensive part) and reuse the same
    # component list for the .cdx.json AND the HTML/Excel SBOM sections.
    $sbom = @()
    try { $sbom = @(Get-TcpkSbomComponents -Path $expanded) }
    catch { Write-TcpkLog -Level ERROR -Component 'sbom.inventory' -Message $_.Exception.Message | Out-Null }
    try {
        $sbomPath = Join-Path $OutDir 'sbom.cdx.json'
        if ($sbom.Count) { Export-TcpkSbom -Components $sbom -OutFile $sbomPath -Profile $targetProfile -CveMatches $cveMatches | Out-Null }
        else             { Export-TcpkSbom -Path $expanded  -OutFile $sbomPath -Profile $targetProfile -CveMatches $cveMatches | Out-Null }
        Write-TcpkLog -Level SUCCESS -Component 'sbom' -Message "SBOM written ($($sbom.Count) components)" | Out-Null
    } catch {
        Write-Information -MessageData "  SBOM build failed: $($_.Exception.Message)" -InformationAction Continue
        Write-TcpkLog -Level ERROR -Component 'sbom' -Message $_.Exception.Message | Out-Null
    }

    # --- exploit plan (CVE matches + exploitable findings -> actionable items) ---
    try {
        $plan = @(Get-TcpkExploitPlan -Findings $findingsFull -CveMatches $cveMatches -Path $expanded)
        $plan | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $OutDir 'exploits.json') -Encoding UTF8
        $expModules = @($plan | Where-Object { $_.Module }).Count
        Write-Information -MessageData "  exploits.json: $(@($plan).Count) actionable items ($expModules with a framework exploit module)" -InformationAction Continue
        Write-TcpkLog -Level SUCCESS -Component 'exploit.plan' -Message "$(@($plan).Count) items, $expModules with a module" | Out-Null
    } catch {
        Write-Information -MessageData "  exploit-plan build failed: $($_.Exception.Message)" -InformationAction Continue
        Write-TcpkLog -Level ERROR -Component 'exploit.plan' -Message $_.Exception.Message | Out-Null
    }

    # --- audit scope (buckets run, LLM, timing) ---
    $bucketsRun = 'A Static, B Manifest, C OS, D Creds, E Runtime, F Network, G WebView2, H Logging, I Memory, J AntiDebug'
    if ($ProcessName) { $bucketsRun += ' (live-process E on)' }
    $llmInfo = 'disabled'
    try {
        $lc = Get-TcpkLlmConfig
        if ($llmRan) { $llmInfo = "$($lc.provider) / $($lc.model) (ran inline; code-construct findings annotated)" }
        elseif ($lc -and $lc.enabled) { $llmInfo = "$($lc.provider) / $($lc.model) (available; pass -EnableLlm or pipe to Invoke-TcpkLlmCodeJudgment)" }
    } catch { }
    # Coverage summary + the non-Ran checks (gated / needs-elevation / skipped / failed), so the
    # report itself answers "was this 100%?" -- full per-check detail lives in coverage.json.
    $covLine = ''; $covGaps = ''
    try { $covLine = Get-TcpkCoverageSummaryLine } catch { }
    try {
        $gapNames = @(Get-TcpkCoverage | Where-Object { $_.status -ne 'Ran' } | ForEach-Object { "$($_.name) [$($_.status)]" })
        if ($gapNames.Count) { $covGaps = ($gapNames -join ', ') }
    } catch { }
    $scope = [pscustomobject]@{
        Buckets      = $bucketsRun
        Llm          = $llmInfo
        Timing       = "scan $([int]$auditSw.Elapsed.TotalSeconds)s"
        Coverage     = $covLine
        CoverageGaps = $covGaps
    }

    # --- write reports ---
    # Deliverables: HTML + Markdown + Excel (+ SARIF + intel). findings.json stays as the
    # INTERNAL data file the GUI tabs (Recon/Exploit/Logs) and the MCP server read -- it is
    # not a "report".
    $jsonPath = Join-Path $OutDir 'findings.json'
    $htmlPath = Join-Path $OutDir 'index.html'
    $xlsxPath = Join-Path $OutDir 'report.xlsx'

    $all | Export-TcpkReportJson -OutFile $jsonPath -Profile $targetProfile

    # Per-DLL hardening matrix (ASLR/DEP/CFG/HighEntropyVA/...) for the Excel sheet
    # AND as a JSON sidecar the GUI's "DLL Mitigation Matrix" tab reads.
    $hardening = @()
    try { $hardening = @(Get-TcpkPeHardening -Path $expanded) }
    catch { Write-TcpkLog -Level ERROR -Component 'hardening' -Message $_.Exception.Message | Out-Null }
    try { $hardening | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $OutDir 'hardening.json') -Encoding UTF8 }
    catch { Write-TcpkLog -Level ERROR -Component 'hardening.json' -Message $_.Exception.Message | Out-Null }

    # Per-DLL signing matrix (signed / not signed -- information only) for the Excel
    # 'DLL Signing' sheet, the HTML signing table, and the GUI 'DLL Signing' tab.
    $signing = @()
    try { $signing = @(Get-TcpkSigningMatrix -Path $expanded) }
    catch { Write-TcpkLog -Level ERROR -Component 'signing' -Message $_.Exception.Message | Out-Null }
    try { $signing | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $OutDir 'signing.json') -Encoding UTF8 }
    catch { Write-TcpkLog -Level ERROR -Component 'signing.json' -Message $_.Exception.Message | Out-Null }

    $all | Export-TcpkReportHtml -OutFile $htmlPath -Target $Target -Profile $targetProfile -Scope $scope -CveMatches $cveMatches -Hardening $hardening -Signing $signing -Sbom $sbom
    # Markdown deliverable (plain-text, client-facing) alongside the HTML.
    try {
        $all | Export-TcpkReportMarkdown -OutFile (Join-Path $OutDir 'report.md') -Target $Target -Profile $targetProfile | Out-Null
    } catch { Write-TcpkLog -Level ERROR -Component 'report.md' -Message $_.Exception.Message | Out-Null }
    try {
        $all | Export-TcpkReportExcel -OutFile $xlsxPath -Hardening $hardening -Signing $signing -Profile $targetProfile -CveMatches $cveMatches -Sbom $sbom -Target $Target
    } catch { Write-TcpkLog -Level ERROR -Component 'report.excel' -Message $_.Exception.Message | Out-Null }
    # SARIF 2.1.0 sidecar for CI code-scanning ingest (GitHub Advanced Security / Azure DevOps).
    try {
        $all | Export-TcpkReportSarif -OutFile (Join-Path $OutDir 'report.sarif') -Target $Target
    } catch { Write-TcpkLog -Level ERROR -Component 'report.sarif' -Message $_.Exception.Message | Out-Null }
    # Self-contained offline "program intelligence" dashboard (severity/confidence + evidence
    # ladder, recon endpoint map, filterable finding cards). One file, no server, no CDN.
    try {
        $all | Export-TcpkReportIntel -OutFile (Join-Path $OutDir 'intel.html') -Target $Target -Profile $targetProfile
    } catch { Write-TcpkLog -Level ERROR -Component 'report.intel' -Message $_.Exception.Message | Out-Null }
    Write-TcpkLog -Level SUCCESS -Component 'report' -Message "HTML + Markdown + Excel + SARIF + intel written ($($all.Count) findings, $(@($hardening).Count) DLLs)" | Out-Null

    # --- finalize structured run-log (drives the Logs / Runtime tab) ---
    foreach ($sev in 'CRITICAL','HIGH','MEDIUM','LOW','INFO') {
        $sc = ($all | Where-Object Severity -eq $sev).Count
        if ($sc -gt 0) { Write-TcpkLog -Level INFO -Component 'summary' -Message "${sev}: $sc" | Out-Null }
    }
    $errCount = @(Get-TcpkRunLog | Where-Object { $_.level -eq 'ERROR' }).Count
    Write-TcpkLog -Level $(if ($errCount) { 'WARN' } else { 'SUCCESS' }) -Component 'audit' `
        -Message "Audit complete in $([int]$auditSw.Elapsed.TotalSeconds)s -- $($all.Count) findings, $errCount check error(s)" `
        -DurationMs ([int]$auditSw.Elapsed.TotalMilliseconds) | Out-Null
    try { Save-TcpkRunLog -Dir $OutDir } catch { }

    # --- coverage manifest (which checks ran / were gated / skipped / failed) ---
    try {
        $attachedPid = $null
        if ($script:TcpkAutoProcess -and $script:TcpkAutoProcess.ProcId) { $attachedPid = $script:TcpkAutoProcess.ProcId }
        elseif ($ProcessName) { try { $attachedPid = (Get-Process -Name $ProcessName -ErrorAction SilentlyContinue | Select-Object -First 1).Id } catch { } }
        Save-TcpkCoverage -Dir $OutDir -Elevated $isElevated -ProcessAttached "$ProcessName" `
            -AttachedPid $attachedPid -OnlineCve ([bool]$OnlineCve) -ScanProfile $ScanProfile `
            -GeneratedAt ((Get-Date).ToString('o')) | Out-Null
        Write-Information -MessageData ("  " + (Get-TcpkCoverageSummaryLine)) -InformationAction Continue
        Write-TcpkLog -Level INFO -Component 'coverage' -Message (Get-TcpkCoverageSummaryLine) | Out-Null
    } catch {
        Write-TcpkLog -Level ERROR -Component 'coverage' -Message $_.Exception.Message | Out-Null
    }

    Clear-TcpkCecilCache   # release the cached IL assemblies (file handles) now the audit is done

    Write-Information -MessageData ("Reports written to: " + $OutDir) -InformationAction Continue

    # --- FailOn gate ---
    if ($FailOn) {
        $worst = ($all | ForEach-Object { Get-TcpkSeverityRank $_.Severity } | Measure-Object -Maximum).Maximum
        $threshold = Get-TcpkSeverityRank $FailOn
        if ($worst -ge $threshold) {
            throw "TCPK audit threshold reached: max severity >= $FailOn"
        }
    }

    # Return all findings as an array (comma operator prevents single-element unwrap)
    , $all.ToArray()
}
