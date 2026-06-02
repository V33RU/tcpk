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
    MSIX file or extracted install directory.

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

.EXAMPLE
    Invoke-TcpkAudit -Target 'C:\Path\To\App.msix' -OutDir .\out\App -Acknowledge

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
        [ValidateSet('INFO','LOW','MEDIUM','HIGH','CRITICAL')][string]$FailOn
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

    # Expand MSIX if needed
    $expanded = try { Expand-TcpkMsix -Path $Target } catch { $Target }

    # --- application-identity search terms (drives the OS / registry bucket) ---
    # Apps store data under product codes, CLSIDs, ProgIDs and brand names that
    # differ from the package name, so we search for a SET of terms derived from
    # the app's own identity (manifest + main exe), not just a hand-typed -PackageName.
    $idTerms = @(Get-TcpkIdentityTerms -Path $expanded -Extra $PackageName)

    # --- collected findings ---
    $all = New-Object 'System.Collections.Generic.List[TcpkFinding]'

    # --- per-check runner ---
    function _RunCheck([string]$Name, [scriptblock]$Block) {
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
        } catch {
            $sw.Stop()
            $msg = "  {0,-32}  FAILED  ({1})" -f $Name, $_.Exception.Message
            Write-Information -MessageData $msg -InformationAction Continue
            Write-TcpkLog -Level ERROR -Component $Name -Message $_.Exception.Message -DurationMs ([int]$sw.Elapsed.TotalMilliseconds) | Out-Null
            $all.Add( (New-TcpkFinding -Module 'meta' -RuleId 'meta.cmdlet-failed' `
                -Severity 'INFO' -Confidence 'Skipped' `
                -Title "Check '$Name' did not complete" `
                -File $Target -Evidence $_.Exception.Message `
                -Description "The audit continued; this check produced no findings.") )
        }
    }

    Write-Information -MessageData "" -InformationAction Continue
    Write-Information -MessageData "Running checks..." -InformationAction Continue

    # Reset structured run-log + per-audit file-text cache
    Clear-TcpkRunLog
    Clear-TcpkTextCache
    Write-TcpkLog -Level INFO -Component 'audit' -Message "Audit start: $Target" | Out-Null
    if ($idTerms.Count) {
        Write-Information -MessageData ("Identity search terms ({0}): {1}" -f $idTerms.Count, ($idTerms -join ', ')) -InformationAction Continue
        Write-TcpkLog -Level INFO -Component 'audit.identity' -Message ("terms: " + ($idTerms -join ', ')) | Out-Null
    }

    # Stopwatch for scan timing (recorded into the report scope footer)
    $auditSw = [System.Diagnostics.Stopwatch]::StartNew()

    # ----- Bucket A (static binary analysis, 21 cmdlets) -----
    _RunCheck 'Test-TcpkSignature'           { Test-TcpkSignature           -Path $Target   }
    _RunCheck 'Test-TcpkPeMitigations'       { Test-TcpkPeMitigations       -Path $expanded }
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
    _RunCheck 'Test-TcpkEmbeddedScripts'     { Test-TcpkEmbeddedScripts     -Path $expanded }
    _RunCheck 'Test-TcpkWebViewNavTargets'   { Test-TcpkWebViewNavTargets   -Path $expanded }
    _RunCheck 'Test-TcpkNamedObjects'        { Test-TcpkNamedObjects        -Path $expanded }
    _RunCheck 'Test-TcpkPacker'              { Test-TcpkPacker              -Path $expanded }
    _RunCheck 'Test-TcpkAuthFlags'           { Test-TcpkAuthFlags           -Path $expanded }
    _RunCheck 'Test-TcpkElectron'            { Test-TcpkElectron            -Path $expanded }
    _RunCheck 'Test-TcpkUnsafeNativeApis'    { Test-TcpkUnsafeNativeApis    -Path $expanded }
    _RunCheck 'Test-TcpkRpcSurface'          { Test-TcpkRpcSurface          -Path $expanded }
    _RunCheck 'Test-TcpkEntropySecrets'      { Test-TcpkEntropySecrets      -Path $expanded }
    _RunCheck 'Test-TcpkCryptoMisuse'        { Test-TcpkCryptoMisuse        -Path $expanded }
    _RunCheck 'Test-TcpkJwt'                 { Test-TcpkJwt                 -Path $expanded }
    _RunCheck 'Test-TcpkSessionHandling'     { Test-TcpkSessionHandling     -Path $expanded }
    _RunCheck 'Test-TcpkZipSlip'             { Test-TcpkZipSlip             -Path $expanded }
    _RunCheck 'Test-TcpkDebugFlags'          { Test-TcpkDebugFlags          -Path $expanded }

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
    }

    # ----- Bucket E (runtime / live process, 14 cmdlets) -----
    if ($ProcessName -and (Get-Process -Name $ProcessName -ErrorAction SilentlyContinue)) {
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
    }
    if ($idTerms.Count) {
        _RunCheck 'Test-TcpkNamedPipes'              { Test-TcpkNamedPipes              -NameLike $idTerms }
        _RunCheck 'Test-TcpkNamedPipeDacl'           { Test-TcpkNamedPipeDacl           -NameLike $idTerms }
        _RunCheck 'Test-TcpkComObjects'              { Test-TcpkComObjects              -NameLike $idTerms }
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
    $resolved = $all | Resolve-TcpkFindings
    $all = New-Object 'System.Collections.Generic.List[TcpkFinding]'
    foreach ($f in $resolved) { $all.Add($f) }
    Write-Information -MessageData "  $before -> $($all.Count) findings after dedupe + triage" -InformationAction Continue
    Write-TcpkLog -Level INFO -Component 'triage' -Message "$before -> $($all.Count) findings after dedupe + triage" | Out-Null

    # --- CVE exposure: match shipped components vs the offline CVE catalog ---
    $cveMatches = @()
    try {
        $cveMatches = @(Get-TcpkCveMatches -Path $expanded)
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
        $targetProfile = Get-TcpkTargetProfile -Path $expanded -Findings $all.ToArray()
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
        $surface = $all.ToArray() | Get-TcpkAttackSurface
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
        if ($sbom.Count) { Export-TcpkSbom -Components $sbom -OutFile $sbomPath -Profile $targetProfile | Out-Null }
        else             { Export-TcpkSbom -Path $expanded  -OutFile $sbomPath -Profile $targetProfile | Out-Null }
        Write-TcpkLog -Level SUCCESS -Component 'sbom' -Message "SBOM written ($($sbom.Count) components)" | Out-Null
    } catch {
        Write-Information -MessageData "  SBOM build failed: $($_.Exception.Message)" -InformationAction Continue
        Write-TcpkLog -Level ERROR -Component 'sbom' -Message $_.Exception.Message | Out-Null
    }

    # --- exploit plan (CVE matches + exploitable findings -> actionable items) ---
    try {
        $plan = @(Get-TcpkExploitPlan -Findings $all.ToArray() -CveMatches $cveMatches -Path $expanded)
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
        if ($lc -and $lc.enabled) { $llmInfo = "$($lc.provider) / $($lc.model) (run separately via Stage-2)" }
    } catch { }
    $scope = [pscustomobject]@{
        Buckets = $bucketsRun
        Llm     = $llmInfo
        Timing  = "scan $([int]$auditSw.Elapsed.TotalSeconds)s"
    }

    # --- write reports ---
    # Deliverables: HTML + Excel. findings.json stays as the INTERNAL data file
    # the GUI tabs (Recon/Exploit/Logs) and the MCP server read -- it is not a
    # "report". Markdown was dropped per requirements.
    $jsonPath = Join-Path $OutDir 'findings.json'
    $htmlPath = Join-Path $OutDir 'index.html'
    $xlsxPath = Join-Path $OutDir 'report.xlsx'

    $all | Export-TcpkReportJson -OutFile $jsonPath -Profile $targetProfile

    # Per-DLL hardening matrix (ASLR/DEP/CFG/HighEntropyVA/...) for the Excel sheet
    $hardening = @()
    try { $hardening = @(Get-TcpkPeHardening -Path $expanded) }
    catch { Write-TcpkLog -Level ERROR -Component 'hardening' -Message $_.Exception.Message | Out-Null }

    $all | Export-TcpkReportHtml -OutFile $htmlPath -Target $Target -Profile $targetProfile -Scope $scope -CveMatches $cveMatches -Hardening $hardening -Sbom $sbom
    try {
        $all | Export-TcpkReportExcel -OutFile $xlsxPath -Hardening $hardening -Profile $targetProfile -CveMatches $cveMatches -Sbom $sbom -Target $Target
    } catch { Write-TcpkLog -Level ERROR -Component 'report.excel' -Message $_.Exception.Message | Out-Null }
    Write-TcpkLog -Level SUCCESS -Component 'report' -Message "HTML + Excel written ($($all.Count) findings, $(@($hardening).Count) DLLs)" | Out-Null

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
