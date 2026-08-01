function Test-TcpkDotnetHostHijack {
<#
.SYNOPSIS
    A43. Modern .NET host redirection: CLR profiler, startup hooks, host probing
    paths, and single-file bundle extraction.

.DESCRIPTION
    Test-TcpkAppDomainHijack covers the .NET Framework AppDomainManager vector.
    This covers the vectors that replaced it on .NET Core / 5+, where the HOST
    decides what to load before any application code runs:

      * CLR profiler        COR_PROFILER / CORECLR_PROFILER load an UNMANAGED
                            DLL into the process before managed code starts, so
                            in-app integrity checks cannot see it. No admin
                            required when set at user scope.
      * Startup hooks       DOTNET_STARTUP_HOOKS runs managed code before Main
                            and is inherited by child processes.
      * Host probing        runtimeconfig.json additionalProbingPaths and
                            DOTNET_ADDITIONAL_DEPS extend assembly resolution.
                            A writable runtimeconfig.json or deps.json rewrites
                            resolution outright.
      * Single-file bundle  A self-extracting bundle unpacks native
                            dependencies to DOTNET_BUNDLE_EXTRACT_BASE_DIR, or
                            to %TEMP%\.net by default. Under a service account
                            that can be a shared, writable staging directory.

    ATTRIBUTION. Findings are split deliberately, because these two are not the
    same kind of problem:

      VENDOR-REPORTABLE  the application's own files and shipped launchers: a
                         writable runtimeconfig.json or deps.json, a probing
                         path that resolves somewhere writable, a launcher
                         script that sets the profiler or hook variables, and
                         an extraction base the app cannot defend.

      ENVIRONMENT STATE  profiler and hook variables already set at machine or
                         user scope. That is not a defect the vendor can fix,
                         and it is reported only when it actually resolves to
                         something, because at that point the audited process
                         is being injected right now. Severity and wording say
                         so explicitly.

    Static: reads configuration and ACLs, never launches the application.

.PARAMETER Path
    File or directory to scan.

.OUTPUTS
    [TcpkFinding]
#>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    $item = Get-Item -LiteralPath $Path -ErrorAction SilentlyContinue
    if (-not $item) { return }
    $dir = if ($item.PSIsContainer) { $item.FullName } else { $item.DirectoryName }

    $onWindows = ($env:OS -eq 'Windows_NT')
    $userRx   = '(?i)\b(Everyone|Authenticated Users|Users|INTERACTIVE|BUILTIN\\Users)\b'
    $rightsRx = 'Write|Modify|FullControl|TakeOwnership|ChangePermissions'

    function _Writable([string]$p) {
        if (-not $p) { return $false }
        if (-not (Test-Path -LiteralPath $p)) { return $false }
        try { $acl = Get-Acl -LiteralPath $p -ErrorAction Stop } catch { return $false }
        return (@($acl.Access | Where-Object {
            $_.IdentityReference.Value -match $userRx -and
            $_.FileSystemRights -match $rightsRx -and
            $_.AccessControlType -eq 'Allow'
        }).Count -gt 0)
    }

    # Only meaningful for a managed target. Presence of runtimeconfig/deps files or a
    # managed PE is the gate; without it this check stays silent rather than reporting
    # machine environment state against an unrelated native app.
    $runtimeCfgs = @(Get-TcpkChildItemSafe -Path $dir -File |
        Where-Object { $_.Name -like '*.runtimeconfig.json' })
    $depsFiles = @(Get-TcpkChildItemSafe -Path $dir -File |
        Where-Object { $_.Name -like '*.deps.json' })
    $isDotnet = ($runtimeCfgs.Count -gt 0 -or $depsFiles.Count -gt 0)
    if (-not $isDotnet) {
        foreach ($pe in @(Get-TcpkPeFiles -Path $dir | Select-Object -First 200)) {
            $info = Read-TcpkPe -Path $pe.FullName
            if ($info -and $info.Imports -contains 'mscoree.dll') { $isDotnet = $true; break }
        }
    }
    if (-not $isDotnet) { return }

    # --- 1. VENDOR-REPORTABLE: the app's own host configuration files ------------
    foreach ($rc in $runtimeCfgs) {
        if (_Writable $rc.FullName) {
            New-TcpkFinding -Module 'static' -RuleId 'dotnethost.runtimeconfig-writable' `
                -Severity 'HIGH' -Confidence 'Confirmed' `
                -Title "runtimeconfig.json is user-writable: $($rc.Name)" `
                -File $rc.FullName `
                -Evidence "$($rc.FullName) writable by a non-admin principal" `
                -Cwe @('CWE-427', 'CWE-732') `
                -Description ('This file tells the .NET host which framework to use and where to ' +
                    'probe for assemblies. A non-admin principal who can rewrite it can add an ' +
                    'additionalProbingPaths entry pointing at a directory they control, and the ' +
                    'host will resolve the application''s assemblies from there.') `
                -Fix 'Restrict the file ACL to SYSTEM and Administrators. Application configuration should not be writable by the user running it.'
        }

        $cfg = $null
        try { $cfg = Get-Content -LiteralPath $rc.FullName -Raw -ErrorAction Stop | ConvertFrom-Json } catch { continue }
        $probes = @()
        try { $probes = @($cfg.runtimeOptions.additionalProbingPaths) } catch { }
        foreach ($pp in $probes) {
            $raw = "$pp"
            if (-not $raw) { continue }
            $resolved = [System.Environment]::ExpandEnvironmentVariables($raw)
            if (-not [System.IO.Path]::IsPathRooted($resolved)) {
                try { $resolved = Join-Path $dir $resolved } catch { continue }
            }
            if (-not (Test-Path -LiteralPath $resolved)) { continue }
            if (-not (_Writable $resolved)) { continue }
            New-TcpkFinding -Module 'static' -RuleId 'dotnethost.probing-path-writable' `
                -Severity 'HIGH' -Confidence 'Confirmed' `
                -Title "Assembly probing path is user-writable: $resolved" `
                -File $rc.FullName `
                -Evidence "additionalProbingPaths entry '$raw' resolves to $resolved, which is writable" `
                -Cwe @('CWE-427') `
                -Description ('The host probes this directory when resolving assemblies. It is ' +
                    'writable by a non-admin principal, so an attacker can place an assembly there ' +
                    'that satisfies a resolution the application performs, and it will be loaded ' +
                    'with the application''s identity.') `
                -Fix 'Remove the probing path, or restrict the directory ACL so only SYSTEM and Administrators can write to it.'
        }
    }

    foreach ($dp in $depsFiles) {
        if (-not (_Writable $dp.FullName)) { continue }
        New-TcpkFinding -Module 'static' -RuleId 'dotnethost.deps-writable' `
            -Severity 'HIGH' -Confidence 'Confirmed' `
            -Title "deps.json is user-writable: $($dp.Name)" `
            -File $dp.FullName `
            -Evidence "$($dp.FullName) writable by a non-admin principal" `
            -Cwe @('CWE-427', 'CWE-732') `
            -Description ('deps.json is the dependency manifest the host uses to locate every ' +
                'assembly the application loads. A non-admin principal who can rewrite it can ' +
                'redirect any dependency to a file of their choosing.') `
            -Fix 'Restrict the file ACL to SYSTEM and Administrators.'
    }

    # --- 2. VENDOR-REPORTABLE: shipped launchers that set host variables ---------
    # A launcher the vendor ships is their code, so setting these there is their defect,
    # unlike the same variable set in the machine environment by someone else.
    $hostVars = 'CORECLR_PROFILER|COR_PROFILER|CORECLR_ENABLE_PROFILING|COR_ENABLE_PROFILING|DOTNET_STARTUP_HOOKS|DOTNET_ADDITIONAL_DEPS|DOTNET_BUNDLE_EXTRACT_BASE_DIR'
    foreach ($sc in @(Get-TcpkChildItemSafe -Path $dir -File |
            Where-Object { $_.Extension.ToLowerInvariant() -in @('.bat', '.cmd', '.ps1', '.vbs') } |
            Select-Object -First 60)) {
        $txt = ''
        try { $txt = Get-Content -LiteralPath $sc.FullName -Raw -ErrorAction Stop } catch { continue }
        if (-not $txt) { continue }
        # Built by concatenation from a single-quoted literal so neither the \$ nor the
        # trailing $ anchor is at the mercy of double-quoted string interpolation.
        $rx = '(?im)^\s*(?:set\s+|\$env:)(' + $hostVars + ')\s*=\s*(.*)$'
        $m = [regex]::Match($txt, $rx)
        if (-not $m.Success) { continue }
        New-TcpkFinding -Module 'static' -RuleId 'dotnethost.launcher-sets-host-var' `
            -Severity 'MEDIUM' -Confidence 'Confirmed' `
            -Title "Shipped launcher sets $($m.Groups[1].Value)" `
            -File $sc.FullName `
            -Evidence (Get-TcpkRedact ($m.Value.Trim())) `
            -Cwe @('CWE-427') `
            -Description ('A launcher script shipped with the application sets a .NET host ' +
                'variable that controls what gets loaded into the process. If the value points ' +
                'anywhere a non-admin can write, or if the script itself is writable, this is a ' +
                'code-execution path the vendor introduced.') `
            -Fix 'Remove the variable from the shipped launcher, or pin it to an absolute path inside the install directory that only administrators can write.'
    }

    # --- 3. VENDOR-REPORTABLE: single-file bundle extraction ---------------------
    # A single-file app unpacks native dependencies before running them. The default
    # base is %TEMP%\.net; under a service identity that can be a shared directory.
    $bundleBase = ''
    if ($onWindows) {
        foreach ($scope in @('Machine', 'User')) {
            try {
                $v = [System.Environment]::GetEnvironmentVariable('DOTNET_BUNDLE_EXTRACT_BASE_DIR', $scope)
                if ($v) { $bundleBase = $v; break }
            } catch { }
        }
    }
    if ($bundleBase) {
        $resolvedBase = [System.Environment]::ExpandEnvironmentVariables($bundleBase)
        if (_Writable $resolvedBase) {
            New-TcpkFinding -Module 'static' -RuleId 'dotnethost.bundle-extract-writable' `
                -Severity 'HIGH' -Confidence 'Confirmed' `
                -Title 'Single-file bundle extraction directory is user-writable' `
                -File $resolvedBase `
                -Evidence "DOTNET_BUNDLE_EXTRACT_BASE_DIR=$bundleBase resolves to $resolvedBase, which is writable" `
                -Cwe @('CWE-427', 'CWE-377') `
                -Description ('A single-file .NET application extracts its native dependencies to ' +
                    'this directory and then loads them. Because the directory is writable by a ' +
                    'non-admin principal, an attacker can pre-place or replace an extracted native ' +
                    'library and win the race, executing code with the application''s identity.') `
                -Fix 'Point DOTNET_BUNDLE_EXTRACT_BASE_DIR at a per-user directory that only that user and administrators can write, or publish with IncludeNativeLibrariesForSelfExtract disabled so nothing is extracted.'
        }
    }

    # --- 4. ENVIRONMENT STATE: profiler / startup hooks already configured -------
    # Not an application defect. Reported only when the variable resolves to something,
    # because at that point the audited process is being injected right now.
    if (-not $onWindows) { return }

    $profilerSets = @(
        @{ Enable = 'COR_ENABLE_PROFILING';     Clsid = 'COR_PROFILER';     Paths = @('COR_PROFILER_PATH', 'COR_PROFILER_PATH_64', 'COR_PROFILER_PATH_32');                 Runtime = '.NET Framework' }
        @{ Enable = 'CORECLR_ENABLE_PROFILING'; Clsid = 'CORECLR_PROFILER'; Paths = @('CORECLR_PROFILER_PATH', 'CORECLR_PROFILER_PATH_64', 'CORECLR_PROFILER_PATH_32'); Runtime = '.NET Core / 5+' }
    )
    foreach ($ps in $profilerSets) {
        foreach ($scope in @('Machine', 'User')) {
            $clsid = ''
            try { $clsid = [System.Environment]::GetEnvironmentVariable($ps.Clsid, $scope) } catch { }
            $dll = ''
            foreach ($pv in $ps.Paths) {
                try {
                    $cand = [System.Environment]::GetEnvironmentVariable($pv, $scope)
                    if ($cand) { $dll = $cand; break }
                } catch { }
            }
            if (-not $clsid -and -not $dll) { continue }

            $resolvedDll = ''
            if ($dll) { $resolvedDll = [System.Environment]::ExpandEnvironmentVariables($dll) }
            $dllWritable = $false
            if ($resolvedDll) { $dllWritable = _Writable $resolvedDll }

            $sev = 'MEDIUM'
            if ($dllWritable) { $sev = 'HIGH' }

            New-TcpkFinding -Module 'static' -RuleId 'dotnethost.profiler-configured' `
                -Severity $sev -Confidence 'Confirmed' `
                -Title "CLR profiler configured at $scope scope ($($ps.Runtime))" `
                -File "env:$($ps.Clsid) ($scope)" `
                -Evidence "$($ps.Clsid)=$clsid; path=$resolvedDll; path-writable=$dllWritable" `
                -Cwe @('CWE-427') `
                -Description ('A CLR profiler is configured in the environment. The profiler DLL is ' +
                    'unmanaged and is loaded into the process before any managed code runs, so the ' +
                    'application cannot detect it with its own integrity checks. This is ENVIRONMENT ' +
                    'state rather than an application defect: the vendor cannot fix it, and it is ' +
                    'reported because it directly affects the audited process. Treat a profiler ' +
                    'nobody deliberately installed as a compromise indicator.') `
                -Fix 'Confirm the profiler is an expected APM or diagnostics agent. If not, clear the variables and investigate how they were set. Where the DLL path is writable, restrict it.'
        }
    }

    foreach ($scope in @('Machine', 'User')) {
        $hooks = ''
        try { $hooks = [System.Environment]::GetEnvironmentVariable('DOTNET_STARTUP_HOOKS', $scope) } catch { }
        if (-not $hooks) { continue }
        $anyWritable = $false
        foreach ($h in ($hooks -split ';')) {
            $hp = [System.Environment]::ExpandEnvironmentVariables($h.Trim())
            if ($hp -and (_Writable $hp)) { $anyWritable = $true; break }
        }
        $sev = 'MEDIUM'
        if ($anyWritable) { $sev = 'HIGH' }

        New-TcpkFinding -Module 'static' -RuleId 'dotnethost.startup-hook-configured' `
            -Severity $sev -Confidence 'Confirmed' `
            -Title "DOTNET_STARTUP_HOOKS configured at $scope scope" `
            -File "env:DOTNET_STARTUP_HOOKS ($scope)" `
            -Evidence "DOTNET_STARTUP_HOOKS=$hooks; any-hook-writable=$anyWritable" `
            -Cwe @('CWE-427') `
            -Description ('A startup hook assembly runs before the application''s Main and is ' +
                'inherited by child processes. This is ENVIRONMENT state rather than an application ' +
                'defect, and is reported because it changes what the audited process executes. ' +
                'Treat a hook nobody deliberately installed as a compromise indicator.') `
            -Fix 'Confirm the hook is expected. If not, clear the variable and investigate. Where a hook assembly path is writable by a non-admin principal, restrict it.'
    }
}
