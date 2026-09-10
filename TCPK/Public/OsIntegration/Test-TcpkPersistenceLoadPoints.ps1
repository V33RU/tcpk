function Test-TcpkPersistenceLoadPoints {
<#
.SYNOPSIS
    C24. Machine-wide Windows persistence load points that are NOT covered by
    Test-TcpkRegistryLoadPoints (which restricts to per-app in-tree DLLs).

.DESCRIPTION
    This is a HOST-POSTURE cmdlet, in the same shape as Test-TcpkHostNameResolution.
    It reads a fixed list of registry keys that Windows honours at logon /
    process launch, and reports any populated value whose target either:
      (a) does not resolve to an OS-shipped default binary under System32, OR
      (b) resolves to a file / directory whose DACL grants a non-admin principal
          a right that permits code injection.

    Every load point below is documented as an ATT&CK persistence primitive:

      HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon
        Shell                        (default "explorer.exe")   T1547.004
        Userinit                     (default "%WINDIR%\system32\userinit.exe,")  T1037.003
        Taskman                      T1547.004
        VmApplet
        System                       (default is empty)
        GinaDLL                      (custom logon UI, XP-era but still honoured)  T1547.004

      HKLM\SYSTEM\CurrentControlSet\Control\Lsa
        Authentication Packages      (default REG_MULTI_SZ: msv1_0)              T1547.002
        Notification Packages        (default REG_MULTI_SZ: scecli)               T1547.002
        Security Packages            (default REG_MULTI_SZ: negoexts, ...)        T1547.005

      HKLM\SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders\*
        DllName per subkey                                                        T1547.003

      HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ShellServiceObjectDelayLoad
        (SSODL) - each VALUE is a CLSID whose DLL loads into Explorer at logon.   T1547.008

      HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\SharedTaskScheduler
        each VALUE is a CLSID whose DLL loads into Explorer.                      T1547.008

      HKLM\SYSTEM\CurrentControlSet\Control\Session Manager
        BootExecute, Execute, S0InitialCommand, SetupExecute, AppCertDlls
        (loaded by smss.exe as SYSTEM at startup)                                 T1546.009

      HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs
        - DACL check on the KnownDLLs KEY: a non-admin write there lets the
          attacker register a KnownDLL that pre-empts the DLL-search-order
          fallback for every process at startup.

    Every emitted finding is a POSTURE observation, not a per-app finding: the
    audited application does not necessarily own the write, so the operator has
    to correlate. Filenames whose ancestor sits under -Path (when supplied) are
    annotated as such in the evidence field.

    Rules:
      loadpoint.winlogon-shell            HIGH   Confirmed  Shell not the default
      loadpoint.winlogon-userinit         HIGH   Confirmed  Userinit not the default
      loadpoint.winlogon-taskman          MEDIUM Confirmed  Taskman populated
      loadpoint.winlogon-gina             HIGH   Confirmed  GinaDLL set
      loadpoint.lsa-package               HIGH   Confirmed  non-default Auth / Notif / Sec
                                                            Packages entry
      loadpoint.time-provider             HIGH   Confirmed  DllName under TimeProviders that
                                                            is not w32time.dll
      loadpoint.ssodl                     HIGH   Confirmed  Non-empty ShellServiceObjectDelayLoad
      loadpoint.shared-task-scheduler     HIGH   Confirmed  Non-empty SharedTaskScheduler
      loadpoint.session-manager           HIGH   Confirmed  Non-default BootExecute / Execute /
                                                            S0InitialCommand / SetupExecute /
                                                            AppCertDlls
      loadpoint.knowndlls-writable        HIGH   Confirmed  Non-admin can write the KnownDLLs key
      loadpoint.value-target-writable     HIGH   Confirmed  The target file / dir named by any of
                                                            the above is user-writable

    The rules deliberately do NOT try to attribute each load point to an app;
    that is Test-TcpkRegistryLoadPoints's job for the six load-point families it
    covers (credential providers, shell extensions, print monitors, print
    processors, netsh helpers, WER runtime-exception helpers).

.PARAMETER Path
    Optional. When provided, evidence notes whether the target of a load point
    resolves inside the audited install tree.

.OUTPUTS
    [TcpkFinding]
#>
    [CmdletBinding()] param([string]$Path)

    if (-not (Assert-TcpkWindows 'Test-TcpkPersistenceLoadPoints')) { return }

    $fileDangerMask =
        0x00000002 -bor 0x00000040 -bor 0x00010000 -bor
        0x00040000 -bor 0x00080000 -bor 0x10000000 -bor 0x40000000
    $riskySids   = @('S-1-1-0','S-1-5-11','S-1-5-32-545','S-1-5-4','S-1-5-32-547')
    $riskyNameRx = '(?i)\b(Everyone|Authenticated Users|Users|INTERACTIVE|BUILTIN\\(Users|Power Users))\b'

    function _AceIsRisky($ace) {
        if ($ace.AccessControlType -ne 'Allow') { return $false }
        $sid = $null
        try {
            if ($ace.IdentityReference -is [Security.Principal.SecurityIdentifier]) { $sid = $ace.IdentityReference.Value }
            else { $sid = ($ace.IdentityReference.Translate([Security.Principal.SecurityIdentifier])).Value }
        } catch { }
        $matched = $false
        if ($sid -and ($riskySids -contains $sid)) { $matched = $true }
        elseif ($ace.IdentityReference.Value -match $riskyNameRx) { $matched = $true }
        if (-not $matched) { return $false }
        $rights = 0
        try {
            if ($ace.PSObject.Properties['FileSystemRights']) { $rights = [int]$ace.FileSystemRights }
            elseif ($ace.PSObject.Properties['RegistryRights']) { $rights = [int]$ace.RegistryRights }
        } catch { }
        return (($rights -band $fileDangerMask) -ne 0)
    }

    # Best-effort resolve of a value into an actual filesystem path. Understands
    # %WINDIR%, %SystemRoot%, %ProgramFiles% and NT-namespace prefixes.
    function _ResolvePath([string]$v) {
        if (-not $v) { return $null }
        $s = $v.Trim().Trim('"')
        # Trim a comma-argv suffix (e.g. 'userinit.exe,')
        if ($s.EndsWith(',')) { $s = $s.TrimEnd(',') }
        # Take the first token before whitespace (some values are 'exe args ...')
        $first = ($s -split '\s+', 2)[0]
        if (-not $first) { return $null }
        try { $first = [Environment]::ExpandEnvironmentVariables($first) } catch { }
        $first = $first -replace '^\\SystemRoot\\', "$env:WINDIR\" -replace '^\\\?\?\\',''
        if ($first -notmatch '[\\/]') {
            $first = Join-Path $env:WINDIR "System32\$first"
        }
        return $first
    }

    function _TargetWritable([string]$fullPath) {
        if (-not $fullPath -or -not (Test-Path -LiteralPath $fullPath -ErrorAction SilentlyContinue)) {
            return @{ Writable = $false; Grant = ''; What = 'target absent' }
        }
        $bad = @()
        try {
            $acl = Get-Acl -LiteralPath $fullPath -ErrorAction Stop
            $bad = @($acl.Access | Where-Object { _AceIsRisky $_ })
        } catch { }
        if ($bad.Count -eq 0) {
            $parent = Split-Path -Parent $fullPath
            if ($parent -and (Test-Path -LiteralPath $parent)) {
                try {
                    $pacl = Get-Acl -LiteralPath $parent -ErrorAction Stop
                    $bad = @($pacl.Access | Where-Object { _AceIsRisky $_ })
                    if ($bad.Count -gt 0) {
                        $g = ($bad | ForEach-Object { "$($_.IdentityReference) -> $($_.FileSystemRights)" } | Select-Object -First 2) -join '; '
                        return @{ Writable = $true; Grant = $g; What = "parent dir '$parent' non-admin writable" }
                    }
                } catch { }
            }
            return @{ Writable = $false; Grant = ''; What = 'target exists, DACL admin-only' }
        }
        $g = ($bad | ForEach-Object { "$($_.IdentityReference) -> $($_.FileSystemRights)" } | Select-Object -First 2) -join '; '
        return @{ Writable = $true; Grant = $g; What = 'target file non-admin writable' }
    }

    function _AnnotateInTree([string]$fullPath) {
        if (-not $Path -or -not $fullPath) { return '' }
        try {
            $rootFull = [IO.Path]::GetFullPath($Path).TrimEnd('\','/') + [IO.Path]::DirectorySeparatorChar
            $tf = [IO.Path]::GetFullPath($fullPath)
            if ($tf.StartsWith($rootFull, [StringComparison]::OrdinalIgnoreCase)) { return ' (target inside audited -Path)' }
        } catch { }
        return ''
    }

    function _EmitLoadPoint([string]$ruleId, [string]$title, [string]$file, [string]$value, [string]$cwe1, [string]$cwe2, [string]$desc, [string]$fix, [string]$sev = 'HIGH') {
        $target = _ResolvePath $value
        $tw = if ($target) { _TargetWritable $target } else { @{ Writable = $false; Grant = ''; What = 'unresolved' } }
        $inTree = if ($target) { _AnnotateInTree $target } else { '' }
        $ev = "value='$value'; resolved='$target'; $($tw.What)$inTree"
        if ($tw.Grant) { $ev += "; $($tw.Grant)" }
        New-TcpkFinding -Module 'os' -RuleId $ruleId `
            -Severity $sev -Confidence 'Confirmed' `
            -Title $title -File $file -Evidence $ev `
            -Cwe @($cwe1, $cwe2) -Description $desc -Fix $fix
        if ($tw.Writable) {
            New-TcpkFinding -Module 'os' -RuleId 'loadpoint.value-target-writable' `
                -Severity 'HIGH' -Confidence 'Confirmed' `
                -Title "Load-point target is non-admin writable: $target" `
                -File $target -Evidence "reached via $ruleId : $($tw.What); $($tw.Grant)" `
                -Cwe @('CWE-732','CWE-427') `
                -Description ('The registry load point above names a file (or directory) whose DACL grants ' +
                    'a non-admin principal a right that permits replacing / creating the load target. Any ' +
                    'user who fits the grant can plant code that the load point will then run as the host ' +
                    'process principal (SYSTEM for logon / smss / spoolsv / lsass load points).') `
                -Fix 'Restrict the load target and its parent to SYSTEM + BUILTIN\Administrators write. If the load point itself is not needed, delete the registry value.'
        }
    }

    # ---- Winlogon values ---------------------------------------------------------
    $wl = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
    if (Test-Path -LiteralPath $wl) {
        $wp = $null; try { $wp = Get-ItemProperty -LiteralPath $wl -ErrorAction SilentlyContinue } catch { }
        if ($wp) {
            $shell = "$($wp.Shell)"
            if ($shell -and $shell -notmatch '(?i)^\s*explorer\.exe\s*$') {
                _EmitLoadPoint 'loadpoint.winlogon-shell' `
                    "Winlogon Shell overridden: $shell" $wl $shell `
                    'CWE-732' 'CWE-1188' `
                    ('Winlogon\Shell defaults to explorer.exe. Any other value is loaded at interactive logon ' +
                     'as the user identity. ATT&CK T1547.004.') `
                    'Reset to explorer.exe. If a per-user Shell is intended, use HKCU\...\Winlogon\Shell instead of the machine key.'
            }
            $uinit = "$($wp.Userinit)"
            if ($uinit -and $uinit -notmatch '(?i)^\s*[A-Z]:\\Windows\\system32\\userinit\.exe,?\s*$' -and $uinit -notmatch '(?i)^\s*%windir%\\system32\\userinit\.exe,?\s*$') {
                _EmitLoadPoint 'loadpoint.winlogon-userinit' `
                    "Winlogon Userinit overridden: $uinit" $wl $uinit `
                    'CWE-732' 'CWE-1188' `
                    ('Winlogon\Userinit defaults to %WINDIR%\system32\userinit.exe. A non-default value is run at ' +
                     'every interactive logon as the user identity. ATT&CK T1037.003.') `
                    'Restore Userinit to the OS default value.'
            }
            $tman = "$($wp.Taskman)"
            if ($tman) {
                _EmitLoadPoint 'loadpoint.winlogon-taskman' `
                    "Winlogon Taskman populated: $tman" $wl $tman `
                    'CWE-732' 'CWE-1188' `
                    ('Winlogon\Taskman names the process launched when the user presses Ctrl+Shift+Esc. ' +
                     'Default is unset. ATT&CK T1547.004.') `
                    'Delete the Taskman value unless a documented alternate task manager is required.' `
                    'MEDIUM'
            }
            $gina = "$($wp.GinaDLL)"
            if ($gina) {
                _EmitLoadPoint 'loadpoint.winlogon-gina' `
                    "Winlogon GinaDLL set: $gina" $wl $gina `
                    'CWE-732' 'CWE-1188' `
                    ('GinaDLL is the XP-era logon UI DLL loaded by winlogon.exe as SYSTEM at boot. Windows 10 / 11 ' +
                     'do not use it, but a value present in the registry is a persistence primitive on any host ' +
                     'that boots into an older kernel or downgrade path. ATT&CK T1547.004.') `
                    'Delete the GinaDLL value.'
            }
        }
    }

    # ---- LSA packages ------------------------------------------------------------
    $lsa = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
    if (Test-Path -LiteralPath $lsa) {
        $lp = $null; try { $lp = Get-ItemProperty -LiteralPath $lsa -ErrorAction SilentlyContinue } catch { }
        if ($lp) {
            $defaults = @{
                'Authentication Packages' = @('msv1_0','msv1_0.dll')
                'Notification Packages'   = @('scecli','scecli.dll','rassfm')
                'Security Packages'       = @('""','kerberos','msv1_0','schannel','wdigest','tspkg','pku2u','cloudap','negoexts')
            }
            foreach ($valueName in 'Authentication Packages','Notification Packages','Security Packages') {
                $arr = $lp.$valueName
                if (-not $arr) { continue }
                foreach ($v in @($arr)) {
                    $vs = "$v".Trim().Trim('"').ToLowerInvariant()
                    if (-not $vs) { continue }
                    if ($defaults[$valueName] -contains $vs) { continue }
                    if ($vs -like '*.dll') { $tgt = $vs } else { $tgt = "$vs.dll" }
                    _EmitLoadPoint 'loadpoint.lsa-package' `
                        "LSA $valueName non-default entry: $vs" $lsa $tgt `
                        'CWE-732' 'CWE-1188' `
                        ("HKLM\SYSTEM\CurrentControlSet\Control\Lsa\'$valueName' names DLLs loaded by lsass.exe as " +
                         'SYSTEM at boot. Any non-default entry is a persistence primitive with direct access ' +
                         'to credential material. ATT&CK T1547.002 / T1547.005.') `
                        "Remove the non-default entry from '$valueName' unless it is a vendor DLL you audited and pinned."
                }
            }
        }
    }

    # ---- Time providers ---------------------------------------------------------
    $tp = 'HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders'
    if (Test-Path -LiteralPath $tp) {
        foreach ($sub in (Get-ChildItem -LiteralPath $tp -ErrorAction SilentlyContinue)) {
            $dp = $null; try { $dp = (Get-ItemProperty -LiteralPath $sub.PSPath -ErrorAction SilentlyContinue).DllName } catch { }
            if (-not $dp) { continue }
            $dpNorm = ($dp -replace '^%.+?%\\','').ToLowerInvariant()
            # The three OS-shipped time providers ship as w32time.dll. Anything else is
            # a persistence primitive.
            if ($dpNorm -eq 'w32time.dll' -or $dpNorm -eq 'system32\w32time.dll') { continue }
            _EmitLoadPoint 'loadpoint.time-provider' `
                "Non-default W32Time provider: $($sub.PSChildName) -> $dp" $sub.PSPath $dp `
                'CWE-732' 'CWE-1188' `
                ('Windows Time Provider DLL loaded by svchost (LocalService) at boot. Default entries all ' +
                 'point at w32time.dll; a non-default DLL is a persistence primitive. ATT&CK T1547.003.') `
                'Delete the non-default TimeProviders subkey unless a vendor time source is documented for this host.'
        }
    }

    # ---- SSODL ------------------------------------------------------------------
    $ssodl = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\ShellServiceObjectDelayLoad'
    if (Test-Path -LiteralPath $ssodl) {
        $sp = $null; try { $sp = Get-ItemProperty -LiteralPath $ssodl -ErrorAction SilentlyContinue } catch { }
        if ($sp) {
            foreach ($n in $sp.PSObject.Properties.Name) {
                if ($n -in 'PSPath','PSParentPath','PSChildName','PSDrive','PSProvider') { continue }
                $clsid = "$($sp.$n)"
                if (-not $clsid) { continue }
                # SSODL values are CLSIDs; resolve to Software\Classes\CLSID\{clsid}\InprocServer32
                $inproc = "HKLM:\SOFTWARE\Classes\CLSID\$clsid\InprocServer32"
                $dll = ''
                try { $dll = "$((Get-ItemProperty -LiteralPath $inproc -ErrorAction SilentlyContinue).'(default)')" } catch { }
                if (-not $dll) { $dll = "<CLSID $clsid>" }
                _EmitLoadPoint 'loadpoint.ssodl' `
                    "ShellServiceObjectDelayLoad entry: $n -> $clsid ($dll)" $ssodl $dll `
                    'CWE-732' 'CWE-1188' `
                    ("ShellServiceObjectDelayLoad values load Explorer-hosted service objects at logon. Every " +
                     'entry is a candidate persistence primitive. Legit third-party entries are rare on modern ' +
                     'Windows. ATT&CK T1547.008.') `
                    'Delete the SSODL value unless it is a documented vendor shell extension.'
            }
        }
    }

    # ---- SharedTaskScheduler ----------------------------------------------------
    $sts = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\SharedTaskScheduler'
    if (Test-Path -LiteralPath $sts) {
        $sp = $null; try { $sp = Get-ItemProperty -LiteralPath $sts -ErrorAction SilentlyContinue } catch { }
        if ($sp) {
            foreach ($n in $sp.PSObject.Properties.Name) {
                if ($n -in 'PSPath','PSParentPath','PSChildName','PSDrive','PSProvider') { continue }
                $clsid = "$($sp.$n)"
                if (-not $clsid) { continue }
                $inproc = "HKLM:\SOFTWARE\Classes\CLSID\$clsid\InprocServer32"
                $dll = ''
                try { $dll = "$((Get-ItemProperty -LiteralPath $inproc -ErrorAction SilentlyContinue).'(default)')" } catch { }
                if (-not $dll) { $dll = "<CLSID $clsid>" }
                _EmitLoadPoint 'loadpoint.shared-task-scheduler' `
                    "SharedTaskScheduler entry: $n -> $clsid ($dll)" $sts $dll `
                    'CWE-732' 'CWE-1188' `
                    ('SharedTaskScheduler values load into Explorer at logon. Same primitive as SSODL, ' +
                     'different registry root. ATT&CK T1547.008.') `
                    'Delete the SharedTaskScheduler value unless documented.'
            }
        }
    }

    # ---- Session Manager --------------------------------------------------------
    $sm = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager'
    if (Test-Path -LiteralPath $sm) {
        $smp = $null; try { $smp = Get-ItemProperty -LiteralPath $sm -ErrorAction SilentlyContinue } catch { }
        if ($smp) {
            $bootExecDefault = @('autocheck autochk *','autocheck autochk *')
            $execDefault = @()
            $vals = @{
                'BootExecute'       = 'BootExecute REG_MULTI_SZ list run by smss.exe at boot. Default is single "autocheck autochk *". Any addition executes as SYSTEM before user session start.'
                'Execute'           = 'Execute REG_MULTI_SZ run in Session 0. Default is empty. ATT&CK T1546.009.'
                'S0InitialCommand'  = 'S0InitialCommand runs in Session 0 first. Default is empty; any value loads code as SYSTEM.'
                'SetupExecute'      = 'SetupExecute runs at first-boot / setup. Default is empty on a working install; any value now is anomalous.'
                'AppCertDlls'       = 'AppCertDlls loads into every process that calls CreateProcess. Default is empty. ATT&CK T1546.009.'
            }
            foreach ($vn in $vals.Keys) {
                $v = $smp.$vn
                if (-not $v) { continue }
                # AppCertDlls is a subkey, not a value, on Windows. Handle both shapes.
                $flat = if ($v -is [array]) { ($v -join '; ') } else { "$v" }
                if ($vn -eq 'BootExecute' -and ($v -is [array]) -and ($v.Count -eq 1) -and ($v[0] -match '(?i)^autocheck\s+autochk\s+\*\s*$')) { continue }
                _EmitLoadPoint 'loadpoint.session-manager' `
                    "Session Manager $vn populated: $flat" $sm $flat `
                    'CWE-732' 'CWE-1188' `
                    $vals[$vn] `
                    "Delete or restore the default for HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\$vn."
            }
        }
        # AppCertDlls as a SUBKEY (values under the subkey are the DLL paths)
        $ac = Join-Path $sm 'AppCertDlls'
        if (Test-Path -LiteralPath $ac) {
            $ap = $null; try { $ap = Get-ItemProperty -LiteralPath $ac -ErrorAction SilentlyContinue } catch { }
            if ($ap) {
                foreach ($n in $ap.PSObject.Properties.Name) {
                    if ($n -in 'PSPath','PSParentPath','PSChildName','PSDrive','PSProvider') { continue }
                    $dll = "$($ap.$n)"
                    if (-not $dll) { continue }
                    _EmitLoadPoint 'loadpoint.session-manager' `
                        "AppCertDlls entry: $n -> $dll" $ac $dll `
                        'CWE-732' 'CWE-1188' `
                        'AppCertDlls values are loaded into every process that calls CreateProcess. Default is none. ATT&CK T1546.009.' `
                        "Delete the AppCertDlls value '$n'."
                }
            }
        }
    }

    # ---- KnownDLLs writable -----------------------------------------------------
    $kd = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs'
    if (Test-Path -LiteralPath $kd) {
        $kdAcl = $null
        try { $kdAcl = Get-Acl -LiteralPath $kd -ErrorAction Stop } catch { }
        if ($kdAcl) {
            $bad = @($kdAcl.Access | Where-Object { _AceIsRisky $_ })
            if ($bad.Count -gt 0) {
                $g = ($bad | ForEach-Object { "$($_.IdentityReference) -> $($_.RegistryRights)" } | Select-Object -First 3) -join '; '
                New-TcpkFinding -Module 'os' -RuleId 'loadpoint.knowndlls-writable' `
                    -Severity 'HIGH' -Confidence 'Confirmed' `
                    -Title 'KnownDLLs registry key is non-admin writable' `
                    -File $kd -Evidence $g `
                    -Cwe @('CWE-732','CWE-427') `
                    -Description ('The KnownDLLs key lists module names Windows will resolve directly to ' +
                        '%SystemRoot%\System32 rather than through the DLL search order. Non-admin write on ' +
                        'this key lets an attacker either remove an entry (forcing a search-order fallback the ' +
                        'attacker plants against) or add an entry pointing at an attacker-controlled DLL. ' +
                        'Both primitives affect every process at startup.') `
                    -Fix 'Restrict the KnownDLLs key ACL to SYSTEM + BUILTIN\Administrators write.'
            }
        }
    }
}
