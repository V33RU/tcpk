function Test-TcpkAppDomainHijack {
<#
.SYNOPSIS
    Detect AppDomainManager injection surface in .NET executables (T1574.014).

.DESCRIPTION
    The CLR honours appDomainManagerAssembly / appDomainManagerType in a
    .config file next to a .NET exe.  If the directory is user-writable an
    attacker can plant (or modify) the config to redirect AppDomain
    initialization into their own assembly -- persistence, privesc, and
    defense-evasion in one move.

    Checks for:
      1. Existing .config with appDomainManagerAssembly / appDomainManagerType
         already set (live hijack or leftover test artifact).
      2. .NET exe whose directory is user-writable AND no .config exists yet
         (config-plantable surface).
      3. .NET exe whose .config is itself user-writable (modifiable).

    Real-world: Iranian APT Screening Serpens (Unit 42, 2026), Operation
    PhantomCLR (CYFIRMA).  MITRE ATT&CK T1574.014.

.PARAMETER Path
    File or directory to scan.

.OUTPUTS
    [TcpkFinding]
#>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    if (-not (Assert-TcpkWindows 'Test-TcpkAppDomainHijack')) { return }

    $userPrincipals = '(?i)\b(Everyone|Authenticated Users|Users|INTERACTIVE|BUILTIN\\Users)\b'
    $writeRights    = 'Write|Modify|FullControl'

    function _IsWritable([string]$ItemPath) {
        try { $acl = Get-Acl -LiteralPath $ItemPath -ErrorAction Stop } catch { return $false }
        $bad = $acl.Access | Where-Object {
            $_.IdentityReference.Value -match $userPrincipals -and
            $_.FileSystemRights -match $writeRights -and
            $_.AccessControlType -eq 'Allow'
        }
        return ($null -ne $bad -and @($bad).Count -gt 0)
    }

    function _AclEvidence([string]$ItemPath) {
        try { $acl = Get-Acl -LiteralPath $ItemPath -ErrorAction Stop } catch { return '' }
        $bad = @($acl.Access | Where-Object {
            $_.IdentityReference.Value -match $userPrincipals -and
            $_.FileSystemRights -match $writeRights -and
            $_.AccessControlType -eq 'Allow'
        })
        if ($bad.Count -eq 0) { return '' }
        return ($bad | ForEach-Object { "$($_.IdentityReference) -> $($_.FileSystemRights)" }) -join '; '
    }

    foreach ($pe in Get-TcpkPeFiles -Path $Path) {
        if ($pe.Extension -ne '.exe') { continue }
        if (Test-TcpkIsFrameworkFile $pe.Name) { continue }

        $text = Read-TcpkAllText -Path $pe.FullName
        if (-not $text) { continue }
        if (-not $text.Contains('BSJB')) { continue }

        $dir        = $pe.DirectoryName
        $configPath = $pe.FullName + '.config'
        $configName = $pe.Name + '.config'

        # --- Check 1: existing .config with appDomainManager entries ---
        if (Test-Path -LiteralPath $configPath) {
            try {
                $raw = Get-Content -LiteralPath $configPath -Raw -ErrorAction Stop
            } catch { $raw = '' }
            if ($raw -match 'appDomainManagerAssembly|appDomainManagerType') {
                $asmMatch  = if ($raw -match 'appDomainManagerAssembly\s*=\s*"([^"]+)"') { $matches[1] } else { '(present)' }
                $typeMatch = if ($raw -match 'appDomainManagerType\s*=\s*"([^"]+)"')     { $matches[1] } else { '(present)' }

                New-TcpkFinding -Module 'static' -RuleId 'appdomain.manager-configured' `
                    -Severity 'HIGH' -Confidence 'Confirmed' `
                    -Title "AppDomainManager already configured: $($pe.Name)" `
                    -File $configPath `
                    -Evidence "assembly=$asmMatch; type=$typeMatch" `
                    -Cwe @('CWE-427','CWE-732') `
                    -Description ('The .config file contains appDomainManagerAssembly/Type entries. ' +
                        'The CLR will load the specified assembly and invoke its InitializeNewDomain ' +
                        'method before the application runs. If the referenced assembly is attacker-controlled ' +
                        'this is a persistence/privesc vector (ATT&CK T1574.014).') `
                    -Fix 'Remove the appDomainManagerAssembly/Type entries unless they are intentional. Restrict write access to the config file and its directory.'
            }

            # Check if the .config itself is writable (modifiable)
            if (_IsWritable $configPath) {
                $ev = _AclEvidence $configPath
                New-TcpkFinding -Module 'static' -RuleId 'appdomain.config-writable' `
                    -Severity 'HIGH' -Confidence 'Confirmed' `
                    -Title "User-writable .config enables AppDomain hijack: $configName" `
                    -File $configPath `
                    -Evidence $ev `
                    -Cwe @('CWE-732','CWE-427') `
                    -Description ('The .config file for this .NET executable is writable by non-admin users. ' +
                        'An attacker can inject appDomainManagerAssembly/Type entries to redirect CLR initialisation ' +
                        'into a malicious assembly (ATT&CK T1574.014).') `
                    -Fix 'Restrict the config file ACL to administrators/SYSTEM only.'
            }
        }
        else {
            # --- Check 2: no .config exists + directory is writable = plantable ---
            if (_IsWritable $dir) {
                $ev = _AclEvidence $dir
                New-TcpkFinding -Module 'static' -RuleId 'appdomain.config-plantable' `
                    -Severity 'HIGH' -Confidence 'Confirmed' `
                    -Title "AppDomain config plantable (writable dir): $($pe.Name)" `
                    -File $pe.FullName `
                    -Evidence "dir=$dir; $ev" `
                    -Cwe @('CWE-427','CWE-732') `
                    -Description ('This .NET executable has no .config file, but its directory is writable by ' +
                        'non-admin users. An attacker can create a .config with appDomainManagerAssembly/Type ' +
                        'entries to hijack CLR initialisation (ATT&CK T1574.014). Unlike DLL hijacking, this ' +
                        'uses a documented .NET runtime feature and bypasses most EDR hooks on LoadLibrary.') `
                    -Fix 'Restrict write access to the application directory to administrators/SYSTEM only.'
            }
        }
    }
}
