function Test-TcpkRegistryCredentialStore {
<#
.SYNOPSIS
    A - Static: first-party code that writes to the registry AND references credential
    fields (the insecure local-data-storage anti-pattern).

.DESCRIPTION
    Thick clients often persist login credentials to HKCU in cleartext -- e.g. a login form
    that does Registry.CurrentUser.CreateSubKey("<app>") then SetValue("password", pass).
    This is a STATIC complement to the runtime Test-TcpkRegistryValues (which scans the live
    keys only once the app has run): it flags a first-party PE that both (a) writes to the
    Windows registry (RegistryKey.SetValue / CreateSubKey / Microsoft.Win32.Registry) and
    (b) references a credential field (password / token / secret / api key / private key).

    Confidence = Inferred (a co-occurrence signal, not proof the SetValue argument IS the
    credential). Severity LOW -- a review pointer: decompile the SetValue call sites and
    confirm no raw credential is written without DPAPI / ProtectedData. Framework, native,
    and Chromium-runtime binaries are skipped (not the app's storage logic).

.PARAMETER Path
    File or directory.

.OUTPUTS
    [TcpkFinding]
#>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    $credRx = [regex]'(?i)(password|passwd|\bpwd\b|secret|api[_-]?key|apikey|access[_-]?token|auth[_-]?token|credential|privatekey)'

    foreach ($pe in Get-TcpkPeFiles -Path $Path) {
        if (Test-TcpkIsFrameworkFile $pe.Name) { continue }
        if (Test-TcpkIsNativeNoise $pe.Name)   { continue }
        $text = Read-TcpkAllText -Path $pe.FullName
        if (-not $text) { continue }
        if (Test-TcpkIsChromiumRuntime -Name $pe.Name -Text $text) { continue }

        # (a) registry WRITE surface: a SetValue call plus a Win32 registry root/type reference.
        if ($text.IndexOf('SetValue', [System.StringComparison]::OrdinalIgnoreCase) -lt 0) { continue }
        $hasReg = ($text.IndexOf('Microsoft.Win32.Registry', [System.StringComparison]::OrdinalIgnoreCase) -ge 0) -or
                  ($text.IndexOf('RegistryKey',  [System.StringComparison]::OrdinalIgnoreCase) -ge 0) -or
                  ($text.IndexOf('CreateSubKey', [System.StringComparison]::OrdinalIgnoreCase) -ge 0)
        if (-not $hasReg) { continue }

        # (b) a credential field is referenced somewhere in the same assembly.
        $cm = $credRx.Match($text)
        if (-not $cm.Success) { continue }

        New-TcpkFinding -Module 'static' -RuleId 'storage.registry-credential' `
            -Severity 'LOW' -Confidence 'Inferred' `
            -Title "$($pe.Name) writes to the registry and references credential fields (verify not stored in cleartext)" `
            -File $pe.FullName -Evidence "registry write (SetValue/CreateSubKey) + credential token '$($cm.Value)'" `
            -Cwe @('CWE-312','CWE-522') `
            -Description 'First-party code both writes to the Windows registry (RegistryKey.SetValue / CreateSubKey) and references credential fields (password / token / secret). Thick clients frequently persist login credentials to HKCU in cleartext. Decompile the SetValue call sites: if a password / token is written without DPAPI (ProtectedData / CryptProtectData) it is recoverable by any process running as that user. Runtime confirmation: run the app, then Test-TcpkRegistryValues scans the live keys for the stored secret.' `
            -Fix 'Never persist raw credentials to the registry. Protect them with DPAPI (ProtectedData) scoped to the current user, or use the Windows Credential Manager; store only non-reversible tokens where possible.'
    }
}
