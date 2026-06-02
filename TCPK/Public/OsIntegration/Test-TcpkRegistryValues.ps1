function Test-TcpkRegistryValues {
<#
.SYNOPSIS
    C17. Secrets stored in the app's registry VALUES (not just key names).

.DESCRIPTION
    Walks the app's registry subtree (HKCU + HKLM Software / WOW6432Node /
    Classes) and inspects every value's DATA for secret material: passwords, API
    keys, tokens, connection strings, private-key blocks, and long base64 blobs
    under secret-suggestive value names. Registry-stored secrets are readable by
    the user (HKCU) or by anyone (HKLM) and survive uninstall.

.PARAMETER NameLike
    One or more vendor / product / package search terms (substring, case-
    insensitive). Pass the set from Get-TcpkIdentityTerms for app-aware coverage.

.OUTPUTS
    [TcpkFinding]
#>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string[]]$NameLike)

    if (-not (Assert-TcpkWindows 'Test-TcpkRegistryValues')) { return }

    $terms = @($NameLike | Where-Object { $_ })
    if (-not $terms.Count) { return }

    $valueNameSuspicious = '(?i)(pass|pwd|secret|key|token|cred|connection|conn[_ ]?str|apikey|api[_-]?key|auth|license|serial)'
    $dataSecret = '(?i)(password\s*=|pwd\s*=|AccountKey=|DefaultEndpointsProtocol=|-----BEGIN|\bAKIA[A-Z0-9]{16}\b|\beyJ[A-Za-z0-9_-]{10,}\.)'
    $b64long = '^[A-Za-z0-9+/]{40,}={0,2}$'

    foreach ($r in (Get-TcpkRegistrySearchRoots)) {
        if (-not (Test-Path $r)) { continue }
        # vendor-root-first (fast): only recurse under matching top-level keys
        $vendorRoots = Get-ChildItem -Path $r -ErrorAction SilentlyContinue |
            Where-Object { Test-TcpkTermMatch -Text $_.PSChildName -Terms $terms }
        $keys = foreach ($vr in $vendorRoots) { $vr; Get-ChildItem -Path $vr.PSPath -Recurse -Depth 4 -ErrorAction SilentlyContinue }
        foreach ($k in $keys) {
            $props = $null
            try { $props = Get-ItemProperty -LiteralPath $k.PSPath -ErrorAction Stop } catch { continue }
            foreach ($p in $props.PSObject.Properties) {
                if ($p.Name.StartsWith('PS')) { continue }
                $val = "$($p.Value)"
                if (-not $val) { continue }
                $keyPath = $k.PSPath -replace 'Microsoft\.PowerShell\.Core\\Registry::',''

                $isSecret = $false; $why = ''
                if ($val -match $dataSecret) { $isSecret = $true; $why = 'value data matches a secret pattern' }
                elseif (($p.Name -match $valueNameSuspicious) -and ($val.Length -ge 16) -and ($val -match $b64long)) {
                    $isSecret = $true; $why = "secret-named value holds a long base64 blob"
                }
                if ($isSecret) {
                    $redacted = if ($val.Length -gt 12) { $val.Substring(0,6) + '...(' + $val.Length + ' chars)' } else { '(short)' }

                    # Is the key readable by all/standard users? A secret in a
                    # world-readable key is exposed to every local account -> CRITICAL.
                    $worldRead = $false; $grant = ''
                    try {
                        $acl = Get-Acl -Path $k.PSPath -ErrorAction Stop
                        $r = $acl.Access | Where-Object {
                            $_.AccessControlType -eq 'Allow' -and
                            "$($_.IdentityReference)" -match '(?i)\b(Everyone|Authenticated Users|BUILTIN\\Users|\\Users$|^Users$|INTERACTIVE)\b' -and
                            "$($_.RegistryRights)" -match 'ReadKey|QueryValues|FullControl|GenericRead'
                        }
                        if ($r) { $worldRead = $true; $grant = ($r | ForEach-Object { "$($_.IdentityReference)=$($_.RegistryRights)" } | Select-Object -Unique) -join '; ' }
                    } catch { }

                    if ($worldRead) {
                        New-TcpkFinding -Module 'os' -RuleId 'registry.secret-world-readable' `
                            -Severity 'CRITICAL' -Confidence 'Confirmed' `
                            -Title "Secret in all-users-readable registry value: $($p.Name)" `
                            -File "$keyPath\$($p.Name)" -Evidence "$why; value=$redacted; read-ACL: $grant" -Cwe @('CWE-312','CWE-732') `
                            -Description 'A secret is stored in a registry key that any local/standard user can READ. Every account on the machine can recover this credential.' `
                            -Fix 'Move the secret out of the registry (DPAPI CurrentUser / Credential Manager) and restrict the key DACL so only the owning user + SYSTEM can read it.'
                    } else {
                        New-TcpkFinding -Module 'os' -RuleId 'registry.secret-value' `
                            -Severity 'HIGH' -Confidence 'Confirmed' `
                            -Title "Secret in registry value: $($p.Name)" `
                            -File "$keyPath\$($p.Name)" -Evidence "$why; value=$redacted" -Cwe @('CWE-312','CWE-256') `
                            -Description 'Sensitive data is stored in the registry. HKCU values are readable by the user (and by malware running as them); HKLM values may be readable by all users. They also persist after uninstall.' `
                            -Fix 'Do not store secrets in the registry. Use DPAPI (CurrentUser scope) or the Windows Credential Manager; clear on logout.'
                    }
                }
            }
        }
    }
}
