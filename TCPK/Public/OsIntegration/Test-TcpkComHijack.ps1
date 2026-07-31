function Test-TcpkComHijack {
<#
.SYNOPSIS
    Detect per-user COM CLSID hijack opportunities.

.DESCRIPTION
    When a thick-client application instantiates COM objects, the OS resolves
    CLSIDs by checking HKCU\Software\Classes\CLSID BEFORE HKLM.  If a CLSID
    is registered in HKLM but NOT in HKCU, any standard user can create their
    own HKCU entry pointing to a malicious DLL -- the next time the application
    creates that COM object it loads the attacker's code.

    This check:
      1. Collects candidate CLSIDs by scanning the raw bytes of each first-party
         PE for GUID-shaped strings, plus GUIDs in shipped .config/.json/.xml/
         .manifest files.  This is a TEXTUAL scan, NOT IL analysis: it does not
         prove the application calls CoCreateInstance on the CLSID, only that
         the GUID appears in the file.  Expect candidates the app never
         instantiates; step 2 filters to those actually registered in HKLM.
      2. For each CLSID registered in HKLM, checks whether HKCU\...\CLSID\{id}
         already exists.  If not, it is hijackable.
      3. Also checks whether the InprocServer32/LocalServer32 binary path
         under HKLM points to a writable location (direct server hijack).

    MITRE ATT&CK T1546.015 (Component Object Model Hijacking).

.PARAMETER Path
    File or directory to scan.

.PARAMETER NameLike
    Identity search terms for registry-based COM discovery.

.OUTPUTS
    [TcpkFinding]
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [string[]]$NameLike
    )

    if (-not (Assert-TcpkWindows 'Test-TcpkComHijack')) { return }

    $userPrincipals = '(?i)\b(Everyone|Authenticated Users|Users|INTERACTIVE|BUILTIN\\Users)\b'
    $writeRights    = 'Write|Modify|FullControl'

    function _IsWritable([string]$ItemPath) {
        try {
            if (-not (Test-Path -LiteralPath $ItemPath)) { return $false }
            $acl = Get-Acl -LiteralPath $ItemPath -ErrorAction Stop
        } catch { return $false }
        $bad = $acl.Access | Where-Object {
            $_.IdentityReference.Value -match $userPrincipals -and
            $_.FileSystemRights -match $writeRights -and
            $_.AccessControlType -eq 'Allow'
        }
        return ($null -ne $bad -and @($bad).Count -gt 0)
    }

    $clsidRx = '\{[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\}'
    $clsids  = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase)

    foreach ($pe in Get-TcpkPeFiles -Path $Path) {
        if (Test-TcpkIsFrameworkFile $pe.Name) { continue }
        $text = Read-TcpkAllText -Path $pe.FullName
        if (-not $text) { continue }
        $ms = [regex]::Matches($text, $clsidRx)
        foreach ($m in $ms) { [void]$clsids.Add($m.Value) }
    }

    $item = Get-Item -LiteralPath $Path -ErrorAction SilentlyContinue
    if (-not $item) { return }
    $root = if ($item.PSIsContainer) { $item.FullName } else { $item.DirectoryName }
    foreach ($cfg in Get-ChildItem -LiteralPath $root -Recurse -File -ErrorAction SilentlyContinue |
        Where-Object { $_.Extension.ToLowerInvariant() -in '.config','.json','.xml','.manifest' }) {
        try {
            $raw = Get-Content -LiteralPath $cfg.FullName -Raw -ErrorAction Stop
            if (-not $raw) { continue }
        } catch { continue }
        $ms = [regex]::Matches($raw, $clsidRx)
        foreach ($m in $ms) { [void]$clsids.Add($m.Value) }
    }

    if ($clsids.Count -eq 0) { return }

    $seen = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase)

    foreach ($clsid in $clsids) {
        if (-not $seen.Add($clsid)) { continue }

        $hklmKey = "HKLM:\Software\Classes\CLSID\$clsid"
        if (-not (Test-Path -LiteralPath $hklmKey)) { continue }

        foreach ($subKey in 'InprocServer32','LocalServer32') {
            $serverKey = "$hklmKey\$subKey"
            if (-not (Test-Path -LiteralPath $serverKey)) { continue }

            $serverPath = $null
            try {
                $serverPath = (Get-ItemProperty -LiteralPath $serverKey -Name '(Default)' -ErrorAction Stop).'(Default)'
            } catch {}
            if (-not $serverPath) { continue }
            $serverPath = $serverPath -replace '"','' -replace '\s+/.*$','' -replace '\s+-.*$',''

            $hkcuKey = "HKCU:\Software\Classes\CLSID\$clsid"
            if (-not (Test-Path -LiteralPath $hkcuKey)) {
                New-TcpkFinding -Module 'os' -RuleId 'comhijack.per-user-plantable' `
                    -Severity 'MEDIUM' -Confidence 'Confirmed' `
                    -Title "COM CLSID hijackable via HKCU: $clsid ($subKey)" `
                    -File $serverPath `
                    -Evidence "HKLM=$subKey -> $serverPath; HKCU entry absent" `
                    -Cwe @('CWE-427') `
                    -Description ('This COM CLSID is registered in HKLM but has no HKCU entry. ' +
                        'Any standard user can create an HKCU\Software\Classes\CLSID\' + $clsid + '\' + $subKey + ' ' +
                        'key pointing to their own DLL. Because HKCU is checked before HKLM, the ' +
                        'application will load the attacker''s server instead of the legitimate one ' +
                        '(ATT&CK T1546.015 COM Hijacking).') `
                    -Fix 'Register the COM server per-user at install time to prevent pre-emption, or validate the loaded server''s signature at runtime.'
            }

            if ($serverPath -and (Test-Path -LiteralPath $serverPath -ErrorAction SilentlyContinue)) {
                if (_IsWritable $serverPath) {
                    New-TcpkFinding -Module 'os' -RuleId 'comhijack.server-writable' `
                        -Severity 'HIGH' -Confidence 'Confirmed' `
                        -Title "COM server DLL is user-writable: $clsid" `
                        -File $serverPath `
                        -Evidence "CLSID=$clsid; $subKey=$serverPath; file is writable by non-admin" `
                        -Cwe @('CWE-732','CWE-427') `
                        -Description ('The COM server binary pointed to by this CLSID is writable by ' +
                            'non-admin users. An attacker can replace it directly without needing ' +
                            'the HKCU hijack technique.') `
                        -Fix 'Restrict write access on the COM server binary to administrators/SYSTEM only.'
                }
            }
        }
    }
}
