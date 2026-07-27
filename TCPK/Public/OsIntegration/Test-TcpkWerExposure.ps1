function Test-TcpkWerExposure {
<#
.SYNOPSIS
    Detect Windows Error Reporting (WER) crash dump data exposure.

.DESCRIPTION
    When an application crashes, Windows Error Reporting can write full or
    mini memory dumps to disk.  These dumps contain the process memory at
    crash time -- including credentials, tokens, encryption keys, and PII
    that were in memory.  If WER is configured to keep local dumps and the
    dump directory is world-readable, any local user can harvest secrets
    from a prior crash.

    Checks:
      1. HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\LocalDumps
         (global or per-exe): DumpFolder path + DumpType (2=full, 1=mini).
      2. The dump folder ACL (world-readable = data exposure).
      3. Existing .dmp files in the default WER folders.

    MITRE ATT&CK T1005 (Data from Local System).

.PARAMETER Path
    File or directory to scan (used to identify the main exe name for
    per-app WER settings).

.OUTPUTS
    [TcpkFinding]
#>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    if (-not (Assert-TcpkWindows 'Test-TcpkWerExposure')) { return }

    $item = Get-Item -LiteralPath $Path -ErrorAction SilentlyContinue
    if (-not $item) { return }
    $root = if ($item.PSIsContainer) { $item.FullName } else { $item.DirectoryName }

    $exeNames = @()
    foreach ($pe in Get-TcpkPeFiles -Path $Path) {
        if ($pe.Extension -eq '.exe' -and -not (Test-TcpkIsFrameworkFile $pe.Name)) {
            $exeNames += $pe.Name
        }
    }

    $userPrincipals = '(?i)\b(Everyone|Authenticated Users|Users|INTERACTIVE|BUILTIN\\Users)\b'

    function _CheckDumpFolder([string]$Folder, [string]$Context, [int]$DumpType) {
        if (-not $Folder -or -not (Test-Path -LiteralPath $Folder)) { return }
        $typeLabel = if ($DumpType -eq 2) { 'Full dump' } elseif ($DumpType -eq 1) { 'Mini dump' } else { 'Custom dump' }

        try { $acl = Get-Acl -LiteralPath $Folder -ErrorAction Stop } catch { return }
        $readable = @($acl.Access | Where-Object {
            $_.IdentityReference.Value -match $userPrincipals -and
            $_.FileSystemRights -match 'Read|ListDirectory|FullControl' -and
            $_.AccessControlType -eq 'Allow'
        })
        if ($readable.Count -gt 0) {
            $ev = ($readable | ForEach-Object { "$($_.IdentityReference) -> $($_.FileSystemRights)" }) -join '; '
            New-TcpkFinding -Module 'os' -RuleId 'wer.dump-folder-readable' `
                -Severity 'MEDIUM' -Confidence 'Confirmed' `
                -Title "WER dump folder is user-readable ($Context)" `
                -File $Folder `
                -Evidence "$typeLabel; $ev" `
                -Cwe @('CWE-532','CWE-200') `
                -Description ('Windows Error Reporting is configured to write crash dumps to ' +
                    'this folder. The folder is readable by non-admin users, so any local user ' +
                    'can access crash dumps that may contain credentials, tokens, encryption keys, ' +
                    'or PII from the application''s memory at crash time.') `
                -Fix 'Restrict the dump folder ACL to SYSTEM/Administrators only, or disable local crash dumps for this application.'
        }

        $dmps = @(Get-ChildItem -LiteralPath $Folder -Filter '*.dmp' -File -ErrorAction SilentlyContinue)
        if ($dmps.Count -gt 0) {
            New-TcpkFinding -Module 'os' -RuleId 'wer.dump-files-present' `
                -Severity 'LOW' -Confidence 'Confirmed' `
                -Title "WER crash dumps on disk: $($dmps.Count) file(s) ($Context)" `
                -File $Folder `
                -Evidence (($dmps | Select-Object -First 5 | ForEach-Object { "$($_.Name) ($([math]::Round($_.Length/1MB,1))MB)" }) -join '; ') `
                -Cwe @('CWE-532') `
                -Description ('Crash dump files exist in the WER dump folder. These files contain ' +
                    'a snapshot of the process memory at crash time and may include sensitive data.') `
                -Fix 'Delete existing dump files and restrict the dump folder ACL.'
        }
    }

    $werBase = 'HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting\LocalDumps'

    if (Test-Path -LiteralPath $werBase) {
        $globalProps = $null
        try { $globalProps = Get-ItemProperty -LiteralPath $werBase -ErrorAction Stop } catch {}
        $globalFolder = if ($globalProps -and $globalProps.DumpFolder) { $globalProps.DumpFolder } else { '' }
        $globalType   = if ($globalProps -and $null -ne $globalProps.DumpType)  { $globalProps.DumpType }  else { 1 }

        foreach ($exeName in $exeNames) {
            $exeKey = "$werBase\$exeName"
            if (-not (Test-Path -LiteralPath $exeKey)) { continue }
            $exeProps = $null
            try { $exeProps = Get-ItemProperty -LiteralPath $exeKey -ErrorAction Stop } catch { continue }
            $folder = if ($exeProps.DumpFolder) { $exeProps.DumpFolder } else { $globalFolder }
            $dtype  = if ($null -ne $exeProps.DumpType) { $exeProps.DumpType } else { $globalType }

            New-TcpkFinding -Module 'os' -RuleId 'wer.local-dumps-per-app' `
                -Severity 'MEDIUM' -Confidence 'Confirmed' `
                -Title "WER local dumps configured for $exeName" `
                -File $exeKey `
                -Evidence "DumpFolder=$folder; DumpType=$dtype" `
                -Cwe @('CWE-532','CWE-200') `
                -Description ('Windows Error Reporting has per-application crash dump settings ' +
                    'for this executable. A full dump (DumpType=2) captures the entire process memory.') `
                -Fix 'Remove the per-app LocalDumps registry key or set DumpType=0.'
            if ($folder) { _CheckDumpFolder $folder "per-app $exeName" $dtype }
        }
    }

}
