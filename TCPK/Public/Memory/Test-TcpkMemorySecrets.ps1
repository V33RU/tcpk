function Test-TcpkMemorySecrets {
<#
.SYNOPSIS
    I04. Live-memory secret scan (read-only) of a running process.

.DESCRIPTION
    Reads the target process's committed private/mapped memory (ReadProcessMemory)
    and applies the secrets.json regex rules to both the ASCII and UTF-16 views.
    This catches secrets that only exist at runtime: decrypted config, bearer
    tokens in the heap, plaintext passwords typed into a form, connection strings.

    Read-only and non-modifying. Image-backed (code) regions are skipped (the
    static scanner already covers those). Same-user processes need no elevation;
    an elevated/SYSTEM target needs an elevated TCPK.

.PARAMETER ProcessName
    Running process name (no .exe).

.PARAMETER MaxScanMB
    Soft cap on total bytes scanned (default 200 MB).

.OUTPUTS
    [TcpkFinding]
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ParameterSetName='ByName')][string]$ProcessName,
        [Parameter(Mandatory, ParameterSetName='ById')][int]$ProcessId,
        [int]$MaxScanMB = 200
    )

    if (-not (Assert-TcpkWindows 'Test-TcpkMemorySecrets')) { return }
    if (-not ('Tcpk.MemRead' -as [type])) {
        New-TcpkSkippedFinding -RuleId 'memory.secrets-unavailable' -Title 'Memory-read primitive unavailable' -Reason 'Tcpk.MemRead failed to load.'
        return
    }

    $procs = if ($PSCmdlet.ParameterSetName -eq 'ByName') { Get-TcpkProcess -ProcessName $ProcessName } else { Get-TcpkProcess -ProcessId $ProcessId }
    if (-not $procs) { return }

    $rules = Get-TcpkSecretRegexRules
    $placeholder = '(?i)(&lt|&gt|&amp|<[a-z_ ]{2,}>|\bsnipped\b|\bplaceholder\b|\bexample\b|\byour[-_ ]|\bchange[-_ ]?me\b|\bdummy\b|\bsample\b|\bredacted\b|x{6,}|\.\.\.|\*{4,})'
    $maxBytes = [int64]$MaxScanMB * 1MB

    foreach ($p in $procs) {
        $h = [Tcpk.MemRead]::Open($p.Id, $false)
        if ($h -eq [IntPtr]::Zero) {
            New-TcpkSkippedFinding -RuleId 'memory.open-denied' -Title "Cannot open $($p.Name) (PID $($p.Id)) for memory read" -Reason 'OpenProcess denied -- run TCPK elevated if the target is elevated/SYSTEM.'
            continue
        }
        try {
            $regions = [Tcpk.MemRead]::Regions($h, 64MB, $false)
            $scanned = [int64]0
            $seen = @{}
            $emitted = 0
            for ($i = 0; $i -lt $regions.Length -and $emitted -lt 50 -and $scanned -lt $maxBytes; $i += 2) {
                $base = $regions[$i]; $size = [int][Math]::Min($regions[$i+1], 16MB)
                $bytes = [Tcpk.MemRead]::ReadBytes($h, $base, $size)
                if (-not $bytes) { continue }
                $scanned += $bytes.Length

                $ascii   = [Text.Encoding]::ASCII.GetString($bytes)
                $wide    = [Text.Encoding]::Unicode.GetString($bytes)
                # odd-byte-aligned wide strings: decode from offset 1 too (~half of wide
                # strings begin at an odd offset and are missed by the offset-0 decode).
                $wideOdd = if ($bytes.Length -gt 1) { [Text.Encoding]::Unicode.GetString($bytes, 1, $bytes.Length - 1) } else { '' }
                foreach ($view in @(@{ S='ascii'; T=$ascii }, @{ S='utf16'; T=$wide }, @{ S='utf16-odd'; T=$wideOdd })) {
                    foreach ($r in $rules) {
                        foreach ($m in $r._RX.Matches($view.T)) {
                            $hit = $m.Value
                            if ($hit.Length -lt 6) { continue }
                            if ($hit -match $placeholder) { continue }
                            $key = "$($r.id)::" + $hit.Substring(0, [Math]::Min(60, $hit.Length))
                            if ($seen.ContainsKey($key)) { continue }
                            $seen[$key] = $true
                            $red = $hit   # un-redacted: show the full value (local operator tool)
                            New-TcpkFinding -Module 'memory' -RuleId "memsecret.$($r.id)" `
                                -Severity $r.severity -Confidence 'Confirmed' `
                                -Title "$($r.title) in live memory of $($p.Name)" `
                                -File "$($p.Name) (PID $($p.Id)) @0x$($base.ToString('x'))" `
                                -Evidence "$red [view=$($view.S)]" -Cwe ([string[]]$r.cwe) `
                                -Description 'A secret was found in the running process memory. Runtime secrets (decrypted config, tokens, typed passwords) are recoverable by anyone who can read the process -- minimise their lifetime and zero buffers after use.' `
                                -Fix 'Use SecureString / protected memory for secrets, clear buffers promptly, and avoid holding long-lived plaintext credentials in the heap.'
                            $emitted++
                            if ($emitted -ge 50) { break }
                        }
                        if ($emitted -ge 50) { break }
                    }
                }
            }
            New-TcpkFinding -Module 'memory' -RuleId 'memsecret.scan-summary' `
                -Severity 'INFO' -Confidence 'Confirmed' `
                -Title "Live-memory scan of $($p.Name): $emitted secret-pattern hit(s)" `
                -File "$($p.Name) (PID $($p.Id))" `
                -Evidence "scanned $([int]($scanned/1MB)) MB across $([int]($regions.Length/2)) regions"
        } finally {
            [void][Tcpk.MemRead]::CloseHandle($h)
        }
    }
}
