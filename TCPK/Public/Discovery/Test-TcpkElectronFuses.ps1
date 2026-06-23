function Test-TcpkElectronFuses {
<#
.SYNOPSIS
    A42. Electron Fuses audit -- the runtime hardening flags baked into the app binary.

.DESCRIPTION
    Electron "fuses" are security flags embedded as a byte string in the main app
    executable (after the sentinel "dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX": one version byte,
    one count byte, then one ASCII state char per fuse -- '0' off, '1' on, 'r' removed).
    They decide app-wide behavior that no webPreference covers, and they are the gap the
    Inspectron (USENIX'24) and SK-Shieldus studies flag. Because the state is parsed
    directly from the binary, these findings are Confirmed facts, not leads.

    Insecure states flagged (FuseV1 order):
      [0] RunAsNode = on                      -> ELECTRON_RUN_AS_NODE node-exec LOLBin
      [1] EnableCookieEncryption = off        -> cookies (incl. auth tokens) stored plaintext
      [3] EnableNodeCliInspectArguments = on  -> --inspect debug port -> code execution
      [4] EnableEmbeddedAsarIntegrityValidation = off -> app.asar tamperable (no integrity)
    A posture INFO finding lists the full wire for the remaining fuses.

.PARAMETER Path
    File or directory.

.OUTPUTS
    [TcpkFinding]
#>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    $item = Get-Item -LiteralPath $Path -ErrorAction SilentlyContinue
    $dir  = if ($item -and $item.PSIsContainer) { $Path } elseif ($item) { Split-Path -Parent $item.FullName } else { $null }
    if (-not $dir) { return }

    # gate: Electron-family only
    $isElectron = $false
    foreach ($marker in 'electron.exe','libcef.dll','nw.exe','ffmpeg.dll') {
        if (Get-ChildItem -LiteralPath $dir -Recurse -File -Filter $marker -ErrorAction SilentlyContinue | Select-Object -First 1) { $isElectron = $true; break }
    }
    if (-not $isElectron -and -not (Get-ChildItem -LiteralPath $dir -Recurse -File -Filter '*.asar' -ErrorAction SilentlyContinue | Select-Object -First 1)) { return }

    $sentinel = 'dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX'
    $enc = [System.Text.Encoding]::GetEncoding(28591)   # ISO-8859-1: 1 byte -> 1 char, for an ordinal byte-pattern search

    function _FindFuseWire {
        param([string]$ExePath)
        $fs = $null
        try { $fs = [System.IO.FileStream]::new($ExePath, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, ([System.IO.FileShare]::ReadWrite -bor [System.IO.FileShare]::Delete)) } catch { return $null }
        try {
            $chunk = 8MB; $ov = $sentinel.Length; $buf = New-Object byte[] ($chunk + $ov); $carry = 0; $found = -1; $base = 0
            while ($true) {
                $n = $fs.Read($buf, $carry, $chunk); $tot = $carry + $n; if ($tot -le 0) { break }
                $i = ($enc.GetString($buf, 0, $tot)).IndexOf($sentinel, [System.StringComparison]::Ordinal)
                if ($i -ge 0) { $found = $base + $i; break }
                if ($n -le 0) { break }
                $keep = $ov; [Array]::Copy($buf, $tot - $keep, $buf, 0, $keep); $carry = $keep; $base += ($tot - $keep)
            }
            if ($found -lt 0) { return $null }
            [void]$fs.Seek($found + $sentinel.Length, [System.IO.SeekOrigin]::Begin)
            $hdr = New-Object byte[] 40; $r = $fs.Read($hdr, 0, 40)
            if ($r -lt 3) { return $null }
            $cnt = [int]$hdr[1]
            if ($cnt -lt 1 -or $cnt -gt 32 -or (2 + $cnt) -gt $r) { return $null }   # malformed -> bail (no guessing)
            $chars = New-Object char[] $cnt
            for ($k = 0; $k -lt $cnt; $k++) { $chars[$k] = [char]$hdr[2 + $k] }
            $fstr = -join $chars
            if ($fstr -notmatch '^[01r]+$') { return $null }
            return [pscustomobject]@{ Version = [int]$hdr[0]; Count = $cnt; Fuses = $fstr }
        } finally { $fs.Dispose() }
    }

    $exes = @(Get-ChildItem -LiteralPath $dir -Recurse -File -Filter '*.exe' -ErrorAction SilentlyContinue |
              Where-Object { $_.Name -notmatch '(?i)(uninstall|^un|setup|crashpad|squirrel|elevate)' } |
              Sort-Object Length -Descending)
    $wire = $null; $wireExe = $null
    foreach ($e in ($exes | Select-Object -First 4)) {
        $w = _FindFuseWire $e.FullName
        if ($w) { $wire = $w; $wireExe = $e; break }
    }
    if (-not $wire) { return }   # no fuse wire (very old Electron, or not an Electron exe)

    $f = $wire.Fuses
    $at = { param($i) if ($i -lt $f.Length) { "$($f[$i])" } else { 'x' } }

    New-TcpkFinding -Module 'static' -RuleId 'fuses.posture' `
        -Severity 'INFO' -Confidence 'Confirmed' `
        -Title "Electron fuse posture: $f" -File $wireExe.FullName `
        -Evidence "version=$($wire.Version) count=$($wire.Count) fuses=$f (in $($wireExe.Name))" -Cwe @('CWE-1188') `
        -Description 'Parsed the Electron fuse wire from the app binary (1=on, 0=off, FuseV1 order: RunAsNode, EnableCookieEncryption, EnableNodeOptionsEnvironmentVariable, EnableNodeCliInspectArguments, EnableEmbeddedAsarIntegrityValidation, OnlyLoadAppFromAsar, ...). Fuses harden the app at a level no webPreference covers; review them against the Electron security checklist.' `
        -Fix 'Set fuses with @electron/fuses at build time: RunAsNode off, EnableCookieEncryption on, EnableNodeOptionsEnvironmentVariable off, EnableNodeCliInspectArguments off, EnableEmbeddedAsarIntegrityValidation on, OnlyLoadAppFromAsar on.'

    if ((& $at 1) -eq '0') {
        New-TcpkFinding -Module 'static' -RuleId 'fuses.cookie-encryption-disabled' `
            -Severity 'MEDIUM' -Confidence 'Confirmed' `
            -Title 'Electron cookie-encryption fuse is OFF (cookies stored in plaintext)' -File $wireExe.FullName `
            -Evidence "EnableCookieEncryption=0 (fuses=$f)" -Cwe @('CWE-312','CWE-522') `
            -Description 'The EnableCookieEncryption fuse is disabled, so the app stores its cookies -- including session and authentication tokens -- in plaintext on disk (unlike Chrome, which encrypts them). Any local process or other user-readable software can read or modify them. The Inspectron study found this true of almost every Electron app.' `
            -Fix 'Enable the EnableCookieEncryption fuse so cookies are encrypted with an OS-level key (DPAPI / Keychain).'
    }
    if ((& $at 0) -eq '1') {
        New-TcpkFinding -Module 'static' -RuleId 'fuses.run-as-node-enabled' `
            -Severity 'LOW' -Confidence 'Confirmed' `
            -Title 'Electron RunAsNode fuse is ON (binary usable as a Node.js interpreter)' -File $wireExe.FullName `
            -Evidence "RunAsNode=1 (fuses=$f)" -Cwe @('CWE-489','CWE-94') `
            -Description 'The RunAsNode fuse is enabled, so the app binary can be relaunched as a general Node.js interpreter via the ELECTRON_RUN_AS_NODE environment variable, letting a local attacker execute arbitrary Node code under the (often signed) app identity -- a living-off-the-land / defense-evasion primitive.' `
            -Fix 'Disable the RunAsNode fuse unless the app genuinely needs ELECTRON_RUN_AS_NODE.'
    }
    if ((& $at 3) -eq '1') {
        New-TcpkFinding -Module 'static' -RuleId 'fuses.node-inspect-enabled' `
            -Severity 'LOW' -Confidence 'Confirmed' `
            -Title 'Electron NodeCliInspectArguments fuse is ON (--inspect debug port allowed)' -File $wireExe.FullName `
            -Evidence "EnableNodeCliInspectArguments=1 (fuses=$f)" -Cwe @('CWE-489') `
            -Description 'The EnableNodeCliInspectArguments fuse is enabled, so the app accepts --inspect / --inspect-brk, exposing a Node debugging port. A local attacker who launches the app with that flag gets a debugger that yields arbitrary code execution (the remote-Chrome-debugging RCE technique).' `
            -Fix 'Disable the EnableNodeCliInspectArguments fuse unless debugging is required.'
    }
    if ((& $at 4) -eq '0') {
        New-TcpkFinding -Module 'static' -RuleId 'fuses.asar-integrity-disabled' `
            -Severity 'LOW' -Confidence 'Confirmed' `
            -Title 'Electron ASAR integrity-validation fuse is OFF (app.asar is tamperable)' -File $wireExe.FullName `
            -Evidence "EnableEmbeddedAsarIntegrityValidation=0 (fuses=$f)" -Cwe @('CWE-353','CWE-494') `
            -Description 'The EnableEmbeddedAsarIntegrityValidation fuse is disabled, so the app does not verify the integrity of its bundled app.asar at load time. A local attacker (or malware) can modify the packaged JavaScript -- injecting a persistent payload -- without detection. This is the inadequate-integrity-verification weakness in the SK-Shieldus study.' `
            -Fix 'Enable the EnableEmbeddedAsarIntegrityValidation fuse (with OnlyLoadAppFromAsar) so tampered app code is rejected at startup.'
    }
}
