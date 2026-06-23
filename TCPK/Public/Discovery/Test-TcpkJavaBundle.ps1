function Test-TcpkJavaBundle {
<#
.SYNOPSIS
    A35. Crack shipped Java archives (jar / war / ear) and scan their entries for secrets
    and insecure-TLS markers.

.DESCRIPTION
    A Java thick client ships its code/config inside ZIP-format archives. TCPK's PE
    scanners never look inside them. This opens each *.jar / *.war / *.ear as a ZIP,
    enumerates entries, and over the text-bearing ones (MANIFEST.MF, *.properties,
    *.xml, *.yml/.yaml, *.json, *.conf, and the string content of *.class) runs the
    shared secret-pattern rule set plus a few Java-specific insecure-TLS markers
    (trust-all TrustManager, all-hosts HostnameVerifier).

    A pattern match is Confidence='Inferred' (it proves the string is present, not that
    it is reachable/live) - decompile with Jadx/JD-GUI to confirm.

.PARAMETER Path
    Folder (recursive) preferred. A single .jar/.war/.ear also works.

.PARAMETER MaxEntries
    Per-archive cap on entries scanned (default 4000).

.OUTPUTS
    [TcpkFinding]
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [int]$MaxEntries = 4000
    )

    try { Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction Stop } catch { }

    $archives = if ((Get-Item -LiteralPath $Path).PSIsContainer) {
        Get-ChildItem -LiteralPath $Path -Recurse -File -ErrorAction SilentlyContinue |
            Where-Object { $_.Extension.ToLowerInvariant() -in '.jar','.war','.ear' }
    } elseif ((Get-Item -LiteralPath $Path).Extension.ToLowerInvariant() -in '.jar','.war','.ear') {
        @(Get-Item -LiteralPath $Path)
    } else { @() }

    $rules = Get-TcpkSecretRegexRules
    $textRx = '(?i)(MANIFEST\.MF$|\.(properties|xml|yml|yaml|json|conf|cfg|ini|txt|sql|env)$)'
    $tlsMarkers = @(
        @{ Rx='(?i)(X509TrustManager|TrustManager\[\]|checkServerTrusted\s*\([^)]*\)\s*\{\s*\})'; Title='Custom/empty TrustManager (TLS trust bypass)'; Cwe=@('CWE-295') },
        @{ Rx='(?i)(ALLOW_ALL_HOSTNAME_VERIFIER|AllowAllHostnameVerifier|NullHostnameVerifier|setHostnameVerifier)'; Title='All-hosts HostnameVerifier (TLS hostname bypass)'; Cwe=@('CWE-297') }
    )

    foreach ($arc in $archives) {
        New-TcpkFinding -Module 'static' -RuleId 'javabundle.archive' `
            -Severity 'INFO' -Confidence 'Confirmed' `
            -Title "Java archive: $($arc.Name)" -File $arc.FullName -Evidence "size=$($arc.Length)" `
            -Description 'A Java jar/war/ear archive. Its entries are scanned for secrets and insecure-TLS markers; decompile with Jadx/JD-GUI to read the source.'

        $zip = $null
        try { $zip = [System.IO.Compression.ZipFile]::OpenRead($arc.FullName) } catch { continue }
        try {
            $n = 0
            foreach ($entry in $zip.Entries) {
                if ($n -ge $MaxEntries) { break }
                if ($entry.Length -le 0) { continue }
                $isText  = $entry.FullName -match $textRx
                $isClass = $entry.FullName.ToLowerInvariant().EndsWith('.class')
                if (-not ($isText -or $isClass)) { continue }
                $n++
                $text = $null
                try {
                    $sr = New-Object System.IO.StreamReader($entry.Open())
                    $text = $sr.ReadToEnd(); $sr.Dispose()
                } catch { continue }
                if (-not $text) { continue }
                $loc = "$($arc.Name)!/$($entry.FullName)"

                foreach ($r in $rules) {
                    $m = $r._RX.Match($text)
                    if (-not $m.Success) { continue }
                    $val = $m.Value; if ($val.Length -gt 80) { $val = $val.Substring(0,80) + ' ...' }
                    New-TcpkFinding -Module 'static' -RuleId "javabundle.$($r.id)" `
                        -Severity $(if ($r.severity) { $r.severity } else { 'MEDIUM' }) -Confidence 'Inferred' `
                        -Title "$($r.title) in $($entry.Name)" `
                        -File $loc -Evidence $val -Cwe (@($r.cwe)) `
                        -Description 'A secret-pattern match inside a Java archive entry. Confirm in a decompiler; rotate if it is a live credential.' `
                        -Fix 'Remove the secret from the bundle; load it from a protected store at runtime.'
                    break   # one secret-rule hit per entry is enough
                }
                if ($isText -or $isClass) {
                    foreach ($t in $tlsMarkers) {
                        $tm = [regex]::Match($text, $t.Rx)
                        if ($tm.Success) {
                            New-TcpkFinding -Module 'static' -RuleId 'javabundle.tls-bypass' `
                                -Severity 'HIGH' -Confidence 'Inferred' `
                                -Title "$($t.Title) in $($entry.Name)" `
                                -File $loc -Evidence ($tm.Value.Substring(0,[Math]::Min(80,$tm.Value.Length))) -Cwe $t.Cwe `
                                -Description 'A Java TLS validation bypass marker. Decompile the class to confirm certificate/hostname checks are actually disabled.' `
                                -Fix 'Use the platform default TrustManager + HostnameVerifier; pin to your CA if needed.'
                            break
                        }
                    }
                }
            }
        } finally { $zip.Dispose() }
    }
}
