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
    # CWE-502: deserialization of untrusted data.
    # ObjectInputStream appears in .class bytecode constant pools as the class reference string.
    # ObjectInputFilter / setObjectInputFilter are the Java 9+ mitigations.
    $deserClassRx  = '(?i)(java/io/ObjectInputStream|Ljava/io/ObjectInputStream;|readObject|readUnshared)'
    $deserFilterRx = '(?i)(ObjectInputFilter|setObjectInputFilter)'
    # Known gadget-chain libraries bundled as nested JARs inside the app archive.
    # These do not cause a vulnerability on their own but raise the severity of any
    # ObjectInputStream finding because ready-made gadget chains (ysoserial) exist for them.
    $gadgetLibRx   = '(?i)(commons-collections-[0-9]|commons-beanutils-[0-9]|' +
                     'spring-core-[1-4]\.|spring-webmvc-[1-4]\.|groovy-[0-2]\.|groovy-all-[0-2]\.|' +
                     'xalan-[0-9]|hibernate-core-[0-5]\.)'

    foreach ($arc in $archives) {
        New-TcpkFinding -Module 'static' -RuleId 'javabundle.archive' `
            -Severity 'INFO' -Confidence 'Confirmed' `
            -Title "Java archive: $($arc.Name)" -File $arc.FullName -Evidence "size=$($arc.Length)" `
            -Description 'A Java jar/war/ear archive. Its entries are scanned for secrets and insecure-TLS markers; decompile with Jadx/JD-GUI to read the source.'

        $zip = $null
        try { $zip = [System.IO.Compression.ZipFile]::OpenRead($arc.FullName) } catch { continue }
        $deserFound  = $false
        $filterFound = $false
        $gadgetFound = [System.Collections.Generic.List[string]]::new()
        try {
            $n = 0
            foreach ($entry in $zip.Entries) {
                if ($n -ge $MaxEntries) { break }

                # Track nested gadget-chain JARs even without reading their content.
                if ($entry.FullName.ToLowerInvariant().EndsWith('.jar') -and
                    $entry.FullName -match $gadgetLibRx) {
                    $gadgetFound.Add($entry.FullName)
                    continue
                }

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
                if ($isClass) {
                    if ($text -match $deserClassRx)  { $deserFound  = $true }
                    if ($text -match $deserFilterRx) { $filterFound = $true }
                }
            }

            # ---- Per-archive deserialization findings ----

            foreach ($gl in $gadgetFound) {
                New-TcpkFinding -Module 'static' -RuleId 'javabundle.gadget-lib' `
                    -Severity 'HIGH' -Confidence 'Inferred' `
                    -Title "Known deserialization gadget-chain library bundled: $gl" `
                    -File $arc.FullName `
                    -Evidence "Nested JAR: $gl" `
                    -Cwe @('CWE-502','CWE-829') `
                    -Description ('A library with known ysoserial gadget chains is bundled inside ' +
                        'this archive. Gadget libraries (commons-collections, spring-core, groovy, ' +
                        'xalan, hibernate) are not vulnerabilities by themselves, but any ' +
                        'ObjectInputStream entry point reachable from untrusted input becomes ' +
                        'immediately exploitable for remote code execution using off-the-shelf tooling. ' +
                        'Confirm whether ObjectInputStream is used in this app and whether its input ' +
                        'originates from an untrusted source (network, file, IPC).') `
                    -Fix ('Remove gadget-chain libraries from the classpath if unused. Upgrade to a ' +
                        'version that has addressed the gadget chain (commons-collections >= 3.2.2 / ' +
                        '4.1). Add ObjectInputFilter (Java 9+) or use a serialization kill-switch to ' +
                        'allowlist expected types. Prefer JSON/protobuf over Java serialization for ' +
                        'network protocols.')
            }

            if ($deserFound -and -not $filterFound) {
                $sev = if ($gadgetFound.Count) { 'CRITICAL' } else { 'HIGH' }
                $gadgetNote = if ($gadgetFound.Count) {
                    " Gadget-chain libraries are also bundled ($($gadgetFound.Count) found), making exploitation with ysoserial immediately practical."
                } else { '' }
                New-TcpkFinding -Module 'static' -RuleId 'javabundle.deser-no-filter' `
                    -Severity $sev -Confidence 'Inferred' `
                    -Title "Java deserialization (ObjectInputStream) without ObjectInputFilter in $($arc.Name)" `
                    -File $arc.FullName `
                    -Evidence "ObjectInputStream present; ObjectInputFilter / setObjectInputFilter absent from all scanned class files" `
                    -Cwe @('CWE-502') `
                    -Description ('One or more class files reference ObjectInputStream (the native Java ' +
                        'deserialization API) and no ObjectInputFilter was found. ObjectInputFilter ' +
                        '(Java 9+) restricts which classes can be deserialized, blocking gadget chains. ' +
                        'Without it, any untrusted byte stream reaching readObject() / readUnshared() ' +
                        'can trigger arbitrary class instantiation.' + $gadgetNote + ' ' +
                        'Decompile with Jadx to trace the ObjectInputStream entry point. Confirm ' +
                        'whether the stream originates from a network socket, file, or IPC channel ' +
                        'under partial attacker control.') `
                    -Fix ('Add ObjectInputFilter on every ObjectInputStream before the first ' +
                        'readObject() call. Use an allowlist of expected types: ' +
                        'stream.setObjectInputFilter(info -> info.serialClass() != null && ' +
                        'ALLOWED.contains(info.serialClass().getName()) ? ALLOWED : REJECTED). ' +
                        'For new code, replace Java serialization with JSON (Jackson) or ' +
                        'protobuf. See JEP 290 and https://owasp.org/www-community/vulnerabilities/Deserialization_of_untrusted_data')
            }
        } finally { $zip.Dispose() }
    }
}
