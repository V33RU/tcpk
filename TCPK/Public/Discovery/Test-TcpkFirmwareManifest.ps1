function Test-TcpkFirmwareManifest {
<#
.SYNOPSIS
    A55. Parse shipped firmware manifests (JSON) and report whether they carry a signature,
    an integrity hash, and downgrade protection.

.DESCRIPTION
    Static complement to Test-TcpkFirmwareImages (A49), Test-TcpkUpdateFlow (F02) and
    Invoke-TcpkFirmwarePlantProbe (K25). A firmware manifest is the JSON file the vendor
    updater reads to decide what to fetch and flash. If it does not carry a signature field
    (or a strong hash + separate authentication), a modified image will pass the client-side
    checks the app runs against it, and the plant-probe primitive is real.

    HOW A FILE QUALIFIES AS A MANIFEST. Not every .json is a manifest. This cmdlet requires
    the object to carry a version-like field AND a download-URL-like field. That is the
    minimum shape an updater needs to decide what to fetch, and it filters out settings
    files, telemetry blobs and unrelated JSON. A file matching only one half is skipped
    silently rather than reported.

    Recognised field aliases (all case-insensitive):
      version:  version, ver, releaseVersion, buildNumber, firmwareVersion
      url:      url, uri, downloadUrl, artifactUrl, packageUrl, firmwareUrl, imageUrl
      sig:      signature, sig, signatureUrl, sigUrl, ecdsa, rsaSig
      hash:     sha256, sha512, sha384, hash, checksum, integrity, md5, sha1, crc32, xxhash
      pubkey:   pubKey, publicKey, key, x5c, certificate, cert
      minver:   minVersion, minimumVersion, minSupportedVersion, previousVersion

    Rules:
      firmware.manifest.no-signature       HIGH    manifest has version + url, no signature
                                                   field of any recognised shape
      firmware.manifest.hash-only           MEDIUM  has an integrity hash but no signature.
                                                   Hash proves the image was transmitted
                                                   intact; it does not prove who created it.
                                                   A MITM (or a plant on the CDN) produces a
                                                   valid hash of the modified image and the
                                                   client accepts it.
      firmware.manifest.weak-hash           HIGH    the declared integrity algorithm is MD5,
                                                   SHA1 or CRC32. Collision-attackable, so
                                                   even the integrity guarantee is weak.
      firmware.manifest.plaintext-url       HIGH    the artifact URL is http://. A MITM can
                                                   substitute the payload regardless of what
                                                   the manifest says about signature or hash,
                                                   because the client fetches whatever comes
                                                   back on the plaintext connection.
      firmware.manifest.no-rollback-guard   LOW     manifest carries no minVersion / previousVersion
                                                   field. Downgrade is not prevented at the
                                                   manifest layer, so an old vulnerable
                                                   version can be re-installed.

    Confidence is Confirmed for what the JSON literally says. Whether the vendor updater
    actually verifies the signature at runtime is a separate concern (Test-TcpkUpdateFlow F02
    infers it from IL, Invoke-TcpkFirmwarePlantProbe K25 proves it dynamically).

.PARAMETER Path
    Install directory (or a single .json file).

.OUTPUTS
    [TcpkFinding]
#>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path)) { return }

    # Aliases. Matched case-insensitively against JSON keys.
    $verKeys    = @('version','ver','releaseversion','buildnumber','firmwareversion')
    $urlKeys    = @('url','uri','downloadurl','artifacturl','packageurl','firmwareurl','imageurl')
    $sigKeys    = @('signature','sig','signatureurl','sigurl','ecdsa','rsasig')
    $hashKeys   = @('sha256','sha512','sha384','hash','checksum','integrity','md5','sha1','crc32','xxhash')
    $pubkeyKeys = @('pubkey','publickey','key','x5c','certificate','cert')
    $minverKeys = @('minversion','minimumversion','minsupportedversion','previousversion')

    # Weak / collision-attackable integrity algorithms, matched against the winning KEY name.
    $weakKeys   = @('md5','sha1','crc32','xxhash')

    $item = Get-Item -LiteralPath $Path
    $files = @()
    if ($item.PSIsContainer) {
        try {
            $files = Get-ChildItem -LiteralPath $Path -Recurse -File -ErrorAction SilentlyContinue |
                Where-Object { $_.Extension -in '.json', '.manifest' -and $_.Length -lt 262144 -and $_.Length -gt 8 }
        } catch { return }
    } else {
        $files = @($item)
    }

    # A local helper: walk any node once, return a hash of {key -> value} of every leaf whose
    # value is a scalar. Depth-capped so a self-referential graph cannot loop, and array
    # elements only contribute their scalar leaves.
    function _FlattenLeaves {
        param($Node, [int]$Depth = 0)
        $out = @{}
        if ($null -eq $Node -or $Depth -gt 6) { return $out }
        if ($Node -is [System.Management.Automation.PSCustomObject]) {
            foreach ($p in $Node.PSObject.Properties) {
                $v = $p.Value
                if ($v -is [System.Management.Automation.PSCustomObject]) {
                    foreach ($kv in (_FlattenLeaves -Node $v -Depth ($Depth + 1)).GetEnumerator()) {
                        $out[$kv.Key] = $kv.Value
                    }
                } elseif ($v -is [System.Array]) {
                    foreach ($el in $v) {
                        if ($el -is [System.Management.Automation.PSCustomObject]) {
                            foreach ($kv in (_FlattenLeaves -Node $el -Depth ($Depth + 1)).GetEnumerator()) {
                                $out[$kv.Key] = $kv.Value
                            }
                        }
                    }
                    # Array key itself: record its length as a scalar so array-only fields (like x5c) are visible.
                    if (-not $out.ContainsKey($p.Name.ToLowerInvariant())) {
                        $out[$p.Name.ToLowerInvariant()] = "[array,$($v.Count)]"
                    }
                } else {
                    $out[$p.Name.ToLowerInvariant()] = "$v"
                }
            }
        }
        return $out
    }

    foreach ($f in $files) {
        $text = ''
        try { $text = [IO.File]::ReadAllText($f.FullName) } catch { continue }
        if (-not $text) { continue }
        # Quick prefilter: must look like JSON with at least a version or url key present in the text
        if ($text -notmatch '(?i)"(version|ver|firmware|url|uri|download|artifact|package|image|manifest|releases)"') { continue }

        $obj = $null
        try { $obj = ConvertFrom-Json $text } catch { continue }
        if (-not $obj) { continue }
        # Only object-rooted JSON qualifies. Arrays of releases (RELEASES lists) will still
        # match via the leaf walk because the array elements are inspected.
        $leaves = _FlattenLeaves -Node $obj

        # Manifest shape gate: version-like AND url-like both present.
        $hasVer = $false; $hasUrl = $false
        foreach ($k in $verKeys) { if ($leaves.ContainsKey($k)) { $hasVer = $true; break } }
        foreach ($k in $urlKeys) { if ($leaves.ContainsKey($k)) { $hasUrl = $true; break } }
        if (-not ($hasVer -and $hasUrl)) { continue }

        # Extract the specific values for evidence and for the plaintext-url check.
        $ver = ''; $url = ''
        foreach ($k in $verKeys) { if ($leaves.ContainsKey($k)) { $ver = "$($leaves[$k])"; break } }
        foreach ($k in $urlKeys) { if ($leaves.ContainsKey($k)) { $url = "$($leaves[$k])"; break } }

        $hasSig = $false; foreach ($k in $sigKeys)    { if ($leaves.ContainsKey($k)) { $hasSig = $true;    break } }
        $hasHash= $false; foreach ($k in $hashKeys)   { if ($leaves.ContainsKey($k)) { $hasHash = $true;   break } }
        $hasKey = $false; foreach ($k in $pubkeyKeys) { if ($leaves.ContainsKey($k)) { $hasKey = $true;    break } }
        $hasMinver = $false; foreach ($k in $minverKeys) { if ($leaves.ContainsKey($k)) { $hasMinver = $true; break } }

        # Rule: plaintext URL. Fires first because it makes every other rule below moot at the wire.
        if ($url -match '^http://') {
            New-TcpkFinding -Module 'discovery' -RuleId 'firmware.manifest.plaintext-url' `
                -Severity 'HIGH' -Confidence 'Confirmed' `
                -Title "Firmware manifest points at http:// artifact URL: $([IO.Path]::GetFileName($f.FullName))" `
                -File $f.FullName -Evidence "url=$url version=$ver" `
                -Cwe @('CWE-319','CWE-494') `
                -Description ("The firmware manifest at this path names an artifact URL over plaintext HTTP. " +
                    "A network attacker on the path can substitute the payload regardless of what the manifest " +
                    "says about signature or hash: the client fetches whatever comes back on the plaintext " +
                    "connection, and if the updater validates only the URL contents (not a pinned signature " +
                    "verified independently), the substituted image is accepted. Fires first because it makes " +
                    "any signature or hash rule below moot at the wire.") `
                -Fix 'Serve the artifact over HTTPS with certificate pinning on the client, and verify a vendor signature over the payload independently of transport.'
        }

        # Rule: no signature (and by transitivity, no signature verification is possible from this manifest alone)
        if (-not $hasSig) {
            New-TcpkFinding -Module 'discovery' -RuleId 'firmware.manifest.no-signature' `
                -Severity 'HIGH' -Confidence 'Confirmed' `
                -Title "Firmware manifest carries no signature field: $([IO.Path]::GetFileName($f.FullName))" `
                -File $f.FullName -Evidence "version=$ver url=$url hasHash=$hasHash hasPubKey=$hasKey" `
                -Cwe @('CWE-347','CWE-494') `
                -Description ("The manifest describes a firmware artifact (version + URL) but names no signature " +
                    "field under any recognised alias ($($sigKeys -join ', ')). If the vendor updater relies " +
                    "solely on this manifest to decide what to flash, there is no cryptographic authenticator " +
                    "over the payload. An attacker who can rewrite the manifest file (see firmware.image-writable " +
                    "and update.endpoint-in-writable-config) or the artifact on the wire can substitute the " +
                    "image. This does NOT prove the updater ignores signatures elsewhere (a pinned pubkey inside " +
                    "the binary, checked against a signature fetched via a separate URL, is common); it does " +
                    "prove the manifest itself is not the anchor.") `
                -Fix 'Add a signature field (base64 detached signature or signature URL) alongside the artifact URL. Pin the verifying public key inside the vendor binary. Reject any manifest whose signature does not verify.'
        } elseif ($hasHash -and -not $hasKey) {
            # Rule: weak-hash first (a weak algorithm is a strictly more serious finding than
            # missing pubkey), then hash-only otherwise.
            $winningKey = ''; $hashSample = ''
            foreach ($k in $hashKeys) {
                if ($leaves.ContainsKey($k)) {
                    $winningKey = $k
                    $hashSample = "$k=$($leaves[$k])"
                    break
                }
            }
            if ($weakKeys -contains $winningKey) {
                New-TcpkFinding -Module 'discovery' -RuleId 'firmware.manifest.weak-hash' `
                    -Severity 'HIGH' -Confidence 'Confirmed' `
                    -Title "Firmware manifest uses a collision-attackable hash: $([IO.Path]::GetFileName($f.FullName))" `
                    -File $f.FullName -Evidence "version=$ver url=$url $hashSample" `
                    -Cwe @('CWE-327') `
                    -Description ("The manifest declares an integrity algorithm ($winningKey) that is " +
                        "collision-attackable, so even if the client validates the hash, an attacker with " +
                        "collision-generation capability can substitute an image whose hash matches. This is " +
                        "practical for MD5 and SHA1 today.") `
                    -Fix 'Switch to SHA-256 or SHA-512 for integrity, and add a signature for authenticity.'
            } else {
                New-TcpkFinding -Module 'discovery' -RuleId 'firmware.manifest.hash-only' `
                    -Severity 'MEDIUM' -Confidence 'Confirmed' `
                    -Title "Firmware manifest has an integrity hash but no signature: $([IO.Path]::GetFileName($f.FullName))" `
                    -File $f.FullName -Evidence "version=$ver $hashSample" `
                    -Cwe @('CWE-345') `
                    -Description ("The manifest carries a hash ($hashSample) but no embedded public key " +
                        "under any recognised alias, so if the client verifies the payload the pubkey has to " +
                        "come from somewhere else (the binary, a config file, a fetched cert). Report reader " +
                        "should confirm that source is trusted and not a location an attacker can influence " +
                        "(a user-writable config, a signed-but-fetched-over-http trust anchor).") `
                    -Fix 'If the signature is verified against a pubkey embedded in the vendor binary, this is fine. If it is verified against a pubkey fetched from the same or a related URL, it is not, because the attacker who rewrites the payload also rewrites the pubkey.'
            }
        }

        # Rule: no downgrade guard. LOW alone; matters most when combined with the above.
        if (-not $hasMinver) {
            New-TcpkFinding -Module 'discovery' -RuleId 'firmware.manifest.no-rollback-guard' `
                -Severity 'LOW' -Confidence 'Confirmed' `
                -Title "Firmware manifest declares no minVersion / previousVersion: $([IO.Path]::GetFileName($f.FullName))" `
                -File $f.FullName -Evidence "version=$ver" `
                -Cwe @('CWE-1329') `
                -Description ("The manifest names a version but no minVersion / previousVersion / " +
                    "minSupportedVersion field, so the updater cannot use the manifest alone to refuse an " +
                    "older, known-vulnerable release. Combined with a manifest-substitution primitive (see " +
                    "firmware.manifest.no-signature and update.endpoint-in-writable-config), an attacker can " +
                    "push an older version whose CVE they know how to exploit.") `
                -Fix 'Add a minVersion (or a monotonic anti-rollback counter) to the manifest, and refuse any candidate whose version is below the currently installed one.'
        }
    }
}
