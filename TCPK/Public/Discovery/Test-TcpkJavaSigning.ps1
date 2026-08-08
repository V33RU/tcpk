function Test-TcpkJavaSigning {
<#
.SYNOPSIS
    JAR signing posture: unsigned archives, signed archives holding entries no signature
    covers, and signatures built on MD5 / SHA-1 digests.

.DESCRIPTION
    TCPK already reads META-INF/MANIFEST.MF for the Class-Path header (Test-TcpkJavaNativeLoad),
    but nothing in the tool asked the prior question: is the archive signed at all, and does the
    signature that is present actually cover what the archive contains. A JVM loads classes from
    a JAR whether or not the JAR is signed, so an application that loads archives out of a
    location a low-privilege user can write is the Java equivalent of DLL search-order hijacking:
    replace or extend the JAR and the new code runs with the application's identity.

    WHAT IS ACTUALLY READ. Each *.jar / *.war / *.ear under -Path is opened with
    [System.IO.Compression.ZipFile]::OpenRead and its entry table is walked without extracting
    anything. Three artifacts are parsed as text: META-INF/MANIFEST.MF, every META-INF/*.SF
    signature file, and the entry names themselves. The .SF and MANIFEST.MF are unfolded first
    (a MANIFEST continuation line begins with exactly one space and belongs to the previous
    line, so a name or digest longer than 72 bytes parses as garbage without unfolding).

    WHAT IS REPORTED.

      javasign.unsigned             No META-INF/*.SF and no META-INF/*.RSA|DSA|EC block file
                                    exist in the archive. Severity is decided by a MEASURED
                                    fact: if the current user can create a file in the
                                    directory holding the archive, the archive can be replaced
                                    or its entries edited with no detectable consequence, which
                                    is a real tamper primitive (HIGH). If the directory refused
                                    the write, the missing signature is a supply-chain and
                                    integrity gap without a demonstrated local write (MEDIUM).

      javasign.incomplete-coverage  A .SF exists, so the archive is signed, but content entries
                                    in the archive appear in NEITHER the .SF Name sections NOR
                                    the MANIFEST.MF Name sections. Those entries carry no digest
                                    from any signer. This is the classic mixed-signature JAR:
                                    the archive still presents as signed, jarsigner reports the
                                    signer, and the added entries load with no verification.

      javasign.weak-digest          The .SF or MANIFEST.MF declares MD5-Digest or SHA1-Digest
                                    (including the -Digest-Manifest and
                                    -Digest-Manifest-Main-Attributes forms). SHA-256 is the
                                    modern jarsigner default; MD5 and SHA-1 are collision-weak,
                                    so a chosen-prefix collision lets a different entry satisfy
                                    the recorded digest.

      javasign.signer-info          Inventory of the signature metadata that is present:
                                    signature file names, block-file names and their extension
                                    (RSA / DSA / EC), digest algorithms named, and the
                                    Created-By / Signature-Version main attributes.

      javasign.archive              One inventory record per archive, emitted whether the
                                    archive is signed or not, so "no finding" is never confused
                                    with "this archive was never opened".

    WHAT THIS CHECK DOES NOT DO, stated plainly because the gap matters. NO CRYPTOGRAPHIC
    VERIFICATION IS PERFORMED. Pure PowerShell cannot validate the PKCS#7 block file, the signer
    certificate chain, the certificate validity dates, or whether any recorded digest matches the
    bytes of the entry it names. That requires jarsigner (jarsigner -verify -verbose -certs) or
    an equivalent JCE implementation. Everything reported here is a STRUCTURAL fact about files
    and headers that were read: a file is present or absent, a header names an algorithm, an
    entry name appears in a Name section or does not. A JAR reported as signed here may carry an
    expired certificate, a self-signed certificate, a certificate from an untrusted issuer, or
    digests that do not match their entries. Run jarsigner before drawing a conclusion about
    signer identity or digest correctness.

    Further limits:

      * The covered set is the UNION of the .SF Name sections and the MANIFEST.MF Name sections.
        Using the union is deliberate and conservative: with a -Digest-Manifest header the .SF
        authenticates the whole manifest at once, so an entry listed only in the manifest is
        still covered, and flagging it would be a false positive. The consequence is that an
        entry present in the manifest but absent from the .SF of a signature that carries no
        -Digest-Manifest header is NOT reported here. Under-report, not over-report.
      * META-INF/* entries are excluded from the coverage comparison entirely. Signature files
        and the manifest are never listed in their own Name sections, and separating "legitimately
        unlisted signature metadata" from "unsigned resource that happens to live under META-INF"
        is not decidable from the entry table alone.
      * Directory entries (a name ending in '/') are excluded: directories are not signed.
      * An entry name containing a byte outside printable ASCII is counted but NOT compared.
        Manifest attribute values are UTF-8 and some tools escape non-ASCII names, so a literal
        comparison would report a covered entry as uncovered.
      * If the entry walk hit -MaxEntries the coverage comparison is suppressed and a Skipped
        record is emitted instead, because a truncated entry list produces uncovered entries that
        are an artifact of the cap rather than of the signature.
      * Writability is probed by CREATING and then DELETING a zero-byte file in the directory
        holding the archive. It answers "can the account running this audit write here", which is
        not the same question as "can a low-privilege principal write here": an elevated audit
        session can write almost anywhere, and a target copied to a staging directory carries the
        auditor's permissions rather than the vendor's. Confirm against a real installation, and
        cross-read the ACL findings (install-dir.*, jni.*) before filing. The probe is the only
        write this check performs; nothing is extracted, launched, or modified.

.PARAMETER Path
    A directory to walk recursively, or a single .jar / .war / .ear file.

.PARAMETER MaxArchives
    Cap on archives opened (default 250). Archives past the cap are counted and disclosed
    through a Skipped record.

.PARAMETER MaxEntries
    Per-archive cap on entries walked (default 20000). An archive that hits the cap has its
    coverage comparison suppressed and reports a Skipped record instead.

.OUTPUTS
    [TcpkFinding]
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [int]$MaxArchives = 250,
        [int]$MaxEntries = 20000
    )

    # ------------------------------------------------------------------ helpers ----

    # Bounded text read of a ZIP entry. ZipArchiveEntry.Length is the size DECLARED in the
    # archive directory, so a crafted archive can declare a small manifest and decompress to
    # gigabytes. The read is capped rather than trusting the declared size, and StreamReader.Read
    # can return short on a decompressing stream so it loops. Returns $null when unreadable,
    # which the caller must keep distinct from "read fine and was empty".
    function _ReadZipText {
        param($Entry, [int]$Cap = 1048576)
        $sr = $null
        try {
            $sr = New-Object System.IO.StreamReader($Entry.Open())
            $sb = New-Object System.Text.StringBuilder
            $buf = New-Object char[] 8192
            while ($sb.Length -lt $Cap) {
                $got = $sr.Read($buf, 0, $buf.Length)
                if ($got -le 0) { break }
                [void]$sb.Append($buf, 0, $got)
            }
            return $sb.ToString()
        } catch {
            return $null
        } finally {
            if ($sr) { try { $sr.Dispose() } catch { } }
        }
    }

    # Unfold a MANIFEST.MF / .SF. A continuation line starts with exactly one space and belongs
    # to the previous line. A blank line ends a section, so a space-prefixed line following one
    # is not a continuation and must not be joined backwards.
    function _UnfoldManifest {
        param([string]$Text)
        $out = New-Object 'System.Collections.Generic.List[string]'
        foreach ($ln in @($Text -split "`r`n|`n|`r")) {
            $last = ''
            if ($out.Count -gt 0) { $last = $out[$out.Count - 1] }
            if ($ln.StartsWith(' ') -and $out.Count -gt 0 -and $last -ne '') {
                $out[$out.Count - 1] = $last + $ln.Substring(1)
            } else {
                $out.Add($ln)
            }
        }
        return $out
    }

    # Parse an unfolded manifest into: the set of Name: values, the set of digest algorithms
    # named by any *-Digest / *-Digest-Manifest / *-Digest-Manifest-Main-Attributes header, and
    # the main-section attributes read before the first Name:.
    function _ParseManifest {
        param([string]$Text)
        $names = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal)
        $algs  = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
        $main  = @{}
        $seenName = $false
        foreach ($ln in (_UnfoldManifest -Text $Text)) {
            if (-not $ln) { continue }
            $nm = [regex]::Match($ln, '^Name\s*:\s*(.+?)\s*$', 'IgnoreCase')
            if ($nm.Success) {
                $seenName = $true
                [void]$names.Add($nm.Groups[1].Value)
                continue
            }
            $dm = [regex]::Match($ln, '^([A-Za-z0-9][A-Za-z0-9\-]*)-Digest(-Manifest(-Main-Attributes)?)?\s*:', 'IgnoreCase')
            if ($dm.Success) {
                [void]$algs.Add($dm.Groups[1].Value)
                continue
            }
            if (-not $seenName) {
                $am = [regex]::Match($ln, '^([A-Za-z0-9][A-Za-z0-9\-_]*)\s*:\s*(.*?)\s*$')
                if ($am.Success) { $main[$am.Groups[1].Value] = $am.Groups[2].Value }
            }
        }
        return [pscustomobject]@{ Names = $names; Algs = $algs; Main = $main }
    }

    # Can the account running this audit create a file in this directory. Measured, not derived
    # from an ACL: write a zero-byte file, then delete it. Returns $true only when the create
    # succeeded. A failure to delete afterwards is reported by the caller rather than swallowed,
    # because this check must not leave a file behind silently.
    function _ProbeDirWritable {
        param([string]$Dir)
        if ([string]::IsNullOrWhiteSpace($Dir)) {
            return [pscustomobject]@{ Writable = $false; Cleaned = $true; Probe = '' }
        }
        $probe = ''
        try {
            $probe = [System.IO.Path]::Combine($Dir, '_tcpk_jsign_' + [guid]::NewGuid().ToString('N').Substring(0, 10) + '.tmp')
            [System.IO.File]::WriteAllBytes($probe, (New-Object byte[] 0))
        } catch {
            return [pscustomobject]@{ Writable = $false; Cleaned = $true; Probe = '' }
        }
        $cleaned = $true
        try { [System.IO.File]::Delete($probe) } catch { $cleaned = $false }
        return [pscustomobject]@{ Writable = $true; Cleaned = $cleaned; Probe = $probe }
    }

    # ------------------------------------------------------------------ inventory ----

    $item = Get-Item -LiteralPath $Path -Force -ErrorAction SilentlyContinue
    if (-not $item) {
        New-TcpkFinding -Module 'static' -RuleId 'javasign.path-unreadable' `
            -Severity 'INFO' -Confidence 'Skipped' `
            -Title 'JAR signing: target path could not be read' `
            -File $Path `
            -Evidence "Get-Item failed for '$($Path)', so NO archive was examined for signing status." `
            -Description 'The scan target could not be opened, so the absence of signing findings says nothing about the target.'
        return
    }

    $exts = @('.jar', '.war', '.ear')
    $archives = @()
    if ($item.PSIsContainer) {
        $archives = @(Get-TcpkChildItemSafe -Path $item.FullName -File |
            Where-Object { $exts -contains "$($_.Extension)".ToLowerInvariant() })
    } elseif ($exts -contains "$($item.Extension)".ToLowerInvariant()) {
        $archives = @($item)
    }

    # No Java archives at all is not a failure to analyze, it is a target with nothing to
    # analyze. Staying silent here keeps this check off every non-Java target.
    if (-not $archives.Count) { return }

    try { Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction Stop } catch { }
    if (-not ('System.IO.Compression.ZipFile' -as [type])) {
        New-TcpkFinding -Module 'static' -RuleId 'javasign.zip-unavailable' `
            -Severity 'INFO' -Confidence 'Skipped' `
            -Title 'JAR signing: no archive could be opened (ZIP API unavailable)' `
            -File $item.FullName `
            -Evidence "System.IO.Compression.ZipFile is unavailable on this host, so $($archives.Count) Java archive(s) were NOT examined for signing status." `
            -Description 'The signing check could not run at all. This is a coverage gap, not a clean result.'
        return
    }

    $archivesSkipped = 0
    if ($archives.Count -gt $MaxArchives) {
        $archivesSkipped = $archives.Count - $MaxArchives
        $archives = @($archives | Select-Object -First $MaxArchives)
    }

    $weakAlgs   = @('MD5', 'SHA1', 'SHA-1')
    $blockRx    = '(?i)^META-INF/[^/]+\.(RSA|DSA|EC)$'
    $sfRx       = '(?i)^META-INF/[^/]+\.SF$'
    $manifestRx = '(?i)^META-INF/MANIFEST\.MF$'

    # Writability is probed once per directory, not once per archive: a lib folder with 200
    # JARs would otherwise mean 200 create/delete round trips against the same directory.
    $dirWritable = @{}
    $probeLeftovers = New-Object 'System.Collections.Generic.List[string]'
    $unreadableArchives = 0

    foreach ($arc in $archives) {
        $zip = $null
        try { $zip = [System.IO.Compression.ZipFile]::OpenRead($arc.FullName) } catch {
            $unreadableArchives++
            New-TcpkFinding -Module 'static' -RuleId 'javasign.archive-unreadable' `
                -Severity 'INFO' -Confidence 'Skipped' `
                -Title "JAR signing: archive could not be opened: $($arc.Name)" `
                -File $arc.FullName `
                -Evidence "ZipFile::OpenRead failed: $($_.Exception.Message). Signing status is UNKNOWN for this archive, not clean." `
                -AttributionBasis 'established-footprint' `
                -Description 'The archive could not be opened as a ZIP, so neither its signature files nor its entry list were read.'
            continue
        }

        try {
            $sfEntries    = New-Object 'System.Collections.Generic.List[object]'
            $blockEntries = New-Object 'System.Collections.Generic.List[string]'
            $manifestEnt  = $null
            $content      = New-Object 'System.Collections.Generic.List[string]'
            $entryCount   = 0
            $dirEntries   = 0
            $metaEntries  = 0
            $nonAscii     = 0
            $truncated    = $false

            foreach ($e in $zip.Entries) {
                if ($entryCount -ge $MaxEntries) { $truncated = $true; break }
                $entryCount++
                $fn = "$($e.FullName)"
                if ($fn.EndsWith('/') -or [string]::IsNullOrEmpty("$($e.Name)")) { $dirEntries++; continue }

                if ($fn -match $manifestRx) { $manifestEnt = $e; $metaEntries++; continue }
                if ($fn -match $sfRx)       { $sfEntries.Add($e); $metaEntries++; continue }
                if ($fn -match $blockRx)    { $blockEntries.Add($fn); $metaEntries++; continue }
                if ($fn -match '(?i)^META-INF/') { $metaEntries++; continue }

                # Non-ASCII entry names are counted but never compared: manifest values are
                # UTF-8 and some tools escape them, so a literal compare would invent a gap.
                if ($fn -match '[^\x20-\x7E]') { $nonAscii++; continue }
                $content.Add($fn)
            }

            $isSigned = ($sfEntries.Count -gt 0 -or $blockEntries.Count -gt 0)

            # ---- parse MANIFEST.MF ----
            $manNames = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal)
            $manAlgs  = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
            $manMain  = @{}
            $manRead  = $false
            if ($manifestEnt) {
                $mtxt = _ReadZipText -Entry $manifestEnt -Cap 4194304
                if ($null -ne $mtxt -and $mtxt.Length -gt 0) {
                    $p = _ParseManifest -Text $mtxt
                    $manNames = $p.Names
                    $manAlgs  = $p.Algs
                    $manMain  = $p.Main
                    $manRead  = $true
                }
            }

            # ---- parse every .SF ----
            $sfNames   = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal)
            $sfAlgs    = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
            $sfMain    = @{}
            $sfNamesList = New-Object 'System.Collections.Generic.List[string]'
            $sfUnread  = 0
            foreach ($sf in $sfEntries) {
                $sfNamesList.Add("$($sf.FullName)")
                $stxt = _ReadZipText -Entry $sf -Cap 4194304
                if ($null -eq $stxt -or $stxt.Length -eq 0) { $sfUnread++; continue }
                $p = _ParseManifest -Text $stxt
                foreach ($n in $p.Names) { [void]$sfNames.Add($n) }
                foreach ($a in $p.Algs)  { [void]$sfAlgs.Add($a) }
                foreach ($k in $p.Main.Keys) { if (-not $sfMain.ContainsKey($k)) { $sfMain[$k] = $p.Main[$k] } }
            }

            $allAlgs = New-Object 'System.Collections.Generic.List[string]'
            foreach ($a in $sfAlgs)  { if (-not $allAlgs.Contains($a)) { $allAlgs.Add($a) } }
            foreach ($a in $manAlgs) { if (-not $allAlgs.Contains($a)) { $allAlgs.Add($a) } }
            $algText = 'none'
            if ($allAlgs.Count -gt 0) { $algText = (@($allAlgs | Sort-Object) -join ', ') }

            $signedWord = 'UNSIGNED'
            if ($isSigned) { $signedWord = 'signed' }

            # ---------------------------------------------------- inventory (always) ----
            $invEvidence = ("entries=$($entryCount); content-entries=$($content.Count); " +
                "meta-inf-entries=$($metaEntries); directory-entries=$($dirEntries); " +
                "signature-files=$($sfEntries.Count); block-files=$($blockEntries.Count); " +
                "manifest=$(if ($manRead) { 'read' } else { 'absent-or-unreadable' }); " +
                "digest-algorithms=$($algText); " +
                "non-ascii-entry-names=$($nonAscii) (excluded from the coverage comparison)")
            New-TcpkFinding -Module 'static' -RuleId 'javasign.archive' `
                -Severity 'INFO' -Confidence 'Confirmed' `
                -Title "Java archive signing status ($($signedWord)): $($arc.Name)" `
                -File $arc.FullName `
                -Evidence $invEvidence `
                -Cwe @('CWE-347') `
                -AttributionBasis 'established-footprint' `
                -Description ('Inventory record for one Java archive, emitted whether or not anything ' +
                    'was wrong with its signing, so an archive that was opened and found clean is ' +
                    'distinguishable from one that was never opened. Structural reading only: no ' +
                    'signature was cryptographically verified.') `
                -Fix 'No action for the inventory record itself.'

            # -------------------------------------------------------- 1. unsigned ----
            if (-not $isSigned) {
                $adir = "$($arc.DirectoryName)"
                if (-not $dirWritable.ContainsKey($adir)) {
                    $dirWritable[$adir] = (_ProbeDirWritable -Dir $adir)
                }
                $w = $dirWritable[$adir]
                if ($w.Writable -and -not $w.Cleaned -and $w.Probe) { $probeLeftovers.Add($w.Probe) }

                $sev = 'MEDIUM'
                $writeWord = 'no (the account running this audit could not create a file there)'
                if ($w.Writable) {
                    $sev = 'HIGH'
                    $writeWord = 'yes (a zero-byte probe file was created and deleted there)'
                }

                New-TcpkFinding -Module 'static' -RuleId 'javasign.unsigned' `
                    -Severity $sev -Confidence 'Confirmed' `
                    -Title "Unsigned Java archive: $($arc.Name)" `
                    -File $arc.FullName `
                    -Evidence ("no META-INF/*.SF and no META-INF/*.RSA|DSA|EC block file among " +
                        "$($entryCount) entries ($($content.Count) content entries); " +
                        "containing directory '$($adir)' writable by current user: $($writeWord)") `
                    -Cwe @('CWE-347') `
                    -AttributionBasis 'established-footprint' `
                    -Description ('This archive carries no JAR signature at all: the entry table holds ' +
                        'neither a META-INF/*.SF signature file nor a META-INF/*.RSA / *.DSA / *.EC ' +
                        'block file. The JVM loads classes from an unsigned JAR exactly as it loads ' +
                        'them from a signed one, and nothing in the class loader will notice that an ' +
                        'entry changed. Where the directory holding the archive is writable, an ' +
                        'attacker replaces the JAR or edits an entry inside it and the modified code ' +
                        'runs with the application''s identity and privileges, which is the Java ' +
                        'equivalent of DLL search-order hijacking. NOTE the writability result is the ' +
                        'answer for the account running this audit, not proof that a low-privilege ' +
                        'principal can write there; an elevated session writes almost anywhere, and a ' +
                        'target copied to a staging directory carries the auditor''s permissions. ' +
                        'Cross-read the directory ACL findings and confirm against a real installation.') `
                    -Fix ('Sign the archive (jarsigner with a SHA-256 digest and a timestamp), and have ' +
                        'the application verify the signer before loading, either by launching with a ' +
                        'security policy that requires a signedBy principal or by checking ' +
                        'JarEntry.getCodeSigners() after reading the entry to end of stream. ' +
                        'Independently, restrict the directory ACL so only SYSTEM and Administrators ' +
                        'can write there.')
            }

            # ------------------------------------------- 2. incomplete coverage ----
            if ($isSigned -and $sfEntries.Count -gt 0) {
                if ($truncated -or ($sfUnread -gt 0) -or ($nonAscii -gt 0) -or (-not $manRead -and $sfNames.Count -eq 0)) {
                    $why = @()
                    if ($truncated)      { $why += "the entry walk stopped at -MaxEntries ($($MaxEntries)), so entries past the cap were never compared" }
                    if ($sfUnread -gt 0) { $why += "$($sfUnread) signature file(s) could not be read as text" }
                    if ($nonAscii -gt 0) { $why += "$($nonAscii) entry name(s) contain a byte outside printable ASCII and were excluded from the comparison, because manifest Name values are UTF-8 and some signing tools escape non-ASCII names, so a literal match would report false gaps" }
                    if (-not $manRead -and $sfNames.Count -eq 0) { $why += 'neither MANIFEST.MF nor any .SF yielded a Name section, so no covered set exists to compare against' }
                    New-TcpkFinding -Module 'static' -RuleId 'javasign.coverage-unevaluated' `
                        -Severity 'INFO' -Confidence 'Skipped' `
                        -Title "JAR signing: signature coverage not evaluated for $($arc.Name)" `
                        -File $arc.FullName `
                        -Evidence ("signature-files=$($sfEntries.Count); content-entries=$($content.Count); " +
                            "reason: " + ($why -join '; ') + ". Coverage is UNKNOWN for this archive, not complete.") `
                        -AttributionBasis 'established-footprint' `
                        -Description 'The archive is signed but the per-entry coverage comparison could not be made, so unsigned entries would not have been detected here.'
                } else {
                    # Covered = union of the .SF Name sections and the MANIFEST.MF Name sections.
                    # The union is deliberate: with a -Digest-Manifest header the .SF authenticates
                    # the whole manifest, so an entry listed only in the manifest IS covered and
                    # flagging it would be a false positive.
                    $uncovered = New-Object 'System.Collections.Generic.List[string]'
                    foreach ($c in $content) {
                        if ($sfNames.Contains($c)) { continue }
                        if ($manNames.Contains($c)) { continue }
                        $uncovered.Add($c)
                    }
                    if ($uncovered.Count -gt 0) {
                        $sample = (@($uncovered | Select-Object -First 8) -join ', ')
                        if ($uncovered.Count -gt 8) { $sample = "showing first 8 of $($uncovered.Count) -- " + $sample }
                        New-TcpkFinding -Module 'static' -RuleId 'javasign.incomplete-coverage' `
                            -Severity 'HIGH' -Confidence 'Confirmed' `
                            -Title "Signed Java archive contains entries no signature covers: $($arc.Name)" `
                            -File $arc.FullName `
                            -Evidence ("signature file(s): " + (@($sfNamesList) -join ', ') +
                                "; $($uncovered.Count) of $($content.Count) content entries have no digest " +
                                "entry in any .SF or in MANIFEST.MF: $($sample)") `
                            -Cwe @('CWE-347') `
                            -AttributionBasis 'established-footprint' `
                            -Description ('The archive is signed, so tooling and users see a signer, but the ' +
                                'listed entries appear in no Name section of any META-INF/*.SF and in no Name ' +
                                'section of META-INF/MANIFEST.MF. No digest records them, so no signature ' +
                                'covers them. This is the mixed-signature JAR: an attacker adds entries to a ' +
                                'signed archive, the signature over the original entries still validates, ' +
                                'jarsigner still names the original signer, and the added classes or resources ' +
                                'load with no verification at all. Java''s own verifier only rejects an entry ' +
                                'whose digest MISMATCHES; an entry with no digest is simply treated as ' +
                                'unsigned, and code that trusts "the JAR is signed" rather than checking ' +
                                'per-entry CodeSigners never sees the difference. The comparison here is ' +
                                'structural: entry names against Name sections. No digest was recomputed and ' +
                                'no certificate was validated. Confirm with: jarsigner -verify -verbose ' +
                                '<archive> and look for entries marked as unsigned in the listing.') `
                            -Fix ('Re-sign the complete archive so every entry gets a digest, and reject ' +
                                'partially signed archives in the build pipeline (jarsigner -verify -verbose ' +
                                'reports unsigned entries; fail the build on any). At load time do not treat ' +
                                '"the archive is signed" as an answer: read each entry to end of stream and ' +
                                'check JarEntry.getCodeSigners() for the expected signer before using the ' +
                                'class or resource.')
                    }
                }
            }

            # --------------------------------------------------- 3. weak digest ----
            if ($isSigned) {
                $weakFound = New-Object 'System.Collections.Generic.List[string]'
                foreach ($a in $sfAlgs) {
                    if ($weakAlgs -contains "$($a)".ToUpperInvariant()) { $weakFound.Add("$($a) (in .SF)") }
                }
                foreach ($a in $manAlgs) {
                    if ($weakAlgs -contains "$($a)".ToUpperInvariant()) { $weakFound.Add("$($a) (in MANIFEST.MF)") }
                }
                if ($weakFound.Count -gt 0) {
                    New-TcpkFinding -Module 'static' -RuleId 'javasign.weak-digest' `
                        -Severity 'MEDIUM' -Confidence 'Confirmed' `
                        -Title "Java archive signature uses a collision-weak digest: $($arc.Name)" `
                        -File $arc.FullName `
                        -Evidence ("weak digest headers declared: " + (@($weakFound) -join '; ') +
                            "; all digest algorithms named: $($algText)") `
                        -Cwe @('CWE-328') `
                        -AttributionBasis 'established-footprint' `
                        -Description ('The signature metadata declares an MD5-Digest or SHA1-Digest header ' +
                            '(the -Digest-Manifest and -Digest-Manifest-Main-Attributes forms count too). ' +
                            'Both algorithms are collision-weak: MD5 collisions are trivial and SHA-1 ' +
                            'chosen-prefix collisions are published and practical. An attacker who can ' +
                            'produce a colliding entry substitutes it for the signed one and the recorded ' +
                            'digest still matches, so the signature validates over content the signer never ' +
                            'approved. Modern JDKs restrict MD5 and SHA-1 in jar signing through ' +
                            'jdk.jar.disabledAlgorithms, so an archive signed this way may also simply fail ' +
                            'to verify on a current runtime and be treated as unsigned. This is read from ' +
                            'the header text only; no digest was recomputed.') `
                        -Fix ('Re-sign with SHA-256 or stronger: jarsigner -digestalg SHA-256 -sigalg ' +
                            'SHA256withRSA -tsa <timestamp-authority>. Keep jdk.jar.disabledAlgorithms at ' +
                            'its default so weak digests are refused rather than accepted.')
                }

                # ------------------------------------------- 4. signer inventory ----
                $blockKinds = New-Object 'System.Collections.Generic.List[string]'
                foreach ($b in $blockEntries) {
                    $bx = [System.IO.Path]::GetExtension($b)
                    if ($bx) { $bx = $bx.TrimStart('.').ToUpperInvariant() }
                    if ($bx -and -not $blockKinds.Contains($bx)) { $blockKinds.Add($bx) }
                }
                $createdBy = ''
                foreach ($k in @('Created-By', 'Signature-Version', 'Manifest-Version', 'Built-By', 'Build-Jdk')) {
                    $v = ''
                    if ($sfMain.ContainsKey($k))      { $v = "$($sfMain[$k])" }
                    elseif ($manMain.ContainsKey($k)) { $v = "$($manMain[$k])" }
                    if ($v) { $createdBy += "$($k)=$($v); " }
                }
                if (-not $createdBy) { $createdBy = 'no Created-By / Signature-Version main attribute present; ' }

                $blockText = 'none'
                if ($blockEntries.Count -gt 0) {
                    $blockText = (@($blockEntries | Select-Object -First 5) -join ', ') + " (type: " + (@($blockKinds) -join '/') + ")"
                }
                New-TcpkFinding -Module 'static' -RuleId 'javasign.signer-info' `
                    -Severity 'INFO' -Confidence 'Confirmed' `
                    -Title "Java archive signature metadata: $($arc.Name)" `
                    -File $arc.FullName `
                    -Evidence ("signature files: " + (@($sfNamesList | Select-Object -First 5) -join ', ') +
                        "; block files: $($blockText); digest algorithms: $($algText); " + $createdBy.TrimEnd(' ', ';')) `
                    -Cwe @('CWE-347') `
                    -AttributionBasis 'established-footprint' `
                    -Description ('Inventory of the signature metadata present in the archive. The block file ' +
                        'extension names the key type the signer used (RSA / DSA / EC) but its PKCS#7 content ' +
                        'was NOT parsed: the signer certificate, its issuer, its validity dates, and whether ' +
                        'any recorded digest matches its entry are all unverified here. Run jarsigner -verify ' +
                        '-verbose -certs <archive> to read the signer identity and validate the chain.') `
                    -Fix 'No action for the inventory record itself. Verify the signer identity with jarsigner before trusting it.'
            }
        } finally {
            if ($zip) { try { $zip.Dispose() } catch { } }
        }
    }

    # ------------------------------------------------------------------ coverage ----
    # Anything a bound removed from the scan is stated. A truncated scan that says nothing is
    # indistinguishable from a clean scan, which is the outcome this check must never produce.
    $notes = @()
    if ($archivesSkipped -gt 0) {
        $notes += "$($archivesSkipped) archive(s) past -MaxArchives ($($MaxArchives)) were not opened at all"
    }
    if ($unreadableArchives -gt 0) {
        $notes += "$($unreadableArchives) archive(s) could not be opened as a ZIP"
    }
    if ($probeLeftovers.Count -gt 0) {
        $notes += ("the writability probe could not delete $($probeLeftovers.Count) zero-byte file(s) it " +
            "created; remove them manually: " + (@($probeLeftovers | Select-Object -First 5) -join ', '))
    }
    if ($notes.Count -gt 0) {
        New-TcpkFinding -Module 'static' -RuleId 'javasign.scan-incomplete' `
            -Severity 'INFO' -Confidence 'Skipped' `
            -Title 'JAR signing: part of the scan did not run' `
            -File $item.FullName `
            -Evidence ('BOUNDED SCAN: ' + ($notes -join '; ') + '.') `
            -Description 'Some archives were not examined for signing status. Their signing posture is unknown, not clean.'
    }
}
